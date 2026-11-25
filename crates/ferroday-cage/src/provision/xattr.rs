//! Extended attributes a tree carries, as the steps that lay one tree into
//! another read them and restate them for the tree they land in.
//!
//! Most attributes are bytes the kernel stores and hands back unread. Two kinds
//! name an id inside their value, and an id means a different user on each side
//! of an identity map. A POSIX access control list names a user or a group in
//! each of its named entries, and a file capability of the namespaced form
//! names the user it is rooted at. The kernel translates both through the user
//! namespace of whoever reads or writes them, so a value read on one side of a
//! map and written on the other has to be restated first: the copy into a root
//! reads its source as the calling user and writes inside the map, and the
//! extractor reads an archive an export wrote inside the map and writes as the
//! calling user. [`Acl`] and [`capability_mapped`] are that restatement, each
//! given the translation its caller holds.
//!
//! A list naming an id the translation has no answer for cannot be carried. It
//! cannot be dropped either, without care. Where a list carries a mask, the
//! group bits of the entry's mode are the mask, not the owning group's own
//! entry, so an entry laid down with its mode and without its list gives the
//! owning group whatever the mask allows: `group::---,mask::rw-` arrives as
//! `g+rw`. [`Acl::narrowed`] is the answer both callers give: the list without
//! its named entries, its owning group's entry cut back by the mask, which is
//! what that group was allowed and no more.

use std::ffi::CStr;
use std::os::fd::BorrowedFd;

use rustix::io::Errno;

/// The attribute holding an entry's POSIX access control list.
pub(super) const ACCESS_ACL: &CStr = c"system.posix_acl_access";

/// The attribute holding the list a directory's new entries inherit.
pub(super) const DEFAULT_ACL: &CStr = c"system.posix_acl_default";

/// The attribute holding a file's capabilities.
pub(super) const CAPABILITY: &CStr = c"security.capability";

/// How many times a listing or a value is read again after it grew between
/// asking its size and reading it.
const XATTR_ATTEMPTS: u32 = 3;

/// The version every list the kernel stores and accepts carries.
const ACL_VERSION: u32 = 2;

/// The tags of a list's entries, as `<linux/posix_acl.h>` numbers them.
const ACL_USER_OBJ: u16 = 0x01;
const ACL_USER: u16 = 0x02;
const ACL_GROUP_OBJ: u16 = 0x04;
const ACL_GROUP: u16 = 0x08;
const ACL_MASK: u16 = 0x10;
const ACL_OTHER: u16 = 0x20;

/// The id an entry that names no one carries.
const ACL_UNDEFINED_ID: u32 = u32::MAX;

/// The revision field of a capability value, and the two revisions the kernel
/// accepts: the plain form, and the namespaced form that names its root.
const VFS_CAP_REVISION_MASK: u32 = 0xFF00_0000;
const VFS_CAP_REVISION_2: u32 = 0x0200_0000;
const VFS_CAP_REVISION_3: u32 = 0x0300_0000;

/// The length of each revision's value.
const VFS_CAP_V2_LEN: usize = 20;
const VFS_CAP_V3_LEN: usize = 24;

/// Extended attributes by name, each with its value.
pub(super) type Named = Vec<(Vec<u8>, Vec<u8>)>;

/// Where an entry's attributes are read from.
pub(super) enum Holder<'a> {
    /// A descriptor of the entry itself, which a regular file and a directory
    /// are read through.
    Fd(BorrowedFd<'a>),
    /// A path naming the entry without following a link at it. A symbolic link
    /// and a named pipe are read this way: neither can be opened to be asked,
    /// a link without being followed and a pipe without waking a writer
    /// blocked on its other end.
    Path(&'a CStr),
}

impl Holder<'_> {
    fn list_size(&self) -> Result<usize, Errno> {
        match self {
            Holder::Fd(fd) => rustix::fs::flistxattr_query(fd),
            Holder::Path(path) => rustix::fs::llistxattr_query(*path),
        }
    }

    fn list(&self, buffer: &mut [u8]) -> Result<usize, Errno> {
        match self {
            Holder::Fd(fd) => rustix::fs::flistxattr(fd, buffer),
            Holder::Path(path) => rustix::fs::llistxattr(*path, buffer),
        }
    }

    fn value_size(&self, name: &CStr) -> Result<usize, Errno> {
        match self {
            Holder::Fd(fd) => rustix::fs::fgetxattr_query(fd, name),
            Holder::Path(path) => rustix::fs::lgetxattr_query(*path, name),
        }
    }

    fn value(&self, name: &CStr, buffer: &mut [u8]) -> Result<usize, Errno> {
        match self {
            Holder::Fd(fd) => rustix::fs::fgetxattr(fd, name, buffer),
            Holder::Path(path) => rustix::fs::lgetxattr(*path, name, buffer),
        }
    }
}

/// Every attribute `holder` carries that the caller can read, by name, with its
/// value, sorted by name.
///
/// Sorted so a copy of one tree is one sequence of frames, as a walk sorts its
/// entries. An attribute removed between the listing and the read is passed
/// over, and a filesystem without extended attributes carries none.
pub(super) fn read_all(holder: Holder<'_>) -> Result<Named, Errno> {
    let listing = read_sized(|| holder.list_size(), |buffer| holder.list(buffer))?;
    let mut attributes = Vec::new();
    for name in listing.split(|byte| *byte == 0) {
        if name.is_empty() {
            continue;
        }
        let mut terminated = name.to_vec();
        terminated.push(0);
        let Ok(name_c) = CStr::from_bytes_with_nul(&terminated) else {
            continue;
        };
        match read_sized(
            || holder.value_size(name_c),
            |buffer| holder.value(name_c, buffer),
        ) {
            Ok(value) => attributes.push((name.to_vec(), value)),
            Err(Errno::NODATA) => {}
            Err(errno) => return Err(errno),
        }
    }
    attributes.sort();
    Ok(attributes)
}

/// The mode `mode` of the entry `fd` holds, cut back to its access control
/// list's narrowing where it carries a list ([`Acl::narrowed`]).
///
/// For a step that lays an entry down without its list: where the list has a
/// mask, the mode's group bits are the mask, and the mode alone would give the
/// owning group what the mask allows rather than what the list gave it. An
/// entry without a list, or on a filesystem without lists, keeps its mode.
#[cfg(any(feature = "debian", feature = "alpine"))]
pub(super) fn narrowed_mode(fd: BorrowedFd<'_>, mode: u32) -> Result<u32, Errno> {
    let value = match read_sized(
        || rustix::fs::fgetxattr_query(fd, ACCESS_ACL),
        |buffer| rustix::fs::fgetxattr(fd, ACCESS_ACL, buffer),
    ) {
        Ok(value) => value,
        Err(Errno::NODATA) => return Ok(mode),
        Err(errno) => return Err(errno),
    };
    Ok(match Acl::parse(&value) {
        Ok(Some(acl)) => acl.narrowed().mode_of(mode),
        Ok(None) | Err(_) => mode,
    })
}

/// Reads a listing or a value whose length `query` answers, through `read`,
/// which fills the buffer it is given and answers the length it filled.
///
/// The length can change between the asking and the reading, which the read
/// answers with `ERANGE`; it is asked again a few times before that is
/// reported. A filesystem without extended attributes has none to read.
///
/// The buffer is never empty, even where the length asked was zero: the kernel
/// takes a read into an empty buffer for another question about the length,
/// and answers it rather than refusing it, so something that grew in between
/// would read as nothing at all.
fn read_sized(
    mut query: impl FnMut() -> Result<usize, Errno>,
    mut read: impl FnMut(&mut [u8]) -> Result<usize, Errno>,
) -> Result<Vec<u8>, Errno> {
    for _ in 0..XATTR_ATTEMPTS {
        let size = match query() {
            Ok(size) => size,
            Err(Errno::NOTSUP) => return Ok(Vec::new()),
            Err(errno) => return Err(errno),
        };
        let mut buffer = vec![0u8; size.max(1)];
        match read(&mut buffer) {
            Ok(read) => {
                buffer.truncate(read);
                return Ok(buffer);
            }
            Err(Errno::RANGE) => continue,
            Err(errno) => return Err(errno),
        }
    }
    Err(Errno::RANGE)
}

/// One entry of an access control list: whom it is for, and what it allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AclEntry {
    tag: u16,
    perm: u16,
    id: u32,
}

/// Why an attribute value is not an access control list this crate carries.
///
/// A list is carried where the kernel stores it and libacl's checker passes
/// it. The two disagree in one place: the kernel stores a list naming one user
/// or group twice, where libacl calls it invalid. No tool writes one, and what
/// the kernel makes of it is nothing a reader of an archive should need to
/// know, so it is refused with the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AclFlaw {
    /// A version other than 2, or a value too short to state one.
    Version,
    /// A length that is not a whole number of entries.
    Length,
    /// A tag no list holds.
    Tag,
    /// Permission bits beyond reading, writing and executing.
    Permissions,
    /// Entries out of the order the kernel takes them in, a required entry
    /// missing or repeated, or named entries without a mask.
    Shape,
    /// One user or group named twice.
    Duplicate,
    /// A named entry holding the id that stands for no one. It is what the
    /// kernel reports, to a reader in a user namespace, for an id the
    /// namespace's map does not hold: it reports the entry, and in place of
    /// its id the id it refuses to store.
    UnmappedId,
}

#[cfg(feature = "tarball")]
impl AclFlaw {
    /// The flaw as the end of a sentence saying why a list was refused.
    pub(super) fn reason(self) -> &'static str {
        match self {
            AclFlaw::Version => "it is not a version-2 list",
            AclFlaw::Length => "its length is not a whole number of entries",
            AclFlaw::Tag => "an entry has a tag no list holds",
            AclFlaw::Permissions => "an entry grants more than reading, writing and executing",
            AclFlaw::Shape => {
                "its entries are out of order, a required entry is missing or repeated, or it \
                 names a user or group without a mask"
            }
            AclFlaw::Duplicate => "it names one user or group twice",
            AclFlaw::UnmappedId => "it names a user or group by the id that stands for no one",
        }
    }
}

/// Where entries of `tag` stand in a list the kernel takes: the owner, the
/// named users, the owning group, the named groups, the mask, then everyone
/// else. `None` for a tag no list holds.
fn rank(tag: u16) -> Option<u8> {
    match tag {
        ACL_USER_OBJ => Some(0),
        ACL_USER => Some(1),
        ACL_GROUP_OBJ => Some(2),
        ACL_GROUP => Some(3),
        ACL_MASK => Some(4),
        ACL_OTHER => Some(5),
        _ => None,
    }
}

/// `entries` as the list they make, held to the rules a carried list keeps
/// ([`AclFlaw`]), or why they make none.
///
/// The kernel takes the tags in [`rank`] order and refuses any other, and
/// that is checked as it stands. Within the named users, and within the named
/// groups, it takes the ids in any order and stores them as given; libacl
/// writes them ascending, and so does this, so that a list is one sequence of
/// bytes whatever order its writer kept. An entry that names no one carries
/// an id the kernel ignores, written here as the one libacl writes,
/// [`ACL_UNDEFINED_ID`].
fn canonical(mut entries: Vec<AclEntry>) -> Result<Vec<AclEntry>, AclFlaw> {
    let mut previous = 0;
    let mut counts = [0usize; 6];
    for entry in &mut entries {
        let rank = rank(entry.tag).ok_or(AclFlaw::Tag)?;
        if entry.perm & !0o7 != 0 {
            return Err(AclFlaw::Permissions);
        }
        if rank < previous {
            return Err(AclFlaw::Shape);
        }
        previous = rank;
        counts[usize::from(rank)] += 1;
        if matches!(entry.tag, ACL_USER | ACL_GROUP) {
            if entry.id == ACL_UNDEFINED_ID {
                return Err(AclFlaw::UnmappedId);
            }
        } else {
            entry.id = ACL_UNDEFINED_ID;
        }
    }
    let [owner, users, group, groups, masks, other] = counts;
    if owner != 1 || group != 1 || other != 1 || masks > 1 || (users + groups > 0 && masks == 0) {
        return Err(AclFlaw::Shape);
    }
    entries.sort_by_key(|entry| (rank(entry.tag), entry.id));
    let repeated = entries.windows(2).any(|pair| {
        matches!(pair[0].tag, ACL_USER | ACL_GROUP)
            && pair[0].tag == pair[1].tag
            && pair[0].id == pair[1].id
    });
    if repeated {
        return Err(AclFlaw::Duplicate);
    }
    Ok(entries)
}

/// A POSIX access control list, as the `system.posix_acl_*` attributes hold
/// one: a version, then each entry as a tag, its permission bits, and an id.
///
/// Every list is one [`canonical`] makes: one the kernel stores and libacl's
/// checker passes, in the order libacl writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Acl {
    entries: Vec<AclEntry>,
}

impl Acl {
    /// Reads a list from an attribute's value.
    ///
    /// `Ok(None)` is a value holding no entry, the version alone or nothing at
    /// all, which the kernel takes as no list: setting it removes the one
    /// there is. An error says why the value is no list this crate carries
    /// ([`AclFlaw`]). The kernel refuses every such value but one naming a
    /// user or group twice.
    pub(super) fn parse(value: &[u8]) -> Result<Option<Acl>, AclFlaw> {
        if value.is_empty() {
            return Ok(None);
        }
        let (version, rest) = value.split_first_chunk::<4>().ok_or(AclFlaw::Version)?;
        if u32::from_le_bytes(*version) != ACL_VERSION {
            return Err(AclFlaw::Version);
        }
        let (entries, remainder) = rest.as_chunks::<8>();
        if !remainder.is_empty() {
            return Err(AclFlaw::Length);
        }
        if entries.is_empty() {
            return Ok(None);
        }
        let entries = entries
            .iter()
            .map(|entry| AclEntry {
                tag: u16::from_le_bytes([entry[0], entry[1]]),
                perm: u16::from_le_bytes([entry[2], entry[3]]),
                id: u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]),
            })
            .collect();
        canonical(entries).map(|entries| Some(Acl { entries }))
    }

    /// The list as an attribute's value.
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut value = Vec::with_capacity(4 + 8 * self.entries.len());
        value.extend_from_slice(&ACL_VERSION.to_le_bytes());
        for entry in &self.entries {
            value.extend_from_slice(&entry.tag.to_le_bytes());
            value.extend_from_slice(&entry.perm.to_le_bytes());
            value.extend_from_slice(&entry.id.to_le_bytes());
        }
        value
    }

    #[cfg(feature = "tarball")]
    /// The list in the text form a `SCHILY.acl.access` or `SCHILY.acl.default`
    /// pax record holds, as GNU tar writes it: an entry a line, its tag spelled
    /// out, its permissions as three letters, and a named user or group by its
    /// id.
    ///
    /// GNU tar applies a list from this form and no other, and passes over the
    /// attribute's own value ([`ACCESS_ACL`]) where it finds both. The ids are
    /// the ones the list holds rather than names looked up anywhere, so the
    /// record means what the attribute means and an export is a function of
    /// the tree alone.
    pub(super) fn text(&self) -> Vec<u8> {
        let mut text = Vec::new();
        for entry in &self.entries {
            let tag: &[u8] = match entry.tag {
                ACL_USER_OBJ | ACL_USER => b"user",
                ACL_GROUP_OBJ | ACL_GROUP => b"group",
                ACL_MASK => b"mask",
                _ => b"other",
            };
            text.extend_from_slice(tag);
            text.push(b':');
            if matches!(entry.tag, ACL_USER | ACL_GROUP) {
                text.extend_from_slice(entry.id.to_string().as_bytes());
            }
            text.push(b':');
            for (bit, letter) in [(0o4, b'r'), (0o2, b'w'), (0o1, b'x')] {
                text.push(if entry.perm & bit != 0 { letter } else { b'-' });
            }
            text.push(b'\n');
        }
        text
    }

    /// The list with each named entry's id read through `uid` or `gid`, or
    /// `None` where either has no answer for one, or the answers make no list:
    /// two ids read as one.
    pub(super) fn mapped(
        &self,
        uid: impl Fn(u32) -> Option<u32>,
        gid: impl Fn(u32) -> Option<u32>,
    ) -> Option<Acl> {
        let mut entries = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let id = match entry.tag {
                ACL_USER => uid(entry.id)?,
                ACL_GROUP => gid(entry.id)?,
                _ => entry.id,
            };
            entries.push(AclEntry { id, ..*entry });
        }
        canonical(entries).ok().map(|entries| Acl { entries })
    }

    /// The list without its named entries and its mask, the owning group's
    /// entry cut back by the mask: what the owner, the owning group, and
    /// everyone else were each allowed under the full list, and nothing the
    /// named entries alone allowed.
    pub(super) fn narrowed(&self) -> Acl {
        let mask = self
            .entries
            .iter()
            .find(|entry| entry.tag == ACL_MASK)
            .map_or(0o7, |entry| entry.perm);
        let entries = self
            .entries
            .iter()
            .filter(|entry| matches!(entry.tag, ACL_USER_OBJ | ACL_GROUP_OBJ | ACL_OTHER))
            .map(|entry| match entry.tag {
                ACL_GROUP_OBJ => AclEntry {
                    perm: entry.perm & mask,
                    ..*entry
                },
                _ => *entry,
            })
            .collect();
        Acl { entries }
    }

    /// The permission bits of `mode` as this list states them: its owner's,
    /// owning group's (or mask's, where it has one), and everyone else's
    /// entries, which is how the kernel shows a list in a mode. The bits above
    /// them, set-user-ID, set-group-ID and sticky, are `mode`'s own.
    pub(super) fn mode_of(&self, mode: u32) -> u32 {
        let perm = |tag: u16| {
            self.entries
                .iter()
                .find(|entry| entry.tag == tag)
                .map(|entry| u32::from(entry.perm & 0o7))
        };
        let user = perm(ACL_USER_OBJ).unwrap_or((mode >> 6) & 0o7);
        let group = perm(ACL_MASK)
            .or_else(|| perm(ACL_GROUP_OBJ))
            .unwrap_or((mode >> 3) & 0o7);
        let other = perm(ACL_OTHER).unwrap_or(mode & 0o7);
        (mode & !0o777) | (user << 6) | (group << 3) | other
    }
}

/// What a file capability comes to once its root is read through a
/// translation.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Restated {
    /// The value to give the file.
    Value(Vec<u8>),
    /// The capability is rooted at an id the translation has no answer for.
    Unmapped,
    /// The value is not one the kernel accepts as a capability.
    Malformed,
}

/// The file capability `value` with the user it is rooted at read through
/// `uid`.
///
/// The plain form names no root and is restated as it stands: written from
/// inside a user namespace, the kernel roots it at that namespace's root,
/// which is the most a namespace's root can grant. The namespaced form names
/// its root, which `uid` reads across the map. Any other revision, the
/// obsolete first one among them, is one the kernel refuses to store.
pub(super) fn capability_mapped(value: &[u8], uid: impl Fn(u32) -> Option<u32>) -> Restated {
    let Some(magic) = value.first_chunk::<4>() else {
        return Restated::Malformed;
    };
    match (
        u32::from_le_bytes(*magic) & VFS_CAP_REVISION_MASK,
        value.len(),
    ) {
        (VFS_CAP_REVISION_2, VFS_CAP_V2_LEN) => Restated::Value(value.to_vec()),
        (VFS_CAP_REVISION_3, VFS_CAP_V3_LEN) => {
            let root = u32::from_le_bytes([value[20], value[21], value[22], value[23]]);
            match uid(root) {
                Some(root) => {
                    let mut restated = value.to_vec();
                    restated[20..24].copy_from_slice(&root.to_le_bytes());
                    Restated::Value(restated)
                }
                None => Restated::Unmapped,
            }
        }
        _ => Restated::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A list from `(tag, perm, id)` triples.
    fn list(entries: &[(u16, u16, u32)]) -> Acl {
        Acl {
            entries: entries
                .iter()
                .map(|&(tag, perm, id)| AclEntry { tag, perm, id })
                .collect(),
        }
    }

    /// The attribute value of `(tag, perm, id)` triples, in the order given.
    fn value(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut value = ACL_VERSION.to_le_bytes().to_vec();
        for (tag, perm, id) in entries {
            value.extend_from_slice(&tag.to_le_bytes());
            value.extend_from_slice(&perm.to_le_bytes());
            value.extend_from_slice(&id.to_le_bytes());
        }
        value
    }

    const NONE: u32 = ACL_UNDEFINED_ID;

    #[test]
    fn a_list_reads_back_as_it_was_encoded() {
        let acl = list(&[
            (ACL_USER_OBJ, 6, NONE),
            (ACL_USER, 4, 1000),
            (ACL_GROUP_OBJ, 0, NONE),
            (ACL_GROUP, 6, 27),
            (ACL_MASK, 6, NONE),
            (ACL_OTHER, 0, NONE),
        ]);
        assert_eq!(Acl::parse(&acl.encode()), Ok(Some(acl)));
        // Another version, or a stray byte, is not a list the kernel stores.
        let mut other_version = value(&[]);
        other_version[0] = 1;
        assert_eq!(Acl::parse(&other_version), Err(AclFlaw::Version));
        let mut ragged = value(&[(ACL_USER_OBJ, 6, NONE)]);
        ragged.push(0);
        assert_eq!(Acl::parse(&ragged), Err(AclFlaw::Length));
    }

    /// Each value below is one the kernel was given through `setxattr` on
    /// Linux 7.2, and the verdict beside it is what the kernel did with it,
    /// except where the comment says libacl's checker decides.
    #[test]
    fn a_list_is_carried_where_the_kernel_stores_it_and_libacl_passes_it() {
        let minimal = [
            (ACL_USER_OBJ, 6, NONE),
            (ACL_GROUP_OBJ, 4, NONE),
            (ACL_OTHER, 0, NONE),
        ];
        assert_eq!(Acl::parse(&value(&minimal)), Ok(Some(list(&minimal))));
        // The version alone, or nothing, removes a list rather than setting one.
        assert_eq!(Acl::parse(&value(&[])), Ok(None));
        assert_eq!(Acl::parse(b""), Ok(None));
        // A mask with no named entry is a list of its own.
        assert!(matches!(
            Acl::parse(&value(&[
                (ACL_USER_OBJ, 6, NONE),
                (ACL_GROUP_OBJ, 0, NONE),
                (ACL_MASK, 6, NONE),
                (ACL_OTHER, 0, NONE),
            ])),
            Ok(Some(_)),
        ));
        let refused = [
            (
                AclFlaw::Shape,
                value(&[
                    (ACL_USER_OBJ, 6, NONE),
                    (ACL_OTHER, 0, NONE),
                    (ACL_GROUP_OBJ, 4, NONE),
                ]),
            ),
            (
                AclFlaw::Shape,
                value(&[
                    (ACL_USER_OBJ, 6, NONE),
                    (ACL_MASK, 6, NONE),
                    (ACL_USER, 4, 1000),
                    (ACL_GROUP_OBJ, 4, NONE),
                    (ACL_OTHER, 0, NONE),
                ]),
            ),
            (
                AclFlaw::Shape,
                value(&[
                    (ACL_USER_OBJ, 6, NONE),
                    (ACL_USER, 4, 1000),
                    (ACL_GROUP_OBJ, 4, NONE),
                    (ACL_OTHER, 0, NONE),
                ]),
            ),
            (
                AclFlaw::Shape,
                value(&[
                    (ACL_USER_OBJ, 6, NONE),
                    (ACL_USER_OBJ, 4, NONE),
                    (ACL_GROUP_OBJ, 4, NONE),
                    (ACL_OTHER, 0, NONE),
                ]),
            ),
            (
                AclFlaw::Shape,
                value(&[(ACL_USER_OBJ, 6, NONE), (ACL_GROUP_OBJ, 4, NONE)]),
            ),
            (
                AclFlaw::Permissions,
                value(&[
                    (ACL_USER_OBJ, 0o16, NONE),
                    (ACL_GROUP_OBJ, 4, NONE),
                    (ACL_OTHER, 0, NONE),
                ]),
            ),
            (
                AclFlaw::Tag,
                value(&[
                    (ACL_USER_OBJ, 6, NONE),
                    (ACL_GROUP_OBJ, 4, NONE),
                    (0x40, 4, NONE),
                    (ACL_OTHER, 0, NONE),
                ]),
            ),
            (
                AclFlaw::UnmappedId,
                value(&[
                    (ACL_USER_OBJ, 6, NONE),
                    (ACL_USER, 4, NONE),
                    (ACL_GROUP_OBJ, 4, NONE),
                    (ACL_MASK, 6, NONE),
                    (ACL_OTHER, 0, NONE),
                ]),
            ),
            // The kernel stores this one; libacl's checker calls it invalid.
            (
                AclFlaw::Duplicate,
                value(&[
                    (ACL_USER_OBJ, 6, NONE),
                    (ACL_USER, 4, 1000),
                    (ACL_USER, 2, 1000),
                    (ACL_GROUP_OBJ, 4, NONE),
                    (ACL_MASK, 6, NONE),
                    (ACL_OTHER, 0, NONE),
                ]),
            ),
        ];
        for (flaw, refused) in refused {
            assert_eq!(Acl::parse(&refused), Err(flaw), "{refused:02x?}");
        }
    }

    #[test]
    fn a_list_is_read_in_the_order_libacl_writes() {
        // The kernel stores named ids in whatever order they come, and ignores
        // the id of an entry that names no one; neither changes the list.
        let read = Acl::parse(&value(&[
            (ACL_USER_OBJ, 6, 0),
            (ACL_USER, 4, 1001),
            (ACL_USER, 4, 1000),
            (ACL_GROUP_OBJ, 4, 0),
            (ACL_MASK, 6, 7),
            (ACL_OTHER, 0, 0),
        ]));
        assert_eq!(
            read,
            Ok(Some(list(&[
                (ACL_USER_OBJ, 6, NONE),
                (ACL_USER, 4, 1000),
                (ACL_USER, 4, 1001),
                (ACL_GROUP_OBJ, 4, NONE),
                (ACL_MASK, 6, NONE),
                (ACL_OTHER, 0, NONE),
            ]))),
        );
    }

    #[test]
    fn a_translation_that_reads_two_ids_as_one_restates_no_list() {
        let acl = list(&[
            (ACL_USER_OBJ, 6, NONE),
            (ACL_USER, 4, 1000),
            (ACL_USER, 4, 1001),
            (ACL_GROUP_OBJ, 4, NONE),
            (ACL_MASK, 6, NONE),
            (ACL_OTHER, 0, NONE),
        ]);
        assert_eq!(acl.mapped(|_| Some(5), Some), None);
        // An answer that reorders the ids reorders the list with them.
        let flipped = acl
            .mapped(|id| Some(2001 - id), Some)
            .expect("both ids map");
        assert_eq!(
            flipped,
            list(&[
                (ACL_USER_OBJ, 6, NONE),
                (ACL_USER, 4, 1000),
                (ACL_USER, 4, 1001),
                (ACL_GROUP_OBJ, 4, NONE),
                (ACL_MASK, 6, NONE),
                (ACL_OTHER, 0, NONE),
            ]),
        );
    }

    #[cfg(feature = "tarball")]
    #[test]
    fn a_list_is_written_as_gnu_tar_writes_its_text() {
        // GNU tar 1.35's `SCHILY.acl.access` for this list, with numbers where
        // it wrote names.
        let acl = list(&[
            (ACL_USER_OBJ, 6, NONE),
            (ACL_USER, 4, 0),
            (ACL_USER, 5, 4242),
            (ACL_GROUP_OBJ, 4, NONE),
            (ACL_GROUP, 6, 4243),
            (ACL_MASK, 7, NONE),
            (ACL_OTHER, 0, NONE),
        ]);
        let text = acl.text();
        assert_eq!(
            text,
            b"user::rw-\nuser:0:r--\nuser:4242:r-x\ngroup::r--\ngroup:4243:rw-\nmask::rwx\nother::---\n",
        );
    }

    #[test]
    fn only_the_named_entries_ids_are_read_through_the_translation() {
        let acl = list(&[
            (ACL_USER_OBJ, 7, ACL_UNDEFINED_ID),
            (ACL_USER, 5, 100_042),
            (ACL_GROUP_OBJ, 5, ACL_UNDEFINED_ID),
            (ACL_GROUP, 5, 100_027),
            (ACL_MASK, 5, ACL_UNDEFINED_ID),
            (ACL_OTHER, 0, ACL_UNDEFINED_ID),
        ]);
        let inside = |id: u32| id.checked_sub(100_000);
        let mapped = acl.mapped(inside, inside).expect("every id maps");
        assert_eq!(
            mapped,
            list(&[
                (ACL_USER_OBJ, 7, ACL_UNDEFINED_ID),
                (ACL_USER, 5, 42),
                (ACL_GROUP_OBJ, 5, ACL_UNDEFINED_ID),
                (ACL_GROUP, 5, 27),
                (ACL_MASK, 5, ACL_UNDEFINED_ID),
                (ACL_OTHER, 0, ACL_UNDEFINED_ID),
            ]),
        );
        // One id without an answer is a list that cannot be restated.
        assert_eq!(acl.mapped(inside, |_| None), None);
    }

    #[test]
    fn a_narrowed_list_gives_the_owning_group_what_the_mask_left_it() {
        // `group::---,mask::rw-` shows as group `rw-` in the mode, which is the
        // mask, not the group. Laid down without the list, the mode alone would
        // give the owning group `rw-`; narrowed, it keeps `---`.
        let acl = list(&[
            (ACL_USER_OBJ, 6, ACL_UNDEFINED_ID),
            (ACL_USER, 6, 1000),
            (ACL_GROUP_OBJ, 0, ACL_UNDEFINED_ID),
            (ACL_MASK, 6, ACL_UNDEFINED_ID),
            (ACL_OTHER, 0, ACL_UNDEFINED_ID),
        ]);
        assert_eq!(acl.mode_of(0o4000), 0o4660, "the full list shows its mask");
        let narrowed = acl.narrowed();
        assert_eq!(narrowed.mode_of(0o4660), 0o4600);
        assert_eq!(
            narrowed,
            list(&[
                (ACL_USER_OBJ, 6, ACL_UNDEFINED_ID),
                (ACL_GROUP_OBJ, 0, ACL_UNDEFINED_ID),
                (ACL_OTHER, 0, ACL_UNDEFINED_ID),
            ]),
        );
        // A group entry the mask allows more than keeps its own.
        let wider_mask = list(&[
            (ACL_USER_OBJ, 7, ACL_UNDEFINED_ID),
            (ACL_GROUP_OBJ, 5, ACL_UNDEFINED_ID),
            (ACL_MASK, 7, ACL_UNDEFINED_ID),
            (ACL_OTHER, 5, ACL_UNDEFINED_ID),
        ]);
        assert_eq!(wider_mask.narrowed().mode_of(0), 0o755);
    }

    #[test]
    fn a_capability_is_restated_with_its_root_read_through_the_translation() {
        let mut plain = VFS_CAP_REVISION_2.to_le_bytes().to_vec();
        plain.extend_from_slice(&[0x00, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let unmapped = |_: u32| None;
        assert_eq!(
            capability_mapped(&plain, unmapped),
            Restated::Value(plain.clone()),
            "the plain form names no root",
        );

        let mut rooted = VFS_CAP_REVISION_3.to_le_bytes().to_vec();
        rooted[0] = 1; // the effective flag
        rooted.extend_from_slice(&[0x00, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        rooted.extend_from_slice(&100_000u32.to_le_bytes());
        let Restated::Value(restated) = capability_mapped(&rooted, |id| id.checked_sub(100_000))
        else {
            panic!("the root maps");
        };
        assert_eq!(&restated[..20], &rooted[..20]);
        assert_eq!(&restated[20..], &0u32.to_le_bytes());
        assert_eq!(capability_mapped(&rooted, unmapped), Restated::Unmapped);

        // The first revision, and a value cut short, are not ones the kernel
        // stores.
        let mut obsolete = 0x0100_0000u32.to_le_bytes().to_vec();
        obsolete.extend_from_slice(&[0; 8]);
        assert_eq!(capability_mapped(&obsolete, unmapped), Restated::Malformed);
        assert_eq!(
            capability_mapped(&rooted[..22], unmapped),
            Restated::Malformed
        );
    }

    #[test]
    fn a_value_that_grew_after_a_zero_length_answer_is_read_whole() {
        // The kernel answers a read into an empty buffer with the length, as
        // it answers the query, so an attribute empty when its length was
        // asked and longer when it was read reads as nothing.
        let value = b"grown";
        let mut asked = 0;
        let read = read_sized(
            || {
                asked += 1;
                Ok(if asked == 1 { 0 } else { value.len() })
            },
            |buffer| {
                if buffer.is_empty() {
                    return Ok(value.len());
                }
                if buffer.len() < value.len() {
                    return Err(Errno::RANGE);
                }
                buffer[..value.len()].copy_from_slice(value);
                Ok(value.len())
            },
        );
        assert_eq!(read, Ok(value.to_vec()));
    }
}
