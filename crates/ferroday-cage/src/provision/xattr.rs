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
//! calling user. A list is read, judged and restated by `file_acl`, and a
//! capability by [`capability_mapped`], each given the translation its caller
//! holds.
//!
//! A list naming an id the translation has no answer for cannot be carried as
//! it stands. `Acl::map_ids_partial` carries it without the entries that name
//! such an id, which takes nothing from anyone the translation answers for.
//!
//! A list that cannot be carried at all, on a filesystem without lists or by a
//! step that lays an entry down without its attributes, cannot be dropped
//! either, without care. Where a list carries a mask, the group bits of the
//! entry's mode are the mask, not the owning group's own entry, so an entry
//! laid down with its mode and without its list gives the owning group
//! whatever the mask allows: `group::---,mask::rw-` arrives as `g+rw`.
//! [`narrowed`] is the answer there: the mode cut back to the list's
//! narrowing, which gives the owning group what it was allowed and no more.

use std::ffi::CStr;
use std::os::fd::BorrowedFd;

use file_acl::Acl;
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
/// list's narrowing where it carries a list ([`narrowed`]).
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
    Ok(match file_acl::xattr::decode(&value) {
        Ok(Some(acl)) => narrowed(&acl, mode),
        Ok(None) | Err(_) => mode,
    })
}

/// `mode` with its permission bits those of `list`'s narrowing
/// (`Acl::narrowed`): its owner's and everyone else's entries, and its owning
/// group's cut back by the mask. The bits above them, set-user-ID,
/// set-group-ID and sticky, are `mode`'s own.
///
/// It is the mode an entry is given in place of a list it cannot carry. The
/// list's own mode bits would not do: where it has a mask, its group bits are
/// the mask's, which can allow the owning group more than its entry did.
pub(super) fn narrowed(list: &Acl, mode: u32) -> u32 {
    (mode & !0o777) | list.narrowed().mode_bits()
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
    use file_acl::{Entry, Perm, Qualifier};

    /// A list from `(qualifier, permission bits)` pairs.
    fn list(entries: &[(Qualifier, u16)]) -> Acl {
        Acl::new(
            entries
                .iter()
                .map(|&(qualifier, bits)| {
                    Entry::new(qualifier, Perm::from_bits(bits).expect("permission bits"))
                })
                .collect(),
        )
        .expect("a valid list")
    }

    #[test]
    fn the_attributes_named_are_the_ones_lists_are_read_from() {
        assert_eq!(ACCESS_ACL.to_str(), Ok(file_acl::xattr::ACCESS));
        assert_eq!(DEFAULT_ACL.to_str(), Ok(file_acl::xattr::DEFAULT));
    }

    #[test]
    fn a_narrowed_mode_gives_the_owning_group_what_the_mask_left_it() {
        // `group::---,mask::rw-` shows as group `rw-` in the mode, which is the
        // mask, not the group. Laid down without the list, the mode alone would
        // give the owning group `rw-`; narrowed, it keeps `---`.
        let acl = list(&[
            (Qualifier::UserObj, 6),
            (Qualifier::User(1000), 6),
            (Qualifier::GroupObj, 0),
            (Qualifier::Mask, 6),
            (Qualifier::Other, 0),
        ]);
        assert_eq!(acl.mode_bits(), 0o660, "the full list shows its mask");
        assert_eq!(narrowed(&acl, 0o4660), 0o4600);
        // A group entry the mask allows more than keeps its own.
        let wider_mask = list(&[
            (Qualifier::UserObj, 7),
            (Qualifier::GroupObj, 5),
            (Qualifier::Mask, 7),
            (Qualifier::Other, 5),
        ]);
        assert_eq!(narrowed(&wider_mask, 0o1000), 0o1755);
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
