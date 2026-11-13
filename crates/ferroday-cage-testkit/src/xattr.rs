//! Extended attributes a test sets on a tree and reads back: the kernel's
//! encoding of a POSIX access control list, one attribute set or read without
//! following a link, and whether a filesystem holds the kinds a test sets.

use std::path::Path;

/// The id an access control list entry holds where its tag names no one in
/// particular: the owner's, the owning group's, the mask's, and others'.
pub const NO_ID: u32 = u32::MAX;

/// The attribute a POSIX access control list is held in.
pub const ACCESS_ACL: &str = "system.posix_acl_access";

/// The attribute a directory's default access control list is held in.
pub const DEFAULT_ACL: &str = "system.posix_acl_default";

/// A POSIX access control list's attribute value, from `(tag, permissions,
/// id)` entries in the order given: the version, 2, then each entry's tag,
/// permissions and id, little-endian.
///
/// The tags are the owner, 0x01, a named user, 0x02, the owning group, 0x04,
/// a named group, 0x08, the mask, 0x10, and others, 0x20. The kernel takes the
/// entries sorted by tag and then by id, and [`NO_ID`] is the id of each entry
/// that names no one.
pub fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
    let mut value = 2u32.to_le_bytes().to_vec();
    for (tag, permissions, id) in entries {
        value.extend_from_slice(&tag.to_le_bytes());
        value.extend_from_slice(&permissions.to_le_bytes());
        value.extend_from_slice(&id.to_le_bytes());
    }
    value
}

/// Sets the attribute `name` on `path`, not following a link, and reports
/// whether it took: a filesystem may hold no attribute of its kind.
pub fn set(path: &Path, name: &str, value: &[u8]) -> bool {
    rustix::fs::lsetxattr(path, name, value, rustix::fs::XattrFlags::empty()).is_ok()
}

/// The value of the attribute `name` on `path`, not following a link, or
/// `None` where it holds none.
///
/// # Panics
///
/// When the attribute cannot be read for any reason but its absence.
pub fn get(path: &Path, name: &str) -> Option<Vec<u8>> {
    // The most an attribute's value can hold.
    let mut value = vec![0u8; 64 * 1024];
    match rustix::fs::lgetxattr(path, name, &mut value[..]) {
        Ok(read) => {
            value.truncate(read);
            Some(value)
        }
        Err(rustix::io::Errno::NODATA) => None,
        Err(errno) => panic!("reading {name} on {}: {errno}", path.display()),
    }
}

/// Whether the filesystem `dir` is on holds POSIX access control lists,
/// asked of a file created in `dir` and removed again.
pub fn holds_acls(dir: &Path) -> bool {
    holds(
        dir,
        ACCESS_ACL,
        &acl(&[(0x01, 6, NO_ID), (0x04, 4, NO_ID), (0x20, 4, NO_ID)]),
    )
}

/// Whether the filesystem `dir` is on holds `user.` attributes, asked of a
/// file created in `dir` and removed again.
pub fn holds_user_attributes(dir: &Path) -> bool {
    holds(dir, "user.probe", b"held")
}

/// Whether a file created in `dir` takes the attribute `name` at `value`.
fn holds(dir: &Path, name: &str, value: &[u8]) -> bool {
    let probe = dir.join(".xattr-probe");
    std::fs::write(&probe, b"").expect("a probe file is created");
    let held = set(&probe, name, value);
    std::fs::remove_file(&probe).expect("the probe file is removed");
    held
}
