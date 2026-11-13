//! The bounds the tree-walking helpers share.
//!
//! The copy-in and export protocols each have a producer and a consumer that
//! agree on how deep a tree may be, how long a name may be, and how large the
//! buffers on either side of the pipe are. Producer and consumer live in
//! different modules — one post-fork, one on the host — so a value declared
//! twice is a value that can drift, and a drift is silent: a host that walks
//! deeper than the child accepts sends a frame the child refuses mid-tree.
//!
//! Each bound is therefore declared once, here, and both sides read it from
//! this module.

/// How deep a tree walk descends before refusing the tree.
///
/// A real rootfs nests a dozen levels; a tree deeper than this is pathological.
/// The bound is what keeps the child's recursion stack finite — it walks with
/// no allocator — and what keeps the host's frame stack an array rather than a
/// growable one.
pub(crate) const MAX_DEPTH: usize = 128;

/// The largest length of a single path component, the kernel's `NAME_MAX`.
///
/// A directory entry's name fits this; a longer one is refused, not truncated,
/// so a name that cannot be recreated faithfully is never recreated wrongly.
pub(crate) const NAME_MAX: usize = 255;

/// The file-data streaming buffer, on both sides of the pipe.
pub(crate) const DATA_BUF: usize = 65536;

/// The symbolic-link target and hardlink anchor buffer; either is at most
/// `PATH_MAX`.
///
/// A sandbox's own symlink op shares it: the build refuses a target that does
/// not fit, and the launch reads a link already at the op's path back into a
/// buffer of this size to compare it.
pub(crate) const LINK_BUF: usize = 4096;

/// The longest name an extended attribute may have, the kernel's
/// `XATTR_NAME_MAX`.
pub(crate) const XATTR_NAME_MAX: usize = 255;

/// The largest value an extended attribute may hold, and the longest list of
/// names one entry may carry: the kernel's `XATTR_SIZE_MAX` and
/// `XATTR_LIST_MAX`, which are the same.
///
/// The export's child reads a list and a value into buffers of this size, and
/// the copy-in child reads a value into one.
pub(crate) const XATTR_SIZE_MAX: usize = 65536;
