//! Writing a change set into a tree.
//!
//! An apply checks every change it is given before it writes anything,
//! stages what it writes in a directory of its own at the target's top, and
//! only then gives each entry its name. See [`Apply`].

use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, SeekFrom, Stat};
use rustix::io::Errno;

use super::super::ProvisionError;
use super::super::containment;
use super::super::copyin::read_names;
use super::super::xattr::{self, Holder};
use super::{Change, ChangeKind, ChangeSet, EntryKind};
use crate::mechanism::delete_tree;

/// A path an [`Apply`] refuses to change.
///
/// Either a path from the target's top, which covers what lies beneath it, or
/// a name at any depth, which covers every entry of that name and what lies
/// beneath each. A change touches one where it lies at or beneath it, where it
/// removes or replaces a directory the target holds it in, and where it leaves
/// anything but a directory above a protected path: a symbolic link added at
/// `.github` would have `.github/workflows` resolve wherever it points.
///
/// Names are compared without regard to ASCII case, as a directory whose
/// filesystem looks names up case-insensitively, such as an ext4 directory
/// with casefolding on, resolves `.GIT` to `.git`. The other folds such a
/// directory makes, the long `ſ` to `s` among them, are not.
///
/// [`defaults`](Self::defaults) is the set an apply starts from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Protected {
    /// A path from the target's top, and what lies beneath it.
    Path(PathBuf),
    /// Every entry of this name, at any depth, and what lies beneath each.
    Name(OsString),
}

impl Protected {
    /// A path from the target's top, relative, such as `.github/workflows`.
    pub fn path(path: impl AsRef<Path>) -> Protected {
        Protected::Path(path.as_ref().to_path_buf())
    }

    /// A name at any depth, such as `.git`.
    pub fn name(name: impl AsRef<OsStr>) -> Protected {
        Protected::Name(name.as_ref().to_os_string())
    }

    /// The paths where a tool acts on what it finds before the user runs
    /// anything of the project's, which an apply refuses to change unless the
    /// caller says otherwise:
    ///
    /// - `.git`, at any depth: git reads a repository's configuration and runs
    ///   its hooks, and `git status` alone runs `core.fsmonitor`;
    /// - `.envrc`, at any depth: direnv loads it on entering the directory;
    /// - `.husky`, at any depth: husky points git's `core.hooksPath` into it,
    ///   so git runs what it holds at the next commit;
    /// - mise's `mise.toml`, `.mise.toml`, `mise.local.toml` and
    ///   `.mise.local.toml`, at any depth, and at the top its `mise`, `.mise`
    ///   and `.config/mise` directories and `.config/mise.toml` and
    ///   `.config/mise.local.toml`: mise reads them on entering the directory,
    ///   and runs the hooks and tasks they define;
    /// - lefthook's configuration at the top: `lefthook` and `lefthook-local`
    ///   in each format it reads (`.yml`, `.yaml`, `.toml`, `.json` and
    ///   `.jsonc`), bare, with a leading dot, and under `.config`, and its
    ///   `.lefthook` and `.lefthook-local` script directories, which the hooks
    ///   it installs in git run;
    /// - `.vscode` and `.idea` at the top: an editor runs the tasks they hold
    ///   on opening the project;
    /// - `.github/workflows` and `.gitlab-ci.yml` at the top: a service runs
    ///   them with the repository's secrets;
    /// - the shell's startup files at the top, for a tree that is a home
    ///   directory: `.profile`, bash's `.bashrc`, `.bash_profile`,
    ///   `.bash_login` and `.bash_logout`, zsh's `.zshenv`, `.zprofile`,
    ///   `.zshrc`, `.zlogin` and `.zlogout`, and fish's `.config/fish`.
    pub fn defaults() -> Vec<Protected> {
        let names = [
            ".git",
            ".envrc",
            ".husky",
            "mise.toml",
            ".mise.toml",
            "mise.local.toml",
            ".mise.local.toml",
        ]
        .map(Protected::name);
        let paths = [
            "mise",
            ".mise",
            ".config/mise",
            ".config/mise.toml",
            ".config/mise.local.toml",
            ".lefthook",
            ".lefthook-local",
            ".vscode",
            ".idea",
            ".github/workflows",
            ".gitlab-ci.yml",
            ".profile",
            ".bashrc",
            ".bash_profile",
            ".bash_login",
            ".bash_logout",
            ".zshenv",
            ".zprofile",
            ".zshrc",
            ".zlogin",
            ".zlogout",
            ".config/fish",
        ]
        .map(Protected::path);
        let lefthook = ["lefthook", "lefthook-local"].into_iter().flat_map(|stem| {
            ["yml", "yaml", "toml", "json", "jsonc"]
                .into_iter()
                .flat_map(move |format| {
                    [
                        format!("{stem}.{format}"),
                        format!(".{stem}.{format}"),
                        format!(".config/{stem}.{format}"),
                    ]
                })
                .map(Protected::path)
        });
        names.into_iter().chain(paths).chain(lefthook).collect()
    }

    /// Whether `change` touches this, as far as the paths alone tell: what the
    /// target holds beneath a directory a change removes is looked for there.
    ///
    /// A change above a protected path touches it where it removes what is
    /// there, or leaves anything but a directory: a symbolic link a run adds
    /// at `.github` would have the protected `.github/workflows` resolve into
    /// whatever directory the link names.
    fn touched_by(&self, change: &Change) -> bool {
        let path = change.path();
        match self {
            Protected::Path(protected) => {
                lies_within(path, protected)
                    || (lies_within(protected, path)
                        && (removes(change.kind()) || change.now() != Some(EntryKind::Directory)))
            }
            Protected::Name(name) => path
                .components()
                .any(|component| same_name(component.as_os_str(), name)),
        }
    }

    /// Whether the entry at `path`, beneath a directory a change removes, is
    /// this or lies beneath it.
    fn holds(&self, path: &Path) -> bool {
        match self {
            Protected::Path(protected) => lies_within(path, protected),
            Protected::Name(name) => path
                .components()
                .any(|component| same_name(component.as_os_str(), name)),
        }
    }
}

/// Whether two names name one entry in a directory that looks names up
/// without regard to ASCII case, as [`Protected`] compares them.
fn same_name(a: &OsStr, b: &OsStr) -> bool {
    a.as_bytes().eq_ignore_ascii_case(b.as_bytes())
}

/// Whether `path` is `within` or lies beneath it, component by component as
/// [`same_name`] compares them: [`Path::starts_with`] without regard to ASCII
/// case.
fn lies_within(path: &Path, within: &Path) -> bool {
    let mut components = path.components();
    within.components().all(|wanted| {
        components
            .next()
            .is_some_and(|got| same_name(got.as_os_str(), wanted.as_os_str()))
    })
}

impl fmt::Display for Protected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protected::Path(path) => write!(f, "the path {path:?}"),
            Protected::Name(name) => write!(f, "the name {name:?} at any depth"),
        }
    }
}

/// Whether a change of `kind` takes away what the target holds at its path.
fn removes(kind: ChangeKind) -> bool {
    matches!(kind, ChangeKind::Removed | ChangeKind::Replaced)
}

/// Whether a symbolic link at `path`, from the target's top, whose target is
/// `target`, leads out of the target, as [Links that lead
/// out](Apply#links-that-lead-out) states: `target` is absolute, climbs above
/// the top from the directory `path` lies in, or climbs after a name.
///
/// Read from the text alone, so the answer does not depend on what the target
/// holds when it is asked. Every `..` before the first name climbs from a
/// directory the apply reaches without following a link, and a link it holds
/// along the way, the target's own or one this apply writes, is judged where
/// it lies. The target is split here rather than by `path::tree_components`,
/// which refuses the `..` this counts.
fn leads_out(path: &Path, target: &[u8]) -> bool {
    if target.first() == Some(&b'/') {
        return true;
    }
    let mut depth = path.components().count().saturating_sub(1);
    let mut named = false;
    for component in target.split(|byte| *byte == b'/') {
        match component {
            b"" | b"." => {}
            b".." if named => return true,
            b".." => match depth.checked_sub(1) {
                Some(above) => depth = above,
                None => return true,
            },
            _ => named = true,
        }
    }
    false
}

/// Writes chosen changes of a [`ChangeSet`] into a target directory, usually
/// the lower the run started from.
///
/// Made with [`ChangeSet::apply`], configured, then [`run`](Self::run).
///
/// ```no_run
/// use ferroday_cage::Overlay;
/// use ferroday_cage::provision::{ChangeSet, Remove};
///
/// # fn main() -> Result<(), ferroday_cage::provision::ProvisionError> {
/// let tree = "/home/user/project";
/// let overlay = Overlay::new()
///     .lower(tree)
///     .upper("/home/user/.cache/runs/1/upper");
/// let changes = ChangeSet::read(&overlay)?;
/// changes
///     .apply(tree)
///     .filter(|change| !change.path().starts_with("target"))
///     .run()?;
/// Remove::overlay_upper("/home/user/.cache/runs/1/upper").run()?;
/// # Ok(())
/// # }
/// ```
///
/// # What is refused
///
/// Every chosen change is checked before anything is written, and one that is
/// refused refuses the whole apply with [`ProvisionError::ApplyRefused`],
/// which names each refused path and why ([`ApplyRefusal`]). The caller's
/// [`filter`](Self::filter) leaves a refused path out on the next call, and
/// [`check`](Self::check) lists the refusals without writing anything. A change
/// is refused where:
///
/// - it touches a [protected path](Protected): by default
///   [`Protected::defaults`];
/// - the target changed it after the run began: an entry at a path the change
///   modifies, removes or replaces whose change time is not before the
///   reference time (below), anything beneath a directory the change removes
///   included. An added path the target now holds is refused, and so is a
///   modified, removed or replaced one the target no longer holds as the
///   lowers did;
/// - the directory it lies in is neither in the target nor added by a chosen
///   change, or a component of its path is a symbolic link in the target;
/// - it lies on another filesystem than the target's top, where the apply
///   stages what it writes;
/// - the reader could not read it whole ([`Change::is_readable`]);
/// - it writes a symbolic link that leads out of the target, unless
///   [`links_leading_out`](Self::links_leading_out) allows one (below).
///
/// # Links that lead out
///
/// A link the run wrote is the run's, and the next tool that writes through it
/// writes where it leads: a link at `.bashrc` naming `/home/user/.bashrc`, or
/// one naming `../../.ssh/authorized_keys`, takes that write out of the tree.
/// So a link is refused where its target is absolute, or where its target,
/// read from the directory the link lies in, climbs above the target's top
/// with `..`. A `..` that follows a name is refused too, wherever it would
/// lead: the name may itself be a link, which the kernel follows before it
/// climbs, so the text alone does not say where such a target ends. A link
/// the target already holds, which a target may lead through, is the
/// target's own.
///
/// # The reference time
///
/// A run begins after its upper is created, so by default the apply holds the
/// target to the upper's birth time, where its filesystem records one.
/// [`since`](Self::since) names another, such as when a session began. A
/// change the caller made while the run had the overlay mounted is one the run
/// may not have seen (the kernel does not define what a mounted overlay shows
/// of a lower that changes), so it is refused rather than written over. A
/// margin of ten milliseconds is taken off the reference, for a kernel that
/// stamps a change time from a clock a tick behind: a change made in those
/// milliseconds before the run counts as one made after it.
///
/// # What is written
///
/// A file's content, with a sparse file's holes kept, and a symbolic link as a
/// link, never followed. The permission bits, without the set-user-ID and
/// set-group-ID bits. The extended attributes in the `user.` namespace and the
/// access control lists, without those the host assigns. Owners and times are
/// not carried: what is written is the caller's, written now. A named pipe, a
/// socket or a device is not written, and the report lists it as skipped.
/// Names that share an inode in the upper are linked in the target where each
/// is applied. A modified file is replaced by a new one, so another name the
/// target gave the old one keeps the old content.
///
/// # How it is written
///
/// Every file and link is first written in full in a staging directory the
/// apply creates at the target's top, under a hidden name ending `.partial`.
/// A failure while writing removes the staging directory and leaves the
/// target as it was. Then, deepest first, what the changes remove is removed;
/// then, in path order, each directory is created and each staged entry is
/// renamed to its name; then each directory's mode and attributes are set,
/// deepest first. Each name is checked again just before it is given. A tree
/// cannot be replaced atomically, so a failure in this second step stops it,
/// removes the staging directory, and reports what was applied in
/// [`ProvisionError::ApplyIncomplete`].
///
/// The upper is held to what [`ChangeSet::read`] found: an entry changed since,
/// by a sandbox still running on it, is refused with
/// [`ProvisionError::SourceChanged`] rather than written unread.
///
/// Every path in the target is resolved by descriptor, one component at a
/// time, never through a symbolic link. Apply to a tree no sandbox has mounted
/// as a lower: the kernel does not define what a mounted overlay shows of a
/// lower that changes beneath it.
pub struct Apply<'a> {
    changes: &'a ChangeSet,
    target: PathBuf,
    filter: Option<Box<ChangePredicate<'a>>>,
    protected: Vec<Protected>,
    since: Option<SystemTime>,
    links_leading_out: bool,
}

/// What [`Apply::filter`] takes: a predicate over a change, `Send` and `Sync`
/// as an export's filter is, so an apply can be built on one thread and run on
/// another.
type ChangePredicate<'a> = dyn Fn(&Change) -> bool + Send + Sync + 'a;

impl fmt::Debug for Apply<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Apply")
            .field("target", &self.target)
            .field("filter", &self.filter.as_ref().map(|_| "<filter>"))
            .field("protected", &self.protected)
            .field("since", &self.since)
            .field("links_leading_out", &self.links_leading_out)
            .finish_non_exhaustive()
    }
}

impl ChangeSet {
    /// An apply of these changes to `target`, a directory, usually the lower
    /// the run started from. See [`Apply`].
    pub fn apply(&self, target: impl AsRef<Path>) -> Apply<'_> {
        Apply {
            changes: self,
            target: target.as_ref().to_path_buf(),
            filter: None,
            protected: Protected::defaults(),
            since: None,
            links_leading_out: false,
        }
    }
}

impl<'a> Apply<'a> {
    /// Applies only the changes `filter` admits.
    pub fn filter(mut self, filter: impl Fn(&Change) -> bool + Send + Sync + 'a) -> Apply<'a> {
        self.filter = Some(Box::new(filter));
        self
    }

    /// Adds `protected` to the paths the apply refuses to change.
    pub fn protect(mut self, protected: Protected) -> Apply<'a> {
        self.protected.push(protected);
        self
    }

    /// Replaces the paths the apply refuses to change, [`Protected::defaults`]
    /// to begin with, with `protected`; an empty set protects nothing.
    pub fn protected(mut self, protected: impl IntoIterator<Item = Protected>) -> Apply<'a> {
        self.protected = protected.into_iter().collect();
        self
    }

    /// Holds the target to `since` rather than to the upper's birth time: an
    /// entry the target changed at or after it is refused.
    pub fn since(mut self, since: SystemTime) -> Apply<'a> {
        self.since = Some(since);
        self
    }

    /// Writes a symbolic link that leads out of the target where `allow`,
    /// rather than refusing it with [`ApplyRefusalReason::LinkLeadsOut`]. See
    /// [Links that lead out](Self#links-that-lead-out).
    ///
    /// For a tree whose links lead out by design, such as a root filesystem's
    /// absolute links. Every such link the run wrote is then written, wherever
    /// it leads, so [`check`](Self::check) the apply without it first.
    pub fn links_leading_out(mut self, allow: bool) -> Apply<'a> {
        self.links_leading_out = allow;
        self
    }

    /// The changes the apply would refuse, each with why, writing nothing.
    /// Empty where [`run`](Self::run) would write every chosen change.
    ///
    /// # Errors
    ///
    /// [`ProvisionError::Io`] where the target cannot be read, and where no
    /// reference time is known: the upper's filesystem records no birth time
    /// and none was given with [`since`](Self::since).
    pub fn check(&self) -> Result<Vec<ApplyRefusal>, ProvisionError> {
        Ok(self.plan()?.refusals)
    }

    /// Writes the chosen changes into the target.
    ///
    /// # Errors
    ///
    /// [`ProvisionError::ApplyRefused`] where a chosen change is refused, with
    /// nothing written; [`ProvisionError::SourceChanged`] where the upper
    /// changed since it was read, and [`ProvisionError::Io`] where staging
    /// failed, with the target as it was; and
    /// [`ProvisionError::ApplyIncomplete`] where giving the staged entries
    /// their names failed part way.
    pub fn run(self) -> Result<ApplyReport, ProvisionError> {
        let plan = self.plan()?;
        if !plan.refusals.is_empty() {
            return Err(ProvisionError::ApplyRefused {
                target: self.target.clone(),
                refusals: plan.refusals,
            });
        }
        let staged = plan.stage(&self.changes.upper)?;
        plan.commit(staged, &self.changes.upper)
    }

    /// The chosen changes, checked against the target.
    fn plan(&self) -> Result<Plan<'_>, ProvisionError> {
        let target = fs::open(
            &self.target,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| ProvisionError::io("applying changes to", &self.target, errno.into()))?;
        let target_dev = fs::fstat(&target)
            .map_err(|errno| ProvisionError::io("applying changes to", &self.target, errno.into()))?
            .st_dev;
        let since = self.since.or(self.changes.born).ok_or_else(|| {
            ProvisionError::io(
                "finding when the run began, for",
                &self.changes.upper,
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the upper's filesystem records no birth time, and no reference time was \
                     given with Apply::since",
                ),
            )
        })?;
        let chosen: Vec<&Change> = self
            .changes
            .changes
            .iter()
            .filter(|change| self.filter.as_ref().is_none_or(|filter| filter(change)))
            .collect();
        let mut plan = Plan {
            target_path: &self.target,
            target,
            target_dev,
            fence: fence(since),
            chosen,
            refusals: Vec::new(),
            protected: &self.protected,
            links_leading_out: self.links_leading_out,
        };
        plan.check()?;
        Ok(plan)
    }
}

/// The margin taken off the reference time, for a kernel that stamps a change
/// time from a clock a tick behind the one a reference is read from.
const CLOCK_MARGIN: Duration = Duration::from_millis(10);

/// The change time, in nanoseconds since the epoch, at or after which an entry
/// counts as changed after the run began.
fn fence(since: SystemTime) -> i128 {
    let since = since
        .checked_sub(CLOCK_MARGIN)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    match since.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(after) => after.as_nanos() as i128,
        Err(before) => -(before.duration().as_nanos() as i128),
    }
}

/// An entry's change time, in nanoseconds since the epoch.
fn changed_at(stat: &Stat) -> i128 {
    i128::from(stat.st_ctime) * 1_000_000_000 + i128::from(stat.st_ctime_nsec as i64)
}

/// What an apply wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyReport {
    applied: Vec<PathBuf>,
    skipped: Vec<PathBuf>,
}

impl ApplyReport {
    /// The paths of the changes written, in the order they were written:
    /// removals first, deepest first, then the rest in path order.
    pub fn applied(&self) -> &[PathBuf] {
        &self.applied
    }

    /// The paths of chosen changes not written: a named pipe, a socket, or a
    /// device the run made.
    pub fn skipped(&self) -> &[PathBuf] {
        &self.skipped
    }
}

/// A change an [`Apply`] refuses, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyRefusal {
    path: PathBuf,
    reason: ApplyRefusalReason,
}

impl ApplyRefusal {
    /// The change's path, relative to the top of the overlay and the target.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Why the change is refused.
    pub fn reason(&self) -> &ApplyRefusalReason {
        &self.reason
    }
}

impl fmt::Display for ApplyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.path, self.reason)
    }
}

impl std::error::Error for ApplyRefusal {}

/// Why an [`Apply`] refuses a change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApplyRefusalReason {
    /// The change touches this protected path.
    Protected(Protected),
    /// The target changed its entry at the path, or one beneath a directory
    /// the change removes, after the run began.
    Changed,
    /// The change adds an entry where the target now holds one.
    Occupied,
    /// The change modifies, removes or replaces an entry the target no longer
    /// holds as the lowers did.
    Missing,
    /// The directory the change lies in is neither in the target nor added by
    /// a chosen change.
    ParentMissing,
    /// A component of the change's path in the target is a symbolic link, or
    /// holds something other than a directory.
    Link,
    /// The change lies on another filesystem than the target's top.
    OtherFilesystem,
    /// The reader could not read the change whole.
    Unreadable,
    /// The change writes a symbolic link to this target, which leads out of
    /// the target directory. See [Links that lead out](Apply#links-that-lead-out).
    LinkLeadsOut(PathBuf),
}

impl fmt::Display for ApplyRefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplyRefusalReason::Protected(protected) => write!(f, "it touches {protected}"),
            ApplyRefusalReason::Changed => {
                f.write_str("the target changed what is there after the run began")
            }
            ApplyRefusalReason::Occupied => f.write_str("the target now holds an entry there"),
            ApplyRefusalReason::Missing => {
                f.write_str("the target no longer holds there what the lowers held")
            }
            ApplyRefusalReason::ParentMissing => f.write_str(
                "the directory it lies in is neither in the target nor added by a chosen change",
            ),
            ApplyRefusalReason::Link => f.write_str(
                "a component of its path in the target is a symbolic link or not a directory",
            ),
            ApplyRefusalReason::OtherFilesystem => {
                f.write_str("it lies on another filesystem than the target's top")
            }
            ApplyRefusalReason::Unreadable => f.write_str("the change could not be read whole"),
            ApplyRefusalReason::LinkLeadsOut(target) => write!(
                f,
                "it is a symbolic link to {target:?}, which leads out of the target"
            ),
        }
    }
}

/// The chosen changes of one apply, and what checking them found.
struct Plan<'p> {
    /// The target's top, as the caller named it, which names it in a failure.
    target_path: &'p Path,
    /// The target's top, opened as the caller named it.
    target: OwnedFd,
    /// The target's top's filesystem.
    target_dev: u64,
    /// The change time from which an entry counts as changed after the run
    /// began; see [`fence`].
    fence: i128,
    chosen: Vec<&'p Change>,
    refusals: Vec<ApplyRefusal>,
    protected: &'p [Protected],
    /// Whether a symbolic link that leads out of the target is written.
    links_leading_out: bool,
}

/// What staging wrote: the staging directory's name at the target's top, its
/// descriptor, and the staged name of each chosen change that has one, by its
/// index among the chosen, with the upper's top it was read from.
struct Staged {
    name: CString,
    dir: OwnedFd,
    entries: HashMap<usize, CString>,
    upper: OwnedFd,
}

impl Plan<'_> {
    /// Checks every chosen change against the target, recording each refusal.
    fn check(&mut self) -> Result<(), ProvisionError> {
        // The directories chosen changes create, beneath which the target
        // holds nothing yet.
        let created: HashSet<&Path> = self
            .chosen
            .iter()
            .filter(|change| creates_dir(change))
            .map(|change| change.path())
            .collect();
        let mut refusals = Vec::new();
        for change in &self.chosen {
            if let Some(reason) = self.refusal(change, &created)? {
                refusals.push(ApplyRefusal {
                    path: change.path().to_path_buf(),
                    reason,
                });
            }
        }
        self.refusals = refusals;
        Ok(())
    }

    /// Why `change` is refused, or `None`.
    fn refusal(
        &self,
        change: &Change,
        created: &HashSet<&Path>,
    ) -> Result<Option<ApplyRefusalReason>, ProvisionError> {
        let kind = change.kind();
        if !change.is_readable() {
            return Ok(Some(ApplyRefusalReason::Unreadable));
        }
        if let Some(protected) = self
            .protected
            .iter()
            .find(|protected| protected.touched_by(change))
        {
            return Ok(Some(ApplyRefusalReason::Protected(protected.clone())));
        }
        if !self.links_leading_out
            && let Some(target) = change.link()
            && leads_out(change.path(), target)
        {
            return Ok(Some(ApplyRefusalReason::LinkLeadsOut(PathBuf::from(
                OsStr::from_bytes(target),
            ))));
        }
        let (parent, leaf) = split(change.path()).map_err(|errno| {
            ProvisionError::io(
                "reading",
                self.target_path.join(change.path()),
                errno.into(),
            )
        })?;
        // Beneath a directory a chosen change creates, the target holds
        // nothing to check: the change is an addition into it.
        if parent
            .ancestors()
            .any(|ancestor| created.contains(ancestor))
        {
            return Ok(None);
        }
        let named = self.target_path.join(change.path());
        let dir = match resolve(self.target.as_fd(), parent) {
            Ok(dir) => dir,
            Err(Errno::NOENT) => return Ok(Some(ApplyRefusalReason::ParentMissing)),
            Err(Errno::NOTDIR | Errno::LOOP) => return Ok(Some(ApplyRefusalReason::Link)),
            Err(errno) => return Err(ProvisionError::io("reading", named, errno.into())),
        };
        let dev = fs::fstat(&dir)
            .map_err(|errno| ProvisionError::io("reading", &named, errno.into()))?
            .st_dev;
        if dev != self.target_dev {
            return Ok(Some(ApplyRefusalReason::OtherFilesystem));
        }
        let held = match fs::statat(&dir, &leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Some(stat),
            Err(Errno::NOENT) => None,
            Err(errno) => return Err(ProvisionError::io("reading", named, errno.into())),
        };
        let reason = match (kind, held) {
            (ChangeKind::Added, None) => None,
            (ChangeKind::Added, Some(_)) => Some(ApplyRefusalReason::Occupied),
            (_, None) => Some(ApplyRefusalReason::Missing),
            (_, Some(stat)) if Some(EntryKind::of(&stat)) != change.before() => {
                Some(ApplyRefusalReason::Missing)
            }
            (_, Some(stat)) if changed_at(&stat) >= self.fence => Some(ApplyRefusalReason::Changed),
            (kind, Some(stat))
                if removes(kind)
                    && FileType::from_raw_mode(stat.st_mode) == FileType::Directory =>
            {
                self.beneath(dir.as_fd(), &leaf, change.path(), &named)?
            }
            _ => None,
        };
        Ok(reason)
    }

    /// Why removing the directory `leaf` of `dir`, at `path`, is refused for
    /// what the target holds beneath it, or `None`: an entry changed after the
    /// run began, or one a protected path covers.
    fn beneath(
        &self,
        dir: BorrowedFd<'_>,
        leaf: &CStr,
        path: &Path,
        named: &Path,
    ) -> Result<Option<ApplyRefusalReason>, ProvisionError> {
        let io = |errno: Errno| ProvisionError::io("reading", named, errno.into());
        let mut stack = vec![(
            containment::open_child_dir(dir, leaf, OFlags::RDONLY).map_err(io)?,
            path.to_path_buf(),
        )];
        while let Some((dir, at)) = stack.pop() {
            for name in read_names(dir.as_fd(), named)? {
                let entry = at.join(OsStr::from_bytes(&name));
                if let Some(protected) = self.protected.iter().find(|p| p.holds(&entry)) {
                    return Ok(Some(ApplyRefusalReason::Protected(protected.clone())));
                }
                let name = cstring(&name, &entry)?;
                let stat = fs::statat(&dir, &name, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
                if changed_at(&stat) >= self.fence {
                    return Ok(Some(ApplyRefusalReason::Changed));
                }
                if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
                    let child =
                        containment::open_child_dir(&dir, &name, OFlags::RDONLY).map_err(io)?;
                    stack.push((child, entry));
                }
            }
        }
        Ok(None)
    }

    /// Writes every chosen file and link in full in a staging directory at the
    /// target's top, removing it again on a failure.
    fn stage(&self, upper: &Path) -> Result<Staged, ProvisionError> {
        let upper_top = fs::open(
            upper,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| ProvisionError::io("reading", upper, errno.into()))?;
        let name = CString::new(format!(".apply.{}.partial", crate::host::unique_hex()))
            .expect("a formatted name holds no NUL");
        let staging =
            |errno: Errno| ProvisionError::io("staging changes in", self.target_path, errno.into());
        fs::mkdirat(&self.target, &name, Mode::from_raw_mode(0o700)).map_err(staging)?;
        let dir = containment::open_child_dir(&self.target, &name, OFlags::RDONLY);
        let dir = match dir {
            Ok(dir) => dir,
            Err(errno) => {
                let _ = delete_tree(self.target.as_fd(), &name);
                return Err(staging(errno));
            }
        };
        let mut staged = Staged {
            name,
            dir,
            entries: HashMap::new(),
            upper: upper_top,
        };
        match self.stage_entries(upper, &mut staged) {
            Ok(()) => Ok(staged),
            Err(err) => {
                let _ = delete_tree(self.target.as_fd(), &staged.name);
                Err(err)
            }
        }
    }

    /// Stages each chosen file and link into `staged`, a file shared by several
    /// chosen names once.
    fn stage_entries(&self, upper: &Path, staged: &mut Staged) -> Result<(), ProvisionError> {
        let mut linked: HashSet<(u64, u64)> = HashSet::new();
        for (index, change) in self.chosen.iter().enumerate() {
            let (Some(now), Some(entry)) = (change.now(), change.upper) else {
                continue;
            };
            if !matches!(now, EntryKind::File | EntryKind::Symlink) {
                continue;
            }
            if now == EntryKind::File && entry.nlink > 1 && !linked.insert((entry.dev, entry.ino)) {
                continue;
            }
            let named = upper.join(change.path());
            let (parent, leaf) = split(change.path())
                .map_err(|errno| ProvisionError::io("reading", &named, errno.into()))?;
            let io = |errno: Errno| ProvisionError::io("reading", &named, errno.into());
            let dir = resolve(staged.upper.as_fd(), parent).map_err(io)?;
            let stat = fs::statat(&dir, &leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
            let unchanged = |stat: &Stat| ProvisionError::SourceChanged {
                path: named.clone(),
                recorded: stat.st_size as u64,
            };
            if !entry.holds(&stat) {
                return Err(unchanged(&stat));
            }
            let staged_name = CString::new(format!("{index}")).expect("a number holds no NUL");
            let target_io = |errno: Errno| ProvisionError::io("staging", &named, errno.into());
            match now {
                // The target the reader read, which the plan judged. A link's
                // target cannot change without a new inode, and the upper
                // still holds the inode the reader read it from.
                EntryKind::Symlink => {
                    let Some(target) = change.link() else {
                        return Err(unchanged(&stat));
                    };
                    fs::symlinkat(OsStr::from_bytes(target), &staged.dir, &staged_name)
                        .map_err(target_io)?;
                }
                _ => {
                    let source =
                        containment::open_typed_file(dir.as_fd(), &leaf, &stat, OFlags::RDONLY)
                            .map_err(|errno| match errno {
                                Errno::STALE => unchanged(&stat),
                                errno => io(errno),
                            })?;
                    let file = fs::openat(
                        &staged.dir,
                        &staged_name,
                        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                        Mode::from_raw_mode(0o600),
                    )
                    .map_err(target_io)?;
                    copy_data(source.as_fd(), file.as_fd(), stat.st_size as u64).map_err(
                        |errno| match errno {
                            Errno::STALE => unchanged(&stat),
                            errno => ProvisionError::io("copying", &named, errno.into()),
                        },
                    )?;
                    let after = fs::fstat(&source).map_err(io)?;
                    if !entry.holds(&after) {
                        return Err(unchanged(&after));
                    }
                    carry_attributes(Holder::Fd(source.as_fd()), file.as_fd()).map_err(io)?;
                    fs::fchmod(&file, Mode::from_raw_mode(carried_mode(entry.mode)))
                        .map_err(target_io)?;
                }
            }
            staged.entries.insert(index, staged_name);
        }
        Ok(())
    }

    /// Gives each staged entry its name, removes what the changes remove,
    /// creates each directory, and sets each directory's mode and attributes.
    fn commit(&self, staged: Staged, upper: &Path) -> Result<ApplyReport, ProvisionError> {
        let mut report = ApplyReport::default();
        let outcome = self.commit_entries(&staged, upper, &mut report);
        let _ = delete_tree(self.target.as_fd(), &staged.name);
        match outcome {
            Ok(()) => Ok(report),
            Err((path, source)) => Err(ProvisionError::ApplyIncomplete {
                target: self.target_path.to_path_buf(),
                applied: report.applied,
                path,
                source,
            }),
        }
    }

    /// [`commit`](Self::commit)'s steps, stopping at the first failure with the
    /// path it failed at.
    fn commit_entries(
        &self,
        staged: &Staged,
        upper: &Path,
        report: &mut ApplyReport,
    ) -> Result<(), (PathBuf, io::Error)> {
        let failed = |change: &Change, err: io::Error| (change.path().to_path_buf(), err);

        // What the changes take away, deepest first, so nothing is removed
        // from beneath a directory already gone.
        for change in self
            .chosen
            .iter()
            .rev()
            .filter(|change| removes(change.kind()))
        {
            let (parent, leaf) =
                split(change.path()).map_err(|errno| failed(change, errno.into()))?;
            let dir = resolve(self.target.as_fd(), parent)
                .map_err(|errno| failed(change, errno.into()))?;
            self.recheck(dir.as_fd(), &leaf, change, true)
                .map_err(|err| failed(change, err))?;
            delete_tree(dir.as_fd(), &leaf).map_err(|errno| failed(change, errno.into()))?;
            if change.kind() == ChangeKind::Removed {
                report.applied.push(change.path().to_path_buf());
            }
        }

        // The rest in path order, so a directory exists before what is put in
        // it; each directory's own mode waits, since one denying its owner
        // write would refuse what goes into it.
        let mut first_of: HashMap<(u64, u64), &Change> = HashMap::new();
        let mut directories: Vec<&Change> = Vec::new();
        for (index, change) in self.chosen.iter().enumerate() {
            let (Some(now), Some(entry)) = (change.now(), change.upper) else {
                continue;
            };
            if now == EntryKind::Other {
                report.skipped.push(change.path().to_path_buf());
                continue;
            }
            let (parent, leaf) =
                split(change.path()).map_err(|errno| failed(change, errno.into()))?;
            let dir = resolve(self.target.as_fd(), parent)
                .map_err(|errno| failed(change, errno.into()))?;
            if change.kind() == ChangeKind::Modified {
                // A directory's change time moves with every entry written or
                // removed in it, this apply's own among them, so it is held to
                // its type alone here; the plan checked its time.
                self.recheck(dir.as_fd(), &leaf, change, now != EntryKind::Directory)
                    .map_err(|err| failed(change, err))?;
            } else {
                match fs::statat(&dir, &leaf, AtFlags::SYMLINK_NOFOLLOW) {
                    Err(Errno::NOENT) => {}
                    Ok(_) => {
                        return Err(failed(
                            change,
                            io::Error::other(refusal(change, ApplyRefusalReason::Occupied)),
                        ));
                    }
                    Err(errno) => return Err(failed(change, errno.into())),
                }
            }
            match now {
                EntryKind::Directory => {
                    if change.kind() != ChangeKind::Modified {
                        fs::mkdirat(&dir, &leaf, Mode::from_raw_mode(0o700))
                            .map_err(|errno| failed(change, errno.into()))?;
                    }
                    directories.push(change);
                }
                EntryKind::File
                    if entry.nlink > 1 && first_of.contains_key(&(entry.dev, entry.ino)) =>
                {
                    let first = first_of[&(entry.dev, entry.ino)];
                    let (first_parent, first_leaf) =
                        split(first.path()).map_err(|errno| failed(change, errno.into()))?;
                    let first_dir = resolve(self.target.as_fd(), first_parent)
                        .map_err(|errno| failed(change, errno.into()))?;
                    containment::link_replacing(first_dir.as_fd(), &first_leaf, dir.as_fd(), &leaf)
                        .map_err(|errno| failed(change, errno.into()))?;
                }
                EntryKind::File | EntryKind::Symlink => {
                    let staged_name = &staged.entries[&index];
                    fs::renameat(&staged.dir, staged_name, &dir, &leaf)
                        .map_err(|errno| failed(change, errno.into()))?;
                    if now == EntryKind::File && entry.nlink > 1 {
                        first_of.insert((entry.dev, entry.ino), change);
                    }
                }
                EntryKind::Other => unreachable!("skipped above"),
            }
            report.applied.push(change.path().to_path_buf());
        }

        // Each directory's mode and attributes, deepest first.
        for change in directories.into_iter().rev() {
            let entry = change.upper.expect("a directory the view holds was read");
            let (parent, leaf) =
                split(change.path()).map_err(|errno| failed(change, errno.into()))?;
            let source_dir = resolve(staged.upper.as_fd(), parent)
                .and_then(|dir| containment::open_child_dir(&dir, &leaf, OFlags::RDONLY))
                .map_err(|errno| failed(change, errno.into()))?;
            let source = fs::fstat(&source_dir).map_err(|errno| failed(change, errno.into()))?;
            if !entry.holds(&source) {
                return Err(failed(
                    change,
                    io::Error::other(format!(
                        "the upper's {:?} changed since it was read",
                        upper.join(change.path())
                    )),
                ));
            }
            let target_dir = resolve(self.target.as_fd(), parent)
                .and_then(|dir| containment::open_child_dir(&dir, &leaf, OFlags::RDONLY))
                .map_err(|errno| failed(change, errno.into()))?;
            align_attributes(source_dir.as_fd(), target_dir.as_fd())
                .map_err(|errno| failed(change, errno.into()))?;
            fs::fchmod(&target_dir, Mode::from_raw_mode(carried_mode(entry.mode)))
                .map_err(|errno| failed(change, errno.into()))?;
        }
        Ok(())
    }

    /// Checks again, just before it is changed, that the target's entry
    /// `leaf` in `dir` is still what the lowers held, and where `time` asks,
    /// unchanged since the run began.
    fn recheck(
        &self,
        dir: BorrowedFd<'_>,
        leaf: &CStr,
        change: &Change,
        time: bool,
    ) -> Result<(), io::Error> {
        let missing = || io::Error::other(refusal(change, ApplyRefusalReason::Missing));
        let stat = match fs::statat(dir, leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Err(missing()),
            Err(errno) => return Err(errno.into()),
        };
        if Some(EntryKind::of(&stat)) != change.before() {
            return Err(missing());
        }
        if time && changed_at(&stat) >= self.fence {
            return Err(io::Error::other(refusal(
                change,
                ApplyRefusalReason::Changed,
            )));
        }
        Ok(())
    }
}

/// The refusal of `change` for `reason`.
fn refusal(change: &Change, reason: ApplyRefusalReason) -> ApplyRefusal {
    ApplyRefusal {
        path: change.path().to_path_buf(),
        reason,
    }
}

/// Whether `change` creates a directory the target does not hold yet.
fn creates_dir(change: &Change) -> bool {
    change.now() == Some(EntryKind::Directory)
        && matches!(change.kind(), ChangeKind::Added | ChangeKind::Replaced)
}

/// The mode an apply gives an entry the upper holds at `mode`: its permission
/// bits and the sticky bit, without the set-user-ID and set-group-ID bits.
fn carried_mode(mode: u32) -> u32 {
    mode & 0o1777
}

/// Sets on `to` the attributes `from` carries that an apply carries: those in
/// the `user.` namespace and the access control lists, without those the host
/// assigns.
fn carry_attributes(from: Holder<'_>, to: BorrowedFd<'_>) -> Result<(), Errno> {
    for (name, value) in xattr::read_all(from)? {
        if !carries(&name) {
            continue;
        }
        let name = CString::new(name).map_err(|_| Errno::INVAL)?;
        fs::fsetxattr(to, &name, &value, fs::XattrFlags::empty())?;
    }
    Ok(())
}

/// Gives the directory `to` the attributes an apply carries that `from` holds,
/// and removes those of them `to` holds and `from` does not, as a run that
/// removed one from its copy of the directory did.
fn align_attributes(from: BorrowedFd<'_>, to: BorrowedFd<'_>) -> Result<(), Errno> {
    carry_attributes(Holder::Fd(from), to)?;
    let keep: HashSet<Vec<u8>> = xattr::read_all(Holder::Fd(from))?
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    for (name, _) in xattr::read_all(Holder::Fd(to))? {
        if carries(&name) && !keep.contains(&name) {
            let name = CString::new(name).map_err(|_| Errno::INVAL)?;
            fs::fremovexattr(to, &name)?;
        }
    }
    Ok(())
}

/// Whether an apply carries the attribute `name`: one in the `user.` namespace
/// or an access control list, and not one the host assigns.
pub(super) fn carries(name: &[u8]) -> bool {
    (name.starts_with(b"user.")
        || name == xattr::ACCESS_ACL.to_bytes()
        || name == xattr::DEFAULT_ACL.to_bytes())
        && !containment::host_assigned_xattr(name)
}

/// Copies the first `size` bytes of `from` into `to`, which is empty, keeping
/// the holes of a sparse file as holes: only the ranges `from` holds data in
/// are copied, and `to` is extended to `size` after. `ESTALE` where `from`
/// holds fewer bytes than `size`.
pub(super) fn copy_data(from: BorrowedFd<'_>, to: BorrowedFd<'_>, size: u64) -> Result<(), Errno> {
    let mut at = 0u64;
    while at < size {
        let data = match fs::seek(from, SeekFrom::Data(at)) {
            Ok(data) => data,
            // Nothing but a hole from here on.
            Err(Errno::NXIO) => break,
            // A filesystem that cannot tell holes: copy the rest whole.
            Err(Errno::INVAL | Errno::OPNOTSUPP) => {
                copy_range(from, to, at, size - at)?;
                break;
            }
            Err(errno) => return Err(errno),
        };
        if data >= size {
            break;
        }
        let hole = fs::seek(from, SeekFrom::Hole(data))?.min(size);
        copy_range(from, to, data, hole - data)?;
        at = hole;
    }
    fs::ftruncate(to, size)
}

/// Copies `len` bytes of `from` at `offset` into `to` at the same offset,
/// through `copy_file_range` where the kernel copies between the two, and a
/// buffer where it does not. `ESTALE` where `from` ends first.
fn copy_range(
    from: BorrowedFd<'_>,
    to: BorrowedFd<'_>,
    offset: u64,
    len: u64,
) -> Result<(), Errno> {
    let mut done = 0u64;
    while done < len {
        let (mut off_in, mut off_out) = (offset + done, offset + done);
        let want = usize::try_from(len - done).unwrap_or(usize::MAX);
        match fs::copy_file_range(from, Some(&mut off_in), to, Some(&mut off_out), want) {
            Ok(0) => return Err(Errno::STALE),
            Ok(copied) => done += copied as u64,
            Err(Errno::INTR) => continue,
            Err(Errno::XDEV | Errno::INVAL | Errno::OPNOTSUPP | Errno::NOSYS) => {
                return copy_buffered(from, to, offset + done, len - done);
            }
            Err(errno) => return Err(errno),
        }
    }
    Ok(())
}

/// [`copy_range`] through a buffer.
fn copy_buffered(
    from: BorrowedFd<'_>,
    to: BorrowedFd<'_>,
    offset: u64,
    len: u64,
) -> Result<(), Errno> {
    let mut buffer = vec![0u8; 64 * 1024];
    let mut done = 0u64;
    while done < len {
        let want = buffer
            .len()
            .min(usize::try_from(len - done).unwrap_or(usize::MAX));
        let read = match rustix::io::pread(from, &mut buffer[..want], offset + done) {
            Ok(0) => return Err(Errno::STALE),
            Ok(read) => read,
            Err(Errno::INTR) => continue,
            Err(errno) => return Err(errno),
        };
        let mut written = 0;
        while written < read {
            match rustix::io::pwrite(to, &buffer[written..read], offset + done + written as u64) {
                Ok(n) => written += n,
                Err(Errno::INTR) => continue,
                Err(errno) => return Err(errno),
            }
        }
        done += read as u64;
    }
    Ok(())
}

/// The directory `path`, relative to `top`, opened by descriptor one component
/// at a time, never through a symbolic link: `ELOOP` or `ENOTDIR` where a
/// component is a link or not a directory.
pub(super) fn resolve(top: BorrowedFd<'_>, path: &Path) -> Result<OwnedFd, Errno> {
    let mut dir = fs::openat(
        top,
        c".",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(Errno::INVAL);
        };
        dir = containment::open_child_dir(&dir, name, OFlags::PATH)?;
    }
    Ok(dir)
}

/// A change's path split into the directory it lies in and its own name.
/// `EINVAL` for a path naming no entry, which no change the reader lists does.
pub(super) fn split(path: &Path) -> Result<(&Path, CString), Errno> {
    let leaf = path.file_name().ok_or(Errno::INVAL)?;
    let leaf = CString::new(leaf.as_bytes()).map_err(|_| Errno::INVAL)?;
    Ok((path.parent().unwrap_or(Path::new("")), leaf))
}

/// `name` as a `CString`, refusing one that carries a NUL.
fn cstring(name: &[u8], path: &Path) -> Result<CString, ProvisionError> {
    CString::new(name).map_err(|_| ProvisionError::EntryRefused {
        path: path.to_path_buf(),
        reason: "the entry name carries a NUL".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::Duration;

    use ferroday_cage_testkit::overlay;

    use super::*;
    use crate::Overlay;
    use crate::scratch::Scratch;

    /// A scratch tree holding a lower and an upper, and the overlay of them.
    fn layers(name: &str) -> (Scratch, Overlay, PathBuf, PathBuf) {
        let scratch = Scratch::new(name);
        let (lower, upper) = (scratch.join("lower"), scratch.join("upper"));
        std::fs::create_dir(&lower).unwrap();
        std::fs::create_dir(&upper).unwrap();
        let overlay = Overlay::new().lower(&lower).upper(&upper);
        (scratch, overlay, lower, upper)
    }

    fn write(path: PathBuf, content: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    /// A reference time after everything laid out so far, by more than the
    /// margin the apply takes off it.
    fn after_a_tick() -> SystemTime {
        std::thread::sleep(CLOCK_MARGIN * 2);
        let now = SystemTime::now();
        std::thread::sleep(CLOCK_MARGIN * 2);
        now
    }

    fn mode(path: PathBuf) -> u32 {
        std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    /// The names a directory holds, sorted.
    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    /// Every kind of change written into the lower, and a change set read
    /// again afterwards shows nothing left.
    #[test]
    fn each_kind_of_change_is_written_into_the_target() {
        let (_scratch, overlay, lower, upper) = layers("apply-each-kind");
        for path in [
            "modify",
            "remove",
            "replace",
            "dir/remove",
            "opaque/old",
            "keep",
        ] {
            write(lower.join(path), "lower\n");
        }
        std::fs::create_dir(lower.join("removed-dir")).unwrap();
        write(lower.join("removed-dir/deep/f"), "lower\n");
        std::fs::set_permissions(lower.join("modify"), PermissionsExt::from_mode(0o644)).unwrap();
        let since = after_a_tick();

        write(upper.join("modify"), "upper\n");
        std::fs::set_permissions(upper.join("modify"), PermissionsExt::from_mode(0o4750)).unwrap();
        write(upper.join("added/new"), "upper\n");
        std::os::unix::fs::symlink("modify", upper.join("link")).unwrap();
        std::fs::create_dir(upper.join("replace")).unwrap();
        write(upper.join("replace/inside"), "upper\n");
        if !overlay::whiteout(&upper.join("remove")) {
            return;
        }
        assert!(overlay::whiteout(&upper.join("removed-dir")));
        std::fs::create_dir(upper.join("dir")).unwrap();
        assert!(overlay::whiteout(&upper.join("dir/remove")));
        write(upper.join("dir/added"), "upper\n");
        std::fs::create_dir(upper.join("opaque")).unwrap();
        assert!(ferroday_cage_testkit::xattr::set(
            &upper.join("opaque"),
            "user.overlay.opaque",
            b"y"
        ));
        write(upper.join("opaque/new"), "upper\n");
        std::fs::hard_link(upper.join("added/new"), upper.join("added/second")).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            upper.join("fifo"),
            FileType::Fifo,
            Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();

        let changes = ChangeSet::read(&overlay).unwrap();
        let report = changes.apply(&lower).since(since).run().unwrap();
        assert_eq!(report.skipped(), [Path::new("fifo")]);
        assert_eq!(
            report.applied().first().map(PathBuf::as_path),
            Some(Path::new("removed-dir")),
            "removals first, deepest first: {:?}",
            report.applied()
        );

        assert_eq!(
            std::fs::read_to_string(lower.join("modify")).unwrap(),
            "upper\n"
        );
        assert_eq!(
            mode(lower.join("modify")),
            0o750,
            "the set-id bits are dropped"
        );
        assert_eq!(
            std::fs::read_link(lower.join("link")).unwrap(),
            Path::new("modify")
        );
        assert_eq!(names(&lower.join("replace")), ["inside"]);
        assert!(!lower.join("remove").exists() && !lower.join("removed-dir").exists());
        assert_eq!(names(&lower.join("dir")), ["added"]);
        assert_eq!(names(&lower.join("opaque")), ["new"]);
        assert_eq!(
            std::fs::metadata(lower.join("added/new")).unwrap().ino(),
            std::fs::metadata(lower.join("added/second")).unwrap().ino(),
            "two names of one file stay one file"
        );
        assert!(!lower.join("fifo").exists());
        assert_eq!(
            std::fs::read_to_string(lower.join("keep")).unwrap(),
            "lower\n"
        );
        assert!(
            names(&lower).iter().all(|name| !name.ends_with(".partial")),
            "the staging directory goes: {:?}",
            names(&lower)
        );

        let again = ChangeSet::read(&overlay).unwrap();
        let left: Vec<(&Path, bool)> = again
            .changes()
            .iter()
            .map(|change| (change.path(), change.content_differs()))
            .collect();
        assert_eq!(
            left,
            [(Path::new("fifo"), false), (Path::new("modify"), false)],
            "what was applied now matches, but for the set-id bits it dropped"
        );
        assert!(again.changes()[1].mode_differs());
    }

    /// A path the target changed after the reference time is refused, and so
    /// is everything else with it: nothing is written.
    #[test]
    fn a_change_the_target_also_made_refuses_the_apply() {
        let (_scratch, overlay, lower, upper) = layers("apply-conflict");
        write(lower.join("edited"), "lower\n");
        write(lower.join("removed-dir/f"), "lower\n");
        write(lower.join("occupied-later"), "x\n");
        std::fs::remove_file(lower.join("occupied-later")).unwrap();
        let since = after_a_tick();
        write(upper.join("edited"), "run\n");
        write(upper.join("added"), "run\n");
        write(upper.join("occupied-later"), "run\n");
        if !overlay::whiteout(&upper.join("removed-dir")) {
            return;
        }
        let changes = ChangeSet::read(&overlay).unwrap();
        // The user, meanwhile.
        write(lower.join("edited"), "user\n");
        write(lower.join("removed-dir/user-file"), "user\n");
        write(lower.join("occupied-later"), "user\n");

        let refusals = changes.apply(&lower).since(since).check().unwrap();
        let reasons: Vec<_> = refusals
            .iter()
            .map(|refusal| {
                (
                    refusal.path().display().to_string(),
                    refusal.reason().clone(),
                )
            })
            .collect();
        assert_eq!(
            reasons,
            [
                ("edited".to_string(), ApplyRefusalReason::Changed),
                ("occupied-later".to_string(), ApplyRefusalReason::Occupied),
                ("removed-dir".to_string(), ApplyRefusalReason::Changed),
            ]
        );
        match changes.apply(&lower).since(since).run() {
            Err(ProvisionError::ApplyRefused {
                refusals: refused, ..
            }) => {
                assert_eq!(refused, refusals);
            }
            other => panic!("{other:?}"),
        }
        assert!(!lower.join("added").exists(), "nothing is written");

        // Leaving the refused paths out applies the rest.
        let refused: Vec<PathBuf> = refusals.iter().map(|r| r.path().to_path_buf()).collect();
        changes
            .apply(&lower)
            .since(since)
            .filter(move |change| !refused.iter().any(|path| path == change.path()))
            .run()
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(lower.join("added")).unwrap(),
            "run\n"
        );
        assert_eq!(
            std::fs::read_to_string(lower.join("edited")).unwrap(),
            "user\n"
        );
    }

    /// The default protected paths refuse a change at, beneath or above them,
    /// a link standing in for a protected directory included, and an empty
    /// set protects nothing.
    #[test]
    fn a_protected_path_refuses_the_apply() {
        let (_scratch, overlay, lower, upper) = layers("apply-protected");
        std::fs::create_dir_all(lower.join(".git/hooks")).unwrap();
        write(lower.join("sub/project/.git/config"), "lower\n");
        let since = after_a_tick();
        write(upper.join(".git/hooks/pre-commit"), "run\n");
        write(upper.join("deep/.envrc"), "run\n");
        write(upper.join("ci/workflows/x.yml"), "run\n");
        std::os::unix::fs::symlink("ci", upper.join(".github")).unwrap();
        if !overlay::whiteout(&upper.join("sub")) {
            return;
        }
        write(upper.join("plain"), "run\n");

        let changes = ChangeSet::read(&overlay).unwrap();
        let reasons: Vec<_> = changes
            .apply(&lower)
            .since(since)
            .check()
            .unwrap()
            .into_iter()
            .map(|refusal| {
                (
                    refusal.path().display().to_string(),
                    refusal.reason().clone(),
                )
            })
            .collect();
        assert_eq!(
            reasons,
            [
                (
                    ".git/hooks/pre-commit".to_string(),
                    ApplyRefusalReason::Protected(Protected::name(".git"))
                ),
                (
                    ".github".to_string(),
                    ApplyRefusalReason::Protected(Protected::path(".github/workflows"))
                ),
                (
                    "deep/.envrc".to_string(),
                    ApplyRefusalReason::Protected(Protected::name(".envrc"))
                ),
                (
                    "sub".to_string(),
                    ApplyRefusalReason::Protected(Protected::name(".git"))
                ),
            ]
        );
        assert!(
            changes
                .apply(&lower)
                .since(since)
                .protected([])
                .check()
                .unwrap()
                .is_empty()
        );
        let refusals = changes
            .apply(&lower)
            .since(since)
            .protected([])
            .protect(Protected::path("plain"))
            .check()
            .unwrap();
        assert_eq!(refusals.len(), 1);
        assert_eq!(refusals[0].path(), Path::new("plain"));
    }

    /// The hooks and configuration git's hook managers and mise act on are
    /// protected by default, and a protected name in another case is the
    /// protected name, as a case-insensitive directory looks it up.
    #[test]
    fn hook_managers_and_other_cases_of_a_protected_name_are_protected() {
        let (_scratch, overlay, lower, upper) = layers("apply-protected-tools");
        let since = after_a_tick();
        for path in [
            ".GIT/config",
            "app/.husky/pre-commit",
            "backend/mise.toml",
            ".config/mise/config.toml",
            ".config/lefthook-local.jsonc",
            ".Lefthook.YML",
            ".lefthook/pre-commit/lint",
            "src/lib.rs",
        ] {
            write(upper.join(path), "run\n");
        }
        let changes = ChangeSet::read(&overlay).unwrap();
        let refused: Vec<_> = changes
            .apply(&lower)
            .since(since)
            .check()
            .unwrap()
            .into_iter()
            .map(|refusal| {
                (
                    refusal.path().display().to_string(),
                    refusal.reason().clone(),
                )
            })
            .collect();
        let protected =
            |path: &str, by: Protected| (path.to_string(), ApplyRefusalReason::Protected(by));
        let mise = || Protected::path(".config/mise");
        let lefthook = || Protected::path(".lefthook");
        assert_eq!(
            refused,
            [
                protected(".GIT", Protected::name(".git")),
                protected(".GIT/config", Protected::name(".git")),
                protected(".Lefthook.YML", Protected::path(".lefthook.yml")),
                protected(
                    ".config/lefthook-local.jsonc",
                    Protected::path(".config/lefthook-local.jsonc"),
                ),
                protected(".config/mise", mise()),
                protected(".config/mise/config.toml", mise()),
                protected(".lefthook", lefthook()),
                protected(".lefthook/pre-commit", lefthook()),
                protected(".lefthook/pre-commit/lint", lefthook()),
                protected("app/.husky", Protected::name(".husky")),
                protected("app/.husky/pre-commit", Protected::name(".husky")),
                protected("backend/mise.toml", Protected::name("mise.toml")),
            ]
        );
    }

    /// A link the run wrote is refused where it leads out of the target, and
    /// written as it is where the caller allows that.
    #[test]
    fn a_link_that_leads_out_of_the_target_is_refused_unless_allowed() {
        let (_scratch, overlay, lower, upper) = layers("apply-links-out");
        write(lower.join("a/b/f"), "lower\n");
        std::fs::create_dir_all(upper.join("a/b")).unwrap();
        let since = after_a_tick();
        for (at, target) in [
            ("bashrc", "/home/user/.bashrc"),
            ("a/b/up", "../../../outside"),
            ("a/b/top", "../../inside"),
            ("a/b/after-name", "f/../../.."),
            ("a/b/sibling", "f"),
            ("a/b/dots", "./..//b/f"),
        ] {
            std::os::unix::fs::symlink(target, upper.join(at)).unwrap();
        }
        let changes = ChangeSet::read(&overlay).unwrap();
        let refused: Vec<_> = changes
            .apply(&lower)
            .since(since)
            .check()
            .unwrap()
            .into_iter()
            .map(|refusal| (refusal.path().to_path_buf(), refusal.reason().clone()))
            .collect();
        let out = |at: &str, target: &str| {
            (
                PathBuf::from(at),
                ApplyRefusalReason::LinkLeadsOut(PathBuf::from(target)),
            )
        };
        assert_eq!(
            refused,
            [
                out("a/b/after-name", "f/../../.."),
                out("a/b/up", "../../../outside"),
                out("bashrc", "/home/user/.bashrc"),
            ]
        );

        let report = changes
            .apply(&lower)
            .since(since)
            .links_leading_out(true)
            .run()
            .unwrap();
        assert_eq!(report.applied().len(), 6);
        assert_eq!(
            std::fs::read_link(lower.join("bashrc")).unwrap(),
            Path::new("/home/user/.bashrc")
        );
        assert_eq!(
            std::fs::read_link(lower.join("a/b/dots")).unwrap(),
            Path::new("./..//b/f")
        );
    }

    /// The target is resolved without following a link, and a change whose
    /// directory the target lacks is refused rather than given one.
    #[test]
    fn a_link_or_a_missing_directory_in_the_target_is_refused() {
        let (scratch, overlay, lower, upper) = layers("apply-target-shape");
        write(lower.join("via/f"), "lower\n");
        write(lower.join("gone/f"), "lower\n");
        let since = after_a_tick();
        write(upper.join("via/f"), "run\n");
        write(upper.join("gone/f"), "run\n");
        let changes = ChangeSet::read(&overlay).unwrap();

        // Another target, where `via` is a link and `gone` is missing.
        let target = scratch.join("target");
        std::fs::create_dir_all(scratch.join("elsewhere")).unwrap();
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(scratch.join("elsewhere"), target.join("via")).unwrap();
        let reasons: Vec<_> = changes
            .apply(&target)
            .since(since)
            .check()
            .unwrap()
            .into_iter()
            .map(|refusal| refusal.reason().clone())
            .collect();
        assert_eq!(
            reasons,
            [ApplyRefusalReason::ParentMissing, ApplyRefusalReason::Link]
        );
        assert!(names(&scratch.join("elsewhere")).is_empty());
    }

    /// An upper changed since it was read is not written unread, and the
    /// target is left as it was.
    #[test]
    fn an_upper_changed_since_it_was_read_is_refused() {
        let (_scratch, overlay, lower, upper) = layers("apply-upper-changed");
        let since = after_a_tick();
        write(upper.join("a"), "reviewed\n");
        write(upper.join("b"), "reviewed\n");
        let changes = ChangeSet::read(&overlay).unwrap();
        std::thread::sleep(CLOCK_MARGIN);
        write(upper.join("b"), "written after the review\n");
        assert!(matches!(
            changes.apply(&lower).since(since).run(),
            Err(ProvisionError::SourceChanged { path, .. }) if path == upper.join("b")
        ));
        assert!(names(&lower).is_empty(), "{:?}", names(&lower));
    }

    /// A sparse file stays sparse.
    #[test]
    fn a_sparse_file_keeps_its_holes() {
        let (_scratch, overlay, lower, upper) = layers("apply-sparse");
        let since = after_a_tick();
        let file = std::fs::File::create(upper.join("sparse")).unwrap();
        file.set_len(1 << 30).unwrap();
        rustix::io::pwrite(&file, b"data", 1 << 20).unwrap();
        drop(file);
        let changes = ChangeSet::read(&overlay).unwrap();
        changes.apply(&lower).since(since).run().unwrap();
        let applied = std::fs::metadata(lower.join("sparse")).unwrap();
        assert_eq!(applied.len(), 1 << 30);
        assert!(
            applied.blocks() * 512 < 1 << 20,
            "{} bytes allocated",
            applied.blocks() * 512
        );
        let read = std::fs::read(lower.join("sparse")).unwrap();
        assert_eq!(&read[1 << 20..(1 << 20) + 4], b"data");
    }

    /// A failure while giving names stops there and says what was applied;
    /// the staging directory goes either way.
    #[test]
    fn a_failure_while_naming_reports_what_was_applied() {
        if rustix::process::geteuid().is_root() {
            ferroday_cage_testkit::require::premise_unmet(
                "root writes into a directory of mode 555",
            );
            return;
        }
        let (_scratch, overlay, lower, upper) = layers("apply-incomplete");
        std::fs::create_dir(lower.join("locked")).unwrap();
        let since = after_a_tick();
        write(upper.join("a-first"), "run\n");
        write(upper.join("locked/new"), "run\n");
        let changes = ChangeSet::read(&overlay).unwrap();
        std::fs::set_permissions(lower.join("locked"), PermissionsExt::from_mode(0o555)).unwrap();
        let outcome = changes.apply(&lower).since(since).run();
        std::fs::set_permissions(lower.join("locked"), PermissionsExt::from_mode(0o755)).unwrap();
        match outcome {
            Err(ProvisionError::ApplyIncomplete { applied, path, .. }) => {
                assert_eq!(applied, [Path::new("a-first")]);
                assert_eq!(path, Path::new("locked/new"));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(names(&lower), ["a-first", "locked"]);
    }

    #[test]
    fn no_reference_time_is_refused_where_the_upper_records_none() {
        let (_scratch, overlay, lower, _upper) = layers("apply-no-reference");
        let mut changes = ChangeSet::read(&overlay).unwrap();
        changes.born = None;
        assert!(matches!(
            changes.apply(&lower).check(),
            Err(ProvisionError::Io { .. })
        ));
        assert!(
            changes
                .apply(&lower)
                .since(SystemTime::now())
                .check()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn the_fence_is_the_reference_less_the_margin() {
        let reference = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        assert_eq!(fence(reference), 100 * 1_000_000_000 - 10_000_000);
    }
}
