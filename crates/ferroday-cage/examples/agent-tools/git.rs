//! Git inside the sandbox, and what comes back from it.
//!
//! A working tree a command can write is input a host tool acts on later, and
//! git acts on it without being asked: every git command reads the
//! configuration of the repository it finds, and `git status` runs that
//! configuration's `core.fsmonitor`. A command that could write a gitdir the
//! caller's git reads, or point the caller's git at one of its own, could run
//! code as the caller the next time the caller runs git. So in every mode the
//! command writes no gitdir the caller's git reads:
//!
//! - **Private**, the default. Each gitdir the tree uses, the top level's and
//!   each submodule's, gets a private one in the session directory, bound at
//!   the gitdir's own path. It borrows the caller's objects read-only through
//!   `objects/info/alternates`, and starts from the caller's refs, `HEAD` and
//!   index, so git in the sandbox stages, commits, branches, stashes and
//!   rebases as it does outside. What it writes stays in the session.
//! - **Read-only.** The caller's gitdirs are bound read-only. Git reads history
//!   and reports status, and a command that writes git state fails.
//! - **Isolated.** The command works in a checkout of the caller's `HEAD` in the
//!   session directory, bound at the working tree's path, over private gitdirs
//!   as above. Nothing it does reaches the caller's tree.
//!
//! In both private modes the command's commits come back through an ordinary
//! `git fetch` into the caller's repository, whose sending side, `git
//! upload-pack`, runs in a sandbox over the private gitdir, and whose receiving
//! side checks every object (`transfer.fsckObjects`). Git starts the side it
//! fetches from as a command, which here is a relay between git and two named
//! pipes, and this process serves the pipes' other ends from the sandbox. The
//! commits come over the fetch protocol rather than in a bundle the sandbox
//! writes, since git checks a fetched pack's objects and does not check a
//! bundle's. They land under
//! `refs/agent/<session>/`. In place, the branch the caller has checked out then
//! moves to the command's, where that is a fast-forward that adds no submodule
//! and leaves `.gitmodules` as it was. Its index follows, and the working tree is
//! left as the command left it.
//!
//! Paths in the tree that git obeys are bound read-only: each submodule's `.git`
//! file, each unpopulated submodule's directory, a linked working tree's `.git`
//! file, every other repository already in the tree, and the files and the hooks
//! directory the configuration names inside the tree. A repository the command
//! creates in the tree is past what a mount can hold, so it is reported after the
//! command.
//!
//! Once a command has run, a private gitdir holds what the command wrote, so the
//! host's git never reads one: everything taken from it comes through the
//! sandboxed `upload-pack`.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{self, Command, ExitStatus, Output};
use std::time::Duration;

use ferroday_cage::{
    Cage, CageBuilder, ErrorChain, Network, PresentedIdentity, Resource, SeccompPolicy,
    SeccompRules, Stdio,
};

/// How git in the sandbox reaches the caller's repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Private gitdirs over the caller's own tree.
    Private,
    /// The caller's gitdirs, read-only.
    ReadOnly,
    /// Private gitdirs over a checkout in the session directory.
    Isolated,
}

impl Mode {
    /// Reads `--git`'s value.
    pub(crate) fn parse(text: &str) -> Result<Mode, String> {
        match text {
            "private" => Ok(Mode::Private),
            "read-only" => Ok(Mode::ReadOnly),
            "isolated" => Ok(Mode::Isolated),
            _ => Err(format!(
                "--git takes private, read-only or isolated, not {text:?}"
            )),
        }
    }

    /// The mode as `--git` spells it.
    fn name(self) -> &'static str {
        match self {
            Mode::Private => "private",
            Mode::ReadOnly => "read-only",
            Mode::Isolated => "isolated",
        }
    }
}

/// Where an import's refs land: each session's beneath a name of its own.
const NAMESPACE: &str = "refs/agent";

/// The mode of every directory the example creates for a session.
const PRIVATE_DIR: u32 = 0o700;

/// The longest `.git` file or `commondir` file read: one line naming a path.
const MAX_POINTER: u64 = 4096;

/// The settings a private gitdir carries over from the caller's configuration,
/// as each scope of it answers, since the caller's own configuration files are
/// out of the sandbox's view.
const CARRIED: &[&str] = &[
    "user.name",
    "user.email",
    "core.filemode",
    "core.symlinks",
    "core.ignorecase",
    "core.precomposeunicode",
    "core.autocrlf",
    "core.eol",
    "core.safecrlf",
    "core.hookspath",
    "core.sparsecheckout",
    "core.sparsecheckoutcone",
];

/// The repository extensions a private gitdir can stand in for. Any other is
/// refused, as git refuses a repository whose extension it does not know: the
/// object format is the private gitdir's own from its creation, and the others
/// change nothing a private gitdir copies.
const KNOWN_EXTENSIONS: &[&str] = &[
    "extensions.objectformat",
    "extensions.refstorage",
    "extensions.worktreeconfig",
];

/// A repository the working tree uses, as the caller's host holds it.
struct Repository {
    /// Its working tree, relative to the tree's top; empty for the top level.
    path: PathBuf,
    /// The repository it is a submodule of, by its place in the session's
    /// list; `None` for the top level.
    parent: Option<usize>,
    /// Its gitdir on the host: `.git` itself, a linked working tree's
    /// directory under `worktrees/`, or a submodule's under `modules/`.
    gitdir: PathBuf,
    /// The gitdir its objects, refs and configuration are kept in: the gitdir
    /// itself, or a linked working tree's main gitdir.
    common: PathBuf,
    /// Where git in the sandbox finds its gitdir: the host gitdir's own path in
    /// place, and beneath the checkout's `.git` in an isolated session.
    seen_at: PathBuf,
    /// The private gitdir standing in for it, in the session directory.
    private: PathBuf,
    /// The hooks directory of the caller's, where hooks are kept in the gitdir
    /// rather than where `core.hooksPath` names.
    hooks: Option<PathBuf>,
    /// The object directories its own borrows from through the host's
    /// alternates, bound read-only at their own paths so the borrowing holds.
    alternates: Vec<PathBuf>,
}

/// What a run sets up for git before the command, and settles after it.
pub(crate) struct Session {
    mode: Mode,
    /// The session directory: the private gitdirs, and an isolated checkout.
    dir: PathBuf,
    /// Whether the directory is this run's alone, removed once it is settled.
    temporary: bool,
    /// The name an import's refs land under, beneath [`NAMESPACE`].
    name: String,
    /// The caller's working tree, which is also where the command sees its
    /// tree.
    worktree: PathBuf,
    /// The host tree bound at the working tree's path: the caller's own, or
    /// the isolated checkout.
    tree: PathBuf,
    /// The repositories, the top level first and each before its submodules.
    repositories: Vec<Repository>,
    /// Paths relative to the tree that the command may not write, bound
    /// read-only.
    read_only: Vec<PathBuf>,
    /// Paths outside the tree bound read-only at their own paths: a linked
    /// working tree's main gitdir, under the read-only mode.
    revealed: Vec<PathBuf>,
    /// The `.git` entries the tree held before the command, relative to it.
    entries: BTreeSet<PathBuf>,
    /// Each held path in the tree and each directory above it there, on the
    /// host, with the entry it named before the command; see
    /// [`Session::check_held`].
    held: Vec<(PathBuf, Option<Identity>)>,
    /// Whether a repository the command creates is reported.
    report: bool,
}

/// What an entry is, as its filesystem and inode number say, whatever its name.
type Identity = (u64, u64);

/// The entry at `path`, not following a link there, or `None` where nothing is.
fn identity(path: &Path) -> Option<Identity> {
    fs::symlink_metadata(path)
        .ok()
        .map(|meta| (meta.dev(), meta.ino()))
}

impl Session {
    /// Sets git up for a command over `worktree` under `mode`, in the session
    /// directory `session`, or in a temporary one where none is given.
    ///
    /// `None` where the working tree is no git repository, since there is
    /// nothing of git's to set up. A working tree inside a repository but not
    /// at its top is refused: the repository's gitdir would be outside what the
    /// session sets up.
    pub(crate) fn open(
        worktree: &Path,
        mode: Mode,
        session: Option<&Path>,
        report: bool,
    ) -> Result<Option<Session>, String> {
        let Some((gitdir, common)) = top_level(worktree)? else {
            return Ok(None);
        };
        let (dir, temporary, named) = match session {
            Some(dir) => (session_dir(dir, worktree)?, false, None),
            None => {
                let name = session_name()?;
                (temporary_dir(&name)?, true, Some(name))
            }
        };
        let fresh = !dir.join("name").exists();
        let name = match fresh {
            true => {
                let name = match named {
                    Some(name) => name,
                    None => session_name()?,
                };
                fs::write(dir.join("worktree"), worktree.as_os_str().as_bytes())
                    .and_then(|()| fs::write(dir.join("mode"), mode.name()))
                    .and_then(|()| fs::write(dir.join("name"), &name))
                    .map_err(|err| {
                        format!("cannot record the session in {}: {err}", dir.display())
                    })?;
                name
            }
            false => {
                let recorded = fs::read_to_string(dir.join("mode")).unwrap_or_default();
                if recorded != mode.name() {
                    return Err(format!(
                        "the session {} was made for --git {recorded}, not --git {}",
                        dir.display(),
                        mode.name()
                    ));
                }
                fs::read_to_string(dir.join("name"))
                    .map_err(|err| format!("cannot read the session's name: {err}"))?
            }
        };
        let tree = match mode {
            Mode::Isolated => dir.join("checkout"),
            Mode::Private | Mode::ReadOnly => worktree.to_path_buf(),
        };
        let mut session = Session {
            mode,
            dir,
            temporary,
            name,
            worktree: worktree.to_path_buf(),
            tree,
            repositories: Vec::new(),
            read_only: Vec::new(),
            revealed: Vec::new(),
            entries: BTreeSet::new(),
            held: Vec::new(),
            report,
        };
        match session.set_up(gitdir, common, fresh) {
            Ok(()) => Ok(Some(session)),
            Err(err) => {
                session.remove();
                Err(err)
            }
        }
    }

    /// Finds the repositories and what the command may not write, and makes
    /// what the mode needs where `fresh`, a session not yet made.
    fn set_up(&mut self, gitdir: PathBuf, common: PathBuf, fresh: bool) -> Result<(), String> {
        let top = Repository {
            path: PathBuf::new(),
            parent: None,
            seen_at: match self.mode {
                Mode::Isolated => self.worktree.join(".git"),
                Mode::Private | Mode::ReadOnly => gitdir.clone(),
            },
            private: self.dir.join("git").join("0"),
            hooks: None,
            alternates: Vec::new(),
            gitdir,
            common,
        };
        self.repositories.push(top);
        let mut at = 0;
        while at < self.repositories.len() {
            self.submodules(at)?;
            at += 1;
        }
        for repository in &mut self.repositories {
            let hooks = hooks_of(repository);
            repository.hooks = hooks;
            repository.alternates = alternates_of(&repository.common.join("objects"))?;
        }

        let worktree = self.worktree.clone();
        let known: BTreeSet<PathBuf> = self
            .repositories
            .iter()
            .map(|repository| repository.path.join(".git"))
            .collect();
        if self.mode != Mode::Isolated {
            for repository in &self.repositories {
                let named = configured_paths(&worktree, repository)?;
                self.read_only.extend(named);
            }
            self.entries = git_entries(&worktree);
            // Every other repository in the tree is the caller's to run git in.
            for entry in &self.entries {
                if !known.contains(entry) {
                    self.read_only.push(entry.clone());
                }
            }
            for repository in &self.repositories {
                let entry = repository.path.join(".git");
                let is_file = fs::symlink_metadata(worktree.join(&entry))
                    .is_ok_and(|meta| meta.file_type().is_file());
                if is_file || self.mode == Mode::ReadOnly {
                    self.read_only.push(entry);
                }
            }
            if self.mode == Mode::ReadOnly {
                let top = &self.repositories[0];
                if !top.common.starts_with(&worktree) {
                    self.revealed.push(top.common.clone());
                }
            }
        }
        if self.mode != Mode::ReadOnly {
            if fresh {
                for at in 0..self.repositories.len() {
                    self.make_private(at)?;
                }
                if self.mode == Mode::Isolated {
                    self.check_out()?;
                }
                for at in 0..self.repositories.len() {
                    self.name_worktree(at)?;
                }
            } else if let Some(missing) = self
                .repositories
                .iter()
                .find(|repository| !repository.private.is_dir())
            {
                // A private gitdir a command has run over is the command's, so
                // nothing is made inside one; a repository new since the
                // session began needs a session of its own.
                return Err(format!(
                    "the session {} was made before {}; start another session",
                    self.dir.display(),
                    described(missing)
                ));
            }
        }
        if self.mode == Mode::Isolated {
            // The checkout's own submodule files point its git at the private
            // gitdirs, and are held as the caller's are in place.
            for repository in &self.repositories[1..] {
                self.read_only.push(repository.path.join(".git"));
            }
        }
        self.read_only.sort();
        self.read_only.dedup();
        self.held = self.held_identities();
        Ok(())
    }

    /// Each held path in the tree and each directory above it there, with the
    /// entry it names now.
    fn held_identities(&self) -> Vec<(PathBuf, Option<Identity>)> {
        let mut paths = BTreeSet::new();
        for path in self.protected() {
            let Ok(within) = path.strip_prefix(&self.tree) else {
                continue;
            };
            for above in within.ancestors() {
                if !above.as_os_str().is_empty() {
                    paths.insert(self.tree.join(above));
                }
            }
        }
        paths
            .into_iter()
            .map(|path| {
                let before = identity(&path);
                (path, before)
            })
            .collect()
    }

    /// Refuses a tree in which a held path, or a directory above one, is no
    /// longer the entry it was before the command.
    ///
    /// The sandbox holds them all: a held path is a read-only mount point, and
    /// each directory above it is bound onto itself, so the command can rename
    /// or remove none of them. This is the second line, which names what moved
    /// if that ever fails, rather than taking in commits from a tree whose git
    /// may now obey another configuration.
    fn check_held(&self) -> Result<(), String> {
        for (path, before) in &self.held {
            if identity(path) != *before {
                return Err(format!(
                    "{} is not the entry it was before the command, so nothing the command \
                     did is taken in; check what the tree's git obeys there before running \
                     git in it",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    /// Adds the submodules of the repository at `at`, and protects the
    /// directory of each one not checked out.
    fn submodules(&mut self, at: usize) -> Result<(), String> {
        let parent = &self.repositories[at];
        let tree = self.worktree.join(&parent.path);
        let listed =
            run(host_git(&parent.gitdir, Some(&tree)).args(["ls-files", "--stage", "-z"]))?;
        let mut found = Vec::new();
        for entry in listed
            .split(|&byte| byte == 0)
            .filter(|entry| !entry.is_empty())
        {
            let Some(tab) = entry.iter().position(|&byte| byte == b'\t') else {
                continue;
            };
            if !entry.starts_with(b"160000 ") {
                continue;
            }
            found.push(PathBuf::from(OsStr::from_bytes(&entry[tab + 1..])));
        }
        for path in found {
            let parent = &self.repositories[at];
            let relative = parent.path.join(&path);
            let checkout = self.worktree.join(&relative);
            let dotgit = checkout.join(".git");
            match fs::symlink_metadata(&dotgit) {
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    // Not checked out. A `.git` the command made here would
                    // make the caller's git enter it, so the directory is
                    // held, made first where it is missing.
                    fs::create_dir_all(&checkout).map_err(|err| {
                        format!(
                            "cannot make the submodule directory {}: {err}",
                            checkout.display()
                        )
                    })?;
                    self.read_only.push(relative);
                }
                Err(err) => return Err(format!("cannot inspect {}: {err}", dotgit.display())),
                Ok(meta) if meta.file_type().is_dir() => {
                    return Err(format!(
                        "the submodule at {} keeps its gitdir inside the working tree, which a \
                         command could have written; move it out with `git submodule \
                         absorbgitdirs` first",
                        relative.display()
                    ));
                }
                Ok(_) => {
                    let gitdir = pointed_at(&dotgit, &checkout)?;
                    // A submodule's gitdir is its parent's: under the parent's
                    // gitdir or its main one, which the command writes no
                    // more than it writes the parent's.
                    let inside_parent =
                        gitdir.starts_with(&parent.gitdir) || gitdir.starts_with(&parent.common);
                    if !inside_parent {
                        return Err(format!(
                            "the submodule at {} names a gitdir, {}, that is not its \
                             repository's own",
                            relative.display(),
                            gitdir.display()
                        ));
                    }
                    let seen_at = match self.mode {
                        Mode::Isolated => {
                            let within = gitdir
                                .strip_prefix(&parent.gitdir)
                                .or_else(|_| gitdir.strip_prefix(&parent.common))
                                .expect("the gitdir is under one of the two");
                            parent.seen_at.join(within)
                        }
                        Mode::Private | Mode::ReadOnly => gitdir.clone(),
                    };
                    let number = self.repositories.len();
                    self.repositories.push(Repository {
                        path: relative,
                        parent: Some(at),
                        common: gitdir.clone(),
                        seen_at,
                        private: self.dir.join("git").join(number.to_string()),
                        hooks: None,
                        alternates: Vec::new(),
                        gitdir,
                    });
                }
            }
        }
        Ok(())
    }
}

/// What the configuration of `repository` names inside the tree at `worktree`,
/// relative to it: the files it includes, and its hooks directory. A missing
/// one is made first, since git reads one the command could otherwise create.
fn configured_paths(worktree: &Path, repository: &Repository) -> Result<Vec<PathBuf>, String> {
    let mut found = Vec::new();
    {
        let tree = worktree.join(&repository.path);
        let mut command = host_config(&repository.gitdir);
        command.args([
            "--show-origin",
            "-z",
            "--get-regexp",
            r"^(include\.path|includeif\..*\.path|core\.hookspath)$",
        ]);
        let listed = run_allowing(&mut command, &[1])?;
        for record in listed
            .split(|&byte| byte == 0)
            .collect::<Vec<_>>()
            .chunks(2)
        {
            let [origin, setting] = record else {
                continue;
            };
            let Some(newline) = setting.iter().position(|&byte| byte == b'\n') else {
                continue;
            };
            let (key, value) = (&setting[..newline], &setting[newline + 1..]);
            let value = expand_home(Path::new(OsStr::from_bytes(value)));
            let (target, directory) = if key == b"core.hookspath" {
                (tree.join(value), true)
            } else {
                let Some(file) = origin.strip_prefix(b"file:") else {
                    continue;
                };
                let base = Path::new(OsStr::from_bytes(file))
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_default();
                (base.join(value), false)
            };
            let Ok(relative) = lexical(&target)
                .strip_prefix(worktree)
                .map(Path::to_path_buf)
            else {
                continue;
            };
            let made = match directory {
                true => fs::create_dir_all(&target),
                false => fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&target)
                    .map(drop),
            };
            made.map_err(|err| format!("cannot make {}: {err}", target.display()))?;
            found.push(relative);
        }
    }
    Ok(found)
}

impl Session {
    /// Makes the private gitdir of the repository at `at` from the caller's.
    ///
    /// Run only for a fresh session, before any command, while the private
    /// gitdir is still this example's own and git may read it.
    fn make_private(&self, at: usize) -> Result<(), String> {
        let repository = &self.repositories[at];
        let private = &repository.private;
        refuse_extensions(&repository.gitdir)?;
        let format =
            text(host_git(&repository.common, None).args(["rev-parse", "--show-object-format"]))?;
        make_dir(private.parent().expect("a private gitdir has a parent"))?;
        run(git()
            .args(["init", "--quiet", "--bare"])
            .arg(format!("--object-format={format}"))
            .arg(private))?;
        // The sample hooks and the description are git's, and the directory is
        // where the caller's hooks are bound, where they are the gitdir's.
        if let Ok(samples) = fs::read_dir(private.join("hooks")) {
            for sample in samples.flatten() {
                let _ = fs::remove_file(sample.path());
            }
        }
        let _ = fs::remove_file(private.join("description"));
        make_dir(&private.join("hooks"))?;
        make_dir(&private.join("host-objects"))?;
        fs::write(private.join("objects/info/alternates"), "../host-objects\n")
            .map_err(|err| format!("cannot write {}'s alternates: {err}", private.display()))?;

        let mut settings = vec![
            ("core.bare".to_string(), b"false".to_vec()),
            ("core.logallrefupdates".to_string(), b"true".to_vec()),
        ];
        for key in CARRIED {
            if let Some(value) = setting(&repository.gitdir, key)? {
                settings.push((key.to_string(), value));
            }
        }
        for (key, value) in settings {
            run(private_git(repository)
                .args(["config", &key])
                .arg(OsStr::from_bytes(&value)))?;
        }

        // The caller's refs, borrowing the caller's objects while they are
        // written, since a ref is refused for an object it cannot find.
        let refs = run(host_git(&repository.gitdir, None)
            .args(["for-each-ref", "--format=%(objectname) %(refname)"]))?;
        let mut updates = Vec::new();
        for line in refs
            .split(|&byte| byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let Some(space) = line.iter().position(|&byte| byte == b' ') else {
                continue;
            };
            let (object, name) = (&line[..space], &line[space + 1..]);
            if name.starts_with(format!("{NAMESPACE}/").as_bytes()) {
                continue;
            }
            updates.extend_from_slice(b"create ");
            updates.extend_from_slice(name);
            updates.push(b' ');
            updates.extend_from_slice(object);
            updates.push(b'\n');
        }
        run_with_input(
            private_git(repository).args(["update-ref", "--stdin"]),
            &updates,
        )?;
        let head = run_allowing(
            host_git(&repository.gitdir, None).args(["symbolic-ref", "--quiet", "HEAD"]),
            &[1],
        )?;
        if head.is_empty() {
            let detached =
                text(host_git(&repository.gitdir, None).args(["rev-parse", "--verify", "HEAD"]))?;
            run(private_git(repository).args(["update-ref", "--no-deref", "HEAD", &detached]))?;
        } else {
            let branch = head.strip_suffix(b"\n").unwrap_or(&head);
            run(private_git(repository)
                .args(["symbolic-ref", "HEAD"])
                .arg(OsStr::from_bytes(branch)))?;
        }

        // What the caller's index and the files beside it say of the tree, in
        // place: the staged changes, what is ignored, how much is checked out.
        let mut copied: Vec<(PathBuf, PathBuf)> = vec![
            (
                repository.common.join("info/exclude"),
                private.join("info/exclude"),
            ),
            (
                repository.common.join("info/attributes"),
                private.join("info/attributes"),
            ),
            (
                repository.gitdir.join("info/sparse-checkout"),
                private.join("info/sparse-checkout"),
            ),
            (repository.common.join("shallow"), private.join("shallow")),
        ];
        if self.mode == Mode::Private {
            copied.push((repository.gitdir.join("index"), private.join("index")));
            let shared = fs::read_dir(&repository.gitdir)
                .map_err(|err| format!("cannot read {}: {err}", repository.gitdir.display()))?;
            for entry in shared.flatten() {
                if entry.file_name().as_bytes().starts_with(b"sharedindex.") {
                    copied.push((entry.path(), private.join(entry.file_name())));
                }
            }
        }
        for (from, to) in copied {
            match fs::copy(&from, &to) {
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(format!("cannot copy {}: {err}", from.display())),
            }
        }

        // A submodule's private gitdir is bound beneath an earlier one's, where
        // its own gitdir lies beneath that one's; the mount needs its target.
        for earlier in &self.repositories[..at] {
            if let Ok(within) = repository.seen_at.strip_prefix(&earlier.seen_at) {
                make_dir(&earlier.private.join(within))?;
            }
        }
        Ok(())
    }

    /// Names `repository`'s working tree in its private gitdir, where the
    /// caller's names one, as a submodule's gitdir does.
    ///
    /// Written last, once nothing more is done to the private gitdir on the
    /// host: a relative one names the tree from where the gitdir is seen in the
    /// sandbox, which on the host is nowhere.
    fn name_worktree(&self, at: usize) -> Result<(), String> {
        let repository = &self.repositories[at];
        let mut settings: Vec<(String, Vec<u8>)> = Vec::new();
        match self.mode {
            Mode::Isolated if at > 0 => {
                let checkout = self.worktree.join(&repository.path);
                settings.push((
                    "core.worktree".to_string(),
                    checkout.into_os_string().into_vec(),
                ));
            }
            _ => {
                let mut command = host_config(&repository.gitdir);
                command.args(["--local", "--get", "core.worktree"]);
                let local = run_allowing(&mut command, &[1])?;
                if !local.is_empty() {
                    let value = local.strip_suffix(b"\n").unwrap_or(&local).to_vec();
                    settings.push(("core.worktree".to_string(), value));
                }
            }
        }
        for (key, value) in settings {
            run(private_git(repository)
                .args(["config", &key])
                .arg(OsStr::from_bytes(&value)))?;
        }
        Ok(())
    }

    /// Checks out the caller's `HEAD`, and each submodule at the commit it
    /// records, into the isolated checkout, from the private gitdirs while they
    /// are still this example's own.
    fn check_out(&self) -> Result<(), String> {
        make_dir(&self.tree)?;
        for repository in &self.repositories {
            let checkout = self.tree.join(&repository.path);
            make_dir(&checkout)?;
            if repository.path.as_os_str().is_empty() {
                // An unborn `HEAD` checks out nothing.
                let born = run_allowing(
                    private_git(repository).args(["rev-parse", "--verify", "--quiet", "HEAD"]),
                    &[1],
                )?;
                if !born.is_empty() {
                    self.read_tree(repository, &checkout)?;
                }
            } else {
                let parent =
                    &self.repositories[repository.parent.expect("a submodule has a parent")];
                let within = repository
                    .path
                    .strip_prefix(&parent.path)
                    .expect("a submodule lies within its parent");
                let listed = run(private_git(parent)
                    .args(["ls-tree", "-z", "HEAD", "--"])
                    .arg(within))?;
                let commit = listed
                    .split(|&byte| byte == b' ')
                    .nth(2)
                    .and_then(|field| field.split(|&byte| byte == b'\t').next())
                    .map(|commit| String::from_utf8_lossy(commit).into_owned());
                let Some(commit) = commit.filter(|_| listed.starts_with(b"160000 ")) else {
                    continue;
                };
                run(private_git(repository).args(["update-ref", "--no-deref", "HEAD", &commit]))?;
                self.read_tree(repository, &checkout)?;
                // Relative, so on the host it names the checkout's own `.git`,
                // which holds nothing, and git there finds no gitdir.
                let depth = repository.path.components().count();
                let within = repository
                    .seen_at
                    .strip_prefix(self.worktree.join(".git"))
                    .expect("an isolated submodule's gitdir is under the checkout's");
                let mut pointer = PathBuf::new();
                for _ in 0..depth {
                    pointer.push("..");
                }
                pointer.push(".git");
                pointer.push(within);
                let mut gitfile = b"gitdir: ".to_vec();
                gitfile.extend_from_slice(pointer.as_os_str().as_bytes());
                gitfile.push(b'\n');
                fs::write(checkout.join(".git"), gitfile)
                    .map_err(|err| format!("cannot write {}/.git: {err}", checkout.display()))?;
            }
        }
        // Where the top level's private gitdir is bound.
        make_dir(&self.tree.join(".git"))
    }

    /// Lays `repository`'s `HEAD` into `checkout`, with the index to match.
    fn read_tree(&self, repository: &Repository, checkout: &Path) -> Result<(), String> {
        run(private_git(repository)
            .arg("--work-tree")
            .arg(checkout)
            .args(["read-tree", "--reset", "-u", "HEAD"]))
        .map(drop)
    }

    /// The host tree bound at the working tree's path.
    pub(crate) fn tree(&self) -> &Path {
        &self.tree
    }

    /// Every path the command may not write, on the host, beneath the tree it
    /// writes: what a runtime's own editing tool, which runs outside the
    /// sandbox, refuses as well.
    pub(crate) fn protected(&self) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = self
            .read_only
            .iter()
            .map(|relative| self.tree.join(relative))
            .collect();
        for repository in &self.repositories {
            if let Ok(within) = repository.seen_at.strip_prefix(&self.worktree) {
                paths.push(self.tree.join(within));
            }
        }
        paths.sort();
        paths.dedup();
        paths
    }

    /// The mounts git needs, laid over a builder whose tree is already bound at
    /// the working tree's path.
    pub(crate) fn mount(&self, mut builder: CageBuilder) -> CageBuilder {
        if self.mode != Mode::ReadOnly {
            for repository in &self.repositories {
                builder = builder
                    .bind(&repository.private, &repository.seen_at)
                    .bind_ro(
                        repository.common.join("objects"),
                        repository.seen_at.join("host-objects"),
                    );
                if let Some(hooks) = &repository.hooks {
                    builder = builder.bind_ro(hooks, repository.seen_at.join("hooks"));
                }
                for alternate in &repository.alternates {
                    builder = builder.bind_ro(alternate, alternate);
                }
            }
        }
        for path in &self.revealed {
            builder = builder.bind_ro(path, path);
        }
        for relative in &self.read_only {
            builder = builder.read_only(self.worktree.join(relative));
        }
        builder
    }

    /// Takes the command's commits in, moves the caller's checked-out branches
    /// on where the mode says, reports what is left, and removes a temporary
    /// session.
    ///
    /// A temporary session whose commits could not be taken in is kept, and
    /// the failure names it, so nothing the command committed is lost.
    pub(crate) fn finish(self) -> Result<(), String> {
        let settled = self.settle();
        match &settled {
            Err(_) if self.temporary => {
                eprintln!("agent-tools: the session is kept at {}", self.dir.display());
            }
            _ => self.remove(),
        }
        settled
    }

    fn settle(&self) -> Result<(), String> {
        self.check_held()?;
        if self.mode != Mode::ReadOnly {
            // A submodule's commits first, so a superproject commit naming one
            // finds it in the caller's repository.
            for repository in self.repositories.iter().rev() {
                self.import(repository)?;
            }
            if self.mode == Mode::Private {
                for repository in self.repositories.iter().rev() {
                    self.adopt(repository)?;
                }
            }
            for repository in &self.repositories {
                self.tidy(repository)?;
            }
        }
        if self.report && self.mode != Mode::Isolated {
            for entry in git_entries(&self.worktree).difference(&self.entries) {
                eprintln!(
                    "agent-tools: the command made a repository at {}: git run there, or in \
                     the tree once it is added as a submodule, obeys the configuration the \
                     command gave it",
                    self.worktree.join(entry).display()
                );
            }
        }
        Ok(())
    }

    /// The refs of this session in the caller's repository.
    fn namespace(&self) -> String {
        format!("{NAMESPACE}/{}", self.name)
    }

    /// Fetches the command's branches, tags and `HEAD` from `repository`'s
    /// private gitdir into the caller's, under the session's namespace.
    fn import(&self, repository: &Repository) -> Result<(), String> {
        let namespace = self.namespace();
        let (taken, said) = self.fetch(
            repository,
            &[
                format!("+refs/heads/*:{namespace}/heads/*"),
                format!("+refs/tags/*:{namespace}/tags/*"),
            ],
        )?;
        if !taken.success() {
            return Err(format!(
                "the command's commits in {} were refused: {said}",
                described(repository)
            ));
        }
        // An unborn or missing `HEAD` has nothing to take, and is said rather
        // than failing the rest.
        let (head, said) = self.fetch(repository, &[format!("+HEAD:{namespace}/HEAD")])?;
        if !head.success() {
            eprintln!(
                "agent-tools: the command's HEAD in {} was not taken in: {said}",
                described(repository)
            );
        }
        Ok(())
    }

    /// Runs `git fetch` from `repository`'s private gitdir into the caller's
    /// repository with `refspecs`, serving it from a sandbox, and answers how
    /// the fetch ended and what it said.
    ///
    /// The fetch starts its `upload-pack` as `sh`, copying git's requests into
    /// one named pipe in the session directory and the other's replies back,
    /// until the replies end.
    /// This process opens the pipes' other ends, waiting for the relay to open
    /// its own, and launches `git upload-pack` in a sandbox with them as its
    /// standard input and output: the private gitdir read-only at its own path,
    /// the caller's objects read-only beneath it, and no network.
    fn fetch(
        &self,
        repository: &Repository,
        refspecs: &[String],
    ) -> Result<(ExitStatus, String), String> {
        let pipes = self.dir.join("pipes");
        make_dir(&pipes)?;
        let requests = pipes.join("requests");
        let replies = pipes.join("replies");
        for fifo in [&requests, &replies] {
            let _ = fs::remove_file(fifo);
            rustix::fs::mknodat(
                rustix::fs::CWD,
                fifo,
                rustix::fs::FileType::Fifo,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                0,
            )
            .map_err(|err| format!("cannot make {}: {}", fifo.display(), io::Error::from(err)))?;
        }
        let said_path = pipes.join("said");
        let said = fs::File::create(&said_path)
            .map_err(|err| format!("cannot make {}: {err}", said_path.display()))?;

        // The replies' end decides when the relay ends: once the sandbox has
        // closed it, the copy of git's requests is stopped, so git sees its
        // answer end however the server ended. A job in the background reads
        // nothing but what it is given, so it is given git's requests by
        // descriptor.
        let mut relay =
            b"--upload-pack=sh -c 'exec 3<&0; cat <&3 >\"$1\" & cat \"$0\"; kill $! 2>/dev/null' "
                .to_vec();
        relay.extend_from_slice(&quoted(replies.as_os_str()));
        relay.push(b' ');
        relay.extend_from_slice(&quoted(requests.as_os_str()));
        let mut git = host_git(&repository.gitdir, None);
        git.args(["-c", "transfer.fsckObjects=true", "fetch", "--quiet"])
            .args([
                "--no-tags",
                "--no-write-fetch-head",
                "--no-recurse-submodules",
            ])
            .arg(OsString::from_vec(relay))
            .arg(&repository.private)
            .args(refspecs)
            .stdin(process::Stdio::null())
            .stdout(process::Stdio::null())
            .stderr(said);
        let mut fetching = git
            .spawn()
            .map_err(|err| format!("cannot run git: {err}"))?;

        // Each open waits for the relay to open the pipe's other end, which it
        // does once git starts it. Where git ends first, an end opened here
        // releases the wait.
        let reading = std::thread::spawn({
            let path = requests.clone();
            move || fs::File::open(path)
        });
        let writing = std::thread::spawn({
            let path = replies.clone();
            move || fs::OpenOptions::new().write(true).open(path)
        });
        let mut ended = None;
        while !(reading.is_finished() && writing.is_finished()) {
            if let Some(status) = fetching
                .try_wait()
                .map_err(|err| format!("cannot wait for git: {err}"))?
            {
                ended = Some(status);
                let _ = fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
                    .open(&requests);
                let _ = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
                    .open(&replies);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let ends = (reading.join(), writing.join());
        if ended.is_none()
            && let (Ok(Ok(requests)), Ok(Ok(replies))) = ends
        {
            serve(repository, requests.into(), replies.into());
        }
        let status = match ended {
            Some(status) => status,
            None => fetching
                .wait()
                .map_err(|err| format!("cannot wait for git: {err}"))?,
        };
        let said = fs::read_to_string(&said_path).unwrap_or_default();
        Ok((status, said.trim().to_string()))
    }

    /// Moves what the caller has checked out in `repository` to what the command
    /// left there, where that is a fast-forward the tree can take.
    ///
    /// The branch's ref moves first, guarded by its old value, and the index
    /// follows through `read-tree -m -i`, which keeps the caller's staged changes
    /// and leaves the working tree as the command left it. A staged change the
    /// move would overwrite puts the ref back.
    fn adopt(&self, repository: &Repository) -> Result<(), String> {
        let namespace = self.namespace();
        let worktree = self.worktree.join(&repository.path);
        let host = |args: &[&str]| -> Command {
            let mut command = host_git(&repository.gitdir, Some(&worktree));
            command.args(args);
            command
        };
        let branch = run_allowing(&mut host(&["symbolic-ref", "--quiet", "HEAD"]), &[1])?;
        let branch = String::from_utf8_lossy(&branch).trim().to_string();
        let (moved, theirs) = match branch.strip_prefix("refs/heads/") {
            Some(name) => (branch.clone(), format!("{namespace}/heads/{name}")),
            None => ("HEAD".to_string(), format!("{namespace}/HEAD")),
        };
        let resolve = |name: &str| -> Result<Option<String>, String> {
            let found = run_allowing(&mut host(&["rev-parse", "--verify", "--quiet", name]), &[1])?;
            let found = String::from_utf8_lossy(&found).trim().to_string();
            Ok((!found.is_empty()).then_some(found))
        };
        let (Some(old), Some(new)) = (resolve("HEAD")?, resolve(&theirs)?) else {
            return Ok(());
        };
        if old == new {
            return Ok(());
        }
        let said = |why: &str| {
            eprintln!(
                "agent-tools: {} in {} is left at {}: the command's is under {theirs}, {why}",
                moved,
                described(repository),
                short(&old)
            );
        };
        let forward = host(&["merge-base", "--is-ancestor", &old, &new])
            .status()
            .map_err(|err| format!("cannot run git: {err}"))?;
        if !forward.success() {
            said("which is not a fast-forward");
            return Ok(());
        }
        if let Some(why) = submodule_change(&run(&mut host(&[
            "diff-tree",
            "-r",
            "-z",
            "--no-renames",
            &old,
            &new,
        ]))?) {
            said(why);
            return Ok(());
        }
        let mut guarded = host(&["update-ref", "-m", "agent-tools: the command's commits"]);
        if moved == "HEAD" {
            guarded.arg("--no-deref");
        }
        run(guarded.args([&moved, &new, &old]))?;
        if let Err(err) = run(&mut host(&["read-tree", "-m", "-i", &old, &new])) {
            let mut back = host(&["update-ref"]);
            if moved == "HEAD" {
                back.arg("--no-deref");
            }
            run(back.args([&moved, &old, &new]))?;
            said(&format!("since the index could not follow: {err}"));
            return Ok(());
        }
        eprintln!(
            "agent-tools: {} in {} moved to the command's {}",
            moved,
            described(repository),
            short(&new)
        );
        Ok(())
    }

    /// Removes the session's refs the caller already has, and names those left.
    fn tidy(&self, repository: &Repository) -> Result<(), String> {
        let namespace = self.namespace();
        let listed = run(host_git(&repository.gitdir, None).args([
            "for-each-ref",
            "--format=%(objectname) %(refname)",
            &namespace,
        ]))?;
        let head = run_allowing(
            host_git(&repository.gitdir, None).args(["rev-parse", "--verify", "--quiet", "HEAD"]),
            &[1],
        )?;
        let head = String::from_utf8_lossy(&head).trim().to_string();
        let mut left = Vec::new();
        for line in String::from_utf8_lossy(&listed).lines() {
            let Some((object, name)) = line.split_once(' ') else {
                continue;
            };
            let within = &name[namespace.len() + 1..];
            let theirs = match within {
                "HEAD" => Some(head.clone()),
                _ => {
                    let found = run_allowing(
                        host_git(&repository.gitdir, None).args([
                            "rev-parse",
                            "--verify",
                            "--quiet",
                            &format!("refs/{within}"),
                        ]),
                        &[1],
                    )?;
                    Some(String::from_utf8_lossy(&found).trim().to_string())
                }
            };
            if theirs.as_deref() == Some(object) {
                run(host_git(&repository.gitdir, None).args(["update-ref", "-d", name, object]))?;
            } else {
                left.push(within.to_string());
            }
        }
        if !left.is_empty() {
            eprintln!(
                "agent-tools: the command's {} in {} are under {namespace}/",
                left.join(", "),
                described(repository)
            );
        }
        Ok(())
    }

    /// Ends a session no command ran in, removing a temporary one.
    pub(crate) fn discard(self) {
        self.remove();
    }

    /// Removes a temporary session directory: a tree sandboxes wrote, under
    /// the single-identity map the command ran under.
    fn remove(&self) {
        if self.temporary {
            let _ = ferroday_cage::provision::Remove::new(&self.dir)
                .identity_map(ferroday_cage::IdentityMap::Single)
                .remove_lock(false)
                .run();
        }
    }
}

/// The top level's gitdir and main gitdir, where `worktree` is the top of a
/// git working tree, `None` where it is in no repository, and the reason where
/// it is in one but not at its top or names a gitdir the example will not trust.
fn top_level(worktree: &Path) -> Result<Option<(PathBuf, PathBuf)>, String> {
    let dotgit = worktree.join(".git");
    match fs::symlink_metadata(&dotgit) {
        Ok(meta) if meta.file_type().is_dir() => {
            // A repository's own gitdir has no `commondir`. One that does was
            // written to point git elsewhere.
            if dotgit.join("commondir").exists() {
                return Err(format!(
                    "{} holds a commondir file, which points git at another repository",
                    dotgit.display()
                ));
            }
            Ok(Some((dotgit.clone(), dotgit)))
        }
        Ok(meta) if meta.file_type().is_file() => {
            // A linked working tree: its gitdir and the main one both lie
            // outside the tree, and its gitdir names this tree back.
            let gitdir = pointed_at(&dotgit, worktree)?;
            let common = match read_bounded(&gitdir.join("commondir")) {
                Ok(text) => canonical(&gitdir.join(trimmed(&text)))?,
                Err(_) => gitdir.clone(),
            };
            let back = read_bounded(&gitdir.join("gitdir")).unwrap_or_default();
            let names_this_tree =
                canonical(Path::new(trimmed(&back))).ok().as_deref() == Some(dotgit.as_path());
            if gitdir.starts_with(worktree) || common.starts_with(worktree) || !names_this_tree {
                return Err(format!(
                    "{} names a gitdir, {}, that is not this working tree's",
                    dotgit.display(),
                    gitdir.display()
                ));
            }
            Ok(Some((gitdir, common)))
        }
        Ok(_) => Err(format!(
            "{} is neither a directory nor a file",
            dotgit.display()
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let enclosing = worktree
                .ancestors()
                .skip(1)
                .find(|ancestor| ancestor.join(".git").exists());
            match enclosing {
                Some(top) => Err(format!(
                    "the working tree is inside the repository at {}; give that as --worktree",
                    top.display()
                )),
                None => Ok(None),
            }
        }
        Err(err) => Err(format!("cannot inspect {}: {err}", dotgit.display())),
    }
}

/// The gitdir a `.git` file names, resolved against `base` and to its real
/// path.
fn pointed_at(dotgit: &Path, base: &Path) -> Result<PathBuf, String> {
    let text =
        read_bounded(dotgit).map_err(|err| format!("cannot read {}: {err}", dotgit.display()))?;
    let Some(named) = text.strip_prefix("gitdir: ") else {
        return Err(format!("{} names no gitdir", dotgit.display()));
    };
    canonical(&base.join(trimmed(named)))
}

/// The directory `repository`'s hooks are run from in the caller's git, where
/// it is the gitdir's own: none where `core.hooksPath` names another, which the
/// private gitdir carries.
fn hooks_of(repository: &Repository) -> Option<PathBuf> {
    let configured = setting(&repository.gitdir, "core.hookspath").ok().flatten();
    let hooks = repository.common.join("hooks");
    (configured.is_none() && hooks.is_dir()).then_some(hooks)
}

/// The object directories `objects` borrows from through its alternates, and
/// theirs in turn, as git follows them.
fn alternates_of(objects: &Path) -> Result<Vec<PathBuf>, String> {
    let mut found: Vec<PathBuf> = Vec::new();
    let mut pending = vec![objects.to_path_buf()];
    // Git follows alternates five deep.
    for _ in 0..5 {
        let mut next = Vec::new();
        for directory in pending {
            let Ok(text) = read_bounded(&directory.join("info/alternates")) else {
                continue;
            };
            for line in text
                .lines()
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
            {
                let Ok(alternate) = canonical(&directory.join(line)) else {
                    continue;
                };
                if !found.contains(&alternate) {
                    found.push(alternate.clone());
                    next.push(alternate);
                }
            }
        }
        pending = next;
    }
    Ok(found)
}

/// Refuses a repository with an extension a private gitdir cannot stand in
/// for, naming it.
fn refuse_extensions(gitdir: &Path) -> Result<(), String> {
    let mut command = host_config(gitdir);
    command.args(["--get-regexp", r"^extensions\."]);
    let listed = run_allowing(&mut command, &[1])?;
    for line in String::from_utf8_lossy(&listed).lines() {
        let key = line.split(' ').next().unwrap_or_default();
        if !KNOWN_EXTENSIONS.contains(&key) {
            return Err(format!(
                "the repository at {} uses {key}, which a private gitdir cannot stand in for; \
                 run with --git read-only",
                gitdir.display()
            ));
        }
    }
    Ok(())
}

/// The value of `key` in the configuration git reads for `gitdir`, every scope
/// of it, or `None` where it is not set.
fn setting(gitdir: &Path, key: &str) -> Result<Option<Vec<u8>>, String> {
    let mut command = host_config(gitdir);
    command.args(["--get", key]);
    let value = run_allowing(&mut command, &[1])?;
    Ok((!value.is_empty()).then(|| value.strip_suffix(b"\n").unwrap_or(&value).to_vec()))
}

/// Why a fast-forward from `old` to `new` touches what makes the caller's git
/// enter a directory, from `git diff-tree -r -z` between them: a submodule
/// added where none was, or a change to `.gitmodules`.
fn submodule_change(diff: &[u8]) -> Option<&'static str> {
    let mut fields = diff.split(|&byte| byte == 0);
    while let (Some(header), Some(path)) = (fields.next(), fields.next()) {
        let modes: Vec<&[u8]> = header.split(|&byte| byte == b' ').collect();
        let (Some(old), Some(new)) = (modes.first(), modes.get(1)) else {
            continue;
        };
        if path == b".gitmodules" {
            return Some("which changes .gitmodules");
        }
        if *new == b"160000" && *old != b":160000" {
            return Some("which adds a submodule");
        }
    }
    None
}

/// Serves `git upload-pack` over `repository`'s private gitdir from a sandbox,
/// reading the fetch's requests from `requests` and writing the replies to
/// `replies`.
///
/// The private gitdir is bound read-only at its own path, the caller's objects
/// read-only beneath it where its alternates find them, and the network is
/// none. What fails is said, and the fetch then fails for want of an answer.
fn serve(repository: &Repository, requests: OwnedFd, replies: OwnedFd) {
    let private = &repository.private;
    let mut builder = Cage::builder()
        .host_rootfs()
        .bind_ro(private, private)
        .bind_ro(
            repository.common.join("objects"),
            private.join("host-objects"),
        );
    for alternate in &repository.alternates {
        builder = builder.bind_ro(alternate, alternate);
    }
    let served = builder
        .present_as(PresentedIdentity::Own)
        .network(Network::None)
        .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
        .rlimit(Resource::CoreDump, 0, 0)
        .stop_with_caller(true)
        .path_lookup(true)
        .env("HOME", "/tmp")
        .stdin(Stdio::from_fd(requests))
        .stdout(Stdio::from_fd(replies))
        // A submodule's gitdir names its working tree relative to where the
        // gitdir is seen, and here it is seen at its own path, so the
        // `pack-objects` the fetch starts would look for a working tree that is
        // not there and refuse. Neither reads one, so it is named as one that
        // is, through the environment, which git consults before the
        // gitdir's configuration.
        .env("GIT_WORK_TREE", "/")
        .command("git")
        .args([
            OsStr::new("upload-pack"),
            OsStr::new("--strict"),
            private.as_os_str(),
        ])
        .build()
        .and_then(|cage| cage.run());
    match served {
        Ok(status) if status.success() => {}
        Ok(status) => eprintln!("agent-tools: the sandboxed upload-pack ended {status}"),
        Err(error) => eprintln!(
            "agent-tools: the sandboxed upload-pack: {}",
            ErrorChain::new(&error)
        ),
    }
}

/// Every `.git` entry beneath `root`, relative to it, without descending into
/// one or following a symbolic link.
fn git_entries(root: &Path) -> BTreeSet<PathBuf> {
    let mut found = BTreeSet::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let Ok(entries) = fs::read_dir(root.join(&relative)) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = relative.join(entry.file_name());
            if entry.file_name() == ".git" {
                found.insert(path);
            } else if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                pending.push(path);
            }
        }
    }
    found
}

/// Git on the host, with nothing of the caller's environment that would point
/// it elsewhere.
fn git() -> Command {
    let mut command = Command::new("git");
    for (name, _) in std::env::vars_os() {
        if name.as_bytes().starts_with(b"GIT_") {
            command.env_remove(name);
        }
    }
    command
}

/// Git on the host over the caller's repository at `gitdir`, and `worktree`
/// where one is given, named explicitly so no `.git` file in the tree is read,
/// and with the settings that run a program turned off: the caller's own git
/// runs those, and these commands need neither.
fn host_git(gitdir: &Path, worktree: Option<&Path>) -> Command {
    let mut command = git();
    command.arg("--git-dir").arg(gitdir);
    if let Some(worktree) = worktree {
        command.arg("--work-tree").arg(worktree);
    }
    command.args([
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
    ]);
    command.env("GIT_OPTIONAL_LOCKS", "0");
    command
}

/// Git on the host over `repository`'s private gitdir, while it is still this
/// example's own: before any command has run.
///
/// The gitdir borrows the caller's objects through `host-objects`, which is
/// bound there only in a sandbox, so on the host they are named through the
/// environment instead.
fn private_git(repository: &Repository) -> Command {
    let mut command = git();
    command.arg("--git-dir").arg(&repository.private).env(
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        repository.common.join("objects"),
    );
    command
}

/// `git config` over the caller's repository at `gitdir`, reading what the
/// caller set rather than [`host_git`]'s overrides.
fn host_config(gitdir: &Path) -> Command {
    let mut command = git();
    command.arg("--git-dir").arg(gitdir).arg("config");
    command
}

/// Runs `command`, answering its standard output, or what it wrote to standard
/// error where it fails.
fn run(command: &mut Command) -> Result<Vec<u8>, String> {
    run_allowing(command, &[])
}

/// [`run`], taking each exit code of `allowed` as an empty answer, as `git
/// config --get` answers a setting that is not set.
fn run_allowing(command: &mut Command, allowed: &[i32]) -> Result<Vec<u8>, String> {
    let output = command
        .output()
        .map_err(|err| format!("cannot run git: {err}"))?;
    answered(command, output, allowed)
}

/// [`run`], with `input` on its standard input.
fn run_with_input(command: &mut Command, input: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Write;
    let mut child = command
        .stdin(process::Stdio::piped())
        .stdout(process::Stdio::piped())
        .stderr(process::Stdio::piped())
        .spawn()
        .map_err(|err| format!("cannot run git: {err}"))?;
    let written = child
        .stdin
        .take()
        .expect("standard input is piped")
        .write_all(input);
    let output = child
        .wait_with_output()
        .map_err(|err| format!("cannot run git: {err}"))?;
    // A git that refused its input stops reading it, and what it said is the
    // failure to report.
    let answer = answered(command, output, &[])?;
    written.map_err(|err| format!("cannot write to git: {err}"))?;
    Ok(answer)
}

/// What a finished `command` answered.
fn answered(command: &Command, output: Output, allowed: &[i32]) -> Result<Vec<u8>, String> {
    match output.status.code() {
        Some(0) => Ok(output.stdout),
        Some(code) if allowed.contains(&code) => Ok(Vec::new()),
        _ => Err(format!(
            "git {} failed: {}",
            command
                .get_args()
                .map(OsStr::to_string_lossy)
                .collect::<Vec<_>>()
                .join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )),
    }
}

/// [`run`]'s answer as one trimmed line of text.
fn text(command: &mut Command) -> Result<String, String> {
    Ok(String::from_utf8_lossy(&run(command)?).trim().to_string())
}

/// How a report names `repository`.
fn described(repository: &Repository) -> String {
    match repository.path.as_os_str().is_empty() {
        true => "the repository".to_string(),
        false => format!("the submodule at {}", repository.path.display()),
    }
}

/// An object name shortened for a report.
fn short(object: &str) -> &str {
    &object[..object.len().min(12)]
}

/// `text` shell-quoted for the command line git runs an `upload-pack` through.
fn quoted(text: &OsStr) -> Vec<u8> {
    let mut quoted = vec![b'\''];
    for &byte in text.as_bytes() {
        match byte {
            b'\'' => quoted.extend_from_slice(b"'\\''"),
            byte => quoted.push(byte),
        }
    }
    quoted.push(b'\'');
    quoted
}

/// The session directory `dir`, made where it is missing, refused where it is
/// inside the working tree, the tree is inside it, or it was made for another
/// tree.
fn session_dir(dir: &Path, worktree: &Path) -> Result<PathBuf, String> {
    make_dir(dir)?;
    let dir = canonical(dir)?;
    if dir.starts_with(worktree) || worktree.starts_with(&dir) {
        return Err(format!(
            "the session {} and the working tree must lie apart",
            dir.display()
        ));
    }
    if let Ok(recorded) = fs::read(dir.join("worktree"))
        && recorded != worktree.as_os_str().as_bytes()
    {
        return Err(format!(
            "the session {} was made for the working tree {}",
            dir.display(),
            String::from_utf8_lossy(&recorded)
        ));
    }
    Ok(dir)
}

/// A temporary session directory of this run's alone, for the session `name`.
fn temporary_dir(name: &str) -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join(format!("agent-tools-{name}"));
    fs::DirBuilder::new()
        .mode(PRIVATE_DIR)
        .create(&dir)
        .map_err(|err| format!("cannot make a session directory {}: {err}", dir.display()))?;
    Ok(dir)
}

/// A name for a session: the seconds since the epoch, this process's id, and
/// how many sessions this process began before it, which sort by when the
/// session began and differ between any two at once.
fn session_name() -> Result<String, String> {
    static BEGUN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| format!("the clock reads before the epoch: {err}"))?;
    let begun = BEGUN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(format!("{}-{}-{begun}", since.as_secs(), process::id()))
}

/// Makes `dir` and its missing parents, the session's own mode on each.
fn make_dir(dir: &Path) -> Result<(), String> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(PRIVATE_DIR)
        .create(dir)
        .map_err(|err| format!("cannot make {}: {err}", dir.display()))
}

/// Reads a small file a repository keeps a path in, bounded.
fn read_bounded(path: &Path) -> io::Result<String> {
    let mut text = String::new();
    fs::File::open(path)?
        .take(MAX_POINTER)
        .read_to_string(&mut text)?;
    Ok(text)
}

/// `text` without the line ending a pointer file ends in.
fn trimmed(text: &str) -> &str {
    text.trim_end_matches(['\n', '\r'])
}

/// `path` resolved to its real path.
fn canonical(path: &Path) -> Result<PathBuf, String> {
    fs::canonicalize(path).map_err(|err| format!("cannot resolve {}: {err}", path.display()))
}

/// `path` with `.` and `..` resolved by their names, for a path that need not
/// exist yet.
fn lexical(path: &Path) -> PathBuf {
    let mut resolved = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                resolved.pop();
            }
            std::path::Component::CurDir => {}
            other => resolved.push(other),
        }
    }
    resolved
}

/// `path` with a leading `~/` read as the caller's home directory, as git reads
/// one in a path setting.
fn expand_home(path: &Path) -> PathBuf {
    match (path.strip_prefix("~"), std::env::var_os("HOME")) {
        (Ok(rest), Some(home)) => Path::new(&home).join(rest),
        _ => path.to_path_buf(),
    }
}
