//! Stage two: turning an unpacked tree into a root `apk` recognizes.
//!
//! Every package's files are on disk by the time anything here runs. What is
//! left is what `apk` does between laying a file down and calling a package
//! installed: run the install scripts, fire the triggers they registered, and
//! write the state a later `apk` reads back.
//!
//! # Why the scripts run in a second wave
//!
//! `apk` interleaves: it unpacks one package, runs its scripts, and moves on.
//! This layer unpacks the whole closure and then runs every script, which is the
//! Debian layer's shape and the one this phase is proving generalizes.
//!
//! The order the scripts run in is what makes the two equivalent. It is a
//! dependency order, not the closure's name order, because Alpine's base
//! packages depend on each other's scripts having run: `alpine-baselayout`'s
//! `.pre-install` calls `addgroup`, which is a `busybox` applet that exists only
//! once `busybox`'s own `.post-install` has run `busybox --install -s`. Run in
//! name order, that `addgroup` finds no command, the `shadow` group is never
//! created, and the failure is silent — the script sends it to `/dev/null` and
//! exits zero.
//!
//! # The scripts are executed, not interpreted
//!
//! A script is written to `/lib/apk/exec` and run there, exactly as `apk` runs
//! it, so the `#!` line decides the interpreter. That matters: `busybox`'s own
//! scripts are `#!/bin/busybox sh`, which works before any applet link exists,
//! while the rest are `#!/bin/sh`, which is a link `busybox-binsh` ships. Naming
//! an interpreter here would override both.
//!
//! # What a script may not do
//!
//! Under the default single-identity map only root is representable, so a script
//! that assigns a system group fails: `alpine-baselayout`'s `.post-install`
//! does `chown root:shadow etc/shadow`, and it fails under `apk` in the same
//! situation for the same reason. Alpine's own scripts tolerate it — every one
//! in the base closure ends `exit 0` — so nothing is stubbed out on their
//! behalf. A range identity map makes the same call succeed.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use super::installed::{DB_DIR, Database, EXEC_DIR};
use super::repository::Repository;
use super::{AlpineError, AlpineEvent, AlpineObserver};
use crate::provision::Stream;
use crate::provision::accounts;
use crate::provision::layer::Rooting;
use crate::provision::rooted::Rooted;
use crate::{IdentityMap, Observer, Stdio};

/// The set the caller asked for, as against the closure it resolved to.
pub(super) const WORLD: &str = "etc/apk/world";

/// The architecture the root was built for.
pub(super) const ARCH: &str = "etc/apk/arch";

/// The repositories a later `apk` fetches from, one URL per line.
pub(super) const REPOSITORIES: &str = "etc/apk/repositories";

/// The keys a later `apk` verifies those repositories against.
const KEYS_DIR: &str = "etc/apk/keys";

/// The environment `apk` gives an install script, less the two it varies per
/// script.
///
/// `apk` passes exactly this `PATH` and, unless the caller preserves the
/// environment, nothing else. So a script's sandbox is launched without the
/// base environment every other sandbox starts from: a script inherits no
/// locale, no `HOME` and no `TERM`, which is also what makes what it does a
/// function of the root rather than of the machine the bootstrap ran on.
const SCRIPT_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// The system's machine id.
///
/// `dbus`'s `.post-install` runs `dbus-uuidgen --ensure=/etc/machine-id`,
/// which writes a random id that every machine deployed from the root would
/// then share.
const MACHINE_ID: &str = "etc/machine-id";

/// The state a finished root hands back to `apk`, beside its database.
///
/// One value because a layered build supplies a different one of each: its
/// `world` and its repositories are the base's plus the increment's, and its
/// keys are written into an upper where the base's copies are already visible
/// through the overlay.
pub(super) struct State<'a> {
    /// What the root asked for, one package per line in `/etc/apk/world`.
    pub(super) world: &'a [String],
    /// The architecture the root was built for.
    pub(super) architecture: &'a str,
    /// The directories a later `apk` fetches indexes and packages from, one URL
    /// per line.
    pub(super) sources: &'a [String],
    /// The repositories whose trust anchors the root is given.
    pub(super) repositories: &'a [Repository],
    /// A tree already holding keys that this one shadows rather than replaces,
    /// which is a layered build's base. `None` for a full bootstrap.
    pub(super) beneath: Option<&'a Rooted>,
}

/// Where an install script runs: the tree, how a cage is rooted on it, the map
/// that cage runs under, and the epoch it is given.
///
/// The four travel together through every step of the configure wave. `Copy`,
/// because each is a borrow or a plain value and every step passes all of them
/// on.
#[derive(Clone, Copy)]
pub(super) struct Site<'a> {
    /// The tree the scripts run against.
    pub(super) staging: &'a Path,
    /// Whole, or over a base layer for a layered build.
    pub(super) rooting: Rooting<'a>,
    /// The map the script cages run under.
    pub(super) identity_map: &'a IdentityMap,
    /// The `SOURCE_DATE_EPOCH` every script is given, and the date the accounts
    /// the run creates are recorded at. `None` gives the scripts none and
    /// leaves the dates as they wrote them.
    pub(super) source_date_epoch: Option<i64>,
}

/// Runs every package's install scripts, fires the triggers they registered,
/// and writes the state the finished root hands back to `apk`.
///
/// `order` is the dependency order the closure was laid down in, and the one the
/// scripts run in. `carried` is the trigger subjects of packages a layered
/// build's base already holds, empty for a full bootstrap; they fire for the
/// directories this wave created exactly as the closure's own do, because a
/// trigger belongs to the installed root rather than to the transaction that ran
/// it.
///
/// Once the last trigger has run, the machine identity the scripts generated is
/// [cleared](clear_run_state), so the finished root carries none, and with an
/// epoch the accounts they created are [dated](date_accounts) by it. A layered
/// build does both in the upper.
pub(super) fn configure(
    site: Site<'_>,
    database: &Database,
    order: &[ScriptSubject],
    carried: &[ScriptSubject],
    state: &State<'_>,
    observer: &mut dyn AlpineObserver,
) -> Result<(), AlpineError> {
    let staging = site.staging;
    let tree = open_tree(staging, state)?;
    write_state(&tree, database, state)?;
    // What the accounts' dates were before any script ran, so that afterwards
    // the ones the run wrote can be told from the ones it found.
    let found = match site.source_date_epoch {
        Some(_) => Some(accounts::account_dates(&tree, state.beneath).map_err(accounts_failure)?),
        None => None,
    };

    for subject in order {
        for kind in [ScriptKind::PreInstall, ScriptKind::PostInstall] {
            let Some(body) = subject.script(kind) else {
                continue;
            };
            if observer.cancelled() {
                return Err(AlpineError::Cancelled);
            }
            observer.progress(AlpineEvent::Script {
                package: &subject.name,
                script: kind.name(),
            });
            run(
                site,
                &tree,
                subject,
                kind,
                body,
                std::slice::from_ref(&subject.version),
                observer,
            )?;
        }
    }

    fire_triggers(site, &tree, database, order, carried, observer)?;
    clear_run_state(&tree)?;
    match (site.source_date_epoch, found) {
        (Some(epoch), Some(found)) => date_accounts(&tree, &found, epoch),
        _ => Ok(()),
    }
}

/// Removes what the scripts leave that belongs to their run rather than to the
/// root: the [machine id](MACHINE_ID) a script generated.
///
/// Removed, where the Debian layer empties the same file, because the two roots
/// boot differently. `machine-id(5)` gives a generic image two states, missing
/// and empty, and `systemd` generates a fresh id from either. Alpine boots
/// OpenRC, and what generates the id there is `dbus`'s own service, whose
/// `start_pre` runs `dbus-uuidgen --ensure=/etc/machine-id`, and OpenRC's
/// `machine-id` service. Both generate an id where the file is missing, while
/// `dbus-uuidgen` refuses an empty file and fails, so an emptied id would stop
/// the system bus from starting.
///
/// Only a regular file with content is removed, since that is the shape an id
/// `dbus-uuidgen` writes has. An empty file, a symbolic link, and a layered
/// build's whiteout are none of them an id this run generated, and removing a
/// whiteout would reveal the base's id through the overlay.
fn clear_run_state(tree: &Rooted) -> Result<(), AlpineError> {
    tree.remove_if(MACHINE_ID, Rooted::is_file_with_content)
        .map_err(AlpineError::at(
            "removing the machine id",
            tree.path(MACHINE_ID),
        ))
}

/// Records every last-change day the run wrote as the day of `epoch`, in
/// `/etc/shadow` and in the previous version busybox keeps beside it.
///
/// busybox's `adduser` writes the day it ran there: it reads the clock and no
/// `SOURCE_DATE_EPOCH`. Every day the run wrote, and only those, is rewritten,
/// as [`accounts::redate`] describes, to the epoch's
/// [`last_change_day`](accounts::last_change_day). A field is a day where it
/// [holds one](is_day).
fn date_accounts(tree: &Rooted, found: &accounts::Dates, epoch: i64) -> Result<(), AlpineError> {
    let day = accounts::last_change_day(epoch);
    accounts::redate(tree, found, day.as_bytes(), is_day).map_err(accounts_failure)
}

/// Whether a last-change field holds a day: a decimal number other than zero.
///
/// An empty field disables aging and a zero demands a new password at the next
/// login, so neither is a date. A script that expires a password writes the
/// zero, and dating it would withdraw the demand.
fn is_day(field: &[u8]) -> bool {
    field.iter().all(u8::is_ascii_digit) && field.iter().any(|&digit| digit != b'0')
}

/// An accounts step's failure, reported as this layer's own.
fn accounts_failure(failure: accounts::Failure) -> AlpineError {
    AlpineError::io(failure.op, failure.path, failure.source)
}

/// Runs the `.trigger` script of every package whose watched paths the finished
/// root contains.
///
/// A trigger fires once, at the end of the whole install, with the directories
/// it matched as its arguments — which is what `apk` does, and why `busybox`'s
/// trigger is safe to run after every package's files are down even though it
/// relinks every applet.
///
/// The patterns are matched against the directories the database records rather
/// than against the filesystem: those are the directories the install created,
/// which is exactly what "changed" means for a root that did not exist before —
/// and, for a layered build, exactly the directories the increment added to a
/// base that already existed.
///
/// A layered build's `carried` subjects are the base's own trigger-watching
/// packages, and they run first: they were installed first, and a base's trigger
/// is the one that knows what to do about the directory it watches.
fn fire_triggers(
    site: Site<'_>,
    tree: &Rooted,
    database: &Database,
    order: &[ScriptSubject],
    carried: &[ScriptSubject],
    observer: &mut dyn AlpineObserver,
) -> Result<(), AlpineError> {
    let directories = database.directories();
    for subject in carried.iter().chain(order) {
        let Some(body) = subject.script(ScriptKind::Trigger) else {
            continue;
        };
        let matched = subject.triggered_by(&directories);
        if matched.is_empty() {
            continue;
        }
        if observer.cancelled() {
            return Err(AlpineError::Cancelled);
        }
        observer.progress(AlpineEvent::Script {
            package: &subject.name,
            script: ScriptKind::Trigger.name(),
        });
        run(
            site,
            tree,
            subject,
            ScriptKind::Trigger,
            body,
            &matched,
            observer,
        )?;
    }
    Ok(())
}

/// Writes one script into the tree and runs it in a cage rooted there.
///
/// The script is removed afterwards whether it succeeded or not, so a finished
/// root carries none: `apk` removes its own the same way, and one left behind
/// would be an executable in the image that nothing installed.
fn run(
    site: Site<'_>,
    tree: &Rooted,
    subject: &ScriptSubject,
    kind: ScriptKind,
    body: &[u8],
    args: &[String],
    observer: &mut dyn AlpineObserver,
) -> Result<(), AlpineError> {
    // The name apk gives it, so a script that inspects `$0` sees what it would
    // see under apk.
    let relative = format!(
        "{EXEC_DIR}/{}-{}.{}",
        subject.name,
        subject.version,
        kind.name(),
    );
    tree.write_mode(&relative, body, 0o755)
        .map_err(AlpineError::at("writing a script", tree.path(&relative)))?;

    let outcome = launch(site, &format!("/{relative}"), subject, kind, args, observer);
    let removed = tree
        .remove(&relative)
        .map_err(AlpineError::at("removing a script", tree.path(&relative)));
    outcome.and(removed)
}

/// Builds and runs the cage one script executes in.
fn launch(
    site: Site<'_>,
    script: &str,
    subject: &ScriptSubject,
    kind: ScriptKind,
    args: &[String],
    observer: &mut dyn AlpineObserver,
) -> Result<(), AlpineError> {
    let Site {
        staging,
        rooting,
        identity_map,
        source_date_epoch,
    } = site;
    let mut builder = rooting
        .builder(staging)
        .command(script)
        .args(args)
        .base_env(false)
        .env("PATH", SCRIPT_PATH)
        .env("APK_SCRIPT", kind.name())
        .env("APK_PACKAGE", &subject.name);
    if let Some(epoch) = source_date_epoch {
        builder = builder.env("SOURCE_DATE_EPOCH", epoch.to_string());
    }
    let cage = builder
        .stdin(Stdio::Null)
        // The script exists only to serve this bootstrap. Tie it to the caller
        // so a caller killed mid-bootstrap does not leave a maintainer script
        // writing into a staging tree the error path is removing.
        .stop_with_caller(true)
        .identity_map(identity_map.clone())
        .build()
        .map_err(AlpineError::Launch)?;
    let mut output = ScriptOutput { emit: observer };
    let status = cage.run_with(&mut output).map_err(AlpineError::Launch)?;
    if status.success() {
        Ok(())
    } else {
        Err(AlpineError::Script {
            package: subject.name.clone(),
            script: kind.name(),
            status,
        })
    }
}

/// Forwards a script's output to the bootstrap's observer.
struct ScriptOutput<'a> {
    emit: &'a mut dyn AlpineObserver,
}

impl Observer for ScriptOutput<'_> {
    fn stdout(&mut self, chunk: &[u8]) {
        self.emit.progress(AlpineEvent::CommandOutput {
            stream: Stream::Stdout,
            bytes: chunk,
        });
    }
    fn stderr(&mut self, chunk: &[u8]) {
        self.emit.progress(AlpineEvent::CommandOutput {
            stream: Stream::Stderr,
            bytes: chunk,
        });
    }
}

/// Writes the state a finished root hands back to `apk`, running nothing.
///
/// What an extract-only bootstrap does in place of [`configure`]. An apk
/// installed record is a file format rather than a program's output — unlike a
/// `dpkg` one, which is `dpkg`'s to write — so a root laid out for an
/// architecture the host cannot execute can still say exactly what it holds.
pub(super) fn register(
    staging: &Path,
    database: &Database,
    state: &State<'_>,
) -> Result<(), AlpineError> {
    write_state(&open_tree(staging, state)?, database, state)
}

/// Opens the tree a run writes, over the base beneath it in a layered build,
/// so a directory a write creates in the upper never hides a link the base
/// holds ([`Rooted::over`]).
fn open_tree(staging: &Path, state: &State<'_>) -> Result<Rooted, AlpineError> {
    Rooted::open(staging)
        .and_then(|tree| tree.over(state.beneath))
        .map_err(AlpineError::at("opening the tree", staging))
}

/// Writes the database and the `/etc/apk` state.
fn write_state(tree: &Rooted, database: &Database, state: &State<'_>) -> Result<(), AlpineError> {
    for (name, contents) in [
        ("installed", database.installed()),
        ("triggers", database.triggers()),
        (
            "scripts.tar",
            database.scripts().map_err(AlpineError::at(
                "writing the script archive",
                tree.path(DB_DIR),
            ))?,
        ),
    ] {
        let path = format!("{DB_DIR}/{name}");
        tree.write(&path, &contents)
            .map_err(AlpineError::at("writing the database", tree.path(&path)))?;
    }

    // What the caller asked for, one per line and sorted, which is what apk
    // writes and what makes the file a function of the request.
    let mut world: Vec<&str> = state.world.iter().map(String::as_str).collect();
    world.sort_unstable();
    world.dedup();
    let mut text = world.join("\n");
    text.push('\n');
    tree.write(WORLD, text.as_bytes())
        .map_err(AlpineError::at("writing the world", tree.path(WORLD)))?;

    let mut architecture = state.architecture.to_string();
    architecture.push('\n');
    tree.write(ARCH, architecture.as_bytes())
        .map_err(AlpineError::at("writing the architecture", tree.path(ARCH)))?;

    // One URL per line, in the order the caller configured them.
    let mut sources = state.sources.join("\n");
    if !sources.is_empty() {
        sources.push('\n');
    }
    tree.write(REPOSITORIES, sources.as_bytes())
        .map_err(AlpineError::at(
            "writing the repositories",
            tree.path(REPOSITORIES),
        ))?;

    write_keys(tree, state)
}

/// Writes each repository's trust anchor into the finished root, leaving alone
/// any key a package already installed.
///
/// `alpine-keys` ships `/etc/apk/keys` itself, so a closure containing it has
/// already written every Alpine key — and overwriting one would be this
/// bootstrap colliding with a package it installed. What is written is what the
/// closure did not supply, which is how a caller's own repository key reaches a
/// root that never installs a package carrying it.
///
/// A layered build looks in its base too. The base's `etc/apk/keys` is visible
/// through the overlay, so a key written into the upper would shadow a file the
/// base already holds rather than add one.
fn write_keys(tree: &Rooted, state: &State<'_>) -> Result<(), AlpineError> {
    for repository in state.repositories {
        for (name, pem) in repository.keys.pems() {
            let path = format!("{KEYS_DIR}/{name}");
            let mut held = tree
                .exists(&path)
                .map_err(AlpineError::at("inspecting a key", tree.path(&path)))?;
            if let (false, Some(beneath)) = (held, state.beneath) {
                held = beneath
                    .exists(&path)
                    .map_err(AlpineError::at("inspecting a key", beneath.path(&path)))?;
            }
            if held {
                continue;
            }
            tree.write(&path, pem.as_bytes())
                .map_err(AlpineError::at("writing a key", tree.path(&path)))?;
        }
    }
    Ok(())
}

/// A package's scripts, and what a run of one needs to know about it.
///
/// Assembled during the extraction so the configure wave holds no package
/// container: everything below is a few kilobytes of shell per package.
pub(super) struct ScriptSubject {
    /// The package name, which names the script file and reaches its scripts.
    pub(super) name: String,
    /// The version, which names the script file and is a script's one argument.
    pub(super) version: String,
    /// The scripts the package carried.
    pub(super) scripts: Vec<(ScriptKind, Vec<u8>)>,
    /// The path patterns whose contents changing runs the trigger.
    pub(super) triggers: Vec<String>,
}

impl ScriptSubject {
    /// The body of `kind`, where the package carries one.
    fn script(&self, kind: ScriptKind) -> Option<&[u8]> {
        self.scripts
            .iter()
            .find(|(carried, _)| *carried == kind)
            .map(|(_, body)| body.as_slice())
    }

    /// The directories this package's triggers match, in path order.
    ///
    /// A pattern must be absolute — `apk` skips one that is not — and a leading
    /// `+` marks it as firing only for a directory that changed, which for a
    /// root being created is every directory it holds.
    fn triggered_by(&self, directories: &HashSet<Vec<u8>>) -> Vec<String> {
        let mut matched: Vec<String> = Vec::new();
        for pattern in &self.triggers {
            let pattern = pattern.strip_prefix('+').unwrap_or(pattern);
            if !pattern.starts_with('/') {
                continue;
            }
            let pattern = Glob::parse(pattern.as_bytes());
            for directory in directories {
                let rooted = format!("/{}", String::from_utf8_lossy(directory));
                if pattern.matches(rooted.as_bytes()) {
                    matched.push(rooted);
                }
            }
        }
        matched.sort_unstable();
        matched.dedup();
        matched
    }
}

/// A trigger's path pattern, read once and matched against every directory.
///
/// `fnmatch(3)` with `FNM_PATHNAME`, which is what `apk` matches a trigger
/// with: `*` and `?` stop at a `/`, and `[...]` names a set. The whole of what
/// Alpine's published triggers use is a trailing `*` on one path component —
/// `/lib/modules/*` — but the set is implemented because a pattern is a
/// repository's to write and half a matcher would silently fire the wrong
/// triggers.
///
/// A pattern comes from a signed `.PKGINFO`, or from a layered base's
/// `triggers` file, which that base's own scripts could have rewritten. So
/// matching costs at most the product of a component's pattern and name
/// lengths, whatever the pattern: every `/` fixes where a component begins, and
/// within one component only the last `*` is ever widened.
struct Glob<'a> {
    /// The pattern's components, split at every `/` that is not inside a set.
    components: Vec<Vec<Element<'a>>>,
}

/// One position of a [`Glob`] component.
#[derive(Clone, Copy)]
enum Element<'a> {
    /// `*`: any run of bytes within the component, including none.
    Star,
    /// `?`: any one byte.
    Any,
    /// `[...]`: one byte the set accepts.
    Set(Set<'a>),
    /// Any other byte, which matches only itself.
    Literal(u8),
}

impl<'a> Glob<'a> {
    /// Reads `pattern` into its components.
    ///
    /// A `[` that opens a set is one; an unterminated `[` is the literal it
    /// looks like, which is how a name such as `cmd:[` matches itself. A `/`
    /// inside a set does not divide a component, and since a path component
    /// holds no `/`, such a set never matches one.
    fn parse(pattern: &'a [u8]) -> Glob<'a> {
        let mut components = Vec::new();
        let mut component = Vec::new();
        let mut rest = pattern;
        while let Some((&byte, after)) = rest.split_first() {
            rest = after;
            match byte {
                b'/' => components.push(std::mem::take(&mut component)),
                b'*' => component.push(Element::Star),
                b'?' => component.push(Element::Any),
                b'[' => match Set::parse(rest) {
                    Some((set, after_set)) => {
                        component.push(Element::Set(set));
                        rest = after_set;
                    }
                    None => component.push(Element::Literal(byte)),
                },
                literal => component.push(Element::Literal(literal)),
            }
        }
        components.push(component);
        Glob { components }
    }

    /// Whether `path` matches the whole pattern: the two hold the same number
    /// of components, and each of the path's matches the pattern's at the same
    /// position.
    fn matches(&self, path: &[u8]) -> bool {
        let mut names = path.split(|&byte| byte == b'/');
        self.components.iter().all(|pattern| {
            names
                .next()
                .is_some_and(|name| component_matches(pattern, name))
        }) && names.next().is_none()
    }
}

/// Whether one path component, `name`, matches one pattern component.
///
/// The two-pointer match: elements are consumed one byte at a time, and on a
/// mismatch the most recent `*` takes one more byte and the elements after it
/// are tried again from there. An earlier `*` never needs widening, because
/// whatever it could absorb the later one can absorb instead. So the work is at
/// most the product of the two lengths, where trying every split for every
/// `*` would be exponential in their count.
fn component_matches(pattern: &[Element<'_>], name: &[u8]) -> bool {
    let (mut at, mut byte) = (0, 0);
    // The element after the most recent `*`, and where in `name` that star's
    // run ends.
    let mut widen: Option<(usize, usize)> = None;
    while at < pattern.len() || byte < name.len() {
        match pattern.get(at) {
            Some(Element::Star) => {
                at += 1;
                widen = Some((at, byte));
                continue;
            }
            Some(element) if name.get(byte).is_some_and(|&found| element.accepts(found)) => {
                at += 1;
                byte += 1;
                continue;
            }
            _ => {}
        }
        match widen {
            Some((after, end)) if end < name.len() => {
                widen = Some((after, end + 1));
                at = after;
                byte = end + 1;
            }
            _ => return false,
        }
    }
    true
}

impl Element<'_> {
    /// Whether this element can match `byte`. A `*` can match any, as part of
    /// its run, though the match widens a star's run rather than asking it.
    fn accepts(self, byte: u8) -> bool {
        match self {
            Element::Star | Element::Any => true,
            Element::Set(set) => set.accepts(byte),
            Element::Literal(literal) => literal == byte,
        }
    }
}

/// A `[...]` set: the bytes between the brackets, and whether it accepts them
/// or everything else.
#[derive(Clone, Copy)]
struct Set<'a> {
    /// Whether a leading `!` or `^` inverted it.
    negated: bool,
    /// The bytes between the brackets, after any inversion, ranges unexpanded.
    members: &'a [u8],
}

impl<'a> Set<'a> {
    /// Reads a `[...]` set, returning it and the pattern after it.
    ///
    /// `rest` begins just after the `[`. A set that is never closed is not a
    /// set: the caller then treats the `[` as the literal it is, which is what
    /// `fnmatch(3)` does and what makes `cmd:[` — a name Alpine really
    /// publishes — match itself.
    fn parse(rest: &'a [u8]) -> Option<(Set<'a>, &'a [u8])> {
        let (negated, rest) = match rest.first() {
            Some(b'!' | b'^') => (true, &rest[1..]),
            _ => (false, rest),
        };
        // A `]` first is the literal, not the terminator.
        let leading = usize::from(rest.first() == Some(&b']'));
        let close = leading + rest[leading..].iter().position(|byte| *byte == b']')?;
        let members = &rest[..close];
        Some((Set { negated, members }, &rest[close + 1..]))
    }

    /// Whether the set accepts `byte`, a member or an `a-z` range naming it.
    fn accepts(self, byte: u8) -> bool {
        let members = self.members;
        let mut at = 0;
        let mut found = false;
        while at < members.len() {
            if at + 2 < members.len() && members[at + 1] == b'-' {
                found |= (members[at]..=members[at + 2]).contains(&byte);
                at += 3;
            } else {
                found |= members[at] == byte;
                at += 1;
            }
        }
        found != self.negated
    }
}

/// A dependency order over the closure: a package appears after everything it
/// needs.
///
/// The graph is the packages' own `depends`, resolved within the closure through
/// the names each package provides as well as its own. It has cycles — Alpine
/// publishes mutually dependent packages — so this is a depth-first post-order
/// that steps over a package it is already visiting rather than a sort that
/// insists on a total order.
///
/// Nothing here consults a name. Two packages neither of which needs the other
/// come out in the order they were handed in, so the same input always produces
/// the same output and a different input may produce a different one. That is
/// the property the callers need and the one they have: a resolution walks a
/// `BTreeMap`, so its input is in name order, and a caller-supplied plan
/// document's is in document order — each reproducible from what it was built
/// from.
pub(super) fn dependency_order(
    depends: &[Vec<String>],
    provides: &HashMap<String, Vec<usize>>,
) -> Vec<usize> {
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Unvisited,
        Visiting,
        Done,
    }

    let mut state = vec![State::Unvisited; depends.len()];
    let mut order = Vec::with_capacity(depends.len());
    // An explicit stack rather than recursion: a closure is thousands of
    // packages deep in the worst case and this runs on the caller's thread.
    let mut stack: Vec<(usize, usize)> = Vec::new();
    for start in 0..depends.len() {
        if state[start] != State::Unvisited {
            continue;
        }
        stack.push((start, 0));
        state[start] = State::Visiting;
        while let Some((at, edge)) = stack.pop() {
            let wanted: Vec<usize> = depends[at]
                .iter()
                .filter_map(|name| provides.get(name))
                .flatten()
                .copied()
                .filter(|to| *to != at)
                .collect();
            match wanted.get(edge) {
                Some(&to) => {
                    stack.push((at, edge + 1));
                    if state[to] == State::Unvisited {
                        state[to] = State::Visiting;
                        stack.push((to, 0));
                    }
                }
                None => {
                    state[at] = State::Done;
                    order.push(at);
                }
            }
        }
    }
    order
}

/// The scripts `apk` knows, re-exported so this module names them without
/// reaching through the container reader.
pub(super) use super::apk::ScriptKind;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

    #[test]
    fn a_pattern_matches_the_way_fnmatch_with_pathname_does() {
        for (pattern, path, expected) in [
            (&b"/bin"[..], &b"/bin"[..], true),
            (b"/bin", b"/binary", false),
            (b"/lib/modules/*", b"/lib/modules/6.12.0", true),
            // FNM_PATHNAME: a star stops at a separator.
            (b"/lib/modules/*", b"/lib/modules/6.12.0/kernel", false),
            (b"/lib/*", b"/lib", false),
            (b"/usr/*/bin", b"/usr/local/bin", true),
            (b"/etc/rc?.d", b"/etc/rcS.d", true),
            (b"/etc/rc?.d", b"/etc/rc.d", false),
            (b"/etc/rc[SL].d", b"/etc/rcL.d", true),
            (b"/etc/rc[SL].d", b"/etc/rcX.d", false),
            (b"/etc/rc[!SL].d", b"/etc/rcX.d", true),
            (b"/etc/[a-c]", b"/etc/b", true),
            (b"/etc/[a-c]", b"/etc/d", false),
            // An unterminated set is the literal bracket, which is how a name
            // like `cmd:[` matches itself.
            (b"/usr/bin/[", b"/usr/bin/[", true),
            // A `/` inside a set does not divide the component, and a set
            // never matches a separator.
            (b"/usr/[a/b]x", b"/usr/ax", true),
            (b"/usr/[a/b]x", b"/usr/b/x", false),
            // A star widens past a false start within its component.
            (b"/lib/*x", b"/lib/axbx", true),
            (b"/lib/*x/y", b"/lib/axbx/y", true),
            (b"/lib/*a*", b"/lib/bbb", false),
        ] {
            assert_eq!(
                Glob::parse(pattern).matches(path),
                expected,
                "{} against {}",
                String::from_utf8_lossy(pattern),
                String::from_utf8_lossy(path),
            );
        }
    }

    #[test]
    fn a_pattern_of_many_stars_is_matched_in_polynomial_time() {
        // Trying every split for every star costs the number of ways to place
        // the stars, which for this pattern is beyond any time limit. A star
        // widened only when it is the latest costs a pass per byte.
        let mut pattern = b"/".to_vec();
        for _ in 0..64 {
            pattern.extend_from_slice(b"*a");
        }
        pattern.push(b'b');
        let mut path = b"/".to_vec();
        path.extend(std::iter::repeat_n(b'a', 200));
        assert!(!Glob::parse(&pattern).matches(&path));
        path.push(b'b');
        assert!(Glob::parse(&pattern).matches(&path));
    }

    #[test]
    fn a_trigger_matches_the_directories_the_install_created() {
        let subject = ScriptSubject {
            name: "busybox".to_string(),
            version: "1.37.0-r30".to_string(),
            scripts: Vec::new(),
            triggers: ["/bin", "/usr/bin", "/lib/modules/*", "relative/path"]
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        };
        let directories: HashSet<Vec<u8>> = ["bin", "usr/bin", "usr/lib", "lib/modules/6.12.0"]
            .iter()
            .map(|path| path.as_bytes().to_vec())
            .collect();
        assert_eq!(
            subject.triggered_by(&directories),
            ["/bin", "/lib/modules/6.12.0", "/usr/bin"],
            "in path order, and a relative pattern matches nothing",
        );
    }

    /// A closure's dependency order, by name.
    fn order(packages: &[(&str, &[&str])]) -> Vec<String> {
        let depends: Vec<Vec<String>> = packages
            .iter()
            .map(|(_, needs)| needs.iter().map(std::string::ToString::to_string).collect())
            .collect();
        let mut provides: HashMap<String, Vec<usize>> = HashMap::new();
        for (at, (name, _)) in packages.iter().enumerate() {
            provides.entry((*name).to_string()).or_default().push(at);
        }
        dependency_order(&depends, &provides)
            .into_iter()
            .map(|at| packages[at].0.to_string())
            .collect()
    }

    #[test]
    fn a_package_runs_after_everything_it_needs() {
        // The case this exists for: `busybox` has to have relinked its applets
        // before `alpine-baselayout`'s pre-install calls one of them.
        let sorted = order(&[
            ("alpine-baselayout", &["alpine-baselayout-data", "/bin/sh"]),
            ("busybox", &["musl"]),
            ("busybox-binsh", &["busybox"]),
            ("musl", &[]),
            ("alpine-baselayout-data", &[]),
        ]);
        let at = |name: &str| {
            sorted
                .iter()
                .position(|package| package == name)
                .unwrap_or_else(|| panic!("{name} is in the order: {sorted:?}"))
        };
        assert!(at("musl") < at("busybox"));
        assert!(at("busybox") < at("busybox-binsh"));
        assert_eq!(sorted.len(), 5);
        // `/bin/sh` is provided by nothing here, so it constrains nothing; the
        // order still holds every package exactly once.
        assert!(at("alpine-baselayout-data") < at("alpine-baselayout"));
    }

    #[test]
    fn a_provided_name_orders_as_the_package_that_provides_it() {
        let packages: [(&str, &[&str]); 3] = [
            ("alpine-baselayout", &["/bin/sh"]),
            ("busybox-binsh", &["busybox"]),
            ("busybox", &[]),
        ];
        let depends: Vec<Vec<String>> = packages
            .iter()
            .map(|(_, needs)| needs.iter().map(std::string::ToString::to_string).collect())
            .collect();
        let mut provides: HashMap<String, Vec<usize>> = HashMap::new();
        for (at, (name, _)) in packages.iter().enumerate() {
            provides.entry((*name).to_string()).or_default().push(at);
        }
        provides.entry("/bin/sh".to_string()).or_default().push(1);

        let sorted: Vec<&str> = dependency_order(&depends, &provides)
            .into_iter()
            .map(|at| packages[at].0)
            .collect();
        assert_eq!(sorted, ["busybox", "busybox-binsh", "alpine-baselayout"]);
    }

    #[test]
    fn a_cycle_is_stepped_over_rather_than_refused() {
        // Alpine publishes mutually dependent packages, so an order that
        // insisted on a total one would refuse closures apk installs.
        let sorted = order(&[("a", &["b"]), ("b", &["a"]), ("c", &["a"])]);
        assert_eq!(sorted.len(), 3);
        assert!(sorted.contains(&"c".to_string()));
        let at = |name: &str| sorted.iter().position(|package| package == name).unwrap();
        assert!(at("a") < at("c"), "{sorted:?}");
    }

    #[test]
    fn one_closure_produces_one_order() {
        let packages: [(&str, &[&str]); 4] =
            [("d", &["c"]), ("c", &["a", "b"]), ("b", &[]), ("a", &[])];
        let once = order(&packages);
        let again = order(&packages);
        assert_eq!(once, again);
    }

    /// A scratch tree, and the same tree opened as the scripts' host side
    /// opens it.
    fn rooted_tree(tag: &str) -> (Scratch, Rooted) {
        let scratch = Scratch::for_test("alpine-bootstrap", tag);
        let tree = Rooted::open(&scratch).expect("the scratch tree opens");
        (scratch, tree)
    }

    /// The accounts `found` in a shadow file, as `accounts::account_dates`
    /// records them.
    fn found(lines: &[(&str, &str)]) -> accounts::Dates {
        lines
            .iter()
            .map(|(name, day)| (name.as_bytes().to_vec(), day.as_bytes().to_vec()))
            .collect()
    }

    /// Dates the shadow file `after` in a scratch tree as a run that found
    /// `before` and was given `epoch`, and returns what the file then holds.
    fn date(tag: &str, before: &accounts::Dates, after: &[u8], epoch: i64) -> Vec<u8> {
        let (staging, tree) = rooted_tree(tag);
        tree.write_mode("etc/shadow", after, 0o640).unwrap();
        date_accounts(&tree, before, epoch).expect("the accounts are dated");
        std::fs::read(staging.join("etc/shadow")).unwrap()
    }

    #[test]
    fn only_the_days_the_run_wrote_are_dated() {
        // root and bin as a package ships them, with no date and with one; klogd
        // created by the run; daemon's date changed by it.
        let before = found(&[("root", ""), ("bin", "0"), ("daemon", "19000")]);
        let after = b"root:::0:::::\nbin:!:0:0:::::\ndaemon:!:20722:0:::::\n\
                      klogd:!:20722:0:99999:7:::\n";
        assert_eq!(
            date("dated", &before, after, 1_700_000_000),
            b"root:::0:::::\nbin:!:0:0:::::\ndaemon:!:19675:0:::::\n\
              klogd:!:19675:0:99999:7:::\n"
        );
    }

    #[test]
    fn the_first_day_of_1970_records_no_date() {
        // A day of zero would demand every account's password be changed at
        // its next login; an empty field disables aging, as useradd writes.
        let after = b"root:::0:::::\nklogd:!:20722:0:99999:7:::\n";
        for epoch in [0, 86_399] {
            assert_eq!(
                date("dated-day-zero", &found(&[("root", "")]), after, epoch),
                b"root:::0:::::\nklogd:!::0:99999:7:::\n",
                "{epoch}",
            );
        }
    }

    #[test]
    fn a_demand_for_a_new_password_is_not_a_date() {
        // A script that expires a password writes a zero, which is not a day
        // the run happened on; dating it would withdraw the demand. Nor is
        // anything that is not a decimal number.
        for field in [&b"0"[..], b"00", b"", b"x1", b"-1"] {
            assert!(!is_day(field), "{:?}", String::from_utf8_lossy(field));
        }
        assert!(is_day(b"20722") && is_day(b"01"));
        let after = b"root:!:0:0:::::\nodd:!:x1:0:::::\n";
        assert_eq!(date("expired", &found(&[]), after, 1_700_000_000), after);
    }

    #[test]
    fn a_generated_machine_id_is_removed() {
        // What `dbus-uuidgen --ensure` leaves: 32 hex digits and a newline.
        let (staging, tree) = rooted_tree("machine-id");
        tree.write_mode(MACHINE_ID, b"bab73fe9c7e4506ef70334906ab8378f\n", 0o444)
            .unwrap();

        clear_run_state(&tree).expect("the run state is cleared");

        assert!(std::fs::symlink_metadata(staging.join(MACHINE_ID)).is_err());
    }

    #[test]
    fn a_machine_id_the_run_did_not_generate_is_left_alone() {
        // No id: nothing is created, since dbus's service generates one from
        // the missing file at boot.
        let (staging, tree) = rooted_tree("no-machine-id");
        clear_run_state(&tree).expect("an absent id clears");
        assert!(std::fs::symlink_metadata(staging.join(MACHINE_ID)).is_err());

        // An empty file is not what `dbus-uuidgen` writes.
        tree.write(MACHINE_ID, b"").unwrap();
        clear_run_state(&tree).expect("an empty id clears");
        assert_eq!(std::fs::read(staging.join(MACHINE_ID)).unwrap(), b"");

        // Nor is anything that is not a regular file. A directory would fail
        // the unlink outright if it were attempted.
        std::fs::remove_file(staging.join(MACHINE_ID)).unwrap();
        std::fs::create_dir(staging.join(MACHINE_ID)).unwrap();
        clear_run_state(&tree).expect("a directory is left alone");
        assert!(staging.join(MACHINE_ID).is_dir());
    }

    #[test]
    fn a_link_at_the_machine_id_is_neither_removed_nor_followed() {
        // The cleanup runs after every script, so a script can leave a link
        // there. It is not an id the run generated, and the file it names is
        // not inspected through it.
        let (staging, tree) = rooted_tree("machine-id-link");
        let victim = staging.join("victim");
        std::fs::write(&victim, b"host contents\n").unwrap();
        std::fs::create_dir_all(staging.join("etc")).unwrap();
        std::os::unix::fs::symlink(&victim, staging.join(MACHINE_ID)).unwrap();

        clear_run_state(&tree).expect("the run state is cleared");

        assert_eq!(std::fs::read(&victim).unwrap(), b"host contents\n");
        assert_eq!(
            std::fs::read_link(staging.join(MACHINE_ID)).unwrap(),
            victim
        );
    }
}
