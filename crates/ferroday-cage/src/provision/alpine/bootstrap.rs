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
/// environment, nothing else. A script inherits no locale, no `HOME` and no
/// `TERM`, which is also what makes what it does a function of the root rather
/// than of the machine the bootstrap ran on.
const SCRIPT_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

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

/// Runs every package's install scripts, fires the triggers they registered,
/// and writes the state the finished root hands back to `apk`.
///
/// `order` is the dependency order the closure was laid down in, and the one the
/// scripts run in. `carried` is the trigger subjects of packages a layered
/// build's base already holds, empty for a full bootstrap; they fire for the
/// directories this wave created exactly as the closure's own do, because a
/// trigger belongs to the installed root rather than to the transaction that ran
/// it.
#[allow(clippy::too_many_arguments)]
pub(super) fn configure(
    staging: &Path,
    rooting: Rooting<'_>,
    database: &Database,
    order: &[ScriptSubject],
    carried: &[ScriptSubject],
    state: &State<'_>,
    identity_map: &IdentityMap,
    observer: &mut dyn AlpineObserver,
) -> Result<(), AlpineError> {
    let tree = Rooted::open(staging).map_err(AlpineError::at("opening the tree", staging))?;
    write_state(&tree, database, state)?;

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
                staging,
                rooting,
                &tree,
                subject,
                kind,
                body,
                std::slice::from_ref(&subject.version),
                identity_map,
                observer,
            )?;
        }
    }

    fire_triggers(
        staging,
        rooting,
        &tree,
        database,
        order,
        carried,
        identity_map,
        observer,
    )
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
#[allow(clippy::too_many_arguments)]
fn fire_triggers(
    staging: &Path,
    rooting: Rooting<'_>,
    tree: &Rooted,
    database: &Database,
    order: &[ScriptSubject],
    carried: &[ScriptSubject],
    identity_map: &IdentityMap,
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
            staging,
            rooting,
            tree,
            subject,
            ScriptKind::Trigger,
            body,
            &matched,
            identity_map,
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
#[allow(clippy::too_many_arguments)]
fn run(
    staging: &Path,
    rooting: Rooting<'_>,
    tree: &Rooted,
    subject: &ScriptSubject,
    kind: ScriptKind,
    body: &[u8],
    args: &[String],
    identity_map: &IdentityMap,
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

    let outcome = launch(
        staging,
        rooting,
        &format!("/{relative}"),
        subject,
        kind,
        args,
        identity_map,
        observer,
    );
    let removed = tree
        .remove(&relative)
        .map_err(AlpineError::at("removing a script", tree.path(&relative)));
    outcome.and(removed)
}

/// Builds and runs the cage one script executes in.
#[allow(clippy::too_many_arguments)]
fn launch(
    staging: &Path,
    rooting: Rooting<'_>,
    script: &str,
    subject: &ScriptSubject,
    kind: ScriptKind,
    args: &[String],
    identity_map: &IdentityMap,
    observer: &mut dyn AlpineObserver,
) -> Result<(), AlpineError> {
    let cage = rooting
        .builder(staging)
        .command(script)
        .args(args)
        .env("PATH", SCRIPT_PATH)
        .env("APK_SCRIPT", kind.name())
        .env("APK_PACKAGE", &subject.name)
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
    let tree = Rooted::open(staging).map_err(AlpineError::at("opening the tree", staging))?;
    write_state(&tree, database, state)
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
            for directory in directories {
                let rooted = format!("/{}", String::from_utf8_lossy(directory));
                if matches(pattern.as_bytes(), rooted.as_bytes()) {
                    matched.push(rooted);
                }
            }
        }
        matched.sort_unstable();
        matched.dedup();
        matched
    }
}

/// Whether `path` matches `pattern`, with `*` and `?` stopping at a `/` and
/// `[...]` naming a set.
///
/// `fnmatch(3)` with `FNM_PATHNAME`, which is what `apk` matches a trigger
/// with. The whole of what Alpine's published triggers use is a trailing `*` on
/// one path component — `/lib/modules/*` — but the set is implemented because a
/// pattern is a repository's to write and half a matcher would silently fire the
/// wrong triggers.
fn matches(pattern: &[u8], path: &[u8]) -> bool {
    match pattern.first() {
        None => path.is_empty(),
        Some(b'*') => {
            // Any run of characters within one component, including none.
            let mut at = 0;
            loop {
                if matches(&pattern[1..], &path[at..]) {
                    return true;
                }
                match path.get(at) {
                    None | Some(b'/') => return false,
                    Some(_) => at += 1,
                }
            }
        }
        Some(b'?') => match path.first() {
            Some(byte) if *byte != b'/' => matches(&pattern[1..], &path[1..]),
            _ => false,
        },
        // A `[` that opens a set behaves as one; an unterminated `[` is the
        // literal it looks like, which is how a name such as `cmd:[` matches
        // itself. So the set is tried first and the literal is the fallback.
        Some(b'[') if set(&pattern[1..]).is_some() => {
            let (accepted, rest) = set(&pattern[1..]).expect("checked just above");
            match path.first() {
                Some(byte) if *byte != b'/' => accepted(*byte) && matches(rest, &path[1..]),
                _ => false,
            }
        }
        Some(literal) => match path.first() {
            Some(byte) if byte == literal => matches(&pattern[1..], &path[1..]),
            _ => false,
        },
    }
}

/// Reads a `[...]` set, returning what it accepts and the pattern after it.
///
/// `rest` begins just after the `[`. A set that is never closed is not a set:
/// the caller then treats the `[` as the literal it is, which is what
/// `fnmatch(3)` does and what makes `cmd:[` — a name Alpine really publishes —
/// match itself.
fn set(rest: &[u8]) -> Option<(impl Fn(u8) -> bool + use<'_>, &[u8])> {
    let (negated, rest) = match rest.first() {
        Some(b'!' | b'^') => (true, &rest[1..]),
        _ => (false, rest),
    };
    // A `]` first is the literal, not the terminator.
    let leading = usize::from(rest.first() == Some(&b']'));
    let close = leading + rest[leading..].iter().position(|byte| *byte == b']')?;
    let members = &rest[..close];
    Some((
        move |byte: u8| {
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
            found != negated
        },
        &rest[close + 1..],
    ))
}

/// A dependency order over the closure: a package appears after everything it
/// needs.
///
/// The graph is the packages' own `depends`, resolved within the closure through
/// the names each package provides as well as its own. It has cycles — Alpine
/// publishes mutually dependent packages — so this is a depth-first post-order
/// that steps over a package it is already visiting rather than a sort that
/// insists on a total order. Ties are broken by name, so one closure always
/// produces one order.
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
        ] {
            assert_eq!(
                matches(pattern, path),
                expected,
                "{} against {}",
                String::from_utf8_lossy(pattern),
                String::from_utf8_lossy(path),
            );
        }
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
}
