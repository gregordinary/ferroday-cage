//! Integration tests for a sandbox placed in a cgroup of its own.
//!
//! A launch creates its cgroup beneath a directory the caller may create
//! cgroups in, which only a delegated subtree is. These tests use the cgroup
//! the test binary runs in: run under `systemd-run --user --scope -p
//! Delegate=yes`, that is a scope of the test's own. The first test to need it
//! moves the whole test process into a leaf beside the sandboxes' cgroups, as
//! a caller does. A run started anywhere else skips them, and
//! `FERRODAY_CAGE_REQUIRE_CGROUP` turns that skip into a failure.

mod common;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use ferroday_cage::{CgroupLimit, CgroupRefusal, Error, Stdio, host};

/// Limits whose controllers the tests' sandboxes need the parent to offer.
const LIMITS: [CgroupLimit; 2] = [CgroupLimit::PidsMax(8), CgroupLimit::MemoryMax(64 << 20)];

/// The delegated directory the sandboxes' cgroups are created beneath, with
/// the test process already moved into a leaf of it, or `None` where the run
/// has none.
fn delegated() -> Option<&'static Path> {
    static PARENT: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    let parent = PARENT.get_or_init(|| {
        let parent = host::own_cgroup().ok_or("the tests run in no cgroup v2 hierarchy")?;
        // A cgroup holding processes of its own cannot enable a controller
        // for its children, so a cgroup the tests share is not one to divide.
        let members = std::fs::read_to_string(parent.join("cgroup.procs"))
            .map_err(|err| format!("{} lists no processes: {err}", parent.display()))?;
        let me = std::process::id().to_string();
        if members.lines().any(|pid| pid != me) {
            return Err(format!(
                "{} holds processes besides the tests'",
                parent.display()
            ));
        }
        let leaf = parent.join(format!("fcage-test-caller-{me}"));
        std::fs::create_dir(&leaf)
            .and_then(|()| std::fs::write(leaf.join("cgroup.procs"), "0"))
            .map_err(|err| {
                format!(
                    "the tests cannot move into a leaf of {}: {err}",
                    parent.display()
                )
            })?;
        wait_vacated(&parent, Duration::from_secs(10))?;
        // The probe leaves the controllers the limits need enabled, as a
        // launch does, so the leaf offers pids to the refusal test below.
        match host::cgroup_blocker(&parent, &LIMITS) {
            None => Ok(parent),
            Some(refusal) => Err(format!(
                "{} cannot hold the sandboxes' cgroups: {refusal}",
                parent.display()
            )),
        }
    });
    match parent {
        Ok(parent) => Some(parent.as_path()),
        Err(reason) => {
            common::require::CGROUP.skip(format!(
                "{reason}; run the tests under systemd-run --user --scope -p Delegate=yes"
            ));
            None
        }
    }
}

/// Waits up to `within` for `cgroup` to hold no thread once the process has
/// moved out of it, and names the threads still there if it does not.
///
/// A process that moves takes its threads with it, except one already
/// exiting, which the kernel leaves where it was until its exit completes.
/// The test harness ends a test's thread as the test ends, so a test here that
/// needs no delegated cgroup can be ending as the process moves. Until its
/// thread has gone, the cgroup holds a task of its own, and refuses to enable
/// a controller for its children, which the probe reports as
/// [`CgroupRefusal::ParentHoldsProcesses`]. The thread does not appear in
/// `cgroup.procs`, which lists only a thread group's leader.
fn wait_vacated(cgroup: &Path, within: Duration) -> Result<(), String> {
    let deadline = Instant::now() + within;
    loop {
        let threads = std::fs::read_to_string(cgroup.join("cgroup.threads"))
            .map_err(|err| format!("{} lists no threads: {err}", cgroup.display()))?;
        if threads.trim().is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "{} still holds the threads {} the tests' move left behind",
                cgroup.display(),
                threads.split_whitespace().collect::<Vec<_>>().join(", "),
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// A builder running `script` under `/bin/sh` on the host's userland, in a
/// cgroup beneath `parent`.
fn sh_in(parent: &Path, script: &str) -> ferroday_cage::CageBuilder {
    common::host_userland()
        .command("/bin/sh")
        .args(["-c", script])
        .cgroup_parent(parent)
}

/// A builder whose command starts a sleeper and exits at once, without a PID
/// namespace, so the sleeper outlives it in the sandbox's cgroup. Its streams
/// are null, so the sleeper holds none of the sandbox's channels open and the
/// wait returns with the command.
fn leaving_a_sleeper(parent: &Path) -> ferroday_cage::CageBuilder {
    sh_in(parent, "sleep 60 & exit 0")
        .pid_namespace(false)
        .stdin(Stdio::Null)
        .stdout(Stdio::Null)
        .stderr(Stdio::Null)
}

/// A parent of the test's own beneath the delegated one, for a test that
/// counts the cgroups beneath its parent: the tests beside it create cgroups
/// beneath the shared one at the same time. It holds no process and needs no
/// controller.
fn own_parent(parent: &Path, test: &str) -> PathBuf {
    let own = parent.join(format!("fcage-test-{test}"));
    std::fs::create_dir_all(&own).expect("a cgroup of the test's own");
    own
}

/// The sandbox cgroups beneath `parent`, by name.
fn sandbox_cgroups(parent: &Path) -> Vec<String> {
    std::fs::read_dir(parent)
        .expect("the parent lists")
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| name.starts_with("fcage-") && !name.starts_with("fcage-test-"))
        .collect()
}

/// The leaf beneath a sandbox's cgroup that the sandbox runs in.
const LEAF: &str = "sandbox";

/// The one sandbox cgroup beneath `parent`, and the processes its leaf holds.
fn sole_sandbox_cgroup(parent: &Path) -> (PathBuf, Vec<u32>) {
    let names = sandbox_cgroups(parent);
    assert_eq!(names.len(), 1, "one sandbox cgroup: {names:?}");
    let cgroup = parent.join(&names[0]);
    let members = std::fs::read_to_string(cgroup.join(LEAF).join("cgroup.procs"))
        .expect("the cgroup lists its processes")
        .lines()
        .map(|pid| pid.parse().expect("a process id"))
        .collect();
    (cgroup, members)
}

/// Asserts that every process of `members` is gone, as a kill of the tree
/// they were in leaves them.
#[track_caller]
fn assert_gone(members: &[u32]) {
    for &pid in members {
        assert!(
            common::wait_gone(pid, Duration::from_secs(5)),
            "the process {pid} the command left outlived the kill",
        );
    }
}

#[test]
fn a_tree_is_held_to_its_process_limit_and_accounted_whole() {
    if !common::require::userns() {
        return;
    }
    let Some(parent) = delegated() else {
        return;
    };
    // Twenty sleepers against a limit of eight: the shell and seven of them.
    let script = "for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do \
                  sleep 1 2>/dev/null & done; wait";
    let output = sh_in(parent, script)
        .cgroup_limit(CgroupLimit::PidsMax(8))
        .build()
        .expect("a valid sandbox configuration")
        .output()
        .expect("the sandbox runs");
    let usage = output.usage.expect("the init reports the usage");
    let peak = usage
        .cgroup_peak_processes
        .expect("the pids controller is offered");
    assert!(peak <= 8, "the tree held {peak} processes: {usage:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("fork")
            || usage.cgroup_peak_processes == Some(8),
        "the limit refused forks: {output:?}",
    );
    assert!(usage.cgroup_user_time.is_some(), "{usage:?}");
    assert!(
        usage.cgroup_peak_memory_bytes.is_some(),
        "the memory controller is accounted where offered: {usage:?}",
    );
}

#[test]
fn a_memory_limit_ends_the_tree_and_is_reported_as_an_oom_kill() {
    if !common::require::userns() {
        return;
    }
    let Some(parent) = delegated() else {
        return;
    };
    // No swap, so the limit is reached rather than swapped past.
    let cage = sh_in(parent, "exec dd if=/dev/zero of=/dev/null bs=256M count=1")
        .cgroup_limit(CgroupLimit::MemoryMax(64 << 20))
        .cgroup_limit(CgroupLimit::MemorySwapMax(0))
        .build()
        .expect("a valid sandbox configuration");
    let output = match cage.output() {
        Err(Error::CgroupRefused {
            reason: CgroupRefusal::LimitUnsupported { file, .. },
            ..
        }) => {
            common::require::CGROUP.skip(format!("this kernel offers no {file}"));
            return;
        }
        other => other.expect("the sandbox runs"),
    };
    assert_eq!(output.status.signal(), Some(9), "{output:?}");
    let usage = output
        .usage
        .expect("the init survives and reports the usage");
    assert!(
        usage.cgroup_oom_kills.is_some_and(|kills| kills >= 1),
        "{usage:?}"
    );
}

#[test]
fn a_killed_sandbox_reports_what_its_cgroup_read() {
    if !common::require::userns() {
        return;
    }
    let Some(parent) = delegated() else {
        return;
    };
    let mut running = sh_in(parent, "exec sleep 30")
        .build()
        .expect("a valid sandbox configuration")
        .spawn()
        .expect("the sandbox launches");
    running.kill().expect("the kill is delivered");
    let status = running.wait().expect("the outcome is collected");
    assert_eq!(status.signal(), Some(9));
    // The kill ended the init before it reported, so only the cgroup's account
    // of the tree remains.
    let usage = running
        .usage()
        .expect("the cgroup reports the tree's usage");
    assert_eq!(usage.user_time, None, "{usage:?}");
    assert_eq!(usage.peak_rss_bytes, None, "{usage:?}");
    assert!(usage.cgroup_user_time.is_some(), "{usage:?}");
    assert!(usage.cgroup_peak_processes.is_some(), "{usage:?}");
}

#[test]
fn a_kill_reaches_a_descendant_that_left_the_command_without_a_pid_namespace() {
    if !common::require::userns() {
        return;
    }
    let Some(parent) = delegated() else {
        return;
    };
    let own = own_parent(parent, "kill-before-outcome");
    // The orphan outlives the command's own process tree: setsid gives it a
    // session of its own, and the command waits on something else. It holds
    // none of the sandbox's streams, which would hold the wait open until it
    // ended by itself.
    let mut observer = common::Collect::default();
    let cage = sh_in(
        &own,
        "setsid sleep 30 </dev/null >/dev/null 2>&1 & echo $!; exec sleep 30",
    )
    .pid_namespace(false)
    .build()
    .expect("a valid sandbox configuration");
    let mut running = cage
        .spawn_with(&mut observer)
        .expect("the sandbox launches");
    // Long enough for the shell to print the orphan's pid, which each call
    // delivers to the observer as it arrives.
    let until = Instant::now() + Duration::from_millis(500);
    while Instant::now() < until {
        let outcome = running.try_wait().expect("the channels are served");
        assert!(outcome.is_none(), "the command ended before it was killed");
        common::readable_by(&running, until);
    }
    running.kill().expect("the kill is delivered");
    let status = running.wait().expect("the outcome is collected");
    drop(running);
    assert_eq!(status.signal(), Some(9));
    // The kill can leave the orphan still exiting as the outcome arrives; the
    // handle's drop waits for the tree to empty and removes the cgroup.
    assert_eq!(sandbox_cgroups(&own), Vec::<String>::new());
    let orphan: u32 = String::from_utf8_lossy(&observer.stdout)
        .trim()
        .parse()
        .expect("the orphan's pid was printed");
    assert!(
        common::wait_gone(orphan, Duration::from_secs(5)),
        "the kill reached the orphan {orphan} through the cgroup",
    );
}

#[test]
fn a_kill_after_the_outcome_ends_what_the_command_left_and_removes_its_cgroup() {
    if !common::require::userns() {
        return;
    }
    let Some(parent) = delegated() else {
        return;
    };
    let own = own_parent(parent, "kill-after-outcome");
    let mut running = leaving_a_sleeper(&own)
        .build()
        .expect("a valid sandbox configuration")
        .spawn()
        .expect("the sandbox launches");
    let status = running.wait().expect("the outcome is collected");
    assert!(status.success(), "{status:?}");
    let (_, members) = sole_sandbox_cgroup(&own);
    assert!(!members.is_empty(), "the sleeper outlived the command");
    running.kill().expect("the kill is delivered");
    drop(running);
    assert_eq!(
        sandbox_cgroups(&own),
        Vec::<String>::new(),
        "the cgroup is removed once the kill has emptied it",
    );
    assert_gone(&members);
}

#[test]
fn a_kill_handle_s_kill_after_the_outcome_removes_the_cgroup_whichever_handle_drops_last() {
    if !common::require::userns() {
        return;
    }
    let Some(parent) = delegated() else {
        return;
    };
    let own = own_parent(parent, "kill-handle-after-outcome");
    for running_drops_first in [true, false] {
        let mut running = leaving_a_sleeper(&own)
            .build()
            .expect("a valid sandbox configuration")
            .spawn()
            .expect("the sandbox launches");
        let killer = running.kill_handle().expect("a kill handle");
        let status = running.wait().expect("the outcome is collected");
        assert!(status.success(), "{status:?}");
        let (_, members) = sole_sandbox_cgroup(&own);
        assert!(!members.is_empty(), "the sleeper outlived the command");
        if running_drops_first {
            drop(running);
            std::thread::spawn(move || killer.kill())
                .join()
                .expect("the killing thread ends")
                .expect("the kill is delivered");
        } else {
            std::thread::spawn(move || killer.kill())
                .join()
                .expect("the killing thread ends")
                .expect("the kill is delivered");
            drop(running);
        }
        assert_eq!(
            sandbox_cgroups(&own),
            Vec::<String>::new(),
            "the cgroup is removed once the last handle drops, running_drops_first \
             {running_drops_first}",
        );
        assert_gone(&members);
    }
}

#[test]
fn dropping_a_tied_handle_ends_the_tree_and_removes_its_cgroup() {
    if !common::require::userns() {
        return;
    }
    let Some(parent) = delegated() else {
        return;
    };
    let own = own_parent(parent, "tied-drop");
    for pid_namespace in [true, false] {
        let running = sh_in(&own, "sleep 60 & exec sleep 60")
            .pid_namespace(pid_namespace)
            .stop_with_caller(true)
            .stdin(Stdio::Null)
            .stdout(Stdio::Null)
            .stderr(Stdio::Null)
            .build()
            .expect("a valid sandbox configuration")
            .spawn()
            .expect("the sandbox launches");
        // The drop waits for the tree it ended to empty, a bounded wait, and
        // removes the cgroup before it returns.
        let started = Instant::now();
        drop(running);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the drop waited {:?}",
            started.elapsed()
        );
        assert_eq!(
            sandbox_cgroups(&own),
            Vec::<String>::new(),
            "the cgroup is removed as the tied handle drops, pid_namespace({pid_namespace})",
        );
    }
}

#[test]
fn a_cgroup_still_holding_what_the_command_left_stays_beneath_the_parent() {
    if !common::require::userns() {
        return;
    }
    let Some(parent) = delegated() else {
        return;
    };
    let own = own_parent(parent, "left-populated");
    let mut running = leaving_a_sleeper(&own)
        .build()
        .expect("a valid sandbox configuration")
        .spawn()
        .expect("the sandbox launches");
    let status = running.wait().expect("the outcome is collected");
    assert!(status.success(), "{status:?}");
    drop(running);
    let (cgroup, members) = sole_sandbox_cgroup(&own);
    assert!(
        !members.is_empty(),
        "the sleeper outlived the command and the handle"
    );
    // What ends it now is the caller's own: the cgroup's kill, and then the
    // removal of its leaf and of it once the tree has emptied.
    std::fs::write(cgroup.join("cgroup.kill"), "1").expect("the tree is killed");
    assert_gone(&members);
    remove_once_empty(&cgroup.join(LEAF), Duration::from_secs(10));
    remove_once_empty(&cgroup, Duration::from_secs(10));
}

/// Removes `cgroup` once its tree has emptied, failing past `within`.
///
/// The kernel refuses the removal with `EBUSY` while it counts a process in
/// the cgroup, which a killed process leaves only as its exit completes.
fn remove_once_empty(cgroup: &Path, within: Duration) {
    let deadline = Instant::now() + within;
    loop {
        match std::fs::remove_dir(cgroup) {
            Ok(()) => return,
            Err(err) if err.kind() == std::io::ErrorKind::ResourceBusy => {}
            Err(err) => panic!("{} is not removed: {err}", cgroup.display()),
        }
        assert!(
            Instant::now() < deadline,
            "{} still holds a process",
            cgroup.display()
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn a_cgroup_is_removed_once_its_sandbox_is_done() {
    if !common::require::userns() {
        return;
    }
    let Some(parent) = delegated() else {
        return;
    };
    let own = own_parent(parent, "removal");
    for pid_namespace in [true, false] {
        let output = sh_in(&own, "cat /proc/self/cgroup")
            .pid_namespace(pid_namespace)
            .build()
            .expect("a valid sandbox configuration")
            .output()
            .expect("the sandbox runs");
        assert!(output.status.success(), "{output:?}");
        // The cgroup namespace the sandbox creates is rooted at its cgroup.
        assert_eq!(String::from_utf8_lossy(&output.stdout), "0::/\n");
        assert_eq!(
            sandbox_cgroups(&own),
            Vec::<String>::new(),
            "nothing is left once the wait returns, pid_namespace({pid_namespace})",
        );
    }
}

#[test]
fn a_parent_holding_processes_is_refused_and_creates_nothing() {
    if !common::require::userns() {
        return;
    }
    let Some(parent) = delegated() else {
        return;
    };
    let leaf = parent.join(format!("fcage-test-caller-{}", std::process::id()));
    assert_eq!(
        host::cgroup_blocker(&leaf, &[CgroupLimit::PidsMax(8)]),
        Some(CgroupRefusal::ParentHoldsProcesses),
    );
    let err = sh_in(&leaf, "true")
        .cgroup_limit(CgroupLimit::PidsMax(8))
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect_err("the leaf holds this test's process");
    assert!(
        matches!(
            &err,
            Error::CgroupRefused {
                reason: CgroupRefusal::ParentHoldsProcesses,
                ..
            }
        ),
        "{err:?}"
    );
    assert!(sandbox_cgroups(&leaf).is_empty(), "nothing was created");
}

#[test]
fn a_parent_outside_a_cgroup_v2_hierarchy_is_refused() {
    if !common::require::userns() {
        return;
    }
    let scratch = common::scratch_dir("cgroup-not-a-cgroup");
    assert_eq!(
        host::cgroup_blocker(&scratch, &[]),
        Some(CgroupRefusal::NotCgroup2)
    );
    let err = common::host_userland()
        .command("/bin/true")
        .cgroup_parent(&scratch)
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect_err("a plain directory is no cgroup");
    assert!(
        matches!(
            &err,
            Error::CgroupRefused {
                reason: CgroupRefusal::NotCgroup2,
                ..
            }
        ),
        "{err:?}"
    );
    let rendered = ferroday_cage::ErrorChain::new(&err).to_string();
    assert!(rendered.contains("cgroup v2"), "{rendered}");
}

#[test]
fn a_missing_parent_is_refused_alike_by_the_probe_and_the_launch() {
    if !common::require::userns() {
        return;
    }
    let missing = common::scratch_dir("cgroup-missing").join("absent");
    assert_eq!(
        host::cgroup_blocker(&missing, &[]),
        Some(CgroupRefusal::Missing)
    );
    let err = common::host_userland()
        .command("/bin/true")
        .cgroup_parent(&missing)
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect_err("nothing is at the parent's path");
    assert!(
        matches!(
            &err,
            Error::CgroupRefused {
                reason: CgroupRefusal::Missing,
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn a_parent_not_delegated_to_the_caller_is_refused_alike_by_the_probe_and_the_launch() {
    if !common::require::userns() {
        return;
    }
    // A cgroup of the service manager's, which an unprivileged caller may read
    // and not divide.
    let Some(hierarchy) = host::own_cgroup().and_then(|own| {
        own.ancestors()
            .find(|dir| dir.join("system.slice").is_dir())
            .map(Path::to_path_buf)
    }) else {
        common::require::premise_unmet("the host's cgroup hierarchy has no system.slice");
        return;
    };
    if !common::require::not_root("root may divide any cgroup") {
        return;
    }
    let parent = hierarchy.join("system.slice");
    assert_eq!(
        host::cgroup_blocker(&parent, &[]),
        Some(CgroupRefusal::NotDelegated)
    );
    let err = common::host_userland()
        .command("/bin/true")
        .cgroup_parent(&parent)
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect_err("the service manager's cgroup is not the caller's");
    assert!(
        matches!(
            &err,
            Error::CgroupRefused {
                reason: CgroupRefusal::NotDelegated,
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn a_parent_that_can_hold_a_sandbox_s_cgroup_is_answered_so_and_left_as_found() {
    if !common::require::userns() {
        return;
    }
    let Some(parent) = delegated() else {
        return;
    };
    let own = own_parent(parent, "probe");
    assert_eq!(host::cgroup_blocker(&own, &LIMITS), None);
    assert_eq!(
        sandbox_cgroups(&own),
        Vec::<String>::new(),
        "the probe's cgroup is removed"
    );
    // The answer is the launch's: one is given its cgroup there.
    let output = sh_in(&own, "true")
        .cgroup_limit(LIMITS[0])
        .cgroup_limit(LIMITS[1])
        .build()
        .expect("a valid sandbox configuration")
        .output()
        .expect("the sandbox runs");
    assert!(output.status.success(), "{output:?}");
}

/// Set in the copy of this test binary that a reach test runs in a sandbox, to
/// `cage` or `restriction`, the kind of sandbox it runs in.
const REACH_PROBE: &str = "FERRODAY_CAGE_TEST_CGROUP_REACH";

/// Set beside [`REACH_PROBE`] for a restriction, naming a cgroup outside the
/// sandbox's tree for the probe to try to move into.
const REACH_OUTSIDE: &str = "FERRODAY_CAGE_TEST_CGROUP_REACH_OUTSIDE";

/// Where the reach probe is bound in a sandbox.
const REACH_PROBE_PATH: &str = "/probe";

/// How many threads the reach probe tries to start, twice the limit its
/// sandbox is held to.
const REACH_THREADS: usize = 16;

/// What the reach probe reported: each step's name and its outcome, one
/// `step outcome` line each.
fn reach_report(output: &ferroday_cage::Output) -> std::collections::BTreeMap<String, String> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("probe done"),
        "the probe failed: {:?}\n{stdout}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix("reach "))
        .filter_map(|line| line.split_once(' '))
        .map(|(step, outcome)| (step.to_string(), outcome.to_string()))
        .collect()
}

/// Asserts what a reach probe held to `PidsMax(8)` reported, and what its
/// cgroup counted, of the threads it tried to start past the limit.
#[track_caller]
fn assert_held_to_the_limit(
    output: &ferroday_cage::Output,
    report: &std::collections::BTreeMap<String, String>,
) {
    let started: usize = report
        .get("threads")
        .and_then(|count| count.parse().ok())
        .unwrap_or_else(|| panic!("the probe reported no thread count: {report:?}"));
    assert!(
        started < REACH_THREADS,
        "the probe started every thread past its limit: {report:?}"
    );
    let peak = output
        .usage
        .and_then(|usage| usage.cgroup_peak_processes)
        .expect("the pids controller is offered");
    assert!(peak <= 8, "the tree held {peak} tasks: {report:?}");
}

#[cfg(feature = "hardening")]
#[test]
fn a_restricted_command_can_neither_lift_its_limit_nor_leave_its_tree() {
    use ferroday_cage::{FsAccess, Restriction, SeccompPolicy, SeccompRules};

    if !(common::landlock() && common::require::seccomp()) {
        return;
    }
    let Some(parent) = delegated() else {
        return;
    };
    let exe = std::env::current_exe().expect("the test binary has a path");
    let outside = parent.join(format!("fcage-test-caller-{}", std::process::id()));
    // What the build requires of a restriction with a cgroup: no write granted
    // on the cgroup hierarchy, and clone3 answered with an errno.
    let output = common::grant_system_trees(Restriction::builder())
        .command(&exe)
        .args(common::rerun_args("probe_reach"))
        .env(REACH_PROBE, "restriction")
        .env(REACH_OUTSIDE, &outside)
        .landlock_fs(
            FsAccess::READ | FsAccess::EXECUTE,
            exe.parent().expect("the test binary is in a directory"),
        )
        .landlock_fs(FsAccess::READ, "/proc")
        .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
        .cgroup_parent(parent)
        .cgroup_limit(CgroupLimit::PidsMax(8))
        .build()
        .expect("a restriction held from its cgroup's files and from clone3")
        .output()
        .expect("the restriction runs");
    let report = reach_report(&output);
    assert!(
        report
            .get("own")
            .is_some_and(|own| own.ends_with("/sandbox")),
        "{report:?}"
    );
    let refused = Some(format!("errno {}", libc::EACCES));
    assert_eq!(report.get("leaf").map(String::as_str), Some("absent"));
    for step in ["limits", "parent", "leave"] {
        assert_eq!(report.get(step), refused.as_ref(), "{step}: {report:?}");
    }
    assert_eq!(
        report.get("clone3"),
        Some(&format!("errno {}", libc::ENOSYS)),
        "{report:?}"
    );
    assert_held_to_the_limit(&output, &report);
}

#[test]
fn a_caged_command_mounting_its_cgroup_namespace_sees_no_limit_to_lift() {
    if !common::require::userns() {
        return;
    }
    let Some(parent) = delegated() else {
        return;
    };
    let exe = std::env::current_exe().expect("the test binary has a path");
    let output = common::host_userland()
        .command(REACH_PROBE_PATH)
        .args(common::rerun_args("probe_reach"))
        .env(REACH_PROBE, "cage")
        .resolv_conf(false)
        .bind_ro(&exe, REACH_PROBE_PATH)
        .cgroup_parent(parent)
        .cgroup_limit(CgroupLimit::PidsMax(8))
        .build()
        .expect("a valid sandbox configuration")
        .output()
        .expect("the sandbox runs");
    let report = reach_report(&output);
    // The cgroup namespace is rooted at the leaf, which holds no limit: the
    // limits are written to the cgroup above it, outside the namespace,
    // whatever the hierarchy's mount options.
    assert_eq!(
        report.get("own").map(String::as_str),
        Some("/"),
        "{report:?}"
    );
    assert_eq!(
        report.get("mount").map(String::as_str),
        Some("ok"),
        "{report:?}"
    );
    for file in ["pids.max", "memory.max"] {
        assert_eq!(
            report.get(file).map(String::as_str),
            Some("absent"),
            "{report:?}"
        );
    }
    assert_held_to_the_limit(&output, &report);
}

/// Starts a child that exits at once in the cgroup at `cgroup`, through
/// `clone3` with `CLONE_INTO_CGROUP` and a descriptor of the cgroup opened with
/// `O_PATH`, which no Landlock right governs.
#[expect(unsafe_code)]
fn clone_into(cgroup: &Path) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    /// `struct clone_args` as far as `cgroup`, every field 64 bits wide.
    #[repr(C)]
    #[derive(Default)]
    struct CloneArgs {
        flags: u64,
        pidfd: u64,
        child_tid: u64,
        parent_tid: u64,
        exit_signal: u64,
        stack: u64,
        stack_size: u64,
        tls: u64,
        set_tid: u64,
        set_tid_size: u64,
        cgroup: u64,
    }
    const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

    let dir = rustix::fs::open(
        cgroup,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let args = CloneArgs {
        flags: CLONE_INTO_CGROUP,
        exit_signal: u64::try_from(libc::SIGCHLD).expect("a signal number"),
        cgroup: u64::try_from(dir.as_raw_fd()).expect("a descriptor"),
        ..CloneArgs::default()
    };
    // SAFETY: `args` is a valid `struct clone_args` of the size passed, and
    // with no `CLONE_VM` the child gets a copy of this process's memory. The
    // child makes one async-signal-safe call, `_exit`, so the locks other
    // threads held at the clone do not matter to it.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &raw const args,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    match pid {
        -1 => Err(std::io::Error::last_os_error()),
        0 => {
            // SAFETY: `_exit` ends the child without running anything of the
            // parent's.
            unsafe { libc::_exit(0) }
        }
        // The probe has no other child, so the one to wait for is this one.
        _ => {
            rustix::process::wait(rustix::process::WaitOptions::empty())?;
            Ok(())
        }
    }
}

/// Writes `max` to the limit file `file`, which the write does not create.
fn lift(file: &Path) -> std::io::Result<()> {
    use std::io::Write;

    std::fs::OpenOptions::new()
        .write(true)
        .open(file)?
        .write_all(b"max")
}

/// The probe the reach tests start in a sandbox: it tries to lift the limits
/// it can find and to leave its cgroup, and then starts threads past its
/// limit, reporting each step.
///
/// In a cage it creates a mount and a cgroup namespace of its own, which its
/// user namespace owns, and mounts cgroup2 there, the hierarchy's root then
/// being the root of the sandbox's cgroup namespace. In a restriction it uses
/// the host's hierarchy: it writes `max` to each `pids.max` from its own
/// cgroup up to the parent, writes its process id to the `cgroup.procs` of the
/// cgroup [`REACH_OUTSIDE`] names, and starts a child there with `clone3`.
#[test]
#[expect(unsafe_code)]
fn probe_reach() {
    let Some(kind) = std::env::var_os(REACH_PROBE) else {
        return;
    };
    let report = |step: &str, outcome: &dyn std::fmt::Display| println!("reach {step} {outcome}");
    // The harness has begun a line of its own naming the test.
    println!();
    let attempt = |result: std::io::Result<()>| match result {
        Ok(()) => "ok".to_string(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => "absent".to_string(),
        Err(err) => format!("errno {}", err.raw_os_error().unwrap_or(0)),
    };
    let own = std::fs::read_to_string("/proc/self/cgroup").expect("the probe names its cgroup");
    report("own", &own.trim().trim_start_matches("0::"));
    if kind == "cage" {
        let mount = Path::new("/tmp/cgroup");
        std::fs::create_dir(mount).expect("the sandbox's /tmp is writable");
        // SAFETY: `unshare_unsafe` is unsafe only because
        // `UnshareFlags::FILES` can invalidate descriptors other threads
        // observe, and these flags do not include it.
        let unshared = unsafe {
            rustix::thread::unshare_unsafe(
                rustix::thread::UnshareFlags::NEWNS | rustix::thread::UnshareFlags::NEWCGROUP,
            )
        };
        let mounted = unshared.and_then(|()| {
            rustix::mount::mount(
                "cgroup2",
                mount,
                "cgroup2",
                rustix::mount::MountFlags::empty(),
                None,
            )
        });
        report("mount", &attempt(mounted.map_err(Into::into)));
        for file in ["pids.max", "memory.max"] {
            report(file, &attempt(lift(&mount.join(file))));
        }
    }
    if kind == "restriction" {
        // The host's hierarchy: the leaf, the cgroup holding the limits above
        // it, and the parent above that.
        let own = host::own_cgroup().expect("the probe finds its cgroup");
        for (step, cgroup) in ["leaf", "limits", "parent"]
            .into_iter()
            .zip(own.ancestors())
        {
            report(step, &attempt(lift(&cgroup.join("pids.max"))));
        }
        let outside = PathBuf::from(
            std::env::var_os(REACH_OUTSIDE).expect("the test names a cgroup outside the tree"),
        );
        let leave = || {
            use std::io::Write;

            std::fs::OpenOptions::new()
                .write(true)
                .open(outside.join("cgroup.procs"))?
                .write_all(std::process::id().to_string().as_bytes())
        };
        report("leave", &attempt(leave()));
        report("clone3", &attempt(clone_into(&outside)));
    }
    // Each thread waits until `hold` drops, the first on the channel and the
    // rest on the lock, so all are alive at once.
    let (hold, held) = std::sync::mpsc::channel::<()>();
    let held = std::sync::Arc::new(std::sync::Mutex::new(held));
    let mut threads = Vec::new();
    for _ in 0..REACH_THREADS {
        let held = std::sync::Arc::clone(&held);
        match std::thread::Builder::new().spawn(move || {
            let _ = held.lock().map(|held| held.recv());
        }) {
            Ok(thread) => threads.push(thread),
            Err(_) => break,
        }
    }
    report("threads", &threads.len());
    drop(hold);
    for thread in threads {
        let _ = thread.join();
    }
    println!("probe done");
}

/// Set in the copy of this test binary that
/// [`a_launch_in_a_cgroup_leaves_the_callers_closed_streams_closed`] starts,
/// naming the delegated parent its probe places its sandboxes beneath.
const CLOSED_STREAMS_PROBE: &str = "FERRODAY_CAGE_TEST_CGROUP_CLOSED_STREAMS";

#[test]
fn a_launch_in_a_cgroup_leaves_the_callers_closed_streams_closed() {
    if !common::require::userns() {
        return;
    }
    let Some(parent) = delegated() else {
        return;
    };
    // The probe is a copy of this test binary, since closing a standard
    // descriptor is process-wide. It starts in this process's leaf, so its
    // sandboxes' cgroups are made beneath the parent as this process's are.
    let output = common::run_bounded(
        common::rerun("probe_closed_streams").env(CLOSED_STREAMS_PROBE, parent),
        Duration::from_secs(120),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("probe done"),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
}

/// The probe [`a_launch_in_a_cgroup_leaves_the_callers_closed_streams_closed`]
/// starts: closes all three standard descriptors, and launches in a cgroup
/// beneath the parent [`CLOSED_STREAMS_PROBE`] names, directly and held at the
/// gate.
///
/// A launch opens its cgroup's descriptors before anything else of its own, so
/// they are the first that could take a closed number: a directory of the
/// cgroup's on standard input's, where the launch would refuse it as a
/// directory handed to the command, and the caller's closed number held for as
/// long as the sandbox runs.
#[test]
fn probe_closed_streams() {
    let Some(parent) = std::env::var_os(CLOSED_STREAMS_PROBE) else {
        return;
    };
    let cage = sh_in(Path::new(&parent), "exit 0")
        .cgroup_limit(CgroupLimit::PidsMax(8))
        .stop_with_caller(true)
        .build()
        .expect("a valid sandbox configuration");
    let closed = [0, 1, 2];
    let findings = common::with_standard_streams_closed(&closed, || {
        let mut findings = Vec::new();
        let still_closed = |when: &str, findings: &mut Vec<String>| {
            for fd in closed {
                if common::is_open(fd) {
                    findings.push(format!("{when}, the caller's descriptor {fd} is open"));
                }
            }
        };
        // The command's outcome, or what kept it from one. Not
        // `common::outcome_within`, which fails the test where it stands: this
        // runs with the standard descriptors closed, where a failure could not
        // be reported, so what went wrong is kept and asserted once they are
        // back.
        let outcome = |launched: Result<ferroday_cage::Running<'_>, Error>| match launched {
            Ok(mut running) => match running.wait_timeout(Duration::from_secs(30)) {
                Ok(Some(status)) if status.success() => None,
                other => {
                    let _ = running.kill();
                    Some(format!("the sandbox ended {other:?}"))
                }
            },
            Err(err) => Some(format!("the launch failed: {err:?}")),
        };

        let launched = cage.spawn();
        still_closed("while a launch runs", &mut findings);
        findings.extend(outcome(launched));

        let launched = match cage.spawn_pending() {
            Ok(pending) => {
                still_closed("while a launch is held", &mut findings);
                pending.proceed()
            }
            Err(err) => Err(err),
        };
        findings.extend(outcome(launched));
        findings
    });
    assert!(findings.is_empty(), "{}", findings.join("\n"));
    println!("probe done");
}
