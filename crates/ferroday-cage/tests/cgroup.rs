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

/// The one sandbox cgroup beneath `parent`, and the processes it holds.
fn sole_sandbox_cgroup(parent: &Path) -> (PathBuf, Vec<u32>) {
    let names = sandbox_cgroups(parent);
    assert_eq!(names.len(), 1, "one sandbox cgroup: {names:?}");
    let cgroup = parent.join(&names[0]);
    let members = std::fs::read_to_string(cgroup.join("cgroup.procs"))
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
            common::require::premise_unmet(format!("this kernel offers no {file}"));
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
    // What ends it now is the caller's own: the cgroup's kill, and then its
    // removal once the tree has emptied.
    std::fs::write(cgroup.join("cgroup.kill"), "1").expect("the tree is killed");
    assert_gone(&members);
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
    if rustix::process::geteuid().is_root() {
        common::require::premise_unmet("root may divide any cgroup");
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
