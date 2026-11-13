//! Integration tests for a sandbox placed in a cgroup of its own.
//!
//! A launch creates its cgroup beneath a directory the caller may create
//! cgroups in, which only a delegated subtree is. These tests use the cgroup
//! the test binary runs in: run under `systemd-run --user --scope -p
//! Delegate=yes`, that is a scope of the test's own. The first test to need it
//! moves the whole test process into a leaf beside the sandboxes' cgroups, as
//! a caller does. A run started anywhere else skips them, since how the run
//! was started is the premise, not something the host lacks.

mod common;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use ferroday_cage::{CgroupLimit, CgroupRefusal, Error};

/// The delegated directory the sandboxes' cgroups are created beneath, with
/// the test process already moved into a leaf of it, or `None` where the run
/// has none.
fn delegated() -> Option<&'static Path> {
    static PARENT: OnceLock<Option<PathBuf>> = OnceLock::new();
    let parent = PARENT.get_or_init(|| {
        let own = std::fs::read_to_string("/proc/self/cgroup").ok()?;
        let relative = own.lines().find_map(|line| line.strip_prefix("0::"))?;
        let parent = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
        let leaf = parent.join(format!("fcage-test-caller-{}", std::process::id()));
        std::fs::create_dir(&leaf).ok()?;
        std::fs::write(leaf.join("cgroup.procs"), "0").ok()?;
        // A cgroup holding processes of its own cannot enable a controller
        // for its children, so anything else left in the parent is a run
        // started in a cgroup it shares.
        let others = std::fs::read_to_string(parent.join("cgroup.procs")).ok()?;
        if !others.trim().is_empty() {
            return None;
        }
        // The leaf offers what the parent enables for its children, which the
        // refusal test needs: pids, at least.
        std::fs::write(parent.join("cgroup.subtree_control"), "+pids").ok()?;
        Some(parent)
    });
    match parent {
        Some(parent) => Some(parent.as_path()),
        None => {
            common::require::premise_unmet(
                "the tests run outside a delegated cgroup of their own; run them under \
                 systemd-run --user --scope -p Delegate=yes",
            );
            None
        }
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

/// The sandbox cgroups beneath `parent`, by name.
fn sandbox_cgroups(parent: &Path) -> Vec<String> {
    std::fs::read_dir(parent)
        .expect("the parent lists")
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| name.starts_with("fcage-") && !name.starts_with("fcage-test-"))
        .collect()
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
fn a_kill_reaches_a_descendant_that_left_the_command_without_a_pid_namespace() {
    if !common::require::userns() {
        return;
    }
    let Some(parent) = delegated() else {
        return;
    };
    // The orphan outlives the command's own process tree: setsid gives it a
    // session of its own, and the command waits on something else. It holds
    // none of the sandbox's streams, which would hold the wait open until it
    // ended by itself.
    let mut observer = common::Collect::default();
    let cage = sh_in(
        parent,
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
fn a_cgroup_is_removed_once_its_sandbox_is_done() {
    if !common::require::userns() {
        return;
    }
    let Some(parent) = delegated() else {
        return;
    };
    // A parent of this test's own, since the tests beside it create cgroups
    // beneath the shared one at the same time. It holds no process and needs
    // no controller.
    let own = parent.join("fcage-test-removal");
    std::fs::create_dir_all(&own).expect("a cgroup of the test's own");
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
