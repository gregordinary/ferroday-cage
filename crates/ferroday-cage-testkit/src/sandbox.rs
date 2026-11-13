//! Sandboxes the suites launch to have something running, and the observer
//! they read a sandbox's output with.

use std::path::Path;
use std::time::Duration;

use ferroday_cage::{Cage, ExitStatus, Observer, Running};

/// A sandbox running `/bin/sh -c script` in `rootfs`, with every other setting
/// the builder's own.
pub fn shell(rootfs: &Path, script: &str) -> Cage {
    Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", script])
        .build()
        .expect("a valid sandbox configuration")
}

/// A sandbox running a long sleep in `rootfs`: a command that stays alive so
/// its namespaces, and whatever is attached to them, can be inspected around
/// it.
pub fn sleeper(rootfs: &Path) -> Cage {
    Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sleep")
        .arg("86399")
        .build()
        .expect("a valid sandbox configuration")
}

/// The outcome of `running`, waited for up to `patience`.
///
/// Fails the test past it, or where the wait itself fails. A sandbox still
/// running then is killed and collected first, so a failing test leaves none
/// behind it.
#[track_caller]
pub fn outcome_within(running: &mut Running<'_>, patience: Duration) -> ExitStatus {
    match running.wait_timeout(patience) {
        Ok(Some(status)) => status,
        other => {
            let _ = running.kill();
            let _ = running.wait_timeout(patience);
            panic!("the sandbox's outcome was not collected within {patience:?}: {other:?}");
        }
    }
}

/// An observer that keeps everything the sandbox writes to standard output.
///
/// For a launch the test observes while it runs: a pending launch, or a handle
/// it waits on. A run to its end has the library's own `Cage::output`.
#[derive(Debug, Default)]
pub struct Collect {
    /// What the sandbox wrote to standard output, in order.
    pub stdout: Vec<u8>,
}

impl Observer for Collect {
    fn stdout(&mut self, chunk: &[u8]) {
        self.stdout.extend_from_slice(chunk);
    }
}
