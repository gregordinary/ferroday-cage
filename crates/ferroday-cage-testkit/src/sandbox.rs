//! Sandboxes the suites launch to have something running, and the observer
//! they read a sandbox's output with.

use std::path::Path;

use ferroday_cage::{Cage, Observer};

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
