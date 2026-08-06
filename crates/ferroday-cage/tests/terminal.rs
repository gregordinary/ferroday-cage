//! Integration tests for a pseudoterminal of the sandbox's own.
//!
//! These launch real sandboxes, so they skip explicitly where the host cannot
//! create unprivileged user namespaces, as the other sandbox tests do.

mod common;

use std::io::{Read as _, Write as _};

use ferroday_cage::{Cage, ConfigError, Error, IdentityMap, Pty, Stdio, Terminal};
// The run-as case is the only one that names an identity, and it needs a range
// map, so it and this import are gated together.
#[cfg(feature = "subid")]
use ferroday_cage::Identity;

/// Everything the sandbox wrote to its terminal, up to end-of-file.
///
/// End-of-file arrives when the last replica descriptor anywhere closes, which
/// the launch guarantees for every process that is not the command, so this
/// terminates on its own once the session ends.
fn drain(pty: &mut Pty) -> String {
    let mut written = Vec::new();
    pty.read_to_end(&mut written)
        .expect("the primary drains to end-of-file rather than failing with EIO");
    String::from_utf8_lossy(&written).into_owned()
}

/// A cage running `/bin/sh -c script` against the fixture rootfs.
fn shell(rootfs: &std::path::Path, script: &str) -> Cage {
    Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", script])
        .build()
        .expect("a valid sandbox configuration")
}

/// A command that reports itself ready, waits for `SIGWINCH`, and answers with
/// the terminal's new size.
///
/// The wait is a bounded sequence of short sleeps rather than one long block:
/// see the comment at its use. Thirty steps is a ceiling for a run where the
/// signal never arrives, not a duration any passing run reaches.
const WAIT_FOR_WINCH: &str = "trap 'echo winch; stty size; exit 0' WINCH; \
     echo ready; i=0; while [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done";

/// [`WAIT_FOR_WINCH`] without the announcement, for a test that asserts on the
/// size alone.
const WAIT_FOR_WINCH_QUIETLY: &str = "trap 'stty size; exit 0' WINCH; \
     echo ready; i=0; while [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done";

/// This process's own controlling-terminal number, or `None` where it has none.
///
/// Field 7 of `/proc/self/stat`, read from after the closing parenthesis so a
/// `comm` holding spaces cannot shift it. Zero means no controlling terminal.
fn caller_tty() -> Option<String> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let (_, rest) = stat.rsplit_once(')')?;
    let tty = rest.split_whitespace().nth(4)?;
    (tty != "0").then(|| tty.to_string())
}

#[test]
fn a_terminal_launch_gives_the_command_a_controlling_terminal() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The sandbox has a controlling terminal, all three of its standard streams
    // are it, and it is not the caller's — which is the whole point: an
    // interactive sandbox that reaches nothing of the terminal it was launched
    // from.
    let cage = shell(
        rootfs,
        "for fd in 0 1 2; do [ -t $fd ] || exit 1; done; \
         echo \"tty=$(cut -d')' -f2- /proc/self/stat | cut -d' ' -f6)\"",
    );
    let (mut running, mut pty) = cage
        .spawn_terminal(&Terminal::new())
        .expect("the sandbox launches on a terminal");
    let written = drain(&mut pty);
    let status = running.wait().expect("the outcome is collected");

    assert!(status.success(), "isatty must hold on all three streams");
    let sandbox_tty = written
        .lines()
        .find_map(|line| line.strip_prefix("tty="))
        .expect("the command reports its controlling terminal");
    assert_ne!(sandbox_tty, "0", "a terminal launch has one");
    if let Some(caller) = caller_tty() {
        assert_ne!(
            sandbox_tty, caller,
            "the sandbox's terminal must not be the caller's",
        );
    }
}

#[test]
fn the_command_starts_at_the_stated_window_size() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The size is set on the replica before the fork, so the command cannot
    // observe a 0x0 window even at its first instruction, and it is whatever the
    // caller stated rather than anything read from the host.
    let cage = shell(rootfs, "stty size");
    let (mut running, mut pty) = cage
        .spawn_terminal(&Terminal::new().size(43, 132))
        .expect("the sandbox launches on a terminal");
    let written = drain(&mut pty);
    running.wait().expect("the outcome is collected");
    assert!(
        written.contains("43 132"),
        "the command sees the stated size: {written:?}",
    );
}

#[test]
fn the_default_terminal_is_the_stated_constant() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let (mut running, mut pty) = shell(rootfs, "stty size")
        .spawn_terminal(&Terminal::new())
        .expect("the sandbox launches on a terminal");
    let written = drain(&mut pty);
    running.wait().expect("the outcome is collected");
    assert!(
        written.contains("24 80"),
        "the default is 80x24, read from nothing on the host: {written:?}",
    );
}

#[test]
fn the_line_discipline_is_the_stated_baseline() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // `ONLCR` and `ECHO` are the two the caller can see from outside: the
    // newline the command writes arrives as CRLF, and what the caller types is
    // echoed back before the command has read it.
    let cage = shell(rootfs, "read line; echo \"got:$line\"");
    let (mut running, mut pty) = cage
        .spawn_terminal(&Terminal::new())
        .expect("the sandbox launches on a terminal");
    pty.write_all(b"typed\n")
        .expect("the primary accepts input");
    let written = drain(&mut pty);
    running.wait().expect("the outcome is collected");

    assert!(
        written.contains("typed\r\n"),
        "ECHO is on, so the input comes back: {written:?}",
    );
    assert!(
        written.contains("got:typed\r\n"),
        "ICANON delivers the line and ONLCR turns the newline into CRLF: {written:?}",
    );
}

#[test]
fn dev_tty_resolves_to_the_sandboxs_own_terminal() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // `/dev/tty` is the character device 5:0, a per-process redirect to the
    // opener's controlling terminal, so the node the private devpts does not
    // carry is beside the point: what it yields here is the sandbox's own
    // terminal, and a write through it reaches the caller's primary.
    let cage = shell(rootfs, "echo through-dev-tty > /dev/tty");
    let (mut running, mut pty) = cage
        .spawn_terminal(&Terminal::new())
        .expect("the sandbox launches on a terminal");
    let written = drain(&mut pty);
    let status = running.wait().expect("the outcome is collected");
    assert!(status.success(), "opening /dev/tty must succeed");
    assert!(
        written.contains("through-dev-tty"),
        "the write reaches the sandbox's own terminal: {written:?}",
    );
}

/// Skips a range-map test when no delegate can establish one on this host.
///
/// `FERRODAY_CAGE_REQUIRE_SUBID` turns the skip into a failure, as elsewhere.
#[cfg(feature = "subid")]
fn range_map_available() -> bool {
    match ferroday_cage::host::range_map_blocker() {
        None => true,
        Some(blocker) => {
            assert!(
                std::env::var_os("FERRODAY_CAGE_REQUIRE_SUBID").is_none(),
                "range maps are required but unavailable: {blocker}"
            );
            eprintln!("skipping: no delegate can establish a range map: {blocker}");
            false
        }
    }
}

#[cfg(feature = "subid")]
#[test]
fn dev_tty_works_for_a_run_as_identity() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !range_map_available() {
        return;
    }
    let map = IdentityMap::Subordinate;
    // The replica's inode is mode 0620 owned by the mapped calling uid, so a
    // command running as a different mapped uid could in principle be refused. It
    // is not: the `5:0` redirect is a per-process lookup of the opener's own
    // controlling terminal, and the permission check the open performs is against
    // the mode-0666 `/dev/tty` node rather than against the replica's inode.
    let cage = Cage::builder()
        .rootfs(rootfs)
        .identity_map(map)
        .run_as(Identity::new(1000, 1000))
        .command("/bin/sh")
        .args(["-c", "echo as-another-uid > /dev/tty"])
        .build()
        .expect("a valid sandbox configuration");
    let (mut running, mut pty) = cage
        .spawn_terminal(&Terminal::new())
        .expect("the sandbox launches on a terminal");
    let written = drain(&mut pty);
    let status = running.wait().expect("the outcome is collected");
    assert!(
        status.success(),
        "a run-as identity opens /dev/tty: {written:?}",
    );
    assert!(
        written.contains("as-another-uid"),
        "and its writes reach the primary: {written:?}",
    );
}

#[test]
fn a_path_for_the_terminal_does_not_resolve() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The stated limit of allocating on the host: the replica's device node
    // lives in the host's devpts, and the sandbox's /dev/pts is a private
    // instance, so anything that resolves a path for its terminal fails. `tty`
    // is the plain case; `GPG_TTY` is the one that bites in practice.
    let cage = shell(rootfs, "tty || echo tty-failed > /dev/tty");
    let (mut running, mut pty) = cage
        .spawn_terminal(&Terminal::new())
        .expect("the sandbox launches on a terminal");
    let written = drain(&mut pty);
    running.wait().expect("the outcome is collected");
    assert!(
        written.contains("tty-failed"),
        "path resolution fails while the descriptor still works: {written:?}",
    );
}

#[test]
fn nested_allocation_uses_the_sandboxs_own_devpts() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The private devpts stays mounted, so a program that allocates a terminal
    // of its own inside the sandbox gets one from that instance — and sees no
    // host pseudoterminal but the single replica it was handed.
    let cage = shell(
        rootfs,
        "ls /dev/pts | tr '\\n' ' '; echo; \
         [ -e /dev/pts/ptmx ] && echo ptmx-present",
    );
    let (mut running, mut pty) = cage
        .spawn_terminal(&Terminal::new())
        .expect("the sandbox launches on a terminal");
    let written = drain(&mut pty);
    running.wait().expect("the outcome is collected");
    assert!(
        written.contains("ptmx-present"),
        "the sandbox can still allocate terminals of its own: {written:?}",
    );
}

#[test]
fn end_of_file_arrives_when_the_session_ends() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The drain-then-wait shape the documentation recommends: end-of-file on
    // the primary means every replica is closed, so the wait after it is prompt.
    // It only terminates because the caller's own copy, `stage_init`'s, and the
    // supervisor's are all dropped.
    let (mut running, mut pty) = shell(rootfs, "echo done")
        .spawn_terminal(&Terminal::new())
        .expect("the sandbox launches on a terminal");
    let written = drain(&mut pty);
    assert!(written.contains("done"), "{written:?}");
    let status = running.wait().expect("the outcome is collected");
    assert!(status.success());
}

#[test]
fn a_concurrent_export_does_not_withhold_end_of_file() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // `kernel_fork` copies the whole descriptor table, so a child forked between
    // the replica's open and its close inherits a copy and could hold the
    // session's end-of-file open for as long as it runs. Every such child sweeps
    // its inherited table early, which is what bounds the exposure — asserted
    // here by starting an export that outlives the session and requiring the
    // drain to finish anyway.
    let export = std::thread::spawn(move || {
        let mut sink = std::io::sink();
        ferroday_cage::provision::export_tar(rootfs, &mut sink, IdentityMap::Single)
    });
    let (mut running, mut pty) = shell(rootfs, "echo brief")
        .spawn_terminal(&Terminal::new())
        .expect("the sandbox launches on a terminal");
    let written = drain(&mut pty);
    running.wait().expect("the outcome is collected");
    assert!(written.contains("brief"), "{written:?}");
    export
        .join()
        .expect("the export thread completes")
        .expect("the export succeeds");
}

#[test]
fn a_terminal_launch_is_refused_against_a_directed_stream() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The replica is all three streams, so a disposition naming a different
    // destination means the caller asked for two things. `Inherit` states no
    // destination and so is no contradiction, which is why the tests above pass
    // without saying anything about their streams.
    for builder in [
        Cage::builder().rootfs(rootfs).stdin(Stdio::Null),
        Cage::builder().rootfs(rootfs).stdout(Stdio::Null),
        Cage::builder().rootfs(rootfs).stderr(Stdio::Null),
    ] {
        let cage = builder
            .command("/bin/sh")
            .args(["-c", "true"])
            .build()
            .expect("the sandbox itself is valid");
        let err = cage
            .spawn_terminal(&Terminal::new())
            .expect_err("a terminal launch is refused");
        assert!(
            matches!(
                err,
                Error::Config(ConfigError::StreamAttachmentConflict { .. })
            ),
            "{err:?}",
        );
    }
}

#[test]
fn a_pending_terminal_launch_hands_the_primary_over_before_proceeding() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The seam and a terminal compose: the caller holds the primary while the
    // command is still held at the gate, attaches whatever it attaches, and
    // proceeds. Nothing has been written to the terminal yet.
    let cage = shell(rootfs, "echo after-the-gate");
    let (pending, mut pty) = cage
        .spawn_pending_terminal(&Terminal::new())
        .expect("the gated sandbox launches on a terminal");
    assert_ne!(pending.netns_pid(), 0, "the seam names a live process");
    let mut running = pending.proceed().expect("the command is released");
    let written = drain(&mut pty);
    let status = running.wait().expect("the outcome is collected");
    assert!(status.success());
    assert!(written.contains("after-the-gate"), "{written:?}");
}

#[test]
fn dropping_the_primary_hangs_the_terminal_up() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // Dropping the primary is how an interactive session is ended deliberately,
    // and it is a safe order: after the hangup the command's writes fail with
    // EIO rather than block, so a caller that has dropped it owes the wait no
    // drain. SIGHUP is ignored here — inherited across the exec, so `head` gets
    // the ignore too — precisely so that nothing but the failing writes can end
    // the command, and the write is far beyond the terminal's buffer, so with
    // nothing draining it would block forever if it did not fail.
    let cage = shell(rootfs, "trap '' HUP; head -c 200000 /dev/zero; exit 7");
    let (mut running, pty) = cage
        .spawn_terminal(&Terminal::new())
        .expect("the sandbox launches on a terminal");
    drop(pty);
    let status = running
        .wait_timeout(std::time::Duration::from_secs(20))
        .expect("the wait does not fail")
        .expect("the command ends rather than blocking on a closed primary");
    assert_eq!(
        status.code(),
        Some(7),
        "the command ran to its own exit rather than being hung up",
    );
}

/// Reads from the primary until `needle` has arrived, returning everything read.
///
/// Used where a test has to act at a point in the session — after the command
/// has installed a handler, say — rather than after it has ended.
fn read_until(pty: &mut Pty, needle: &str) -> String {
    let mut seen = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        let read = pty.read(&mut chunk).expect("the primary reads");
        assert_ne!(read, 0, "the session ended before {needle:?} arrived");
        seen.extend_from_slice(&chunk[..read]);
        if String::from_utf8_lossy(&seen).contains(needle) {
            return String::from_utf8_lossy(&seen).into_owned();
        }
    }
}

#[test]
fn a_resize_reaches_the_running_command() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // A terminal's size changes over the life of a session, so the launch-time
    // constant is a starting point and `resize` is the rest. It both sets the
    // size and delivers SIGWINCH to the sandbox's foreground process group,
    // which is what lets a full-screen program redraw.
    let cage = shell(
        rootfs,
        // The shell waits in short steps rather than one long block. A shell
        // acts on a trapped signal at a command boundary, and a signal that
        // arrives while it is already inside a blocking read may not interrupt
        // that read — so a single long wait makes the latency the signal's
        // arrival time relative to that boundary, which is a race. Stepping
        // bounds it to one step. The step count bounds a run where the signal
        // never arrives at all, so a defect fails the assertions below rather
        // than hanging the suite.
        WAIT_FOR_WINCH,
    );
    let (mut running, mut pty) = cage
        .spawn_terminal(&Terminal::new().size(24, 80))
        .expect("the sandbox launches on a terminal");
    read_until(&mut pty, "ready");
    pty.resize(60, 200).expect("the resize applies");

    let written = drain(&mut pty);
    running.wait().expect("the outcome is collected");
    assert!(
        written.contains("winch"),
        "the resize delivers SIGWINCH: {written:?}",
    );
    assert!(
        written.contains("60 200"),
        "and the command sees the new size: {written:?}",
    );
}

#[test]
fn a_shared_primary_serves_a_reader_thread_and_a_resize() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The shape the `&Pty` implementations exist for: a reader thread beside the
    // main thread, which resizes and then waits. A `Pty` that had to be moved
    // into the reader would leave the resize path with nothing to call, and a
    // mutex would be worse — the reader holds it while blocked in `read`, so a
    // resize would land only when the sandbox next produced output.
    let cage = shell(rootfs, WAIT_FOR_WINCH_QUIETLY);
    let (mut running, pty) = cage
        .spawn_terminal(&Terminal::new())
        .expect("the sandbox launches on a terminal");
    let pty = std::sync::Arc::new(pty);

    let reader = {
        let pty = std::sync::Arc::clone(&pty);
        std::thread::spawn(move || {
            let mut written = Vec::new();
            // `&Pty` is what makes this possible: the thread borrows through the
            // `Arc` rather than taking the terminal away from the main thread.
            (&*pty)
                .read_to_end(&mut written)
                .expect("the primary drains to end-of-file");
            String::from_utf8_lossy(&written).into_owned()
        })
    };
    // Resize while the reader is blocked in `read`, which is the case a mutex
    // could not serve.
    std::thread::sleep(std::time::Duration::from_millis(200));
    pty.resize(41, 121).expect("the resize applies");

    let written = reader.join().expect("the reader thread completes");
    running.wait().expect("the outcome is collected");
    assert!(
        written.contains("41 121"),
        "the resize reached the command while the reader held the same Pty: {written:?}",
    );
}
