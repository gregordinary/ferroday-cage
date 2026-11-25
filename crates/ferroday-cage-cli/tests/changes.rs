//! Integration tests for `fcage --changes` and `fcage --apply-changes`: what
//! each prints, and what an apply writes and refuses.
//!
//! Each upper is laid out by hand over a lower the test writes, so nothing
//! here builds a sandbox; an upper's whiteout needs a kernel that lets an
//! unprivileged process make one, and a test skips where it cannot.

mod common;

use std::path::Path;
use std::process::{Command, Output};
use std::time::Duration;

/// The built binary under test.
const FCAGE: &str = env!("CARGO_BIN_EXE_fcage");

/// Runs `fcage` with `args` to completion.
fn fcage(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(FCAGE).args(args).output().expect("fcage runs")
}

/// A lower holding `keep` and `gone`, and an upper that modifies `keep`,
/// removes `gone`, and adds `.envrc` and `new`, laid out in `dir`, or `None`
/// where this kernel refuses an unprivileged whiteout.
fn layers(dir: &Path) -> Option<()> {
    let (lower, upper) = (dir.join("lower"), dir.join("upper"));
    std::fs::create_dir(&lower).unwrap();
    std::fs::write(lower.join("keep"), "lower\n").unwrap();
    std::fs::write(lower.join("gone"), "lower\n").unwrap();
    // The upper's birth time is the reference an apply holds the lower to,
    // less ten milliseconds; the lower is laid out before that.
    std::thread::sleep(Duration::from_millis(50));
    std::fs::create_dir(&upper).unwrap();
    std::fs::write(upper.join("keep"), "upper\n").unwrap();
    std::fs::write(upper.join("new"), "upper\n").unwrap();
    std::fs::write(upper.join(".envrc"), "export X=1\n").unwrap();
    ferroday_cage_testkit::overlay::whiteout(&upper.join("gone")).then_some(())
}

#[test]
fn changes_prints_one_change_a_line() {
    let dir = common::scratch_dir("fcage-changes");
    if layers(&dir).is_none() {
        return;
    }
    let out = fcage(&[
        "--changes".as_ref(),
        dir.join("upper").as_os_str(),
        "--overlay-lower".as_ref(),
        dir.join("lower").as_os_str(),
    ]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "A \".envrc\"\nD \"gone\"\nM \"keep\" content\nA \"new\"\n"
    );
}

#[test]
fn apply_changes_refuses_a_protected_path_and_writes_the_rest_without_it() {
    let dir = common::scratch_dir("fcage-apply-changes");
    if layers(&dir).is_none() {
        return;
    }
    let (lower, upper) = (dir.join("lower"), dir.join("upper"));
    let apply = |extra: &[&str]| {
        let mut args: Vec<&std::ffi::OsStr> = vec![
            "--apply-changes".as_ref(),
            upper.as_os_str(),
            "--overlay-lower".as_ref(),
            lower.as_os_str(),
            "--to".as_ref(),
            lower.as_os_str(),
        ];
        args.extend(extra.iter().map(|arg| std::ffi::OsStr::new(*arg)));
        fcage(&args)
    };

    let refused = apply(&[]);
    assert_eq!(refused.status.code(), Some(125), "{refused:?}");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("refused \".envrc\": it touches the name \".envrc\" at any depth"),
        "{stderr}"
    );
    assert!(!lower.join("new").exists(), "nothing is written");

    let applied = apply(&["--only", "keep", "--only", "gone", "--only", "new"]);
    assert!(applied.status.success(), "{applied:?}");
    assert_eq!(
        String::from_utf8_lossy(&applied.stdout),
        "\"gone\"\n\"keep\"\n\"new\"\n"
    );
    assert_eq!(
        std::fs::read_to_string(lower.join("keep")).unwrap(),
        "upper\n"
    );
    assert!(!lower.join("gone").exists());
    assert!(!lower.join(".envrc").exists());
}

#[test]
fn the_change_modes_take_their_own_flags_alone() {
    let out = fcage(&[
        "--changes".as_ref(),
        "/srv/upper".as_ref(),
        "--overlay-lower".as_ref(),
        "/srv/lower".as_ref(),
        "--to".as_ref(),
        "/srv/target".as_ref(),
    ]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    for (args, said) in [
        (
            &["--changes", "/srv/upper"][..],
            "--changes requires --overlay-lower",
        ),
        (
            &[
                "--apply-changes",
                "/srv/upper",
                "--overlay-lower",
                "/srv/lower",
            ][..],
            "--apply-changes requires --to",
        ),
        (
            &[
                "--apply-changes",
                "/srv/upper",
                "--overlay-lower",
                "/l",
                "--to",
                "/t",
                "--only",
                "../up",
            ][..],
            "--only requires a path relative to the target's top",
        ),
    ] {
        let args: Vec<&std::ffi::OsStr> = args.iter().map(std::ffi::OsStr::new).collect();
        let out = fcage(&args);
        assert_eq!(out.status.code(), Some(2), "{out:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(said), "{stderr}");
    }
}
