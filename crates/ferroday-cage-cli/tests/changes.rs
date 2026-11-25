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

/// The one document `fcage` printed, which is a line of its own.
fn document(out: &Output) -> serde_json::Value {
    let stdout = String::from_utf8(out.stdout.clone()).expect("the document is UTF-8");
    let line = stdout
        .strip_suffix('\n')
        .expect("the document ends its line");
    assert!(!line.contains('\n'), "one line: {stdout}");
    serde_json::from_str(line).expect("the document is JSON")
}

#[test]
fn changes_prints_one_document_with_json() {
    let dir = common::scratch_dir("fcage-changes-json");
    if layers(&dir).is_none() {
        return;
    }
    let out = fcage(&[
        "--changes".as_ref(),
        dir.join("upper").as_os_str(),
        "--overlay-lower".as_ref(),
        dir.join("lower").as_os_str(),
        "--json".as_ref(),
    ]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        document(&out),
        serde_json::json!({"changes": [
            {"kind": "added", "path": ".envrc", "now": "file", "size": 11, "readable": true},
            {"kind": "removed", "path": "gone", "before": "file", "readable": true},
            {"kind": "modified", "path": "keep", "before": "file", "now": "file", "size": 6,
             "differs": ["content"], "readable": true},
            {"kind": "added", "path": "new", "now": "file", "size": 6, "readable": true},
        ]})
    );
}

#[test]
fn a_path_that_is_not_utf_8_is_listed_as_its_bytes() {
    use std::os::unix::ffi::OsStrExt as _;

    let dir = common::scratch_dir("fcage-changes-json-bytes");
    let (lower, upper) = (dir.join("lower"), dir.join("upper"));
    std::fs::create_dir(&lower).unwrap();
    std::fs::create_dir(&upper).unwrap();
    let name = std::ffi::OsStr::from_bytes(b"caf\xe9");
    std::fs::write(upper.join(name), "x").unwrap();
    let out = fcage(&[
        "--changes".as_ref(),
        upper.as_os_str(),
        "--overlay-lower".as_ref(),
        lower.as_os_str(),
        "--json".as_ref(),
    ]);
    assert!(out.status.success(), "{out:?}");
    // Base64 of the four bytes, which a reader takes back exactly.
    assert_eq!(
        document(&out)["changes"][0]["path"],
        serde_json::json!({"base64": "Y2Fm6Q=="})
    );
    // The text quotes it, escaped.
    let text = fcage(&[
        "--changes".as_ref(),
        upper.as_os_str(),
        "--overlay-lower".as_ref(),
        lower.as_os_str(),
    ]);
    assert_eq!(String::from_utf8_lossy(&text.stdout), "A \"caf\\xE9\"\n");
}

#[test]
fn a_change_the_reader_cannot_read_is_marked_in_both_forms() {
    use std::os::unix::fs::PermissionsExt as _;

    if rustix::process::geteuid().is_root() {
        common::require::premise_unmet(
            "root reads a file of mode 000, so nothing is unreadable to it",
        );
        return;
    }
    let dir = common::scratch_dir("fcage-changes-unreadable");
    let (lower, upper) = (dir.join("lower"), dir.join("upper"));
    std::fs::create_dir(&lower).unwrap();
    std::fs::create_dir(&upper).unwrap();
    std::fs::write(lower.join("f"), "same\n").unwrap();
    std::fs::write(upper.join("f"), "same\n").unwrap();
    std::fs::set_permissions(upper.join("f"), std::fs::Permissions::from_mode(0o000)).unwrap();
    let list = |json: bool| {
        let mut args: Vec<&std::ffi::OsStr> = vec![
            "--changes".as_ref(),
            upper.as_os_str(),
            "--overlay-lower".as_ref(),
            lower.as_os_str(),
        ];
        if json {
            args.push("--json".as_ref());
        }
        fcage(&args)
    };
    let (text, json) = (list(false), list(true));
    std::fs::set_permissions(upper.join("f"), std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(text.status.success(), "{text:?}");
    assert_eq!(
        String::from_utf8_lossy(&text.stdout),
        "M \"f\" content,mode unreadable\n"
    );
    assert!(json.status.success(), "{json:?}");
    assert_eq!(
        document(&json),
        serde_json::json!({"changes": [
            {"kind": "modified", "path": "f", "before": "file", "now": "file", "size": 5,
             "differs": ["content", "mode"], "readable": false},
        ]})
    );
}

#[test]
fn apply_changes_prints_what_it_refused_or_wrote_as_one_document() {
    let dir = common::scratch_dir("fcage-apply-changes-json");
    if layers(&dir).is_none() {
        return;
    }
    let (lower, upper) = (dir.join("lower"), dir.join("upper"));
    // A named pipe the run made, which an apply passes over.
    rustix::fs::mknodat(
        rustix::fs::CWD,
        upper.join("pipe"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .expect("the named pipe is made");
    let apply = |extra: &[&str]| {
        let mut args: Vec<&std::ffi::OsStr> = vec![
            "--apply-changes".as_ref(),
            upper.as_os_str(),
            "--overlay-lower".as_ref(),
            lower.as_os_str(),
            "--to".as_ref(),
            lower.as_os_str(),
            "--json".as_ref(),
        ];
        args.extend(extra.iter().map(|arg| std::ffi::OsStr::new(*arg)));
        fcage(&args)
    };

    // A refusal is still a failure, and standard error says so once; the
    // refusals themselves are the document's.
    let refused = apply(&[]);
    assert_eq!(refused.status.code(), Some(125), "{refused:?}");
    assert_eq!(
        document(&refused),
        serde_json::json!({
            "applied": [],
            "skipped": [],
            "refused": [{
                "path": ".envrc",
                "reason": "protected",
                "protected-name": ".envrc",
                "text": "fcage: refused \".envrc\": it touches the name \".envrc\" at any depth",
            }],
        })
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(stderr.contains("nothing was written"), "{stderr}");
    assert!(!lower.join("new").exists(), "nothing is written");

    // What the text says on standard error of a path passed over is the
    // document's too.
    let applied = apply(&[
        "--only", "keep", "--only", "gone", "--only", "new", "--only", "pipe",
    ]);
    assert!(applied.status.success(), "{applied:?}");
    assert!(applied.stderr.is_empty(), "{applied:?}");
    assert_eq!(
        document(&applied),
        serde_json::json!({
            "applied": ["gone", "keep", "new"],
            "skipped": ["pipe"],
            "refused": [],
        })
    );
    assert_eq!(
        std::fs::read_to_string(lower.join("keep")).unwrap(),
        "upper\n"
    );
}

#[test]
fn apply_changes_refuses_a_link_leading_out_unless_told_to_write_it() {
    let dir = common::scratch_dir("fcage-apply-changes-links");
    let (lower, upper) = (dir.join("lower"), dir.join("upper"));
    std::fs::create_dir(&lower).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    std::fs::create_dir(&upper).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", upper.join("out")).unwrap();
    let apply = |extra: &[&str]| {
        let mut args: Vec<&std::ffi::OsStr> = vec![
            "--apply-changes".as_ref(),
            upper.as_os_str(),
            "--overlay-lower".as_ref(),
            lower.as_os_str(),
            "--to".as_ref(),
            lower.as_os_str(),
            "--json".as_ref(),
        ];
        args.extend(extra.iter().map(|arg| std::ffi::OsStr::new(*arg)));
        fcage(&args)
    };

    let refused = apply(&[]);
    assert_eq!(refused.status.code(), Some(125), "{refused:?}");
    assert_eq!(
        document(&refused),
        serde_json::json!({
            "applied": [],
            "skipped": [],
            "refused": [{
                "path": "out",
                "reason": "link-leads-out",
                "link-target": "/etc/passwd",
                "text": "fcage: refused \"out\": it is a symbolic link to \"/etc/passwd\", \
                         which leads out of the target",
            }],
        })
    );
    assert!(std::fs::symlink_metadata(lower.join("out")).is_err());

    let applied = apply(&["--links-leading-out"]);
    assert!(applied.status.success(), "{applied:?}");
    assert_eq!(
        std::fs::read_link(lower.join("out")).unwrap(),
        Path::new("/etc/passwd")
    );
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
