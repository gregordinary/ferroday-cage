//! Integration tests for JSON in and out of `fcage`'s modes: a profile written
//! in JSON, and `--json` on the listings whose text is a TOML document.
//!
//! `--changes`' and `--apply-changes`' documents are tested in
//! `tests/changes.rs`, beside their text.

mod common;

use std::process::{Command, Output, Stdio};
use std::time::Duration;

/// The built binary under test.
const FCAGE: &str = env!("CARGO_BIN_EXE_fcage");

/// How long one run may take before its test fails.
const PATIENCE: Duration = Duration::from_secs(60);

/// Runs `fcage` with `args`, standard input null and the other two captured.
fn fcage(args: &[&str]) -> Output {
    common::run_bounded(
        Command::new(FCAGE)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        PATIENCE,
    )
}

/// What a run that succeeded printed: the TOML document it printed as JSON's
/// data, or the JSON document it printed, which is a line of its own.
fn printed(output: &Output, json: bool) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout.clone()).expect("the listing is UTF-8");
    if json {
        let line = stdout
            .strip_suffix('\n')
            .expect("the document ends its line");
        assert!(!line.contains('\n'), "one line: {stdout}");
        serde_json::from_str(line).expect("the document is JSON")
    } else {
        let table: toml::Table = stdout.parse().expect("the listing is TOML");
        serde_json::to_value(table).expect("TOML's data is JSON's")
    }
}

#[test]
fn the_host_report_in_json_is_its_toml_document() {
    let text = printed(&fcage(&["--host-report"]), false);
    let json = printed(&fcage(&["--host-report", "--json"]), true);
    assert_eq!(text, json);
    assert!(json["user-namespaces"]["available"].is_boolean(), "{json}");
}

#[test]
fn the_resolved_inputs_in_json_are_their_toml_document() {
    let args = [
        "--print-resolved",
        "--host-rootfs",
        "--netstack",
        "--netstack-allow",
        "example.com:443",
        "--forward-loopback",
        "8080",
        "127.0.0.1:9",
        "--timeout",
        "30",
        "--setenv",
        "GREETING",
        "hello",
        "--",
        "/bin/true",
    ];
    let text = printed(&fcage(&args), false);
    let json = printed(&fcage(&[&["--json"][..], &args].concat()), true);
    assert_eq!(text, json);
    assert_eq!(json["env"]["GREETING"], "hello", "{json}");
    assert_eq!(json["fcage"]["timeout"], 30.0, "{json}");
    assert_eq!(
        json["fcage"]["netstack"]["allow"][0], "example.com:443",
        "{json}"
    );

    // A restriction's resolved inputs, the other builder.
    let args = [
        "--restrict",
        "--landlock-ro",
        "/usr",
        "--print-resolved",
        "/bin/true",
    ];
    let text = printed(&fcage(&args), false);
    let json = printed(&fcage(&[&["--json"][..], &args].concat()), true);
    assert_eq!(text, json);
}

#[test]
fn a_json_profile_through_a_descriptor_resolves_as_its_toml_twin_does() {
    let dir = common::scratch_dir("fcage-json-profile");
    let toml_profile = dir.join("profile.toml");
    std::fs::write(
        &toml_profile,
        "host-rootfs = true\ncommand = \"/bin/sh\"\nargs = [\"-c\", \"exit 3\"]\n\
         hostname = \"twin\"\n\n[env]\nGREETING = \"hello\"\n\n\
         [netstack]\nallow = [\"example.com:443\"]\n",
    )
    .expect("the profile is written");
    let toml_profile = toml_profile.to_str().expect("a UTF-8 scratch path");
    let from_toml = printed(
        &fcage(&[
            "--profile",
            toml_profile,
            "--netstack",
            "--print-resolved",
            "--json",
        ]),
        true,
    );

    // The shell hands fcage the profile on descriptor 3, from a pipe, so
    // there is no file to name.
    let json_profile = r#"{"host-rootfs": true, "command": "/bin/sh", "args": ["-c", "exit 3"],
        "hostname": "twin", "env": {"GREETING": "hello"},
        "netstack": {"allow": ["example.com:443"]}}"#;
    let script = format!(
        "exec {FCAGE} --profile /dev/fd/3 --netstack --print-resolved --json 3<&0 </dev/null"
    );
    let mut child = common::spawn_grouped(
        Command::new("/bin/sh")
            .args(["-c", &script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    {
        use std::io::Write as _;
        let mut stdin = child.stdin.take().expect("the shell's input");
        stdin
            .write_all(json_profile.as_bytes())
            .expect("the profile is written");
    }
    let from_json = printed(&common::finish_bounded(child, PATIENCE), true);
    assert_eq!(from_toml, from_json);
    assert_eq!(from_json["hostname"], "twin", "{from_json}");
}
