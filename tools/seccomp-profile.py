#!/usr/bin/env python3
"""Add the syscalls a launch makes to a container runtime's seccomp profile.

A container runtime's default seccomp profile refuses the syscalls a sandbox is
built from: creating namespaces, mounting, pivoting into a new root, and a
session keyring of its own. `tools/seccomp-additions.toml` lists them, each with
what the launch makes it for. This reads the default profile the operator's
runtime uses and writes it back with one rule more: one that allows every
addition the profile does not already allow outright. It reads moby's format,
which Docker, Podman and CRI-O take, and the OCI runtime specification's, which
containerd takes, since both keep their rules in one `syscalls` list.

An addition the profile names in a rule of another action, such as an explicit
refusal, is taken out of that rule, whether the rule holds for every call or
only under its conditions. A profile naming one syscall under two unconditional
actions is one a runtime will not load, and a refusal conditioned on an argument
or on a capability is aimed at exactly the calls a launch makes: an `unshare`
creating a user namespace, by a container without `CAP_SYS_ADMIN`. That holds
whatever the profile's default action: a profile that allows what it does not
name can still refuse an addition by name, and once the refusal is gone the
default allows it, so no rule is added. A rule that allows an addition under
conditions, such as only to a container holding a capability, is left as it
is, beside the rule that allows it outright. Everything else the profile says is
unchanged, so the result refuses whatever the runtime's default refuses, except
these.

Usage:

    python3 tools/seccomp-profile.py DEFAULT.json > PROFILE.json
    python3 tools/seccomp-profile.py --self-test

The script reads the profiles in `CASES` before any other, and refuses to write
one where it gets a case wrong. `--self-test` reads only those.

DEFAULT.json is the runtime's default profile, such as moby's `default.json`.
The result is what Docker's `--security-opt seccomp=PROFILE.json` and a
Kubernetes `Localhost` seccomp profile take.
"""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path

ADDITIONS = Path(__file__).resolve().parent / "seccomp-additions.toml"

ALLOW = "SCMP_ACT_ALLOW"


def additions() -> list[str]:
    """The syscall names the additions file lists, in its order."""
    with ADDITIONS.open("rb") as file:
        return list(tomllib.load(file))


def unconditional(rule: dict) -> bool:
    """Whether a rule applies to every call of the syscalls it names."""
    return not (rule.get("args") or rule.get("includes") or rule.get("excludes"))


def extend(profile: dict, names: list[str]) -> dict:
    """The profile, with `names` allowed outright.

    Each of `names` is taken out of every rule of another action, conditional
    or not. Where the default action refuses, one rule more allows those no
    unconditional rule already allows. Where it allows, they are allowed once
    nothing names them otherwise, and no rule is added.
    """
    allowed_by_default = profile.get("defaultAction") == ALLOW
    rules = []
    allowed = set()
    for rule in profile.get("syscalls", []):
        rule_names = rule.get("names", [])
        if rule.get("action") == ALLOW:
            if unconditional(rule):
                allowed.update(rule_names)
        else:
            rule_names = [name for name in rule_names if name not in names]
            if not rule_names:
                continue
            rule = {**rule, "names": rule_names}
        rules.append(rule)
    missing = [name for name in names if name not in allowed]
    if missing and not allowed_by_default:
        rules.append(
            {
                "names": missing,
                "action": ALLOW,
                "comment": "The syscalls a ferroday-cage launch makes: "
                "tools/seccomp-additions.toml.",
            }
        )
    return {**profile, "syscalls": rules}


# Profiles the extension must get right: each a name, a profile, the additions,
# and the rules the result holds.
CASES = [
    (
        "an unconditional refusal in a profile that allows by default",
        {
            "defaultAction": ALLOW,
            "syscalls": [
                {"names": ["keyctl", "reboot"], "action": "SCMP_ACT_ERRNO"},
            ],
        },
        ["keyctl", "mount"],
        [{"names": ["reboot"], "action": "SCMP_ACT_ERRNO"}],
    ),
    (
        "a refusal conditioned on an argument, in either default",
        {
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [
                {"names": ["read"], "action": ALLOW},
                {
                    "names": ["unshare", "personality"],
                    "action": "SCMP_ACT_ERRNO",
                    "args": [{"index": 0, "value": 268435456, "op": "SCMP_CMP_MASKED_EQ"}],
                },
            ],
        },
        ["unshare"],
        [
            {"names": ["read"], "action": ALLOW},
            {
                "names": ["personality"],
                "action": "SCMP_ACT_ERRNO",
                "args": [{"index": 0, "value": 268435456, "op": "SCMP_CMP_MASKED_EQ"}],
            },
            {"names": ["unshare"], "action": ALLOW},
        ],
    ),
    (
        "a refusal conditioned on a capability, and a grant conditioned on one",
        {
            "defaultAction": ALLOW,
            "syscalls": [
                {
                    "names": ["mount"],
                    "action": "SCMP_ACT_ERRNO",
                    "excludes": {"caps": ["CAP_SYS_ADMIN"]},
                },
                {
                    "names": ["setns"],
                    "action": ALLOW,
                    "includes": {"caps": ["CAP_SYS_ADMIN"]},
                },
            ],
        },
        ["mount", "setns"],
        [
            {
                "names": ["setns"],
                "action": ALLOW,
                "includes": {"caps": ["CAP_SYS_ADMIN"]},
            },
        ],
    ),
]


def self_test() -> list[str]:
    """Every case the extension gets wrong, described."""
    failures = []
    for name, profile, names, expected in CASES:
        got = [
            {key: value for key, value in rule.items() if key != "comment"}
            for rule in extend(profile, names)["syscalls"]
        ]
        if got != expected:
            failures.append(f"{name}: wrote {got!r}, expected {expected!r}")
    return failures


def main(argv: list[str]) -> int:
    problems = self_test()
    for problem in problems:
        print(f"seccomp-profile.py gets a case wrong: {problem}", file=sys.stderr)
    if problems:
        return 1
    if argv[1:] == ["--self-test"]:
        print(f"{len(CASES)} profiles extended as expected.")
        return 0
    if len(argv) != 2 or argv[1].startswith("-"):
        print(
            "usage: python3 tools/seccomp-profile.py DEFAULT.json > PROFILE.json",
            file=sys.stderr,
        )
        return 2
    with open(argv[1], "rb") as file:
        profile = json.load(file)
    if not isinstance(profile, dict) or not isinstance(profile.get("syscalls", []), list):
        print(f"{argv[1]}: not a seccomp profile", file=sys.stderr)
        return 1
    json.dump(extend(profile, additions()), sys.stdout, indent="\t")
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
