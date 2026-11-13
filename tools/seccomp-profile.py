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

An addition the profile names in a rule of another action and no conditions,
such as an explicit refusal, is taken out of that rule, since a profile naming
one syscall under two unconditional actions is one a runtime will not load. A
rule that grants an addition only to a container holding a capability is left as
it is. Everything else the profile says is unchanged, so the result refuses
whatever the runtime's default refuses, except these.

Usage:

    python3 tools/seccomp-profile.py DEFAULT.json > PROFILE.json

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
    """The profile, with `names` allowed outright."""
    if profile.get("defaultAction") == ALLOW:
        # A profile that allows what it does not name refuses none of them.
        return profile
    rules = []
    allowed = set()
    for rule in profile.get("syscalls", []):
        rule_names = rule.get("names", [])
        if unconditional(rule):
            if rule.get("action") == ALLOW:
                allowed.update(rule_names)
            else:
                rule_names = [name for name in rule_names if name not in names]
                if not rule_names:
                    continue
                rule = {**rule, "names": rule_names}
        rules.append(rule)
    missing = [name for name in names if name not in allowed]
    if missing:
        rules.append(
            {
                "names": missing,
                "action": ALLOW,
                "comment": "The syscalls a ferroday-cage launch makes: "
                "tools/seccomp-additions.toml.",
            }
        )
    return {**profile, "syscalls": rules}


def main(argv: list[str]) -> int:
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
