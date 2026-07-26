# Building an orchestrator

A profile is plain data, and composing a profile with per-invocation overrides
is ordinary builder work. Put the two together and a small tool falls out: a
profile-driven orchestrator that keeps a directory of named sandboxes and runs
commands inside them. The library ships one as a worked example.

Where `fcage` takes a single profile file with `--profile`, an orchestrator
keeps a directory of profiles and selects one by name. The profiles are
*groups*: a group describes a sandbox posture — its root filesystem, network,
environment, and mounts — rather than a single application, so many commands
share one group.

```sh
orchestrator run offline -- cargo test
orchestrator run offline -- cargo build
orchestrator run net-dev -- curl https://example.com
```

## Composition

Because a profile is a `CageBuilder`, the orchestrator composes by
deserializing the group profile and then layering builder calls onto it:

- **List overrides extend.** `bind`, `bind_ro`, and `env` add to whatever the
  profile already carries.
- **Scalar overrides replace.** The network posture, working directory, or
  root filesystem given at the prompt replaces the profile's value.
- **The command replaces as a unit.** A group may carry a default command; a
  command given at the prompt replaces it — `clear_args` first, so the new
  command does not inherit the group's arguments, then `command` and `args`.

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let text = std::fs::read_to_string("offline.toml")?;
let mut builder: ferroday_cage::CageBuilder = toml::from_str(&text)?;
// A command from the prompt replaces the group's default as a unit.
builder = builder.clear_args().command("/bin/echo").args(["hello"]);
// An override bind extends the group's mounts.
builder = builder.bind_ro("/etc/hostname", "/host-hostname");
let status = builder.build()?.run()?;
assert!(status.success());
# Ok(())
# }
```

`clear_args` is what makes a unit override possible from a builder alone:
`command` sets the program but leaves the arguments in place, and `arg` and
`args` append, so a consumer holding a deserialized profile clears the profile's
arguments before setting the new command. The composition rules are the same
ones [Profiles](profiles.md) documents for `fcage`.

## Running the example

The example lives at `crates/ferroday-cage/examples/orchestrator.rs`, with a few
sample group profiles beside it. It builds with the `serde` feature:

```sh
cargo run --example orchestrator --features serde -- --help
```

The profile directory comes from `--profiles DIR` or the
`FERRODAY_CAGE_PROFILES` environment variable. `list` names the groups it finds;
`run` launches a command in one:

```sh
PROFILES=crates/ferroday-cage/examples/orchestrator-profiles

# The groups the directory offers:
cargo run --example orchestrator --features serde -- --profiles "$PROFILES" list

# A command in the "offline" group, against a root filesystem of your own:
cargo run --example orchestrator --features serde -- \
    --profiles "$PROFILES" run offline --rootfs /srv/rootfs/alpine -- /bin/echo hello
```

The sample profiles name a root filesystem at `/srv/rootfs/alpine`; `--rootfs`
overrides it, or edit the profile. The command's exit code becomes the
orchestrator's, so it composes into scripts like any other launcher.

## A group profile

A group profile is a sandbox specification — the format [Profiles](profiles.md)
documents in full. The sample `offline` group denies the network outright and
starts in a tmpfs working directory:

```toml
network = "none"
hostname = "offline"
workdir = "/tmp"

[env]
LANG = "C.UTF-8"
```

Grouping by posture rather than by application is what lets a handful of
profiles serve a whole workflow: an `offline` group for hermetic work, a
`net-dev` group for commands that fetch, a `builder` group with a scratch mount
and a default command. Adding a group is dropping a `.toml` file in the
directory.
