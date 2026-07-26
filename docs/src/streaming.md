# Streaming output

By default the command inherits the caller's standard streams: output goes
wherever the caller's goes, and nothing is captured. For programmatic
consumption, a launch can instead capture the command's standard output and
standard error — whole, with [`output`], or live, with an observer.

## Collecting the whole output

[`output`] runs the command and returns its exit status together with
everything it wrote, the shape `std::process::Command::output` has:

```rust,no_run
use ferroday_cage::Cage;

fn main() -> ferroday_cage::Result<()> {
    let result = Cage::builder()
        .rootfs("/srv/rootfs/alpine")
        .command("/bin/sh")
        .args(["-c", "echo out; echo err >&2"])
        .build()?
        .output()?;

    assert!(result.status.success());
    assert_eq!(result.stdout, b"out\n");
    assert_eq!(result.stderr, b"err\n");
    Ok(())
}
```

`stdout` and `stderr` are raw bytes: not lines, and not guaranteed to be
UTF-8. `status` is the same [`ExitStatus`] every other launch method returns,
so a non-zero exit is data here too.

What `output` keeps is unbounded, which is the right default for a command
whose output the caller controls and the wrong one for a command whose output
it does not. A command that writes without stopping is held entirely in
memory. For model-generated code, an untrusted build, or anything else that
might not stop, stream through an observer that caps what it retains — the
next section shows one — and pair it with a deadline from [the process
model](process-model.md).

## The observer

An observer implements the `Observer` trait: a callback per stream, each
with an empty default body, receiving raw byte chunks as they are read.
Chunks are not lines and not necessarily UTF-8; their boundaries carry no
meaning. An observer that wants lines assembles them itself.

```rust,no_run
use ferroday_cage::{Cage, Observer};

#[derive(Default)]
struct Log {
    errors: Vec<u8>,
}

impl Observer for Log {
    fn stdout(&mut self, chunk: &[u8]) {
        print!("{}", String::from_utf8_lossy(chunk));
    }
    fn stderr(&mut self, chunk: &[u8]) {
        self.errors.extend_from_slice(chunk);
    }
}

fn main() -> ferroday_cage::Result<()> {
    let cage = Cage::builder()
        .rootfs("/srv/rootfs/alpine")
        .command("/bin/sh")
        .args(["-c", "echo out; echo err >&2"])
        .build()?;

    let mut log = Log::default();
    let status = cage.run_with(&mut log)?;
    assert!(status.success());
    assert_eq!(log.errors, b"err\n");
    Ok(())
}
```

`run_with` is the blocking convenience; `spawn_with` returns the running
handle with the observer attached for the handle's lifetime.

### Capping what you keep

An observer decides for itself how much to retain, which is what makes it the
right tool for a command whose output volume the caller does not control:

```rust,no_run
use ferroday_cage::{Cage, Observer};

/// Keeps at most `LIMIT` bytes of each stream and counts the rest.
struct Capped {
    stdout: Vec<u8>,
    dropped: usize,
}

const LIMIT: usize = 1 << 20;

impl Observer for Capped {
    fn stdout(&mut self, chunk: &[u8]) {
        let room = LIMIT.saturating_sub(self.stdout.len());
        let (kept, spilled) = chunk.split_at(chunk.len().min(room));
        self.stdout.extend_from_slice(kept);
        self.dropped += spilled.len();
    }
}

fn main() -> ferroday_cage::Result<()> {
    let mut capped = Capped { stdout: Vec::new(), dropped: 0 };
    let cage = Cage::builder()
        .rootfs("/srv/rootfs/alpine")
        .command("/usr/bin/analyze")
        .build()?;
    cage.run_with(&mut capped)?;
    if capped.dropped > 0 {
        eprintln!("dropped {} bytes past the cap", capped.dropped);
    }
    Ok(())
}
```

The command still runs to completion — the pump keeps draining the pipes, so
nothing blocks — but the caller's memory use is bounded by `LIMIT` regardless
of what the command writes. Bounding the *time* as well is
[`wait_deadline`](process-model.md)'s job, and bounding what the command can
consume while it runs is [`rlimit`](hardening.md#resource-limits)'s.

## Launch progress

Alongside the command's output, an observer receives the library's own
launch milestones through `progress`, a third callback with an empty default
body. Each launch reports a `Progress` value at three points, in order:

- **`Launching`** — the sandbox's channels are created and its launch stage
  is forked.
- **`Supervised`** — the namespaces exist and the supervisor is published.
  For a direct launch the command is about to run; for a held launch (the
  [userspace-networking](userspace-networking.md) seam) this is the gate,
  where a network stack attaches before the command runs.
- **`Executing`** — the command has been executed and is now running.

Milestones are the library's own progress, not the command's output, so an
observer can drive a launch log or a progress display without parsing the
streams. They are delivered on the calling thread during the launch itself,
before any captured output flows, and `Progress` is `#[non_exhaustive]` so
finer milestones can arrive without breaking an existing observer.

## How delivery works

The library is synchronous and spawns no threads. Captured output is pumped
inside the blocking calls — `run_with` itself, or the handle's `wait`,
`wait_deadline`, and `wait_timeout` — with a single `poll` over the capture
pipes, on the calling thread. That has three practical consequences:

- The observer runs on the caller's thread, so it can borrow freely from
  the caller's state; no synchronization is imposed.
- Output flows while a wait is in progress. Between `spawn_with` and the
  first wait, output accumulates in the pipes' kernel buffers; a command
  that outruns them blocks writing until the caller pumps, the ordinary
  pipe discipline.
- A deadline wait delivers everything produced before the deadline, even
  when it returns with the command still running — and the wait after a
  [`kill`] drains what the command wrote before the kill.

Capture covers the whole sandbox: the command's child processes inherit its
streams, so their output arrives interleaved with the command's own, as it
would in a terminal.

That inheritance also sets capture's endpoint. A wait completes once the
command's outcome is known and both captured streams have reached
end-of-file. Under the default PID namespace, the teardown at command exit
closes every remaining copy of the streams promptly. With
`pid_namespace(false)` there is no teardown: a descendant the command
leaves behind holds the streams open, and an unbounded wait — `run_with`,
or the handle's `wait` — blocks until the last holder closes them. A
caller combining `pid_namespace(false)` with capture should prefer
`wait_deadline` or `wait_timeout` when the command may leave such
descendants behind.

## Standard input

Stdin has a disposition of its own, independent of capture:

- **`Stdin::Inherit`** (default) — the command reads the caller's standard
  input.
- **`Stdin::Null`** — the command reads `/dev/null`: immediate end-of-file,
  for batch runs that must not compete with the caller for input.
- **[`Stdin::from_fd`]** — the command reads a descriptor the caller supplies.

```rust,no_run
# use ferroday_cage::{Cage, Stdin};
# fn main() -> ferroday_cage::Result<()> {
let cage = Cage::builder()
    .rootfs("/srv/rootfs/alpine")
    .stdin(Stdin::Null)
    .command("/usr/bin/build")
    .build()?;
# Ok(())
# }
```

### Feeding the command input

`Stdin::from_fd` takes anything readable — the read end of a pipe the caller
writes, an open file, a pseudoterminal replica — and duplicates it onto the
command's file descriptor 0. It is how a command is handed input that wants to
be a stream rather than a file:

```rust,no_run
use std::io::Write;

use ferroday_cage::{Cage, Stdin};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (reader, mut writer) = std::io::pipe()?;
    let cage = Cage::builder()
        .rootfs("/srv/rootfs/alpine")
        .stdin(Stdin::from_fd(reader.into()))
        .command("/usr/bin/python3")
        .build()?;

    // Write the input and close the write end, so the command sees
    // end-of-file rather than waiting for more.
    writer.write_all(b"print(1 + 1)\n")?;
    drop(writer);

    let result = cage.output()?;
    assert_eq!(result.stdout, b"2\n");
    Ok(())
}
```

Two things to know about the shape:

- **Write, then close, then wait.** A pipe holds 64 KiB by default. Writing
  more than that from the same thread that later waits deadlocks: the write
  blocks for a reader, and nothing is draining the command's output meanwhile.
  For input that fits, write it and close the write end before waiting, as
  above. For input that does not, drive the write from another thread while
  the main thread pumps.
- **The descriptor is shared, not consumed.** A `Cage` is a frozen plan that
  launches any number of times, so every launch wires the same descriptor and
  the second launch reads whatever the first left. A cage feeding distinct
  input per launch is built per launch.

There is no conversational form on top of this — no way to write a statement,
read the reply, and write another to a process that is already running, and no
pseudoterminal the library sets up for you. A caller can build the first
half itself with two pipes and a thread; the second needs a PTY the caller
opens and passes here as the stdin descriptor. An interactive model with the
library's own PTY handling is a later, additive entry point.

[`kill`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Running.html#method.kill
[`output`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Cage.html#method.output
[`ExitStatus`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.ExitStatus.html
[`Stdin::from_fd`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.Stdin.html#method.from_fd
