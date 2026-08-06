# A terminal of the sandbox's own

A sandboxed command can be given a pseudoterminal allocated for it: `isatty` is
true on all three of its standard streams, a full-screen program behaves,
`/dev/tty` resolves, and a shell inside the sandbox runs jobs of its own —
against a terminal the caller does not share.

That last part is the point. [Streaming output](streaming.md) describes the two
postures available without it, and both are compromises. Inheriting standard
input makes an interactive command work, but everything that works there works
by reaching into the caller's session: the sandbox can read what is typed at the
caller's terminal, change its settings, and take its foreground process group.
Not inheriting it closes that, and nothing that wants a terminal works. A
terminal of the sandbox's own gives both.

## Starting one

A terminal is a *launch mode* rather than builder state, so it is passed to the
launch and hands back a live resource:

```rust,no_run
use ferroday_cage::{Cage, Terminal};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cage = Cage::builder()
        .rootfs("/srv/rootfs/alpine")
        .command("/bin/sh")
        .env("TERM", "xterm-256color")
        .build()?;

    let (mut running, mut pty) = cage.spawn_terminal(&Terminal::new())?;
    std::io::copy(&mut pty, &mut std::io::stdout())?;
    let status = running.wait()?;
    assert!(status.success());
    Ok(())
}
```

`Terminal` states the window size and nothing else: `Terminal::new()` is 80
columns by 24 rows, a stated constant rather than anything read from the host,
and `Terminal::new().size(rows, cols)` says otherwise. The replica is wired onto
the command's file descriptors 0, 1 and 2 — a terminal is one stream — and the
launch owns its session, so the pseudoterminal is the sandbox's controlling
terminal whatever the standard-input disposition would otherwise have decided.

`Pty` is the caller's end. It reads what the sandbox wrote to its terminal and
writes what the sandbox reads as typed input.

Three things are the caller's to supply, because the library reads nothing from
the host:

- **`TERM`** is an environment variable rather than terminal configuration, so
  set it with `.env("TERM", ...)`. Without one, `vim` fails on first use.
- **The size**, if the caller has a better answer than 80x24 — and afterwards,
  because a terminal's size changes over the life of a session and no
  launch-time constant can track it. See [Resizing](#resizing).
- **The caller's own terminal**, which an interactive session must put into raw
  mode. See [The relay](#the-relay).

## Draining, and the one order that deadlocks

The primary's buffer is a few kilobytes. A command that writes more than that
blocks, so a caller that waits without reading deadlocks — which is why `run`
and `output` are not terminal entry points at all. When an unbounded `wait()`
starts, the `Pty` is in one of three states:

- **Drained to end-of-file** — safe. End-of-file means every replica is closed
  and the command is already gone.
- **Dropped** — safe. After the hangup the command's writes fail with `EIO`
  rather than block, so a caller that has dropped the primary owes the wait no
  drain.
- **Held and unread** — the deadlocking case.

This is the same obligation `Stdio::from_fd` already carries for a pipe, with
the same answer: where the caller owns both ends, the feed and the drain are the
caller's, and a wait that must be bounded is bounded.

**A caller that sends no input** drains to end-of-file and then waits. That
terminates on its own — the example above is the whole pattern, and its second
line is the part worth understanding.

**An interactive caller** needs both directions at once, which needs
concurrency: writes to the primary block too once its input buffer fills, so a
large paste into a command that is not reading stalls a relay that writes from
the thread it also reads on. Two threads is the right minimum — a reader beside
the main thread in the wait:

```rust,no_run
use std::io::Read as _;
use std::sync::Arc;

use ferroday_cage::{Cage, Terminal};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cage = Cage::builder()
        .rootfs("/srv/rootfs/alpine")
        .command("/bin/sh")
        .build()?;
    let (mut running, pty) = cage.spawn_terminal(&Terminal::new())?;
    let pty = Arc::new(pty);

    let reader = {
        let pty = Arc::clone(&pty);
        std::thread::spawn(move || {
            // `Read` is implemented for `&Pty`, so the thread borrows through
            // the `Arc` rather than taking the terminal away from the main
            // thread — which is what lets the size still be set from here.
            let mut out = std::io::stdout();
            std::io::copy(&mut &*pty, &mut out)
        })
    };

    // ... write to `&*pty`, resize it on SIGWINCH ...

    let status = running.wait()?;
    reader.join().expect("the reader thread completes")?;
    println!("exited with {status:?}");
    Ok(())
}
```

`Read` and `Write` are implemented for `&Pty` as well as for `Pty`, and `resize`
takes `&self`, which is what makes that shape possible at all. Wrapping the
`Pty` in a mutex instead is worse: the reader holds the lock while blocked in
`read`, so a resize lands only when the sandbox next produces output.

## Resizing

`Pty::resize` sets the window size and delivers `SIGWINCH` to the sandbox's
foreground process group, which is how a full-screen program learns to redraw.
An interactive caller calls it on every `SIGWINCH` of its own, with the size its
own terminal reports.

`Pty::size` reads the size back.

## Closing input

There is no way to close the write side of a pseudoterminal. End-of-file is sent
as the `VEOF` character — `^D` in the baseline below — and that is a line
discipline behavior rather than a property of the descriptor: it holds only
while the replica is in canonical mode. A program that has put its terminal in
raw mode, an editor or a shell reading a line itself, receives `VEOF` as the
literal byte `0x04` and does whatever it does with it, and even in canonical
mode `VEOF` on a partial line flushes that line rather than signalling
end-of-file, so a strict end-of-input takes it twice.

A caller that needs end-of-input to be unambiguous **drops the `Pty`**, which
hangs the terminal up and cannot be mistaken for data, or does not use a
terminal at all — `Stdio::from_fd` on a pipe closes for real.

Dropping the primary is also how a session is ended deliberately: the kernel
sends `SIGHUP` to the sandbox's foreground process group. Dropping it early ends
the session early, which is why it normally outlives the wait.

## The termios baseline

The line discipline is stated by the library rather than inherited from
anything, so it is a promise rather than whatever the kernel happened to
default to. It is field for field the kernel's own `tty_std_termios`:

| Group | Flags |
| --- | --- |
| Input | `ICRNL`, `IXON` |
| Output | `OPOST`, `ONLCR` |
| Control | `B38400`, `CS8`, `CREAD`, `HUPCL` |
| Local | `ISIG`, `ICANON`, `ECHO`, `ECHOE`, `ECHOK`, `ECHOCTL`, `ECHOKE`, `IEXTEN` |
| Characters | `VINTR` `^C`, `VQUIT` `^\`, `VERASE` `DEL`, `VKILL` `^U`, `VEOF` `^D`, `VSTART` `^Q`, `VSTOP` `^S`, `VSUSP` `^Z`, `VREPRINT` `^R`, `VDISCARD` `^O`, `VWERASE` `^W`, `VLNEXT` `^V` |
| Reads | `VMIN` 1, `VTIME` 0; `VEOL` and `VEOL2` unset |

It governs line-mode behavior only. A full-screen application calls `tcsetattr`
on the replica itself and takes the terminal from there.

One consequence is visible immediately: `OPOST | ONLCR` means a `\n` the command
writes arrives at the primary as `\r\n`. **A terminal rewrites what the sandbox
wrote**, so no reproducibility-sensitive path should ever use one. None can:
a terminal arrives only from `spawn_terminal`, which captures nothing and takes
no observer, so no capturing pipeline — `output`, an export, provisioning — can
compose one.

## What does not work

**Path resolution for the terminal fails; descriptor operations work.** The
pseudoterminal is allocated on the host rather than in the sandbox's own
`devpts` instance, which is what keeps the feature small. The cost is that the
replica's device node lives in the host's `devpts` while the sandbox's
`/dev/pts` is a private instance, so `ttyname` fails inside the sandbox.
Affected: `tty(1)`, `who`, and `GPG_TTY`, which gpg populates from `tty` and
pinentry then opens.

Not affected: `isatty`, `tcgetattr`, `tcsetattr`, the line discipline, the
window size, job control, and `/dev/tty` — which is the character device `5:0`,
a per-process redirect to the opener's own controlling terminal, so what it
yields inside a terminal launch is the sandbox's own terminal.

The private `devpts` stays mounted, so nested allocation — `tmux`, `script`,
`sshd`, Python's `pty` — works normally and still sees no host pseudoterminal
but its own. The sandbox holds exactly one descriptor to one host
pseudoterminal: its own, whose only reader is the caller. `TIOCSTI` on it
injects into its own input queue.

**A terminal launch reports no launch milestones.** The observer is the progress
sink as well as the capture sink, and the terminal entry points take no
observer, so `Progress::Launching`, `Supervised`, and `Executing` go
unwitnessed. For an interactive session the loss is small: a human is watching
the terminal itself.

## Refusals

A terminal is all three standard streams, so a sandbox that directs one of them
somewhere else has asked for two different things. The launch refuses it:

```rust,no_run
# use ferroday_cage::{Cage, ConfigError, Error, Stdio, Terminal};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let cage = Cage::builder()
    .rootfs("/srv/rootfs/alpine")
    .command("/bin/sh")
    .stdout(Stdio::Null)
    .build()?;

let refused = cage.spawn_terminal(&Terminal::new());
assert!(matches!(
    refused.err(),
    Some(Error::Config(ConfigError::StreamAttachmentConflict { .. })),
));
# Ok(())
# }
```

`Stdio::Inherit` — the default on all three — states no *destination*, so it is
not a contradiction: the launch is free to supply one. Only `Stdio::Null` and
`Stdio::from_fd` name a destination of their own.

A profile cannot describe a terminal, and `resolved_inputs()` does not report
one. Both follow from the same boundary: the record reports the plan — what
every launch of the cage shares — and a launch-time attachment supersedes it at
the one call site that made it. A terminal describes how the caller attaches
rather than what the sandbox is.

## With the network seam

`Cage::spawn_pending_terminal` is the composition an interactive session
usually wants — a shell with outbound networking:

```rust,no_run
# use ferroday_cage::{Cage, Terminal};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let cage = Cage::builder().rootfs("/r").command("/bin/sh").build()?;
let (pending, mut pty) = cage.spawn_pending_terminal(&Terminal::new())?;
// ... attach a stack to /proc/<pending.netns_pid()>/ns/net ...
let mut running = pending.proceed()?;
# let _ = (&mut pty, &mut running);
# Ok(())
# }
```

The primary comes back beside the `Pending` rather than out of `proceed`,
because the pseudoterminal is allocated before the fork and the gate sits after
its controlling terminal is established. Nothing writes to the terminal while
the launch is held, so the caller attaches its stack and proceeds with the
primary already in hand.

## The restriction fallback

`Restriction::spawn_terminal` gives the [restriction
fallback](restriction-fallback.md) the same interactive story: a host-allocated
pseudoterminal needs no `devpts` instance, so nothing about it depends on the
namespaces a restriction does not have.

## At a shell prompt

`fcage --terminal` is the whole of this from the command line:

```sh
fcage --rootfs /srv/rootfs/alpine --terminal -- /bin/sh
```

It allocates the terminal, copies *this* terminal's current size into it, and
relays the two. `TERM` passes through as it does for every `fcage` run, so
`--setenv TERM ...` overrides it. It composes with `--restrict` and with
`--netstack`; `--terminal` with `--stdin null` is refused at parse time, naming
both flags. From a script, where `fcage`'s own input is not a terminal, it
degrades to a plain byte relay around a sandbox that still has a real terminal
of its own, at 80x24.

## The relay

`fcage`'s relay is the reference implementation for a consumer building the same
thing. It lives in one self-contained module,
[`crates/ferroday-cage-cli/src/terminal.rs`][relay], and this is its design.

The library deliberately does not do any of it. Whoever sets raw mode must
restore it on normal exit, on error, on panic, on `SIGINT`/`SIGTERM`/`SIGQUIT`,
and on a leaked handle — and a library that can leave the user's shell unusable
is a worse failure than the one this feature started from. A binary can own
process-global state; a library cannot.

**Raw mode is entered last.** The order is: parse, build, spawn the terminal
launch, and only then — immediately before the relay loop — save the caller's
termios and enter raw mode. Every failure before that point exits with the
terminal untouched, which shrinks the restoration problem to one region with
known exits. On the way out the order reverses: the loop ends, the terminal is
restored, and only then are diagnostics printed and the exit status mapped.

**One restorer, three triggers.** The original termios is saved into a
process-global before raw mode is entered, and restoring replays it with a
flush. Restoring is idempotent, so every path may call it without coordination.
The flush is deliberate: input pending at restoration is raw bytes typed at a
session that no longer exists, and discarding them beats letting half an escape
sequence land at the caller's prompt. Three triggers cover every exit the
process can observe:

- a guard in the relay's frame, dropped on normal exit, on error, and on panic
  unwind;
- a panic hook, installed once, that restores *before* delegating to the default
  hook — with `OPOST` off a backtrace prints stair-stepped, so restoration must
  precede the message, which a drop alone cannot arrange;
- the stop path below, which restores before the process stops and re-enters raw
  mode when it continues.

`SIGKILL` and `SIGSTOP` are uncatchable and out of scope, with the same honesty
the leaked-handle case gets: the remedy is `stty sane`, and no process can
promise otherwise. Restoration means *termios*. Screen contents — an alternate
screen left active, a hidden cursor — were written by the sandboxed program
through the relay verbatim and belong to it, exactly as `ssh` treats them.

**Signals are data.** The relay blocks `SIGWINCH`, `SIGINT`, `SIGTERM`,
`SIGHUP`, `SIGQUIT`, `SIGTSTP`, and `SIGCONT` before anything else starts — in
particular before any thread the run may create, since a thread inherits the
creating thread's mask — and reads them as one channel of its poll loop, from a
signal descriptor. No relay code runs in signal context: there are no handlers,
no async-signal-safety reasoning, and no shared flags.

- **`SIGWINCH`** — read the caller terminal's size and call `Pty::resize`.
- **`SIGINT`, `SIGTERM`, `SIGHUP`, `SIGQUIT`** — forward: terminate the sandbox
  and keep relaying. The sandbox's exit closes the replicas, end-of-file ends
  the loop, and restoration happens on the normal path. A second such signal
  escalates to a kill. These arrive only from *outside*: in raw mode a typed
  `^C` is a byte the relay forwards, which the sandbox's own line discipline
  turns into the sandbox's own `SIGINT`, delivered to the sandbox's own
  foreground process group. Forwarding the four from outside is what keeps the
  caller's shell managing `fcage` as one job and `fcage` passing that on.
- **`SIGTSTP`** — restore the terminal, then stop with a self-directed
  `SIGSTOP`.
- **`SIGCONT`** — re-enter raw mode and re-read the window size, which may have
  changed while stopped. The discipline `less` follows.

**The loop.** One thread, one poll: the caller's standard input, the primary,
and the signal descriptor. The primary is set non-blocking so a large paste
cannot stall the loop; bytes that do not fit yet wait in a pending buffer behind
`POLLOUT`, and standard input is left unwatched while that buffer is occupied,
so it cannot grow without bound. End-of-file on the caller's standard input
sends `VEOF` to the primary — read from the replica's *current* settings rather
than assumed, since a program inside is free to have changed it — and retires
that channel. End-of-file on the primary ends the loop. `--timeout` is the poll
deadline, answered with the same terminate-then-kill escalation the
non-terminal path uses.

When `fcage`'s own standard input is not a terminal, raw mode, the size copy,
and resize are all skipped and the relay still relays. A terminal that reports a
size of zero in either dimension is treated as reporting none: that is what a
pseudoterminal nobody has sized says, and passing it through would hand the
sandbox a terminal that answers "no size" to everything that asks it.

[relay]: https://github.com/gregordinary/ferroday-cage/blob/main/crates/ferroday-cage-cli/src/terminal.rs
