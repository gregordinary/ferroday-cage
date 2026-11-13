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
and `Terminal::new().size(rows, cols)` says otherwise. A zero dimension is left
at its default: zero is what a terminal reports when its size is *unknown*, not
a terminal with no rows, and a caller passing along what its own terminal
reported should not have to filter that out. The replica is wired onto
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
  mode and restore afterwards. `ferroday_cage::relay` does both; what stays the
  caller's is saying so. See [The relay](#the-relay).

## Draining, and the one order that deadlocks

The primary's buffer is a few kilobytes. A command that writes more than that
blocks, so a caller that waits without reading deadlocks — which is why `run`
and `output` are not terminal entry points at all. When an unbounded `wait()`
starts, the `Pty` is in one of three states:

- **Drained to end-of-file** — safe. End-of-file means every replica is
  closed, so nothing can block writing to the terminal. It does not mean the
  command has exited: one that closes its standard streams goes on running, and
  the wait lasts as long as it does.
- **Dropped** — safe. After the hangup the command's writes fail with `EIO`
  rather than block, so a caller that has dropped the primary owes the wait no
  drain.
- **Held and unread** — the deadlocking case.

This is the same obligation `Stdio::from_fd` already carries for a pipe, with
the same answer: where the caller owns both ends, the feed and the drain are the
caller's, and a wait that must be bounded is bounded.

**A caller that sends no input** drains to end-of-file and then waits. That
cannot deadlock. It ends when the last process holding the terminal closes it,
which under the default PID namespace is the command's exit. Without one, a
descendant that outlives the command can hold the terminal open, and the drain
lasts as long as that descendant does. The example above is the whole pattern,
and its second line is the part worth understanding.

**An interactive caller** needs both directions at once, and
[the relay](#the-relay) is the answer: one poll loop that cannot be stalled by
either direction, with the signal handling and the raw-mode discipline an
interactive session also owes. Everything below is for a caller composing
something else out of a `Pty` — a recorder, a test harness, a driver that is not
a terminal session at all.

Both directions at once needs concurrency: writes to the primary block too once
its input buffer fills, so a large paste into a command that is not reading
stalls a loop that writes from the thread it also reads on. Two threads is the
right minimum — a reader beside the main thread in the wait:

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

## Where the terminal comes from

The sandbox allocates its terminal itself. Once its root is in place, the first
process of the sandbox opens the `/dev/ptmx` the command will see. It makes the
terminal the controlling terminal of the sandbox's session, and sends the
primary back to the caller over a channel of the launch's own. The replica stays
behind for the command, and the sandbox holds no host pseudoterminal at all.

The replica is therefore a node in the sandbox's own `devpts` instance, and a
program that names its terminal by path finds it. `ttyname` reports
`/dev/pts/0`, so `tty(1)`, `who`, and `GPG_TTY` all work. gpg fills `GPG_TTY`
from `tty`, and pinentry then opens that path. Under a [run-as
identity](identity-maps.md#running-as-a-non-root-identity) the replica belongs
to that identity, the way a login's terminal belongs to the user logging in.
The command can then open its terminal by that path as well as use the
descriptor.

`/dev/tty` is the character device `5:0`, a per-process redirect to the opener's
own controlling terminal. Inside a terminal launch it yields the sandbox's own
terminal. `TIOCSTI` on that terminal injects into its own input queue, which
only the command reads.

Nested allocation, by `tmux`, `script`, `sshd`, or Python's `pty`, draws on the
same private instance, and sees no pseudoterminal but the sandbox's own.

### What the allocation needs

The managed `/dev` profile provides both the `/dev/ptmx` the allocation opens and
the `devpts` instance behind it. `mount_dev(false)` or `managed_mounts(false)`
removes them. A terminal launch in a root that ships no `/dev/ptmx` of its own
then fails, reporting `SetupStep::AllocateTerminal`. A caller that assembles
`/dev` itself mounts a `devpts` instance with `newinstance` and links
`/dev/ptmx` to its `ptmx`, as the managed profile does.

A sandbox's private instance draws on the host's pseudoterminal budget. The
budget is `/proc/sys/kernel/pty/max`, less the `/proc/sys/kernel/pty/reserve`
kept for the host's own instance. A host that has spent it reports
`Error::TerminalsExhausted`.

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

The primary comes back beside the `Pending` rather than out of `proceed`. The
sandbox allocates the terminal and sends its primary before the command reaches
the gate, so `spawn_pending_terminal` waits for the primary and then returns. A
setup step that fails before the terminal exists is reported there rather than
from `proceed`. Nothing writes to the terminal while the launch is held, so the
caller attaches its stack and proceeds with the primary already in hand.

## The restriction fallback

`Restriction::spawn_terminal` gives the [restriction
fallback](restriction-fallback.md) the same interactive story, by the same
mechanism. A restriction has no `/dev` of its own, so the `/dev/ptmx` its
command sees is the host's. Its terminal therefore comes from the host's
`devpts`, and a path for it resolves against the host's `/dev/pts`, which the
command also sees.

## At a shell prompt

`fcage --terminal` is the whole of this from the command line:

```sh
fcage --rootfs /srv/rootfs/alpine --terminal -- /bin/sh
```

It asks for a terminal the current size of *this* one, and relays the two. `TERM` passes through as it does for every `fcage` run, so
`--setenv TERM ...` overrides it. It composes with `--restrict` and with
`--netstack`; `--terminal` with `--stdin null` is refused at parse time, naming
both flags. From a script, where `fcage`'s own input is not a terminal, it
degrades to a plain byte relay around a sandbox that still has a real terminal
of its own, at 80x24.

## The relay

`ferroday_cage::relay` is the caller's side of an interactive session: one poll
loop over the sandbox's terminal, the caller's own terminal, and the signals a
session has to handle, with raw mode and its restoration on every exit the
process can observe.

```rust,no_run
use std::os::fd::AsFd as _;
use std::time::Duration;

use ferroday_cage::relay::{Escalation, Relay, Signals, install_panic_restore};
use ferroday_cage::{Cage, Terminal};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // First of all: blocking the relayed signals is process-wide, and a thread
    // inherits the signal mask of the thread that created it. A failed install
    // leaves the mask as it found it, so a program that reports this and carries
    // on still answers a SIGINT.
    let signals = Signals::install()?;
    // Restores the terminal before a backtrace prints, which a guard cannot.
    install_panic_restore();

    let cage = Cage::builder()
        .rootfs("/srv/rootfs/alpine")
        .command("/bin/sh")
        .env("TERM", "xterm-256color")
        .build()?;
    let (mut running, pty) = cage.spawn_terminal(&Terminal::new().size(30, 100))?;

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let outcome = Relay::new(stdin.as_fd(), stdout.as_fd())
        .raw(true)
        .escalation(Escalation::new(
            Some(Duration::from_secs(3600)),
            Duration::from_secs(5),
        ))
        .run(&mut running, &pty, &signals)?;

    match outcome {
        Some(status) => println!("the session ended with {status:?}"),
        None => println!("the session ran out of time"),
    }
    Ok(())
}
```

### What stays yours

The relay does nothing process-global as a side effect and reads nothing from
the environment, so four decisions belong to the program driving the session:

- **Installing `Signals`**, early and on the main thread, and keeping the
  handle. Blocking the relayed set is process-wide, so it is an explicit call
  rather than something `run` does on the way past — and it must precede every
  thread the run may start, because a thread inherits the mask of the thread
  that created it.

  The library starts threads in two places. Attaching the [native network
  stack](userspace-networking.md) starts its pump, which runs for as long as
  the stack is attached. A program composing a relay with a stack therefore
  installs the signals before it attaches one. `HttpFetch::fetch_all` runs a
  provisioner's batch downloads on scoped workers and joins each before it
  returns. Those matter only to a program that provisions while it relays a
  session.

  Nothing restores the mask, deliberately: a relay that unblocked on the way out
  would leave a window in which the signals it exists to handle were fatal
  again, and a program that relays one session usually relays another. What
  follows from that is the handle's lifetime. Dropping it closes the descriptor
  and unblocks nothing, so the eight signals stay blocked with nowhere to be
  read from and the process then ignores `SIGINT`, `SIGTERM`, `SIGHUP` and
  `SIGQUIT` entirely — a shell's `^C` and a supervisor's `SIGTERM` both do
  nothing, and only `SIGKILL` is left. For `fcage` the handle lives to process
  exit; a longer-lived program holds it for the program's life, which is also
  the one-per-process shape the type asks for.

  That permanence belongs to a *successful* install. A call that blocks the set
  and then cannot open the descriptor — descriptor exhaustion, a seccomp policy
  refusing `signalfd4` — restores the exact mask it found before it reports the
  failure, so a program that logs it and carries on is not left unable to answer
  `SIGINT` by the call that told it the relay was unavailable. The prior mask is
  restored rather than the relayed set unblocked, so a signal the program had
  blocked for its own reasons stays blocked.
- **Raw mode.** `Relay::raw` is off unless asked. Whether the caller's own
  standard input *is* a terminal is the program's reading to make; `fcage` asks
  `tcgetattr` and passes the answer.
- **The panic hook.** `install_panic_restore()` is one call, or a program with a
  hook of its own calls `restore_terminal()` from it.
- **The sandbox's terminal.** `Terminal` states a size; a program that wants its
  own window's size reads it and passes it, because the library reads nothing of
  the host. See [Resizing](#resizing).

### What the loop does

One thread, one poll: the primary, the signal descriptor, the command's exit,
and the caller's input — in that order, because the input is the one channel
that retires and a retired channel must leave the polled set rather than be
given an empty events mask. `poll` reports `POLLHUP`, `POLLERR`, and `POLLNVAL` whatever the requested
events are, so a muted slot on a hung-up pipe is ready on every pass and the
loop stops blocking; dropping the slot is what keeps `producer | fcage --terminal
...` from burning a core after the producer exits.

The primary is set non-blocking so a large paste cannot stall the loop; bytes
that do not fit yet wait in a pending buffer behind `POLLOUT`, and the input is
left unwatched while that buffer is occupied, so it cannot grow without bound.
End of input sends `VEOF` to the primary — read from the replica's *current*
settings rather than assumed, since a program inside is free to have changed it
— and retires that channel. An invalid input (`fcage --terminal ... 0<&-`) takes
the same path, since it says the same thing. An `Escalation` is the poll
deadline, consulted on every wakeup rather than only on the one `poll` timed out
on, so a sandbox printing without pause cannot postpone its own expiry.

End-of-file on the primary ends the relaying, and says nothing more: no replica
is open, and a command that closed its standard streams is still running. The
relay restores the caller's terminal and waits for the command's exit. The
deadline and the relayed signals stay in force, so a timeout still escalates and
a `SIGTERM` from outside still reaches the command.

The command's exit ends the relaying too, even while its terminal stays open.
Without a PID namespace, a descendant that outlives the command can hold the
terminal for as long as it runs, and a kill reaches only the command. Once the
command has exited, the relay delivers what the terminal holds at that moment
and stops. That includes everything the command wrote, since Linux queues only
a few tens of kilobytes between a pseudoterminal's two ends. The drain reads at
most 64 KiB, so a descendant writing without pause cannot prolong it. A timeout
or an interrupt therefore ends the session however long a descendant keeps the
terminal.

Signals are read as data rather than handled: no library code runs in signal
context, so there are no handlers, no async-signal-safety reasoning, and no
shared flags. `SIGWINCH` resizes the sandbox's terminal;
`SIGINT`/`SIGTERM`/`SIGHUP`/`SIGQUIT` from *outside* terminate the sandbox and a
second one kills it, while a typed `^C` is a byte the sandbox's own line
discipline acts on; `SIGTSTP` restores and stops; `SIGCONT` re-enters raw mode
and re-reads the size. The module's own documentation carries the whole table,
including why `SIGTTOU` is blocked and why `SIGTTIN` never arises.

Raw mode is entered only while the relaying process is in the foreground process
group of its terminal. With `SIGTTOU` blocked, nothing else would stop a session
started in the background, `fcage --terminal ... &`, from rewriting the settings
of the shell that holds the terminal. Such a session relays without raw mode,
and enters it on the first `SIGCONT` that finds it in the foreground, which is
what `fg` sends. A continue from `bg` leaves it in the background and changes
nothing.

The caller's input waits for the foreground the same way. A session in the
background neither watches nor reads its terminal, so what is typed there is the
shell's. The session keeps relaying the sandbox's output, and a timeout or a
`SIGTERM` still ends it. A read from the background would stop the session with
`SIGTTIN`, and the `fg` that continued it would find the read waiting for a line
in a cooked terminal, with nothing relayed until one came.

The two directions are not symmetric: the caller-bound one is a plain blocking
write, outside the poll. Making it symmetric would need `O_NONBLOCK` on the
output descriptor, and that flag lives on the open file description rather than
on the descriptor — setting it would set it for the caller's shell and for every
other process in the pipeline the program was started from. What is given up is
that a stopped downstream reader stalls the loop, including the signal channel;
`ssh` has the same shape for the same reason.

### What restoration promises

Raw mode is entered last — everything fallible happens first, so a failure
before the loop leaves the caller's terminal untouched — and undone by three
things that between them cover every exit the process can observe: a guard in
`run`'s own frame, dropped on normal exit, on error, and on a panic unwinding
through it; the optional panic hook, which restores *before* the default hook
prints, because with `OPOST` off a backtrace prints stair-stepped and a drop
runs after the hook; and the stop path, which restores before the process stops
and re-enters raw mode when it continues in the foreground.

`SIGKILL` and `SIGSTOP` are uncatchable and out of scope, with the same honesty
the leaked-handle case gets: the remedy is `stty sane`, and no process can
promise otherwise. Restoration means *termios*. Screen contents — an alternate
screen left active, a hidden cursor — were written by the sandboxed program
through the relay verbatim and belong to it, exactly as `ssh` treats them.

`restore_terminal()` reaches the terminal of the raw session in force, with the
settings that session found there. Sequential sessions are each covered, on one
terminal or on several. Outside a session it does nothing: the terminal's
settings are the shell's again, and replaying a finished session's settings
overwrites whatever the shell has set since. It also does nothing while the
process is in the background. The job in the foreground holds the terminal
then, and the session's own guard restores it as the session ends.

Called during a panic, from the hook or from a drop the panic unwinds through,
it restores only for a panic that ends the session or the process: one on the
thread the session runs on, one on the main thread, or any panic in a build that
aborts on panic. A panic on another thread of a build that unwinds ends that
thread alone, and the session goes on in raw mode. The network stack's pump is
such a thread: the library catches its panic, and a `--terminal --netstack`
session keeps its raw mode through it.

### What the sandbox's output reaches

The relay copies the sandbox's output to the caller's terminal byte for byte, so
its escape sequences act on the caller's terminal emulator. That is how a
full-screen program draws. It also lets the program set the window title and,
where the emulator permits it, the clipboard. The same holds for any command
whose output is the caller's terminal, with or without the relay.

Some sequences are queries: a cursor-position report, a device-attributes
request, a color query. The emulator answers each by writing the reply into its
own input, as though it had been typed. While the session is relayed, that input
is read as the caller's and forwarded to the sandbox, which asked. A reply that
arrives after the session ends lands at whatever reads the terminal next,
usually the caller's shell. Restoration discards the input pending at that
moment, but not a reply still on its way.

A reply carries what the emulator reports about itself, not text the program
chose. The exception is an emulator configured to report its window title, which
echoes text the program set. Modern emulators disable that report by default for
this reason. The relay filters nothing, as `ssh` filters nothing, so a caller
that runs an untrusted command keeps such reports off.

### The worked consumer

`fcage --terminal` is this, configured: it reads whether its standard input is a
terminal and what size it reports, installs the hook when it is one, and hands
the relay descriptors 0 and 1. Everything else it does with a session is a
library call. [`crates/ferroday-cage-cli/src/terminal.rs`][fcage-relay] is the
whole of what is left.

[fcage-relay]: https://github.com/gregordinary/ferroday-cage/blob/main/crates/ferroday-cage-cli/src/terminal.rs
