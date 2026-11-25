# The process model

A sandbox is a small tree of processes. Understanding it explains what runs
where, what happens when the command misbehaves, and what the library
guarantees about lifetimes and signals.

## The process tree

```text
caller
└── launch stage            resets signal state, unshares the namespaces,
    (exits immediately)     sweeps descriptors, replaces the session
                            keyring, establishes the identity map,
                            publishes the supervisor
    └── init  (PID 1)       leaves the caller's process group or
                            session, sets the sandbox up, then
                            supervises
        └── command (PID 2) execs the configured command
```

A launch forks a short-lived stage that creates the namespaces and hands a
pidfd for the sandbox's supervisor back to the caller before exiting. With
the default PID namespace, the supervisor is a minimal init running as
PID 1 inside the namespace. The command runs as PID 2 beneath it.

Throughout this guide, and in the library's own errors, *the supervisor* is
that process: the one the returned handle anchors on, kills, and collects the
command's outcome from. *The launch stage* is the separate, short-lived process
that built the namespaces.

The init:

- adopts and collects processes orphaned inside the sandbox;
- forwards termination requests to the command;
- reports the command's exit status to the caller when it terminates, and
  then exits itself.

The init's exit destroys the PID namespace, and the kernel then kills every
process remaining in it. The sandbox's lifetime is therefore the command's
lifetime: a process the command leaves behind cannot outlive the launch,
and cannot keep [`run`] from returning. That holds for a process tracing the
command too. A tracer holds the command's exit until it lets go, so once the
command has exited, the init ends the namespace's other processes, the tracer
with them. A sandbox started with no command of its own lives until it is
ended instead; see [Further commands](#further-commands).

With [`pid_namespace(false)`], there is no init: the command process is itself
the supervisor, and the launch stage remains outside the sandbox as its parent
until the outcome arrives. It collects that outcome and watches the caller's
handle, as the init would. The command shares the host's PID space, and its
descendants are ordinary host processes that can outlive it. A descendant
tracing the command holds the outcome until it lets go.

## What the command starts with

Regardless of what state the calling process is in, the command starts
with:

- **default signal dispositions and an empty signal mask.** Ignored
  dispositions survive `execve`, so without this reset a command would
  inherit, for example, the ignored `SIGPIPE` every Rust program sets —
  and pipelines inside the sandbox would misbehave.
- **a descriptor table holding only its standard streams.** The launch
  closes every inherited descriptor other than the streams before the
  command is forked, so no caller descriptor leaks into the sandbox and no
  caller resource is pinned by it. This is stronger than the usual
  close-on-exec convention, which depends on every descriptor in the
  process having been opened carefully. The launch keeps its own
  descriptors above the standard streams' numbers, so a standard stream the
  caller has closed reaches the command closed, unless the configuration or
  the launch wires it.
- **the composed environment**, standard streams per the configuration,
  and the working directory, as described in
  [How the sandbox is built](how-the-sandbox-is-built.md).

## The handle

[`spawn`] starts the command and returns a `Running` handle. The launch is
complete when `spawn` returns: setup errors surface there, and the handle
means the command is executing.

- **`wait()`** blocks until the command terminates and returns its exit
  status.
- **`wait_deadline(instant)`** / **`wait_timeout(duration)`** additionally
  return when the deadline passes, reporting that the command still runs.
  Nothing is killed by a deadline; escalation belongs to the caller.
- **`terminate()`** requests a graceful stop: the supervisor delivers
  `SIGTERM` to the command process, which may trap it, clean up, or ignore
  it.
- **`signal(number)`** delivers another signal the same way, such as the
  `SIGINT` a program forwards from its own terminal. It takes the signals the
  kernel names and refuses a real-time signal, since a libc keeps some of
  those for itself.
- **`kill()`** ends the sandbox: `SIGKILL` to the supervisor through a
  pidfd — immune to pid reuse — which, as namespace init, takes the whole
  namespace with it. Nothing inside survives.
- **`kill_handle()`** returns a detached handle that can terminate, signal or
  kill from another thread while one blocks in a wait.
- **`usage()`** reports, once a wait has returned the outcome, the processor
  time and peak memory the command and its descendants used. See
  [Resource usage](#resource-usage).

The bounded-stop recipe composes them:

```rust,no_run
# use std::time::Duration;
# fn main() -> ferroday_cage::Result<()> {
# let cage = ferroday_cage::Cage::builder().rootfs("/r").command("/c").build()?;
let mut running = cage.spawn()?;
let status = match running.wait_timeout(Duration::from_secs(60))? {
    Some(status) => status,
    None => {
        running.terminate()?;
        match running.wait_timeout(Duration::from_secs(10))? {
            Some(status) => status,
            None => {
                running.kill()?;
                running.wait()?
            }
        }
    }
};
# Ok(())
# }
```

Waits are fused: once the outcome is known, every further wait returns it.
Killing or terminating an already-exited sandbox is not an error. A wait
returns once the supervisor has exited, which with a PID namespace follows the
namespace's teardown.

Dropping the handle without waiting does not kill the sandbox and does not
collect its outcome. It does give back the caller's terminal, where the launch
lent it to the sandbox; see [Signals and the caller](#signals-and-the-caller).
Prefer waiting, including after a kill, which also drains any output produced
before it. A file bind's target that the launch created in
the root goes once the sandbox is gone. A handle dropped while the sandbox runs
leaves it, since removing it would unmount the running sandbox's bind.

## Further commands

[`Running::exec`] runs a further command in a sandbox that is running. An
[`Exec`] states the command, its arguments, variables set over the launch's
environment, a working directory, and its standard streams. Its identity,
resource limits and hardening are the launch's.

```text
caller
├── launch stage ─ init (PID 1) ─ command (PID 2)
└── join stage                joins the sandbox's namespaces, forks the
    (supervises from outside) further command, reports its outcome
    └── further command       PID 3 or later, its parent shown as 0
```

The join stage enters the sandbox with one `setns`, through the pidfd the
handle holds. That is the init's, or the launch stage's without a PID
namespace. The stage forks the further command into the sandbox and supervises
it from outside, as a launch stage does without a PID namespace. The command
then enters a nested user and mount namespace of its own, copied from the
sandbox's setup, and applies the hardening. It is a Landlock domain and a
seccomp filter of its own, with the launch's rules.

The commands share the sandbox. Its root and every mount the setup made are
theirs, and so are its processes, its network and its hostname. So are any
network stack attached to it, its IPC namespace, and its cgroup and limits. A
mount one command makes in its own namespace is not seen by another. Each is a
user namespace of its own, so none can `ptrace` another or read another's
`/proc/<pid>/environ`, `fd` or `mem`.

Each sees the others in `/proc` and can signal them, unless the hardening sets
[`LandlockScope::Signal`]. A further command's handle governs that command and
not the sandbox, and its [`kill`] ends the command. Where the sandbox has a
cgroup, the command runs in a cgroup of its own beneath it, held to the
sandbox's limits. The kill then ends everything the command started. Without a
cgroup, what it started runs on until the sandbox ends.

The sandbox ends as it always does, with its first command. With a PID
namespace, every further command ends with it. An exec costs a fork, the join,
the nested namespace and the hardening: about a millisecond, a fraction of a
launch.

```rust,no_run
# fn main() -> ferroday_cage::Result<()> {
use ferroday_cage::{Cage, Exec};

let sandbox = Cage::builder()
    .host_rootfs()
    .stop_with_caller(true)
    .build()?
    .start()?;
sandbox.exec(&Exec::new("/bin/sh").args(["-c", "python3 -m http.server 8000 &"]))?
    .wait()?;
let status = sandbox
    .exec(&Exec::new("/usr/bin/curl").arg("http://127.0.0.1:8000/"))?
    .wait()?;
# let _ = status;
# Ok(())
# }
```

### A sandbox with no command of its own

[`Cage::start`] starts a sandbox and returns its handle without running a
command. Its init holds the sandbox for further commands. A session's sandbox
lives for the session rather than for one command, and needs nothing in its
root to keep it up. Built without a command, a `Cage` is made for this, and
refuses the launches that run its command. The init takes none of the caller's
streams, and needs a PID namespace.

[`terminate`] sends `SIGTERM` to every process of such a sandbox, which ends
once none is left. Its wait then reports an exit code of 0. A process that
ignores the request keeps it up until a [`kill`]. A [`signal`] reaches every
process of it too, and the sandbox holds once they are gone. [`Cage::start_pending`] holds
the sandbox at the gate, so a network stack attaches before the handle is given
out, as it does for a pending launch.

The `session-sandbox` example keeps one sandbox for a session and runs each
line it reads as a further command in it.

## Signals and the caller

The library installs no signal handlers — how the embedding application
responds to its own signals is application policy. The defined behavior:

- **A command that inherits the caller's standard input stays in the caller's
  session, in a process group of its own.** The init moves the sandbox into a
  group of its own before the command exists. A signal the command sends its
  own group, `kill(0, sig)`, reaches the sandbox alone, and no group of the
  caller's is visible from its PID namespace. Any other standard input, and
  every terminal launch, gives the sandbox a session of its own. See
  [Stream dispositions](streaming.md#stream-dispositions).
- **An interactive run borrows the caller's terminal.** Its standard input and
  standard output are both the caller's controlling terminal, and the caller's
  group holds that terminal's foreground. The sandbox's group takes the
  foreground before the command runs. A `^C` typed at the terminal then reaches
  the command, which reads the terminal as a foreground job does. The caller's
  group is a background job meanwhile, and a process in it that reads the
  terminal stops until its shell resumes it.
- **Any other run leaves the terminal with the caller.** With output piped,
  redirected, or captured, the caller's job keeps the foreground, and a pager at
  a pipeline's far end reads the terminal as before. A caller in the background
  of its terminal lends nothing either. The sandbox is then a background group
  of the terminal, orphaned once the launch stage exits, so its reads of it
  fail. A `^C` reaches the caller's job rather than the sandbox: `fcage`'s
  stop-with-caller tie, on unless its command line or a profile it trusts
  turns it off, ends the sandbox with `fcage`, and a library caller decides
  for itself. A capturing launch, such as `Cage::output`, never takes
  the terminal from its caller.
- **The foreground comes back to the caller.** The wait that collects the
  outcome gives it back, and so does dropping the handle. A sandbox still
  running then is in the background of the terminal. A read of the terminal
  there fails or stops the reader, and a `^C` reaches the caller's group again.
  A `^Z` typed while the sandbox holds the terminal does nothing, as [the
  caller's terminal](streaming.md#the-dispositions-and-the-callers-terminal)
  explains.
- **Without a PID namespace, a command that inherits the caller's standard
  input shares the caller's process group**, as it shares the caller's PID
  space. It can name the caller's processes directly, so a group of its own
  would bound nothing.
  [`LandlockScope::Signal`] is the bound on that reach. A `^C` typed at the
  terminal reaches the caller and the command alike.
- **The library's own processes outlive the signals sent to the caller's
  process group.** The init is immune to them as PID 1 of its namespace.
  Without a PID namespace, the launch stage stays in the caller's process group
  as the command's parent. It ignores every signal but `SIGCHLD` and the
  faults. A `^C`, a hangup, or a shell's `kill %1` that ends the caller leaves
  it to collect the outcome and stop the sandbox as asked. `SIGKILL`, or a
  fault's signal, sent to the group still ends it, and a command in a session
  of its own then runs on.
  The command starts with every signal at its default.
- **A signal delivered to the caller alone does not affect the sandbox.**
  An application that wants its `SIGTERM` to stop the sandbox calls
  [`terminate`]/[`kill`] from its handler path, per the recipe above.
- **`stop_with_caller(true)`** ties the sandbox's lifetime to the caller's:
  when the calling process exits — cleanly, by signal, or by crash — or
  the last handle to the launch is dropped, the supervisor stops the
  sandbox. The tie is a descriptor held by the handle, not a signal
  arrangement, so it works from any thread and holds even for `SIGKILL`.
  It is off by default: an abandoned sandbox otherwise runs to completion,
  supervised, and is torn down when the command exits. A process the caller
  forks holds a copy of the descriptor until it exits or executes, and the tie
  waits for that copy too.

## Reaping and zombies

Inside the sandbox, orphaned processes reparent to the init, which collects
each as soon as it exits: every child's exit wakes the init with a `SIGCHLD`,
however long the command runs. Teardown at command exit clears everything.
Without a PID namespace, orphaned processes reparent to the host's init as
usual.

On the caller's side, a launch never leaks a zombie when it is waited: the
short-lived launch stage is collected during `spawn` (or by `wait`, without a
PID namespace), and a further command's join stage by that command's `wait`. A
handle dropped without waiting leaves a stage that supervises from outside, the
launch stage without a PID namespace and every join stage, a zombie child of
the caller once it exits, until the caller exits. The in-namespace init is not
the caller's child process, unless the caller is a child subreaper
(`PR_SET_CHILD_SUBREAPER`), to which the kernel reparents it once the launch
stage has exited. The wait collects it then too, once it has exited.

## Resource usage

The library does the waiting, so it also reports what the wait would have told
the caller. [`Running::usage`] returns a [`ResourceUsage`]: user and system
processor time, and the largest peak resident set size any one process reached.
[`Output`] carries the same value. A sandbox in a [cgroup of its
own](hardening.md#limits-on-the-whole-tree) also reports what its whole tree
used, read from the cgroup.

The supervisor reads the figures from the kernel right after it collects the
command's exit. They cover every process collected by then:

- **Under a PID namespace**, every process of the sandbox that had exited. The
  init collects the orphans as well as the command, so a descendant counts
  whether or not the command waited for it.
- **Without one**, a descendant counts only through the process that waited for
  it. An orphan reparents outside the sandbox and is not counted.

A process still running when the command exits is not counted. A kill under a
PID namespace ends the init before it reports, so a killed sandbox has none of
these figures. Its cgroup's figures for the whole tree are still reported, and
a killed sandbox without a cgroup has an outcome and no usage.

The peak resident set has a floor: the resident set the calling process had
when it launched the sandbox, its heap and stacks above all. The launch forks
copies of the calling process down to the command, and each copy's resident
set counts the pages it shares with the caller. When the command's `execve`
replaces the last copy, the kernel records that copy's peak as the command's.
A service holding 2 GiB that runs `/bin/true` therefore reports about 2 GiB.
No figure that leaves the replaced image out is readable without privilege. A
peak below the caller's own is therefore not one the field can show.

[`run`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Cage.html#method.run
[`spawn`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Cage.html#method.spawn
[`terminate`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Running.html#method.terminate
[`signal`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Running.html#method.signal
[`kill`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Running.html#method.kill
[`Running::usage`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Running.html#method.usage
[`ResourceUsage`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.ResourceUsage.html
[`Output`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Output.html
[`pid_namespace(false)`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.pid_namespace
[`LandlockScope::Signal`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.LandlockScope.html#variant.Signal
[`Running::exec`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Running.html#method.exec
[`Exec`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Exec.html
[`Cage::start`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Cage.html#method.start
[`Cage::start_pending`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Cage.html#method.start_pending
