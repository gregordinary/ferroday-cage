# The process model

A sandbox is a small tree of processes. Understanding it explains what runs
where, what happens when the command misbehaves, and what the library
guarantees about lifetimes and signals.

## The process tree

```text
caller
└── launch stage            resets signal state, unshares the namespaces,
    (exits immediately)     sweeps descriptors, establishes the identity
                            map, publishes the supervisor
    └── init  (PID 1)       sets the sandbox up, then supervises
        └── command (PID 2) execs the configured command
```

A launch forks a short-lived stage that creates the namespaces and hands a
pidfd for the sandbox's supervisor back to the caller before exiting. With
the default PID namespace, the supervisor is a minimal init running as
PID 1 inside the namespace; the command runs as PID 2 beneath it.

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
and cannot keep [`run`] from returning.

With [`pid_namespace(false)`], there is no init: the command process is itself
the supervisor, and the launch stage remains outside the sandbox as its parent
until the outcome arrives. The command shares the host's PID space, and its
descendants are ordinary host processes that can outlive it.

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
  process having been opened carefully.
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
- **`kill()`** ends the sandbox: `SIGKILL` to the supervisor through a
  pidfd — immune to pid reuse — which, as namespace init, takes the whole
  namespace with it. Nothing inside survives.
- **`kill_handle()`** returns a detached handle that can terminate or kill
  from another thread while one blocks in a wait.

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

Waits are fused — once the outcome is known, every further wait returns it
— and killing or terminating an already-exited sandbox is not an error.
Dropping the handle without waiting does not kill the sandbox and does not
collect its outcome; prefer waiting, including after a kill, which also
drains any output produced before it.

## Signals and the caller

The library installs no signal handlers — how the embedding application
responds to its own signals is application policy. The defined behavior:

- **The command shares the caller's process group and session.** A
  terminal `^C` delivers `SIGINT` to the foreground process group, which
  includes the command; an interactive command exits with the foreground
  job, exactly as it would outside the sandbox.
- **A signal delivered to the caller alone does not affect the sandbox.**
  An application that wants its `SIGTERM` to stop the sandbox calls
  [`terminate`]/[`kill`] from its handler path, per the recipe above.
- **`stop_with_caller(true)`** ties the sandbox's lifetime to the caller's:
  when the calling process exits — cleanly, by signal, or by crash — or
  the last handle to the launch is dropped, the supervisor stops the
  sandbox. The tie is a descriptor held by the handle, not a signal
  arrangement, so it works from any thread and holds even for `SIGKILL`.
  It is off by default: an abandoned sandbox otherwise runs to completion,
  supervised, and is torn down when the command exits.

## Reaping and zombies

Inside the sandbox, orphaned processes reparent to the init and are
collected on its next wake-up: when the command exits, when control
traffic arrives, or on the init's reaping tick, which fires once per
second while the sandbox runs. A zombie therefore lingers for at most
about a second, regardless of how long the command runs; teardown at
command exit clears everything. Without a PID namespace, orphaned
processes reparent to the host's init as usual.

On the caller's side, a launch never leaks a zombie when it is waited: the
short-lived launch stage is collected during `spawn` (or by `wait`, in the
supervisor-outside mode), and the in-namespace init is not the caller's
child process at all.

[`run`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Cage.html#method.run
[`spawn`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Cage.html#method.spawn
[`terminate`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Running.html#method.terminate
[`kill`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Running.html#method.kill
[`pid_namespace(false)`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.pid_namespace
