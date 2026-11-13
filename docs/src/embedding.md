# Embedding in a runtime

The library is synchronous: a launch blocks the thread that made it, and
captured output is pumped inside that blocking call, on that thread. Launching
and waiting start no thread. The library starts threads in two places, both
outside that path. An attached [native network stack](userspace-networking.md)
runs its pump on a thread of its own for as long as it is attached.
`HttpFetch::fetch_all`, which a provisioner's downloads reach, runs a batch on
scoped workers and joins every one before it returns. A service that wants to
launch sandboxes from a thread pool or an async runtime therefore launches from
a blocking context. It waits there, or hands the wait to its event loop through
the handle's [readiness descriptor](#waiting-without-a-thread). This chapter is
that connection.

## One cage, many launches

A [`Cage`] is a frozen plan holding no live resources. It is `Clone`, it is
`Send + Sync`, and every launch method takes `&self`, so one cage behind an
`Arc` serves an entire pool:

```rust,no_run
use std::sync::Arc;

use ferroday_cage::Cage;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cage = Arc::new(
        Cage::builder()
            .rootfs("/srv/rootfs/alpine")
            .command("/bin/sh")
            .args(["-c", "echo from a worker"])
            .build()?,
    );

    std::thread::scope(|scope| {
        for _ in 0..8 {
            let cage = Arc::clone(&cage);
            scope.spawn(move || {
                let result = cage.output().expect("the sandbox launches");
                assert!(result.status.success());
            });
        }
    });
    Ok(())
}
```

Nothing is shared between those launches but the plan itself: each gets its own
namespaces, its own supervisor, and its own channels.

Setup cost is small enough that per-command overhead is rarely the thing worth
optimizing. On an ordinary developer machine against a small Alpine root, 20
sequential launches of a trivial command took 22.3 ms — about **1.1 ms per
launch** — and 8 concurrent launches from 8 threads against one shared
`Arc<Cage>` completed in 3.2 ms in total. Treat those as an order of magnitude
rather than a promise: they move with the mount profile, the rootfs, and the
host. The point is the order of magnitude.

## Launching from an async runtime

A launch blocks, so it belongs on a blocking thread. In tokio that is
`spawn_blocking`:

```rust,ignore
let cage = Arc::clone(&cage);
let status = tokio::task::spawn_blocking(move || cage.run()).await??;
```

That much is unremarkable. The part that is not obvious is cancellation.

## Waiting without a thread

A wait blocks its thread for the sandbox's whole life, so a service running
many sandboxes this way parks a thread on each. The handle offers the wait in
a form an event loop drives instead. [`Running`] implements `AsFd`: its
descriptor is readable whenever the handle has work, such as output to
deliver, the outcome to read, or the teardown to observe.
[`Running::try_wait`] does that work without blocking, and returns the outcome
once it is known.

In tokio, the descriptor goes to an `AsyncFd`, and the task calls `try_wait`
once and again each time the descriptor is readable:

```rust,ignore
use std::os::fd::AsFd;

use ferroday_cage::{Cage, ExitStatus};
use tokio::io::unix::AsyncFd;

async fn run(cage: &Cage) -> Result<ExitStatus, Box<dyn std::error::Error>> {
    // Blocks only until the command is executing.
    let mut running = cage.spawn()?;
    let ready = AsyncFd::new(running.as_fd().try_clone_to_owned()?)?;
    loop {
        if let Some(status) = running.try_wait()? {
            return Ok(status);
        }
        ready.readable().await?.clear_ready();
    }
}
```

The launch itself still blocks, for as long as the sandbox's setup takes. A
handle is not `Send`, for the reason the next section gives, so a future that
holds one runs on a `LocalSet` or on a current-thread runtime. An observer
given to `spawn_with` is called inside `try_wait`, on that thread. One call
reads at most one chunk of each captured stream, so a command that writes
without pause cannot hold the task, and the descriptor stays readable while
more is waiting.

## Cancelling from async

[`Running`] and [`Pending`] are deliberately neither `Send` nor `Sync`: they
borrow an observer that carries no thread bounds, and the library delivers
output on the thread that waits. So a handle cannot cross an await point, and
the handle is exactly what holds the kill.

[`KillHandle`] is the piece that does cross threads — it is `Send + Sync` — but
it is obtained from the `Running` that is now inside the blocking task. The
pattern that works is to ship the kill handle out of the task over a channel as
soon as the sandbox is up, and keep it on the async side:

```rust,ignore
use std::sync::Arc;
use std::time::Duration;

use ferroday_cage::{Cage, KillHandle};

async fn run_bounded(cage: Arc<Cage>) -> Result<(), Box<dyn std::error::Error>> {
    let (tx, rx) = tokio::sync::oneshot::channel::<KillHandle>();

    let task = tokio::task::spawn_blocking(move || {
        let mut running = cage.spawn()?;
        // Hand the killer to the runtime before blocking on the wait.
        let _ = tx.send(running.kill_handle()?);
        running.wait()
    });

    let killer = rx.await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    killer.kill()?; // cancel from the async context

    let status = task.await??; // terminated by SIGKILL
    assert_eq!(status.signal(), Some(9));
    Ok(())
}
```

The ordering matters: the kill handle is sent *before* the wait begins, so the
async side holds it for the whole life of the sandbox. `kill_handle` can be
called again later from the blocking side if a second one is wanted; each owns
its own duplicated channel ends.

A sandbox's [cgroup](hardening.md#limits-on-the-whole-tree), where it has one,
is shared by the `Running` and its kill handles, and the last of them to drop
removes it. After a kill, that drop first waits for the killed processes to
exit. That takes about a millisecond, a fraction of a second for one releasing
gigabytes of memory, and five seconds at most, where one is in an
uninterruptible sleep. A kill handle the async side drops while the blocking
task still holds the `Running` leaves that wait to the blocking task.

For a graceful stop, `KillHandle::terminate` sends SIGTERM instead, and the
escalation recipe in [the process model](process-model.md) applies unchanged —
either driven from the blocking side with `wait_deadline`, or from the async
side with a `tokio::time::timeout` around the handle's `terminate` and `kill`.

Two alternatives are worth knowing:

- **A deadline inside the task.** If the bound is purely a timeout, there is no
  need to involve the runtime at all: `wait_deadline` inside the blocking task
  is simpler and needs no channel.
- **[`stop_with_caller`].** Tying the sandbox's lifetime to the calling process
  covers the case where the *service* exits rather than the individual task; it
  is not a per-task cancellation mechanism.

## Getting output back

An observer runs on the thread that waits, which is inside the blocking task,
so an observer that forwards to the async side is the natural shape:

```rust,ignore
use ferroday_cage::Observer;

struct Forward(tokio::sync::mpsc::Sender<Vec<u8>>);

impl Observer for Forward {
    fn stdout(&mut self, chunk: &[u8]) {
        // The blocking task is not in the runtime, so the blocking send is
        // the correct one here.
        let _ = self.0.blocking_send(chunk.to_vec());
    }
}
```

`blocking_send` rather than `send`: the task is on a blocking thread, not
inside the reactor. A bounded channel then gives back-pressure for free — when
the consumer falls behind, the observer blocks, the pump stops draining, and
the command blocks writing, which is the ordinary pipe discipline rather than
unbounded memory growth. For the whole-output case, [`output`] inside the
blocking task is simpler, with the caution about unbounded capture from
[Streaming output](streaming.md).

## What crosses a thread boundary

The rule the library follows is that a seam it *stores* carries thread bounds
and a seam it merely *borrows* for one call does not:

| Type | `Send` | `Sync` | Why |
| --- | --- | --- | --- |
| `Cage`, `CageBuilder` | yes | yes | Frozen configuration, no live resources |
| `KillHandle` | yes | yes | Owns duplicated channel ends; exists to cross threads |
| `Error`, `ConfigError` | yes | yes | A worker returns one to a coordinator |
| `Running`, `Pending` | no | no | Borrow a `&mut dyn Observer`, called on the waiting thread |
| `Provision`, `ProvisionRequest` | no | no | Borrow a `&mut dyn ProvisionObserver`, likewise |

A consumer that needs one of the borrowed handles on the far side of a thread
boundary moves the *inputs* across and constructs it there — which is what the
`Arc<Cage>` fan-out above does.

## Recording what a build ran under

What a command produces depends on the filesystem it sees and the environment it
carries. It also depends on the identity and privileges it holds, whether it can
reach a network, and which syscalls succeed. A runtime that publishes artifacts
usually needs to state those in the artifact's provenance, and the library
version alone does not: the mount profile and the base environment are both
[outside the compatibility promise](stability.md#what-is-not-covered) and may
change in a patch release.

[`resolved_inputs`] reports them as data. It is a projection of the frozen
launch plan, computed on demand, so calling it costs nothing until asked and
adds nothing to a launch:

```rust
use std::path::Path;

use ferroday_cage::{Cage, RawMount};

/// The provenance record of a build over `rootfs`, with `sources` at
/// `/usr/src`.
fn provenance(rootfs: &Path, sources: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/usr/bin/make")
        // Prevention: the library contributes no mount and no variable of
        // its own, in this release or any later one.
        .managed_mounts(false)
        .base_env(false)
        // The one mount a container cannot do without: the procfs its nested
        // user namespace establishes an identity map through. The flags are
        // MS_NOSUID | MS_NODEV | MS_NOEXEC, as the managed procfs has them.
        .raw_mount(RawMount::new("/proc").fstype("proc").flags(0xe))
        .env("PATH", "/usr/bin:/bin")
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .bind_ro(sources, "/usr/src")
        .build()?;

    // Verification: what the sandbox will actually apply, ready to stamp
    // beside the consumer's own version pin.
    Ok(toml::to_string(&cage.resolved_inputs())?)
}
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# // Directories every host has, so the recipe builds wherever it is tested.
# let record = provenance(&std::env::temp_dir(), Path::new("/etc"))?;
# assert!(record.contains("fstype = \"proc\""), "{record}");
# Ok(())
# }
```

Without the managed mounts, a profile declares its own procfs. Every container
enters a nested user namespace, which is what locks its mount flags, and that
namespace's identity map is written through a procfs. A build that declares
none is refused with `NestedUsernsNeedsProcfs`. [Identity
maps](identity-maps.md) sets out the one configuration that needs none.

The two are complements. The opt-outs keep the inputs from drifting under a
library upgrade. The record states what they were, which catches the case where
a declaration and the sandbox disagree. It also holds what no other accessor
reports. With the managed profile in force, it lists the six `/dev` device nodes
and the five `/dev` symlinks one by one, where `get_mount_dev()` answers only
whether `/dev` is assembled.

### What the record carries

`root` is what the command's filesystem *is*, and it is a field of its own
rather than an entry in `mounts`: a mount is something laid over the root, and
the root is what it is laid over. A plain rootfs records its canonicalized path;
an overlay records its whole lower stack, its upper, and its work directory,
because that stack is what the root was made of. Recording only the mounts would
leave two builds — one on a rootfs, one on an overlay over the same base —
looking identical.

`identity`, `run-as`, `present-as`, `no-new-privileges`, `network`,
`network-filter`, `pid-namespace`, `hostname`, `streams`, `rlimits`, and
`hardening` are the posture the launch puts the command under, and each
changes what a build produces:

- **`identity`** — the identity map: which ids exist inside the sandbox. A
  file's recorded ownership follows from it.
- **`run-as`** — the run-as identity, where one is configured, in the keys a
  profile's `[run-as]` table takes. Where the key is absent the command runs as
  uid 0, or as the identity `present-as` names. A Debian build's
  `Rules-Requires-Root` handling turns on exactly this. A non-root id also
  leaves the command no capabilities, unless the hardening keep set carries
  some across.
- **`present-as`** — the uid and gid the single-identity map presents the
  caller to the command as, where one is configured. `own` is recorded as the
  ids it resolved to. The command holds no capabilities, unless the hardening
  keep set carries some across. On the host it is still the caller.
- **`no-new-privileges`** — whether a set-user-ID binary or a file capability
  grants anything across `execve`. A run-as identity sets it, so does a
  presented identity, and so does any hardening control.
- **`network`** — the namespace the sandbox creates. A stack attached to a
  pending launch is not visible here, being established after the cage is built.
- **`network-filter`** — the syscalls [the network
  filter](how-the-sandbox-is-built.md#the-network-filter) refuses under an
  isolated or a denied network, each by name, with the value its first argument
  holds where that decides it, and the errno it answers. A configure test that
  probes vsock or io_uring reads the refusal as an absent feature. The key is
  absent under the host network, which installs no filter.
- **`pid-namespace`** — whether the command runs under the sandbox's own init.
  Without one it sees the caller's processes, and its descendants can outlive
  it.
- **`hostname`** — the name the command sees. Where none is configured it is the
  host's, read when the record is made, so two hosts write two records.
- **`streams`** — where the command's three standard streams are wired:
  inherited, `/dev/null`, or a descriptor the caller supplied. Whether a stream
  is a terminal steers debconf's frontend, a compiler's color, and every
  progress display.
- **`rlimits`** — a build that adapts its parallelism to `RLIMIT_NOFILE`, or
  fails a link under `RLIMIT_AS`, produces different output.
- **`hardening`** — the subtlest, and the one most worth recording: a seccomp
  policy changes which syscalls succeed, and a configure test that probes a
  syscall reads the refusal as an absent feature. The Landlock grants are
  recorded in full, by path and by port; the seccomp filter is recorded as its
  instruction count, since the program itself is thousands of instructions and
  means nothing to a reader. A posture that asks for Landlock also records the
  kernel's Landlock ABI, which the requested rights are narrowed to at launch.

`hardening` is present whether or not the `hardening` feature is compiled in,
reporting `unavailable` when it is not. A record that simply left the key out
could not be told apart from one written before the key existed, and a
provenance record has to be readable without knowing which build wrote it.
`unavailable` and an applied posture with no controls are different facts: the
second is a build that could have hardened and did not.

The value's *shape* is stable API, and so are the keys it serializes to. Its
*contents* follow the defaults and may change, which is precisely why recording
it is worth doing.

[`Cage`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Cage.html
[`Running`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Running.html
[`Running::try_wait`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Running.html#method.try_wait
[`Pending`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Pending.html
[`KillHandle`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.KillHandle.html
[`output`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Cage.html#method.output
[`resolved_inputs`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Cage.html#method.resolved_inputs
[`stop_with_caller`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.stop_with_caller
