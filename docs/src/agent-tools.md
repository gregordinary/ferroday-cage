# Confining an agent's tool commands

A coding agent works by running commands its model chooses: a test suite, a
search, a build. An agent runtime runs each one in a sandbox. The command sees
the host's programs and the project it works on, and writes only to the project.
It reaches none of the user's credentials, and talks to one service the runtime
chooses. The library ships such a sandbox as a worked example, `agent-tools`,
and `fcage` loads the same sandbox from a profile.

```sh
agent-tools --worktree ~/project -- git status
```

Each part of the sandbox is an ordinary builder call. This chapter takes them in
turn, then the service, the limits, and the report the example prints at the end.

## The sandbox

The example's builder calls, for a working tree at `/home/user/project`:

```rust,no_run
use ferroday_cage::{
    Cage, Network, PresentedIdentity, Resource, SeccompPolicy, SeccompRules, Stdio,
};

# fn main() -> ferroday_cage::Result<()> {
let tree = "/home/user/project";
let cage = Cage::builder()
    .host_rootfs()
    .bind(tree, tree)
    .current_dir(tree)
    .hide("/home/user/project/.env")
    .read_only("/home/user/project/.git/hooks")
    .read_only("/home/user/project/.git/config")
    .present_as(PresentedIdentity::Own)
    .env("HOME", "/tmp")
    .network(Network::Isolated)
    .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
    .landlock_resolve_unix(true)
    .rlimit(Resource::CoreDump, 0, 0)
    .stdin(Stdio::Null)
    .stop_with_caller(true)
    .path_lookup(true)
    .command("git")
    .arg("status")
    .build()?;
# let _ = cage;
# Ok(())
# }
```

The limits come later in the chapter, since the example chooses them at run
time. A core-dump limit of 0 holds in every case, because a core dump lands in
the working tree. The command's standard input is empty. If the example exits,
the sandbox stops with it.

### The root

[`host_rootfs`] roots the sandbox on the host's own tree, read-only, so the
command finds every program and library the host has. The root hides `/home`,
`/root`, `/run`, `/var/run` and `/var/tmp`, which hold the user's credentials and
the host's live sockets. [The host's own
root](how-the-sandbox-is-built.md#the-hosts-own-root) sets out what stays in
view.

`--empty-root` composes an [empty
root](how-the-sandbox-is-built.md#an-empty-root) instead. It binds the host's
`/usr` and `/etc` read-only. The top-level directories follow the host's: a
directory is bound, and a link a merged `/usr` made is made again. The command
then sees what the example names, and nothing else of the host. A program
installed elsewhere, such as under `/opt`, is then missing, and `--expose` binds
it back read-only.

### The working tree

The working tree is bound read-write at its own path, so a path in the command's
output names the same file on the host. It is the one place the command writes,
besides the sandbox's own `/tmp`. Three paths in it are treated apart:

- `.env` is hidden, since it conventionally holds the project's secrets. A
  hidden file reads empty and refuses a write, and a tree without one hides
  nothing.
- `.git/hooks` and `.git/config` are read-only. Git runs the hooks, and obeys
  the configuration, the next time the user runs git outside the sandbox. A
  command that can write them can run code there.

A path that [`read_only`] protects must exist, since a path left missing is one
the command can create. Where a git working tree lacks either path, the example
creates it empty first, and says so on standard error. `--hide` and
`--read-only` add paths of the caller's, and a relative one is taken inside the
working tree. `--expose` binds a host path read-only at its own path, such as a
toolchain installed under the hidden home directory.

### The identity

[`present_as`] with `PresentedIdentity::Own` runs the command as the caller's own
uid and gid. Files the caller owns read as the command's, and `id` finds the
caller's account in the host's `/etc/passwd`. A program that refuses to run as
root, or behaves differently as root, sees an ordinary user. The command holds no
capability, runs with no-new-privileges, and cannot become root inside.
[Presenting the caller as another
identity](identity-maps.md#presenting-the-caller-as-another-identity) gives the
detail.

A command that is not root inside gets no `HOME` from the base environment, and
the caller's own home directory is hidden. The example sets `HOME` to `/tmp`,
which is empty at each launch and is discarded with the sandbox. A tool that
keeps a cache in the home directory then has a writable one. A tool that reads
its configuration there finds none, and the caller passes what it needs with
`--env`.

### The restrictions

[`SeccompRules::curated`] denies the syscalls a tool command has no use for:
mounting, creating or entering a namespace, loading a kernel module, and tracing
among them. A tool that builds a sandbox of its own, such as a browser under
test, needs a policy of its own. The [seccomp
section](hardening.md#seccomp-syscall-filters) lists the roster.

A read-only mount refuses a write, and does not refuse a connection to a socket.
A hidden path covers only the places it names. So a pathname socket anywhere else
in view, such as one in the working tree, accepts the command's connection.
[`landlock_resolve_unix`] refuses those connections, except to a socket the
command or a process it started created. It needs Landlock ABI 9, and a kernel
below it refuses the build that asks for it. The example therefore asks for it
where [`host::landlock_enforces_fs`] reports that the kernel enforces
`FsAccess::RESOLVE_UNIX`, and says on standard error where it cannot.

The sandbox's own PID and network namespaces keep its signals and its abstract
sockets from the host's processes. No [Landlock
scope](hardening.md#landlock-scopes) is needed for either.

## The service

The sandbox's network namespace has a loopback of its own, which reaches nothing
outside. The runtime gives the command one way out: a TCP port on that loopback,
which the runtime serves itself. [`Pending::listen`] makes the listener in the
sandbox's namespace before the command starts, and hands it to the caller:

```rust,no_run
use std::net::{Ipv4Addr, SocketAddr};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let cage = ferroday_cage::Cage::builder().host_rootfs().command("/usr/bin/git").build()?;
let pending = cage.spawn_pending()?;
let listener = pending.listen(SocketAddr::from((Ipv4Addr::LOCALHOST, 8080)))?;
listener.set_nonblocking(true)?;
let mut running = pending.proceed()?;
# let _ = (listener, running.wait()?);
# Ok(())
# }
```

The example answers each connection with a stand-in service, which replies to an
HTTP request with a line naming it. A runtime puts its own service there, such
as a proxy that admits the registries a build needs. What that service carries,
and where, is the runtime's policy, and the command's network reaches nothing
else. `--port` moves the port.

Nothing of the caller's runs inside the sandbox, so the command is the sandbox's
only program, and a request to stop reaches it directly.

### Waiting

The example waits on two descriptors in one `poll`. The handle's [readiness
descriptor](embedding.md#waiting-without-a-thread) is readable while
[`Running::try_wait`] has work, and the listener is readable once the command
connects. The timeout is the next deadline of an [`Escalation`]. Once
`--timeout` runs out, the escalation asks the command to stop, and kills it 5
seconds later:

```rust,no_run
# use std::net::TcpListener;
# use std::time::Instant;
# use ferroday_cage::relay::Escalation;
# use ferroday_cage::{ExitStatus, Running};
use rustix::event::{PollFd, PollFlags, Timespec};

# fn serve(
#     running: &mut Running<'_>,
#     listener: &TcpListener,
#     escalation: &mut Escalation,
# ) -> Result<ExitStatus, Box<dyn std::error::Error>> {
let status = loop {
    if let Some(status) = running.try_wait()? {
        break status;
    }
    if escalation.passed() {
        escalation.expire(running)?;
        continue;
    }
    let timeout = escalation
        .deadline()
        .map(|deadline| deadline.saturating_duration_since(Instant::now()))
        .and_then(|left| Timespec::try_from(left).ok());
    let mut ready = [
        PollFd::new(&*running, PollFlags::IN),
        PollFd::new(listener, PollFlags::IN),
    ];
    rustix::event::poll(&mut ready, timeout.as_ref())?;
    if !ready[1].revents().is_empty() {
        if let Ok((connection, _)) = listener.accept() {
            // Answer on a thread of its own, so the wait goes on.
            std::thread::spawn(move || drop(connection));
        }
    }
};
# Ok(status)
# }
```

An event loop registers the same two descriptors. A listener keeps the
sandbox's network namespace in being, so the example drops it once the wait
returns.

## The limits

A command can fork without end and allocate without end, so the example bounds
both. Where it runs in a delegated cgroup, it bounds the whole process tree in a
[cgroup of the command's own](hardening.md#limits-on-the-whole-tree). Elsewhere
it bounds each process alone:

```rust,no_run
use ferroday_cage::{Cage, CgroupLimit, Resource};

# fn main() -> ferroday_cage::Result<()> {
# let delegated: Option<std::path::PathBuf> = None;
let builder = Cage::builder().host_rootfs().command("/usr/bin/make");
let builder = match delegated {
    Some(parent) => builder
        .cgroup_parent(parent)
        .cgroup_limit(CgroupLimit::MemoryMax(4 << 30))
        .cgroup_limit(CgroupLimit::MemorySwapMax(0))
        .cgroup_limit(CgroupLimit::PidsMax(1024)),
    None => builder
        .rlimit(Resource::Data, 4 << 30, 4 << 30)
        .rlimit(Resource::Processes, 1024, 1024),
};
# let _ = builder.build()?;
# Ok(())
# }
```

A memory limit alone lets a tree that reaches it go on in swap, and a swap limit
of 0 keeps the tree in memory. A host that does not account swap has no
`memory.swap.max`, and the library refuses the launch with
`Error::CgroupRefused`, which the example learns from `host::cgroup_blocker`
before it chooses the limits. The per-process limits bound less: each process can hold
4 GiB of writable memory, and [Resource limits](hardening.md#resource-limits)
says how the kernel counts processes.

### Finding a delegated cgroup

A delegated cgroup is one the caller can create cgroups in. The example looks for
one in the cgroup it runs in:

1. [`host::own_cgroup`] names the cgroup it runs in.
2. It takes that cgroup only where it runs there alone, since a cgroup that holds
   processes cannot enable a controller for its children.
3. It creates a leaf named `agent-tools`, and moves itself into it. The
   commands' cgroups are then created beside the leaf. The move is the
   example's own: the library moves no process of the caller's.
4. [`host::cgroup_blocker`] answers whether the cgroup can hold a command's
   cgroup with the limits, by the steps a launch takes. Its answer is the
   refusal a launch would fail with: a cgroup not delegated to the example, a
   controller the cgroup does not offer, or a kernel without
   `memory.swap.max`, among others.

Where a step fails, the example uses the per-process limits, and says why on
standard error. A scope from `systemd-run --user --scope -p Delegate=yes` is a
delegated cgroup with nothing else in it, and so is a service with
`Delegate=yes`.

## The report

Once the command has exited, the example reports its status and what it used, on
standard error. Under a cgroup the figures are the whole tree's: processor time,
peak memory, the most processes at once, and the processes the memory limit
ended. Otherwise they are the processor time of the command and its collected
descendants, and the peak memory of the largest one process. A command that
allocates past the memory limit reports:

```text
agent-tools: limits on the whole tree, in a cgroup beneath /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/run-r2d51.scope
agent-tools: the command's status: terminated by signal 9
agent-tools: the whole tree used 0.16 s of user time and 1.98 s of system time, and held at most 4096.0 MiB of memory and 3 processes
agent-tools: the memory limit ended a process of the tree
```

A command that ignores the request to stop is killed. The kill ends the
sandbox's init before it reports, as [The process
model](process-model.md#resource-usage) sets out, so a killed command reports
the whole tree's figures under a cgroup and none otherwise.

The example exits with the command's own exit code, or 128 plus the number of
the signal that ended it. A command that outlives `--timeout` gives 124, as
`fcage --timeout` does.

## From the command line

`crates/ferroday-cage/examples/agent-tools.toml` gives `fcage` the same sandbox.
The profile holds what every command shares. The command line adds the working
tree, its protected paths, and a forward of the loopback port to the runtime's
service on the host:

```sh
fcage --profile crates/ferroday-cage/examples/agent-tools.toml \
    --bind "$PWD" "$PWD" --chdir "$PWD" --hide "$PWD/.env" \
    --read-only "$PWD/.git/hooks" --read-only "$PWD/.git/config" \
    --forward-loopback 8080 127.0.0.1:8080 \
    --timeout 600 -- git status
```

`--forward-loopback` copies each connection to the target the service listens
at on the host, a TCP address or a unix socket.

The profile carries the per-process limits. With a delegated parent,
`--cgroup-parent DIR` adds limits on the whole tree, each named by a `--cgroup`
flag: `--cgroup memory-max=4294967296`, `--cgroup memory-swap-max=0` and
`--cgroup pids-max=1024`. [Limits on the whole
tree](hardening.md#limits-on-the-whole-tree) shows a shell moving itself into a
leaf first.

The profile leaves the unix-socket restriction to the host root's default,
which applies where the kernel enforces it. `--landlock-resolve-unix` asks for
it outright, and a kernel below Landlock ABI 9 then refuses the launch. The example's tests hold the profile, composed
with the flags above, to the sandbox the example builds.

## Running the example

The example lives at `crates/ferroday-cage/examples/agent-tools.rs` and needs
the `hardening` feature. `--worktree` names the working tree, and the current
directory is the working tree without it. A command without a slash is found on
the sandbox's `PATH`:

```sh
cargo run --example agent-tools --features hardening -- \
    --worktree ~/project -- git status
cargo run --example agent-tools --features hardening -- \
    --worktree ~/project -- curl -s http://127.0.0.1:8080/status
```

To bound the whole tree, run the example in a scope of its own. `cargo run`
replaces itself with the example, which then runs in the scope alone:

```sh
systemd-run --user --scope -p Delegate=yes \
    cargo run --example agent-tools --features hardening -- \
    --worktree ~/project -- git status
```

## What stays in view

The sandbox confines what the command writes and whom it talks to. Three things
remain the caller's to decide:

- The rest of the host's tree stays readable, `/etc`, `/opt` and `/sys` among
  it. A path there that holds a secret is hidden with `--hide`, or left out by
  `--empty-root`.
- The service is as narrow as its policy. A proxy that admits every
  destination gives the command the network.
- The curated seccomp roster is a convenience posture rather than a boundary
  claim, and neither limit covers I/O or disk use. [What this boundary does not
  cover](hardening.md#what-this-boundary-does-not-cover) sets out the rest.

[`host_rootfs`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.host_rootfs
[`read_only`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.read_only
[`present_as`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.present_as
[`SeccompRules::curated`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.SeccompRules.html#method.curated
[`landlock_resolve_unix`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.landlock_resolve_unix
[`host::landlock_enforces_fs`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.landlock_enforces_fs.html
[`host::own_cgroup`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.own_cgroup.html
[`host::cgroup_blocker`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.cgroup_blocker.html
[`Pending::listen`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Pending.html#method.listen
[`Running::try_wait`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Running.html#method.try_wait
[`Escalation`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/relay/struct.Escalation.html
