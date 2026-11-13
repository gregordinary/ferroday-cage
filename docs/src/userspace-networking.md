# Userspace networking

The default network is an isolated namespace whose only interface is loopback:
the sandbox can talk to itself and nothing else. [`Network::Host`] trades that
isolation for the host's interfaces, and [`Network::None`] removes even
loopback. Between them sits a third option — an isolated namespace that still
reaches the outside, through a *userspace network stack*.

A userspace network stack terminates the sandbox's network traffic in ordinary
host sockets: a tap interface inside the namespace carries the guest's packets,
a stack reads them, and it forwards the flows out through the host as any
application would. The library ships its own, the native stack, behind the
`netstack` feature; it also leaves the seam open for an external stack such as
[`pasta`] or [`slirp4netns`]. Either way the sandbox keeps its private
namespace and the host network policy stays outside it.

## The seam

Attaching a stack has an ordering requirement: the tap must exist before the
command relies on the network, or the command's first socket call races the
stack's startup. The seam is a pause that removes the race.

[`Cage::spawn_pending`] builds the sandbox — creating its namespaces — but
holds the command at a gate just before it runs, returning a [`Pending`]
handle instead of a running one. The handle exposes
[`netns_pid`][`Pending::netns_pid`], a host pid of a process inside the
sandbox's network namespace. A stack attaches to that namespace, and
[`proceed`][`Pending::proceed`] then releases the command and returns the usual
[`Running`] handle. Because the stack is up before the command runs, the
sandbox sees the network from its first instruction.

Dropping a `Pending` without proceeding tears the launch down — the supervisor
is killed and the launch stage reaped — so an aborted attach leaves no sandbox
running. [`spawn_pending_with`][`Cage::spawn_pending_with`] is the streaming
counterpart: it binds an observer that receives the command's output once
`proceed` releases it.

The seam is meaningful only where the sandbox has a private network namespace:
[`Network::Isolated`] (the default) or [`Network::None`]. Under
[`Network::Host`] the sandbox shares the host's namespace, where attaching a
stack is neither needed nor correct.

## A listener on the sandbox's loopback

A sandbox often needs exactly one way out: the command speaks TCP to a loopback
address, such as an HTTP base URL, and the service it reaches lives outside.
[`Pending::listen`] serves that without a stack. It makes a TCP listener on the
sandbox's loopback and hands it to the caller, which accepts the connections the
command makes there:

```rust,no_run
# use ferroday_cage::Cage;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let cage = Cage::builder().rootfs("/srv/rootfs").command("/usr/bin/agent").build()?;
let pending = cage.spawn_pending()?;
let listener = pending.listen("127.0.0.1:4100".parse()?)?;
let mut running = pending.proceed()?;
std::thread::spawn(move || {
    for connection in listener.incoming() {
        // ... serve the command's request, or carry it elsewhere ...
        # let _ = connection;
    }
});
let status = running.wait()?;
# let _ = status;
# Ok(())
# }
```

The listener belongs to the sandbox's network namespace, and the caller holds
it. Nothing of the caller's runs inside the sandbox, so the command is the
sandbox's only program, and a [`terminate`][`Running::terminate`] reaches the
command itself rather than a relay standing in front of it. Made before
`proceed`, the listener is in place for the command's first connection.

The address is a loopback address, in `127.0.0.0/8` or `::1`, on any port. A
privileged port is as available as any other: a helper process makes the
listener inside the sandbox's user namespace, where it holds
`CAP_NET_BIND_SERVICE`. Only [`Network::Isolated`] gives the sandbox a loopback
of its own, so a sandbox under [`Network::None`] or [`Network::Host`] is refused
with [`Error::ListenRefused`], as is an address that is not a loopback one.

A socket keeps its network namespace alive. The listener therefore keeps the
sandbox's namespace in being until the caller closes it, and once the sandbox
has exited an `accept` on it waits for a connection that cannot come. The caller
closes the listener when its wait returns, and a thread of its own that accepts
is released by a `shutdown` of the listener's socket or by polling it beside a
signal of the caller's.

A Landlock network grant governs `connect` to every TCP port, loopback
included. A sandbox carrying one grants `NetAccess::CONNECT` on the listener's
port, or the command's connection is refused.

`fcage --forward-loopback PORT TARGET` is the command-line form, over the same
call. `PORT` is an `ADDRESS:PORT` or a bare port on `127.0.0.1`, and `TARGET` is
an absolute path naming a unix socket or an `ADDRESS:PORT` on the host. The flag
is repeatable, needs the isolated network, and composes with `--netstack`.

Each forward is one thread of `fcage`'s, however many connections the command
makes. It accepts each connection and carries it to the target, each direction
ending on its own: a command that shuts down its sending half still receives the
reply. Its bounds are the network stack's for a published port:

- A forward holds at most 128 connections at once, counting those whose
  connection to the target is still being made. A connection past that is
  reset at once, so the command's first read fails rather than reading an
  empty reply. The first is reported on standard error, and later ones are
  not.
- A connection the target refuses, or does not take within 30 seconds, has
  the command's connection reset. The first such failure is reported on
  standard error, and later ones are not until a connection to the target is
  made again. A unix socket whose accept queue is full is tried again until
  then.
- Each direction holds at most 64 KiB on its way across, so a peer that stops
  reading stalls only the direction toward it.
- A forward never waits on standard error to report. Its reports go to one
  thread of `fcage`'s that writes them, so a reader that stops reading stalls
  no connection. A report past the 64 still waiting is dropped, and the number
  dropped is reported once the rest are written. The run's end waits for the
  reports to be written.

A connection ends in order once both directions have ended, and every other
end resets it: a failure of either side resets the other, as the network stack
does for a flow, so a peer reading to the end never takes a cut-off stream for
a complete one. A unix target has no reset to read, and reads an end of stream.
The run's end resets every forwarded connection still open, whatever its peers
are doing, and closes the listener. A connection still being made is abandoned,
and what a connection holds that its peer has not taken is dropped.

## The native stack

With the `netstack` feature, [`NetStack`] is the library's own stack, attached
from inside the caller's own process. It creates and configures
the tap device in the sandbox's namespace, terminates the guest's TCP and UDP
flows in an in-process TCP/IP implementation, and forwards each over an
ordinary host socket. The result is unprivileged outbound IPv4 and IPv6: the
host sees a normal application making connections, and the sandbox sees a
gateway to the world. Connections run the other way only through a port the
caller [publishes](#publishing-a-port).

A stack is built from a [`NetStackBuilder`], attached to a pending launch, and
stopped once the command has finished:

```rust,no_run
# use ferroday_cage::{Cage, NetStack};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let cage = Cage::builder().rootfs("/srv/rootfs").command("/usr/bin/job").build()?;
let stack = NetStack::builder().build()?;

let pending = cage.spawn_pending()?;
let handle = stack.attach(&pending)?; // the tap is up and configured
let mut running = pending.proceed()?; // the command runs with the network live
let status = running.wait()?;
handle.stop()?; // tear the stack down after the command
# let _ = status;
# Ok(())
# }
```

One `NetStack` attaches to any number of sandboxes; each attachment runs its
own pump and configures its guest independently. Their host resources are not
isolated from one another, though — see [Resource model and
tenancy](#resource-model-and-tenancy). [`NetStack::default`] is the default
configuration, ready to attach as-is.

### Defaults

The builder configures the addressing and interface. Within a configured
network the stack always places the gateway at host 2 and the guest at host
15.

| Setting | Default | Builder method |
|---|---|---|
| IPv4 | on | [`ipv4`][`NetStackBuilder::ipv4`] |
| IPv6 | on | [`ipv6`][`NetStackBuilder::ipv6`] |
| IPv4 network | `10.0.2.0/24` (guest `.15`, gateway `.2`) | [`ipv4_cidr`][`NetStackBuilder::ipv4_cidr`] |
| IPv6 network | `fd00::/64` (guest `::15`, gateway `::2`) | [`ipv6_cidr`][`NetStackBuilder::ipv6_cidr`] |
| MTU | 1500 | [`mtu`][`NetStackBuilder::mtu`] |
| Interface name | `tap0` | [`interface`][`NetStackBuilder::interface`] |
| Host-loopback mapping | off | [`host_loopback`][`NetStackBuilder::host_loopback`], [`host_loopback_port`][`NetStackBuilder::host_loopback_port`] |
| Published ports | none | [`publish`][`NetStackBuilder::publish`] |

With the `serde` feature the builder is also the stack's profile format: it
serializes and deserializes as the stack specification, for embedding in a
consumer's own configuration. Keys are kebab-case, unknown keys are rejected,
and the CIDR fields read and write as `"address/len"` strings.

### The handle owns the stack

[`attach`][`NetStack::attach`] returns a [`NetStackHandle`] that owns the pump
thread serving the tap. The pump holds the tap descriptor open, which pins the
device and, through it, the sandbox's network namespace — so the pump never
observes the sandbox's death on its own. Two rules follow:

- **Wait, then stop.** Wait for the command to finish, then call
  [`stop`][`NetStackHandle::stop`]. `stop` signals the pump, joins it, and
  reports any error the pump ended on. Stopping before the command exits
  simply cuts the network early. The host peer of each connection still open
  is reset, and the guest's side is left to the guest's own timeouts.
- **Dropping the handle is safe.** A dropped handle stops the pump the same
  way and discards its outcome. It never affects the sandbox: a running
  command merely loses connectivity. The stack is an attachment, not a
  lifeline.

[`is_running`][`NetStackHandle::is_running`] reports whether the pump is still
serving the tap — false after `stop`, or on its own if the pump hit an
unrecoverable error, which `stop` then reports.

### Resource model and tenancy

Each attachment bounds what one guest can consume. A guest serves at most 128
concurrent TCP flows of its own and 128 more through its published ports. It
tracks at most 256 UDP flows, and every flow holds a host socket. The TCP caps
count flows in flight rather than connections made. A flow's slot, buffers, and
host socket are released once the exchange has closed on both sides, whichever
closed first. A guest opening and closing connections back to back is therefore
not throttled by the table.

A connection that ends any other way ends with a reset to each peer it has.
That covers a reset from either peer, a host connect that fails, and a flow the
stack reclaims: one that has not established both sides within 30 seconds, or
one where a peer has finished sending and the other stops reading what it sent,
so that the flow moves nothing for 100 seconds. Neither peer is handed an end of
stream for a connection that did not finish, so a cut-off transfer never reads
as a complete one.

Those caps are per attachment, not per process. The pump and every host socket
run in the caller's own process. Several attachments in one process therefore
share one descriptor table and one heap, which the per-guest caps do not
partition. Once the process reaches its `RLIMIT_NOFILE`, a guest that fills its
own budget can starve a co-resident attachment, or the caller's own opening of
descriptors.

The native stack is accordingly intended for one — or a few mutually trusted —
sandboxes per process. A caller that must isolate untrusted tenants from one
another should run each in its own process, or [supply an external
stack](#bring-your-own-stack) whose resource accounting is the operating
system's rather than one shared address space's.

### What the stack forwards

The stack is an egress NAT. A destination it accepts is reached from the host's
own network position and source address. The guest therefore reaches what the
host reaches, the host's network neighbors included. A host service bound to a
wildcard address, `0.0.0.0` or `::`, answers on the host's own addresses. The
guest reaches it there, though its loopback address is refused. A caller that
must bound egress confines it outside the stack, with a host firewall or an
[external stack](#bring-your-own-stack) of its own.

A [Landlock network rule](hardening.md#landlock-network-rules) bounds egress by
port from inside the sandbox, and the stack carries nothing past it. Once a
stack is attached, the rule is that bound rather than an addition to the
namespace's, so [`attach`][`NetStack::attach`] refuses a sandbox whose rule the
kernel cannot enforce: below Landlock ABI 4, or without the LSM.

Multicast, broadcast, unspecified, loopback, and link-local destinations are
always refused. Refusing loopback keeps the sandbox away from services bound to
the host's `127.0.0.1`.

Link-local covers the cloud metadata services at `169.254.169.254`. AWS also
serves its instance services over IPv6, from `fd00:ec2::/32`. That block holds
the metadata service at `fd00:ec2::254`, the DNS resolver, and the time service.
It is a unique local block the host routes like any other, so the stack refuses
it by name. A metadata service at any other routable address is reachable.

Only TCP and UDP from the guest's own address are carried. A segment or datagram
from any other source is dropped, since no reply to it could be delivered.

A refused TCP connection is answered with a reset, so denial costs the guest
nothing. A refused UDP datagram is dropped. Whether the guest also receives an
ICMP port-unreachable depends on whether the stack holds a socket on that port
for another destination. Read nothing into either outcome. One refusal reaches
the guest by silence rather than by a reset, described below.

Two refusals follow from the same principle. The IPv4 `0.0.0.0/8` block is
refused in full rather than only the unspecified address, and an IPv6 address
that embeds an IPv4 one — the mapped `::ffff:a.b.c.d` and the deprecated
compatible `::a.b.c.d` alike — is refused so that an IPv4 refusal cannot be
re-expressed in the other family. The guest's own subnet is refused too: it is a
private link between the guest and the stack, and forwarding it would send the
guest's on-link traffic to the host's view of those addresses, which collides
with a real LAN wherever the default `10.0.2.0/24` overlaps one.

NAT64's well-known prefix, `64:ff9b::/96`, is how an IPv6-only host reaches IPv4
destinations, through a translator that connects to the IPv4 address in the last
32 bits. The guest reaches what the host reaches, so the prefix is carried. The
embedded address is held to the IPv4 rules, so `64:ff9b::169.254.169.254` is
refused and `64:ff9b::203.0.113.9` is carried. A network-specific translation
prefix looks like any other routable address, and the stack treats it as one.

That subnet refusal is the silent one. Those addresses are on-link from the
guest's point of view, so it resolves a hardware address before it sends a
segment, and the stack answers ARP and neighbor discovery only for the gateway.
Nothing replies, and the connection fails a few seconds later, when the guest's
own address resolution gives up.

### What answers, and what checks reachability

The stack holds one address per family — the gateway — and answers for that and
nothing else. That is narrower than it sounds, because the interface accepts
packets for every destination so that routed traffic reaches its sockets, and
accepting a packet and answering for its address are the same question to the
underlying stack. The pump asks the narrower one instead: an address-resolution
request or an ICMP echo request naming an address the stack does not hold is
dropped before the interface can answer it.

The stack answers ICMP echo for the gateway, and a sandboxed command cannot send
one. `ping` needs a raw socket or an ICMP datagram socket, and the command holds
no capability over the sandbox's network namespace and is outside that
namespace's `ping_group_range`, so `ping` is refused in every sandbox, with a
stack attached or without one; [what the command gives
up](how-the-sandbox-is-built.md#what-the-command-gives-up) explains why. A
refused `ping` says nothing about the stack. A TCP or UDP connection is the
reachability check, since those are what the stack forwards: a connection to a
destination reports whether that destination answers.

The gateway address is the one deliberate exception. With
[`host_loopback(true)`][`NetStackBuilder::host_loopback`], a connection to the
gateway (`10.0.2.2` or `fd00::2` by default) is forwarded to the host's
`127.0.0.1` or `::1`, port preserved — the conventional way to reach a
host-local service, granted explicitly rather than by opening the whole
loopback range.

[`host_loopback_port`][`NetStackBuilder::host_loopback_port`] grants the same
mapping one port at a time. A command that needs the host's database and
nothing else names that database's port, and every other port of the gateway
stays refused. The two combine, so `host_loopback(true)` beside a named port
maps every port. TCP and UDP are mapped alike.

The mapping lands on that one address, so it reaches a host service only if the
service is bound there. A service on another loopback address is not reached,
and systemd-resolved's `127.0.0.53` stub is the case that catches people out:
it is a loopback destination like any other, so the guest cannot address it
directly, and the gateway mapping goes to `127.0.0.1` where the stub is not
listening.

### Publishing a port

Everything above is the guest reaching out. [`publish`][`NetStackBuilder::publish`]
runs a connection the other way, for a server inside the sandbox, such as a
development web server. The stack listens on a host address, and carries each
connection it accepts to a TCP port of the guest's:

```rust,no_run
# use ferroday_cage::{Cage, NetStack};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let cage = Cage::builder().rootfs("/srv/rootfs").command("/usr/bin/server").build()?;
let stack = NetStack::builder()
    .publish("127.0.0.1:8080".parse()?, 80)
    .build()?;
let pending = cage.spawn_pending()?;
let handle = stack.attach(&pending)?;
let mut running = pending.proceed()?;
// http://127.0.0.1:8080/ on the host reaches port 80 in the sandbox.
let status = running.wait()?;
handle.stop()?;
# let _ = status;
# Ok(())
# }
```

A published connection reaches the guest from the gateway address, on the
guest's address of the listener's family. A guest with nothing listening on the
port refuses it, and the stack resets the host side. Once both ends are up, a
published connection is forwarded like any other flow, with the same
half-closes and the same deadlines. It counts against a budget of its own, 128
published connections at once. The stack resets a connection past that on the
host side, so its peer's first read fails rather than reading an empty reply.
A peer holding published connections open cannot crowd out the guest's own
connections, nor the guest's crowd out the published ones.

The host address decides who can connect. `127.0.0.1` admits the host's own
processes, and every local user's process is among them. `0.0.0.0` or `::`
admits whatever reaches the host over the network. The stack listens where it is
told and imposes nothing further.

`attach` binds the listeners, so an address that something else holds fails
there, as `NetStackError::Publish`. Port 0 has the kernel choose a free one, and
[`NetStackHandle::published`] reports the address each listener is bound to.
Publishing covers TCP. A UDP service inside the sandbox is not reachable from
the host.

### One datagram, one packet

The stack does not fragment IP packets, in either direction. A UDP datagram
therefore has to fit in a single packet: the MTU less the family's IP header
and UDP's own eight bytes, so 1472 bytes over IPv4 and 1452 over IPv6 at the
default 1500-byte MTU. A larger reply from a host peer is dropped rather than
delivered in part, and a larger datagram from the guest never leaves it, since
the guest's own kernel fragments what it cannot send whole.

This matters mostly for DNS. A resolver that advertises a large EDNS receive
buffer — 4096 bytes is a common default for diagnostic tools, and DNSSEC
answers do reach that size — asks for answers the stack cannot carry, and the
guest sees a timeout rather than an error. Raise the MTU with
[`mtu`][`NetStackBuilder::mtu`] if the guest needs larger datagrams, or
configure its resolver for a smaller EDNS buffer.

TCP is unaffected: the stack terminates the guest's connections, so each side
segments to its own path.

### DNS

The stack carries packets; it does not resolve names. A sandbox resolves
through whatever `/etc/resolv.conf` it has, and that file is the caller's to
provide. One case needs care: a host running systemd-resolved lists only
`127.0.0.53`, a loopback stub the stack refuses, so binding that
`resolv.conf` into the sandbox yields no working DNS. A cloud host's
link-local resolver is refused the same way. Bind the host's `resolv.conf`
only when it names a nameserver the stack forwards to, point the sandbox at a
public resolver, or address services by IP.
[`forwards`][`NetStack::forwards`] answers the first question for each
address, by the stack's own rules. The [`fcage`](#the-command-line) command and
the `fetch-sandbox` example both ask it. Large answers have a size ceiling of
their own — see [One datagram, one packet](#one-datagram-one-packet).

Reaching a host-local resolver through the gateway is the remaining option,
and it has a precise requirement: the resolver must listen on `127.0.0.1`,
because that is the only address the gateway maps onto. Give the sandbox a
`resolv.conf` naming the gateway address and enable
[`host_loopback`][`NetStackBuilder::host_loopback`]. This does not work for
systemd-resolved's stub as shipped, which listens on `127.0.0.53` instead.

### One namespace move, on a helper process

Joining the sandbox's network namespace requires `CAP_SYS_ADMIN` in the
caller's own user namespace as well as the target's, and acquiring that means
entering the sandbox's user namespace first — which the kernel refuses to a
multithreaded process. `attach` therefore does its namespace work on a
freshly forked, single-threaded helper process, which joins the user and
network namespaces, creates and configures the tap, hands the descriptor back,
and exits. The caller's own threads never change namespace. This is internal
to `attach`; a consumer sees only the call.

### The command line

The [`fcage`](quick-start.md) tool exposes the native stack with `--netstack`:

```sh
fcage --rootfs ./alpine --netstack /usr/bin/wget -qO- http://example.org
```

Every builder setting has a flag. `--netstack-cidr` and `--netstack-cidr6` set
the two networks, `--netstack-mtu` and `--netstack-interface` the tap itself,
and `--netstack-host-loopback` maps the gateway address onto host `127.0.0.1`.
`--netstack-no-ipv4` and `--netstack-no-ipv6` run one protocol alone, for a host
or a workload where the other is unwanted; turning both off is refused, there
being no stack left to attach.

`--netstack-host-port PORT` maps one port of the gateway onto host loopback.
`--netstack-publish HOST GUEST_PORT` publishes a guest port, where `HOST` is an
`ADDRESS:PORT` or a bare port on `127.0.0.1`. A publication on port 0 has
`fcage` report the port the kernel chose, on standard error, before the command
starts.

`--netstack` binds the host's `resolv.conf` into the sandbox when it names a
nameserver the stack forwards to. A host whose resolvers are all loopback or
link-local composes nothing and warns. The sandbox then keeps whatever
`resolv.conf` its rootfs ships, which may name a routable resolver and work
perfectly well. The warning reports what was not composed rather than
predicting the run's DNS.

`--no-resolv-conf` opts out of the composition, and so does
`--no-managed-mounts`, whose promise is that the sandbox carries exactly the
binds the command line names. A profile setting either toggle governs it the
same way. A mount of the caller's own onto `/etc/resolv.conf` replaces the
composed one rather than sitting under it, whether `--bind`, `--ro-bind` or
`--raw-mount` made it. So does a host directory bound over `/etc`. A run that
supplies its own resolver configuration therefore need not also decline this
one. These are the rules the library's own bind follows for a host-network
sandbox, read from [`get_resolv_conf`][`CageBuilder::get_resolv_conf`]. A
rootfs that ships no `/etc/resolv.conf` gets one created to mount onto and
taken away again afterwards, as every file bind target does. The flag conflicts
with `--share-net` and with `--restrict`.

### A worked example

The `fetch-sandbox` example provisions an Alpine root, attaches the stack, and
fetches a URL. It drives the stack's whole life in order, from the builder to
`stop`:

```sh
cargo run --example fetch-sandbox --features netstack,tarball -- \
    --rootfs ./alpine --tarball alpine-minirootfs.tar.gz http://example.org
```

## Bring your own stack

The seam also accepts an external stack. `slirp4netns` takes the target pid and
a tap name, creates the tap inside the namespace, and signals readiness by
writing one byte to a caller-provided descriptor. A consumer wires that
descriptor to the seam:

```rust,ignore
let pending = cage.spawn_pending()?;
let pid = pending.netns_pid();

// slirp4netns <pid> tap0 --configure --ready-fd=<fd>
let (ready_read, ready_write) = /* a pipe */;
let mut helper = Command::new("slirp4netns")
    .args([&pid.to_string(), "tap0", "--configure", "--ready-fd=3"])
    .fd(3, ready_write) // the ready descriptor as fd 3 in the child
    .spawn()?;

// Block until slirp4netns has created and configured the tap.
read_one_byte(&ready_read)?;

let mut running = pending.proceed()?;
let status = running.wait()?;

// The helper runs for the sandbox's lifetime; it exits when the namespace
// goes away, and the caller reaps it.
helper.wait()?;
```

The helper is the caller's process to own: it runs alongside the sandbox,
exits when the sandbox's network namespace is destroyed, and is reaped by the
caller. The library's responsibility ends at the namespace and the gate.

## What the seam provides

The seam gives a stack exactly two things: a network namespace with a live
process to target, and the guarantee that the command does not run until the
caller proceeds. Everything else — which stack, its addressing, port
forwarding, DNS — is the stack's, whether that is the native [`NetStack`] or an
external helper. A stack that needs the sandbox to reach it over loopback finds
loopback already up under [`Network::Isolated`]; one that configures every
interface itself can start from the bare namespace of [`Network::None`].

A stack carries what routes through the namespace and nothing else. Whichever
stack is attached, the command keeps [the network
filter](how-the-sandbox-is-built.md#the-network-filter), which refuses vsock and
the other routes out that a namespace does not cover. The stack itself runs
outside the sandbox and is not filtered.

[`Network::Host`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.Network.html
[`Network::Isolated`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.Network.html
[`Network::None`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.Network.html
[`Cage::spawn_pending`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Cage.html#method.spawn_pending
[`Cage::spawn_pending_with`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Cage.html#method.spawn_pending_with
[`Pending`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Pending.html
[`Pending::netns_pid`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Pending.html#method.netns_pid
[`Pending::proceed`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Pending.html#method.proceed
[`Running`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Running.html
[`Pending::listen`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Pending.html#method.listen
[`Running::terminate`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Running.html#method.terminate
[`Error::ListenRefused`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.Error.html#variant.ListenRefused
[`NetStack`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStack.html
[`NetStack::attach`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStack.html#method.attach
[`NetStack::default`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStack.html
[`NetStack::forwards`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStack.html#method.forwards
[`CageBuilder::get_resolv_conf`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.get_resolv_conf
[`NetStackBuilder`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackBuilder.html
[`NetStackBuilder::ipv4`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackBuilder.html#method.ipv4
[`NetStackBuilder::ipv6`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackBuilder.html#method.ipv6
[`NetStackBuilder::ipv4_cidr`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackBuilder.html#method.ipv4_cidr
[`NetStackBuilder::ipv6_cidr`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackBuilder.html#method.ipv6_cidr
[`NetStackBuilder::mtu`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackBuilder.html#method.mtu
[`NetStackBuilder::interface`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackBuilder.html#method.interface
[`NetStackBuilder::host_loopback`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackBuilder.html#method.host_loopback
[`NetStackBuilder::host_loopback_port`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackBuilder.html#method.host_loopback_port
[`NetStackBuilder::publish`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackBuilder.html#method.publish
[`NetStackHandle::published`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackHandle.html#method.published
[`NetStackHandle`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackHandle.html
[`NetStackHandle::stop`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackHandle.html#method.stop
[`NetStackHandle::is_running`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackHandle.html#method.is_running
[`pasta`]: https://passt.top/
[`slirp4netns`]: https://github.com/rootless-containers/slirp4netns
