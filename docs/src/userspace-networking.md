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
network the stack always places the gateway at host 2, its nameserver at host
3, and the guest at host 15.

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
| Nameserver | on, asking the host's resolver | [`nameserver`][`NetStackBuilder::nameserver`], [`upstream`][`NetStackBuilder::upstream`] |
| Destination rules | none | [`allow`][`NetStackBuilder::allow`], [`deny`][`NetStackBuilder::deny`] |

With the `serde` feature the builder is also the stack's profile format: it
serializes and deserializes as the stack specification, for embedding in a
consumer's own configuration. Keys are kebab-case, unknown keys are rejected,
the CIDR fields read and write as `"address/len"` strings, and the `allow` and
`deny` lists hold each rule as its text. Each setting reads back through a
getter named for it, such as [`get_allow`][`NetStackBuilder::get_allow`] for
`allow`. A consumer can then inspect a specification it loaded before it
builds the stack.

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
guest reaches it there, though its loopback address is refused. A caller bounds
that with [destination rules](#destination-rules).

A [Landlock network rule](hardening.md#landlock-network-rules) bounds egress by
port from inside the sandbox, and the stack carries nothing past it. Once a
stack is attached, the rule is that bound rather than an addition to the
namespace's, so [`attach`][`NetStack::attach`] refuses a sandbox whose rule the
kernel cannot enforce: below Landlock ABI 4, or without the LSM.

Multicast, broadcast, unspecified, loopback, and link-local destinations are
always refused. Refusing loopback keeps the sandbox away from services bound to
the host's `127.0.0.1`.

Link-local covers the cloud metadata services at `169.254.169.254`. Clouds also
serve them over IPv6, at unique local addresses the host routes like any other,
so the stack refuses them by name:

- AWS's `fd00:ec2::/32`, which holds the metadata service at `fd00:ec2::254`,
  the DNS resolver, and the time service.
- Google Cloud's metadata server at `fd20:ce::254`.
- Oracle Cloud's metadata service at `fd00:c1::a9fe:a9fe`.

A metadata service at any other routable address is reachable.

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

### Destination rules

[`allow`][`NetStackBuilder::allow`] and [`deny`][`NetStackBuilder::deny`]
bound where the guest's flows go. Each takes a [`DestinationRule`], parsed from
the text `fcage` and the stack's profile format take as well:

| Rule | Matches |
|---|---|
| `192.0.2.7`, `2001:db8::1` | the address |
| `192.0.2.0/24`, `2001:db8::/32` | every address in the network |
| `example.com` | the name, by way of the stack's [nameserver](#names) |
| `*.example.com` | every name below `example.com`, at any depth, and not `example.com` itself |
| `RULE:443`, `RULE:80,443`, `RULE:8000-8999` | the rule, on those ports alone |
| `tcp:RULE`, `udp:RULE` | the rule, over that transport alone |

An IPv6 address or network with ports is bracketed, as in `[2001:db8::1]:443`.
Unbracketed, its colons are its own and it carries no ports. An address rule
covers TCP and UDP unless a transport says otherwise. A name rule admits TCP
alone, so `udp:` does not qualify one. A name is compared without regard to
case.

The rules decide a destination together:

- A deny rule that matches refuses it, whatever else matches.
- Once any allow rule is given, a destination no allow rule admits is refused.
- With deny rules alone, a destination no deny rule refuses is carried.
- With no rules, the stack carries what it always has.

So allow rules alone read as "only these", and deny rules alone as "everything
but these":

```rust
# use ferroday_cage::{NetStack, Transport};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
// Only the mirror's network, and only over HTTPS.
let mirror = NetStack::builder()
    .allow("tcp:203.0.113.0/24:443".parse()?)
    .build()?;
assert!(mirror.forwards(Transport::Tcp, "203.0.113.9:443".parse()?));
assert!(!mirror.forwards(Transport::Tcp, "198.51.100.1:443".parse()?));

// Everything but the local network.
let outward = NetStack::builder()
    .deny("192.168.0.0/16".parse()?)
    .deny("fc00::/7".parse()?)
    .build()?;
assert!(outward.forwards(Transport::Udp, "198.51.100.1:53".parse()?));
assert!(!outward.forwards(Transport::Tcp, "192.168.1.1:80".parse()?));
# Ok(())
# }
```

A refused destination is refused as the stack refuses any other: a TCP
connection is reset and a datagram is dropped. The stack [reports](#reports)
each refusal, naming the rule that took it. The rules belong to the stack's
configuration, so every attachment of one `NetStack` applies them, and they do
not change while a sandbox runs.

Some of the stack's behaviour sits outside the rules:

- The refusals above stand under every rule. No rule admits loopback,
  link-local, multicast, a cloud's IPv6 instance services, or the guest's own
  subnet.
- The gateway's [loopback mapping](#what-answers-and-what-checks-reachability)
  and the [published ports](#publishing-a-port) are grants of their own, and a
  rule neither widens nor narrows them.
- A connection to the [nameserver](#dns) is the stack's own too. The rules
  decide the questions it relays instead, as [names](#names) describes.
- An IPv4 rule covers the address's NAT64 spelling, `64:ff9b::a.b.c.d`, too,
  since a translator carries a flow there to the IPv4 address. A deny rule
  cannot be passed by way of the translator.

#### Names

A name rule works through the stack's [nameserver](#dns), which the sandbox's
`resolv.conf` has to name. The nameserver holds each question to the rules
before it relays anything:

- A deny name rule without ports refuses the names it matches.
- Once any allow rule is given, a name no allow name rule matches is refused.
  An address rule admits no name.
- A question for any other name is relayed to the host's resolver.

A refused name is answered NXDOMAIN, and its question never leaves the stack.
Both glibc and musl take NXDOMAIN at once and as final. A refused lookup
therefore fails without a wait and without a retry. Where the guest's resolver reads EDNS,
the answer carries Extended DNS Error 15, "Blocked", with the reason, which
`dig` shows.

The nameserver reads each answer it relays. Every address the answer gives the
asked name, through any aliases on the way, is pinned to that name for the
sandbox's life. A record's time to live does not end a pin. Programs hold an
address past it, and a content network's records often live under a minute.
A record in the answer for some other name pins nothing.

A flow is then held to the names pinned at its address:

- An allow name rule admits a TCP flow to an address pinned to a name it
  matches.
- It admits no UDP flow there. A QUIC client falls back to TCP.
- It admits no address in a private range: `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`, `100.64.0.0/10` and `fc00::/7`. A name anyone can register
  can be resolved to the host's own network, and a wildcard over such names
  would otherwise reach it.
- It admits no address on the host's own networks either, as they stand when
  the stack attaches: each network the host's routing table reaches without a
  gateway, and the network of each of its global IPv6 addresses. That covers a
  LAN numbered from global addresses, and the host's own public address, where
  a service bound to every address answers. A network the host joins later is
  not among them.
- A deny name rule refuses a flow on its ports to an address pinned to a name it
  matches. It refuses both transports, unless `tcp:` qualifies it.

An address rule admits what a name rule leaves out. Under allow rules, the stack
refuses a flow to an address it resolved no name to, unless an address rule
admits it. Such an address is a literal, or one the guest learned from a
resolver of its own. Under deny rules alone such a flow is carried. A deny name
rule then holds only where the guest resolves through the stack, or names the
server in its first bytes ([server names](#server-names)).

Under any name rule, the nameserver answers a question for a name's HTTPS or
SVCB records with none. Those records carry the keys a client encrypts its
server name with.

[`build`][`NetStackBuilder::build`] refuses `*`, and a wildcard over the names
under one label such as `*.com`, as an allow rule, since either admits nearly
every name. It refuses an allow name rule where the nameserver is turned off,
since nothing then resolves the names it admits by. Both refusals are
[`NetStackError::RuleInvalid`]. A deny name rule builds without the nameserver,
and refuses the servers flows name in their first bytes. Parsing refuses a name
whose last label is a number, such as `2130706433` or `127.1`, since some
resolvers read such a name as an address.

#### Server names

Several names share an address wherever a content network serves them, and the
name a client sends picks the site. Under name rules the stack therefore reads
the server a TCP flow's first bytes ask for before it forwards anything the
guest sent:

- **TLS**: the server name of the ClientHello, read across as many records as it
  spans. First bytes are TLS where they begin a handshake record of a version a
  server reads as TLS's, as Go's reads any below `0x1000`.
- **HTTP/1**: the `Host` header, and the host of an absolute or a `CONNECT`
  target.
- **Anything else** is carried as it stands. Its address was admitted when the
  guest connected. SSH to a Git host is the common case. Whether bytes are an
  HTTP request is judged as the most lenient server judges it, so bytes some
  server reads as one are never carried unread.

The server is held to the rules on the flow's port:

- On a flow an allow name rule admitted, an allow name rule must admit the
  server too. A client that names no server is admitted by the name it
  resolved. That is a ClientHello without a server name, or a request without a
  `Host`. An address as the host is admitted only where it is the flow's own
  destination.
- On any flow it reads, a deny name rule refuses the server it matches.
- A flow an address rule admitted is held to the deny rules alone, since the
  address is the grant.

The stack holds the guest's bytes, not the connection. The host connect starts
when the guest's does, and a server that speaks first is heard at once. A guest
that has begun a ClientHello or a request must finish it within ten seconds, or
the flow is reset. One that sends nothing is held to no deadline. First bytes
not whole within the stream's first 16 KiB are refused.

A refusal is answered in the flow's own protocol, and the flow is then closed:

| | TLS | HTTP |
|---|---|---|
| The rules refuse the server | alert `unrecognized_name` | `403 Forbidden` |
| The stack does not read the server | alert `decode_error` | `400 Bad Request` |

The alert is sent in the clear, as a server's own is before any key is agreed.
The HTTP response's body says why, in one line. Clients report the alert in
their TLS library's words:

- OpenSSL, under curl, Python and Node: `tlsv1 unrecognized name`.
- GnuTLS, under git on Debian and Ubuntu: `The server name sent was not
  recognized`.
- Go: `tls: unrecognized name`.

The stack refuses first bytes a server could read another server from than the
stack would:

- A ClientHello naming two servers, or one whose first record carries a
  version other than TLS's, which no client writes and Go's server still reads.
- A request line opened by whitespace, spaced by anything but spaces and tabs,
  or holding a control byte.
- A header folded onto a further line, or a carriage return that ends no line.
- Two `Host` headers, or user information in a target.
- HTTP/2 without TLS, whose host is in compressed headers.

A name rule is only as strong as the tie between a name and the site a flow
reaches:

- Inside TLS the stack sees neither the HTTP host nor anything after the
  ClientHello. A client can name an admitted server and ask it for another site,
  which is called domain fronting. It reaches that site wherever the content
  network still routes such a request. A name rule over a large content network
  or cloud host is weaker than it reads.
- Only the first request of a plain HTTP connection is read. A later one on the
  same connection can name another host.
- A client using Encrypted Client Hello with keys it learned elsewhere names its
  provider's public server, which is refused unless a rule admits it.
- The name a flow is held to is the one the guest asked for. The aliases its
  answer passes through are not held to the rules.
- A guest can spell data into names below an admitted wildcard, and those
  questions reach that zone's own servers. Questions for every name the rules
  refuse stay in the stack.

#### What the rules leave to the caller

The rules bound the flows the guest sends through the stack. A sandbox can have
other ways out, which the stack never sees:

- A socket in a directory bound into the sandbox, such as a service's unix
  socket. [`landlock_resolve_unix`](hardening.md#landlock-and-unix-sockets)
  refuses connections to the pathname sockets in view.
- The host's `/run`, which holds the sockets of its resolver and its message
  buses. [The host's own root](how-the-sandbox-is-built.md#the-hosts-own-root)
  hides it, and a `reveal` of it brings them back.
- A [listener on the sandbox's loopback](#a-listener-on-the-sandboxs-loopback),
  the gateway's loopback mapping, and a published port. Each is a grant of the
  caller's own.

The stack decides by address, by name, and by the server a flow's first bytes
ask for. It does not open TLS, so it holds no rule on a path, a method or a
header, and adds no credentials to a request. Those need the caller's keys and
certificate trust. A caller that needs them runs a proxy of its own. It gives
the sandbox that proxy through a listener on its loopback, or admits it with an
address rule.
[Confining an agent's tool commands](agent-tools.md) shows a listener beside a
stack bounded to package registries.

### Reports

The stack reports each decision it takes about a flow of the guest's. A flow is
a TCP connection attempt, or the datagrams between one port of the guest's and
one UDP destination. A [`NetStackReport`] names the transport, the guest's end,
and the destination, with the name the nameserver resolved to the destination's
address where it resolved one. It then says what admitted the flow or why the
stack refused it:

- A [`FlowAdmission`] says what admitted the flow: no rule refuses it, a named
  allow rule admits it, or the gateway's loopback mapping carries it.
- A [`FlowRefusal`] says why the stack refused it: no allow rule admits it, or a
  named deny rule refuses it. A name rule's refusals say no name was resolved to
  the address. Otherwise they name the rule that leaves out a UDP flow or a
  private address. A refusal at a flow's first bytes names the server they ask
  for, or says why the stack does not read it.
  Otherwise it names the kind of destination the stack always refuses, or says
  the stack already carries all the flows it holds.

The nameserver's questions are reported too, each once: relayed to the host's
resolver, refused, or answered with no HTTPS or SVCB records. A question's
report names the guest's end, the name, the record type, and the decision.

A report writes as one line:

```text
carried tcp from 10.0.2.15:41236 to 192.0.2.7:443 (example.com): the allow rule example.com admits it
refused the AAAA question for example.net from 10.0.2.15:53140: no allow rule admits it
```

[`take_reports`][`NetStackHandle::take_reports`] hands over the receiving end, a
[`NetStackReports`], which a thread of the caller's reads:

```rust,no_run
# use ferroday_cage::{Cage, NetStack};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let cage = Cage::builder().rootfs("/srv/rootfs").command("/usr/bin/job").build()?;
let stack = NetStack::builder()
    .allow("tcp:203.0.113.0/24:443".parse()?)
    .build()?;
let pending = cage.spawn_pending()?;
let mut handle = stack.attach(&pending)?;
let reports = handle.take_reports().expect("the reports are not yet taken");
let reader = std::thread::spawn(move || {
    while let Ok(report) = reports.recv() {
        if report.is_refusal() {
            eprintln!("{report}");
        }
    }
});
let mut running = pending.proceed()?;
let status = running.wait()?;
handle.stop()?;
reader.join().expect("the reader finishes");
# let _ = status;
# Ok(())
# }
```

A flow is reported once. A refused TCP attempt is answered with a reset, so the
guest does not repeat it. A refused UDP flow is reported at its first datagram.
It is reported again only after the guest has sent it nothing for two minutes,
as an idle flow expires. A TCP flow refused at its first bytes was carried when
the guest connected, and is reported a second time, refused.

The pump never waits on the reader. Its queue holds 1024 reports, and a report
it has no room for is dropped and counted, which
[`dropped`][`NetStackReports::dropped`] answers. A caller that never takes the
reports pays for the queue and nothing more. Dropping the receiving end stops
the stack making them. The reports end once the stack has stopped and
every queued report has been read, so a thread reading them ends after `stop`.

The stack's own grants are not reported: the connections a published port
accepts, and a connection or datagram to the nameserver. Its questions have
reports of their own.

A stack with no rules reports every flow it carries, with the name its
nameserver resolved for the destination. Its reports are therefore the list an
allowlist starts from.

### What answers, and what checks reachability

The stack holds the gateway's address in each family, and the nameserver's where
it serves one, and answers for those and nothing else. That is narrower than it
sounds, because the interface accepts
packets for every destination so that routed traffic reaches its sockets, and
accepting a packet and answering for its address are the same question to the
underlying stack. The pump asks the narrower one instead: an address-resolution
request or an ICMP echo request naming an address the stack does not hold is
dropped before the interface can answer it.

The stack answers ICMP echo for the addresses it holds, and a sandboxed command
cannot send one. `ping` needs a raw socket or an ICMP datagram socket, and the command holds
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
buffer asks for answers too long for one packet. Diagnostic tools commonly
advertise 4096 bytes, and DNSSEC answers do reach that size. The stack's
own [nameserver](#dns) answers such a query truncated, and the guest's resolver
asks again over TCP. A guest that asks a resolver past the stack directly gets
no such answer: the reply is dropped, and the guest sees a timeout rather than
an error. Raise the MTU with [`mtu`][`NetStackBuilder::mtu`] if the guest needs
larger datagrams from such a resolver, or configure the resolver for a smaller
EDNS buffer.

TCP is unaffected: the stack terminates the guest's connections, so each side
segments to its own path.

### DNS

The stack serves the guest's DNS. Its nameserver answers on port 53, over UDP
and TCP, at host 3 of each network: `10.0.2.3` and `fd00::3` by default, the
addresses [`nameservers`][`NetStack::nameservers`] returns. It relays each query
to a resolver of the host's and the answer back. That resolver is the first
nameserver the host's `/etc/resolv.conf` names when the stack attaches. Where
the file names none, the stack asks `127.0.0.1`, as the host's C library does.
[`upstream`][`NetStackBuilder::upstream`] names another, on any port.

The stack's sockets are the host's, so a resolver on the host's loopback is
reached, though the guest's own connections to loopback are refused. A host
running systemd-resolved names only its `127.0.0.53` stub, which is the common
case. A cloud host's link-local resolver is reached the same way. The stub then
resolves for the sandbox as it does for the host, split DNS and VPN routes
included.

The sandbox's `resolv.conf` has to name the nameserver for the guest to ask it.
[`CageBuilder::nameservers`] places one, a file of the sandbox's own, under the
same rules as the library's other managed mounts:

```rust,no_run
# use ferroday_cage::{Cage, NetStack};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let stack = NetStack::default();
let cage = Cage::builder()
    .rootfs("/srv/rootfs")
    .nameservers(stack.nameservers())
    .command("/usr/bin/job")
    .build()?;
let pending = cage.spawn_pending()?;
let handle = stack.attach(&pending)?;
let mut running = pending.proceed()?;
let status = running.wait()?;
handle.stop()?;
# let _ = status;
# Ok(())
# }
```

Under [destination rules](#names), the nameserver answers a question for a name
the rules refuse itself. The addresses its answers give are what a name rule
admits a flow by.

Each query goes upstream on a socket of its own, over the transport the guest
asked on. An answer too long for one packet is answered truncated, which sends
the guest's resolver to TCP. The nameserver relays at most 64 queries at once,
each given up after five seconds, and serves at most 16 TCP connections. A
datagram past those bounds is dropped, and a query on a TCP connection is
answered with SERVFAIL. So is a query the resolver refuses.

[`nameserver(false)`][`NetStackBuilder::nameserver`] turns the nameserver off.
Host 3 is then refused, as the rest of the guest's subnet is. The sandbox
resolves through whatever its `resolv.conf` names that the stack forwards to.
[`forwards`][`NetStack::forwards`] answers that for each address, by the stack's
own rules.

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

A profile's `[netstack]` table holds the same settings in the stack's own
format, and `--netstack` attaches the stack it configures. The flags compose
with it as with the rest of a profile, as [Profiles at the command
line](profiles.md#profiles-at-the-command-line) sets out. A policy can
therefore live in the profile beside the sandbox it bounds:

```toml
[netstack]
allow = ["index.crates.io:443", "static.crates.io:443"]
```

`--netstack-upstream ADDRESS` has the nameserver ask another resolver, on port 53
or on the port of an `ADDRESS:PORT`, and `--netstack-no-nameserver` turns the
nameserver off. `--netstack-allow RULE` and `--netstack-deny RULE` give the
[destination rules](#destination-rules), by address or by name, each as often
as needed. `--netstack-host-port PORT` maps one port of the gateway onto
host loopback.

Under destination rules, `fcage` writes each refusal the stack
[reports](#reports) on standard error, so the command's caller reads why a
connection failed:

```text
fcage: the network stack refused tcp from 10.0.2.15:41234 to 192.0.2.1:443: no allow rule admits it
```

`--netstack-log` writes every report, the flows the stack carries and the
questions it relays too. With no rules that is a log of where the sandbox goes,
by name, which is how to learn what an allowlist needs.
`--netstack-publish HOST GUEST_PORT` publishes a guest port, where `HOST` is an
`ADDRESS:PORT` or a bare port on `127.0.0.1`. A publication on port 0 has
`fcage` report the port the kernel chose, on standard error, before the command
starts.

`--netstack` names the stack's nameserver in the sandbox's `resolv.conf`,
through [`nameservers`][`CageBuilder::nameservers`], under every root, the
host's own included. `--nameserver ADDRESS` names other servers in its place.

`--no-resolv-conf` opts out, and so does `--no-managed-mounts`, whose promise is
that the sandbox carries exactly the mounts the command line names. A profile
setting either toggle, or naming nameservers, governs it the same way. A mount
of the caller's own onto `/etc/resolv.conf` replaces the file rather than
sitting under it, whether `--bind`, `--ro-bind` or `--raw-mount` made it. So
does a host directory bound over `/etc`. These are the rules every managed
`resolv.conf` follows, read from
[`get_resolv_conf`][`CageBuilder::get_resolv_conf`].

With `--netstack-no-nameserver` nothing is named, and the sandbox keeps the
`resolv.conf` its rootfs ships. The flag conflicts with `--share-net` and with
`--restrict`.

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
[`NetStack::nameservers`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStack.html#method.nameservers
[`CageBuilder::nameservers`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.nameservers
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
[`NetStackBuilder::nameserver`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackBuilder.html#method.nameserver
[`NetStackBuilder::upstream`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackBuilder.html#method.upstream
[`NetStackBuilder::allow`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackBuilder.html#method.allow
[`NetStackBuilder::deny`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackBuilder.html#method.deny
[`NetStackBuilder::get_allow`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackBuilder.html#method.get_allow
[`NetStackBuilder::build`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackBuilder.html#method.build
[`DestinationRule`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.DestinationRule.html
[`NetStackError::RuleInvalid`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.NetStackError.html#variant.RuleInvalid
[`NetStackHandle::published`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackHandle.html#method.published
[`NetStackHandle`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackHandle.html
[`NetStackHandle::stop`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackHandle.html#method.stop
[`NetStackHandle::is_running`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackHandle.html#method.is_running
[`NetStackHandle::take_reports`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackHandle.html#method.take_reports
[`NetStackReport`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.NetStackReport.html
[`NetStackReports`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackReports.html
[`NetStackReports::dropped`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStackReports.html#method.dropped
[`FlowAdmission`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.FlowAdmission.html
[`FlowRefusal`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.FlowRefusal.html
[`pasta`]: https://passt.top/
[`slirp4netns`]: https://github.com/rootless-containers/slirp4netns
