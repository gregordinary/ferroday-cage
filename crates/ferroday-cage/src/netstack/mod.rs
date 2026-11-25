//! The native userspace network stack.
//!
//! The default sandbox network is an isolated namespace whose only interface
//! is loopback. This module attaches the library's own network stack to
//! such a sandbox at the [`Pending`] seam: [`NetStack::attach`] creates a
//! tap device in the sandbox's network namespace, configures its addresses
//! and routes, and hands the device's descriptor to a pump thread in the
//! caller's process. The pump terminates the guest's TCP connections and
//! UDP flows in an in-process TCP/IP implementation and forwards each over
//! an ordinary, unprivileged host socket, so the sandbox gets outbound
//! connectivity while the host sees a normal application. The stack is
//! self-contained, and the privilege it needs is exactly what creating the
//! sandbox already granted: the caller's user owns the sandbox's user
//! namespace, and entering it confers the network capabilities inside.
//!
//! The stack is an egress NAT. An accepted destination is reached from the
//! host's own network position, so the guest reaches what the host reaches:
//! peers on the host's own networks, and a host service bound to a wildcard
//! address, through the host's own addresses. Multicast, broadcast, loopback,
//! and link-local destinations are refused, and link-local covers the IPv4
//! cloud metadata services. The clouds' IPv6 instance services, AWS's
//! `fd00:ec2::/32` and Google Cloud's and Oracle Cloud's metadata servers, are
//! refused too, under any configuration. A caller bounds the rest with destination rules, by address
//! or by name: [`allow`](NetStackBuilder::allow) names what the guest may
//! reach, and [`deny`](NetStackBuilder::deny) what it may not. One exception is
//! deliberate: [`host_loopback`](NetStackBuilder::host_loopback) and
//! [`host_loopback_port`](NetStackBuilder::host_loopback_port) map connections
//! to the gateway address onto the host's loopback. A refused TCP connection is
//! answered with a reset, with one exception: the guest's own subnet is
//! on-link from the guest's point of view, so it resolves a hardware address
//! before it sends a segment, and the stack answers address resolution only
//! for the addresses it holds. Those destinations fail when the guest's own
//! resolution gives up rather than on a reset. A refused UDP datagram is dropped, and
//! whether the guest also receives an ICMP port-unreachable depends on
//! whether the stack happens to hold a socket on that port for some other
//! destination, so a caller must not read anything into either outcome.
//!
//! The stack reports each decision it takes about a flow or a question of the
//! guest's, carried or refused and why, to a queue the caller reads through
//! [`NetStackHandle::take_reports`]. The pump never waits on that reader: a
//! report the queue has no room for is dropped and counted.
//!
//! Connections run the other way only where the caller publishes a port:
//! [`publish`](NetStackBuilder::publish) has the stack listen on a host address
//! and carry each connection it accepts to a TCP port of the guest's.
//!
//! The stack serves the guest's DNS itself, on port 53 of host 3 of each
//! network, `10.0.2.3` and `fd00::3` by default: the addresses
//! [`NetStack::nameservers`] names for the sandbox's `resolv.conf`. Its
//! nameserver relays each query to a resolver of the host's and the answer
//! back, over host sockets as everything else the stack carries. The host's
//! resolver is commonly on its loopback, which the guest itself cannot reach;
//! see [`NetStackBuilder::nameserver`]. The destination rules decide each
//! question before it is relayed, and the addresses each answer gives are what
//! a name rule admits a flow by. Under name rules the stack also reads the
//! server a TCP flow's first bytes ask for, a TLS server name or an HTTP host,
//! and holds it to the rules before it forwards anything the guest sent.
//!
//! Only TCP and UDP are forwarded, and only from the guest's own address: a
//! segment or datagram from any other source is dropped, since nothing sent
//! back to it could be delivered. The stack answers ICMP echo for the addresses
//! it holds, the gateway's and the nameserver's, and for nothing else, and a
//! sandboxed command cannot send one: it
//! holds no capability over its network namespace and is outside the
//! namespace's `ping_group_range`, so `ping` is refused inside a sandbox
//! whether or not a stack is attached. Reachability is what a TCP or UDP
//! connection reports.
//!
//! Attachment happens in a forked, short-lived helper process that joins
//! the sandbox's user and network namespaces, creates and configures the
//! tap, passes its descriptor back, and exits; the caller's own threads
//! never change namespace ([`tap`] explains why the kernel forces this
//! shape). The returned [`NetStackHandle`] owns the pump thread. The pump's
//! open tap descriptor pins the device and its namespace, so the handle
//! outlives the sandbox gracefully: wait for the command first, then
//! [`stop`](NetStackHandle::stop) the stack. Dropping the handle stops the
//! pump the same way and leaves the sandbox running — a sandbox without its
//! stack merely loses connectivity.

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::OwnedFd;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use smoltcp::wire::{IpAddress, IpEndpoint};

use crate::reports::Reports;
use crate::running::Pending;

pub use policy::{DestinationRule, ParseDestinationRuleError, Transport};
pub use report::{FlowAdmission, FlowRefusal, NetStackReport};

mod device;
mod dns;
#[cfg(fuzzing)]
pub(crate) mod fuzzing {
    //! The stack's readers of guest input, for the fuzz targets alone.

    /// Reads `message` as the stack's nameserver reads a guest's DNS message,
    /// and writes every reply it can write to it.
    pub fn dns_query(message: &[u8]) {
        super::dns::exercise(message);
    }

    /// Reads a ClientHello's body as the stack reads a TCP flow's first bytes,
    /// in one record and in records of the size `input`'s first byte gives.
    pub fn client_hello(input: &[u8]) {
        super::server_name::exercise_client_hello(input);
    }

    /// Reads `bytes` as the stack reads a TCP flow's first bytes, as a request
    /// head where they begin one.
    pub fn http_head(bytes: &[u8]) {
        super::server_name::exercise_http_head(bytes);
    }
}
mod nameserver;
mod own;
mod pins;
mod policy;
mod prefix;
mod pump;
mod report;
mod server_name;
mod sniff;
mod tap;
mod tcp;
mod udp;

/// The guest interface's MAC address: locally administered and stable, so
/// the guest side of every exchange is deterministic.
const GUEST_MAC: [u8; 6] = [0x02, 0xfc, 0x0d, 0x00, 0x00, 0x0f];

/// The gateway MAC address the stack's interface answers with.
const GATEWAY_MAC: [u8; 6] = [0x02, 0xfc, 0x0d, 0x00, 0x00, 0x02];

/// The host part of the guest's IPv4 address within the configured network.
const GUEST_HOST_V4: u32 = 15;
/// The host part of the gateway's IPv4 address. The stack's interface owns
/// this address; the guest's default route points at it.
const GATEWAY_HOST_V4: u32 = 2;
/// The host part of the guest's IPv6 address (`::15`).
const GUEST_HOST_V6: u128 = 0x15;
/// The host part of the gateway's IPv6 address (`::2`).
const GATEWAY_HOST_V6: u128 = 0x2;
/// The host part of the nameserver's IPv4 address. The stack's interface owns
/// this address where the stack serves the guest's DNS.
const NAMESERVER_HOST_V4: u32 = 3;
/// The host part of the nameserver's IPv6 address (`::3`).
const NAMESERVER_HOST_V6: u128 = 0x3;

/// The widest IPv4 prefix that leaves room for the address plan: the
/// gateway at host 2 and the guest at host 15, below the broadcast address.
const MAX_PREFIX_V4: u8 = 27;
/// The widest IPv6 prefix that leaves the address plan a full final byte.
const MAX_PREFIX_V6: u8 = 120;

/// The smallest usable MTU with IPv4 alone (RFC 791's reassembly minimum).
const MIN_MTU_V4: u16 = 576;
/// The smallest usable MTU when IPv6 is enabled (RFC 8200's link minimum).
const MIN_MTU_V6: u16 = 1280;

/// A frozen network-stack configuration, ready to attach to sandboxes.
///
/// Built by [`NetStackBuilder`]; the default configuration is valid and
/// matches the builder's defaults. One `NetStack` may be attached to any
/// number of sandboxes — [`attach`](Self::attach) borrows it and every
/// attachment is independent.
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let cage = ferroday_cage::Cage::builder().rootfs("/r").command("/bin/x").build()?;
/// use ferroday_cage::NetStack;
///
/// let stack = NetStack::default();
/// let pending = cage.spawn_pending()?;
/// let handle = stack.attach(&pending)?;
/// let mut running = pending.proceed()?;
/// let status = running.wait()?;
/// handle.stop()?;
/// # let _ = status;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct NetStack {
    plan: Plan,
}

/// The validated address and interface plan an attachment executes.
#[derive(Debug, Clone)]
struct Plan {
    /// The IPv4 side, when enabled.
    v4: Option<PlanV4>,
    /// The IPv6 side, when enabled.
    v6: Option<PlanV6>,
    /// The tap interface's MTU.
    mtu: u16,
    /// The tap interface's name inside the sandbox.
    interface: String,
    /// Which ports of the gateway address map to host loopback.
    host_loopback: HostLoopback,
    /// The guest ports published on the host, in the order they were asked
    /// for.
    publish: Vec<Publication>,
    /// Whether the stack serves the guest's DNS at its nameserver addresses.
    nameserver: bool,
    /// The resolver the nameserver asks, where the configuration names one;
    /// otherwise the host's, read when the stack attaches.
    upstream: Option<SocketAddr>,
    /// The caller's destination rules.
    policy: policy::Policy,
}

impl Plan {
    /// The addresses the stack's interface holds, each with its network's
    /// prefix length: in each enabled family the gateway, then the
    /// nameserver where the stack serves one.
    fn held(&self) -> impl Iterator<Item = (IpAddr, u8)> + '_ {
        let v4 = self.v4.iter().flat_map(move |v4| {
            let nameserver = self.nameserver.then_some(IpAddr::V4(v4.nameserver));
            [Some(IpAddr::V4(v4.gateway)), nameserver]
                .into_iter()
                .flatten()
                .map(move |address| (address, v4.prefix_len))
        });
        let v6 = self.v6.iter().flat_map(move |v6| {
            let nameserver = self.nameserver.then_some(IpAddr::V6(v6.nameserver));
            [Some(IpAddr::V6(v6.gateway)), nameserver]
                .into_iter()
                .flatten()
                .map(move |address| (address, v6.prefix_len))
        });
        v4.chain(v6)
    }

    /// Whether `destination` is the stack's nameserver: port 53 of a
    /// nameserver address, where the stack serves one.
    fn serves(&self, destination: IpEndpoint) -> bool {
        self.nameserver
            && destination.port == nameserver::PORT
            && match IpAddr::from(destination.addr) {
                IpAddr::V4(addr) => self.v4.as_ref().is_some_and(|v4| v4.nameserver == addr),
                IpAddr::V6(addr) => self.v6.as_ref().is_some_and(|v6| v6.nameserver == addr),
            }
    }

    /// Whether `addr` is the guest's own address in its family.
    ///
    /// TCP and UDP are carried from that address alone. A segment or datagram
    /// from any other source names a peer the stack has no route to: the
    /// guest's link holds no other host, and the stack resolves no neighbor but
    /// the guest. Anything sent back to such a source waits on a hardware
    /// address that never arrives, and a UDP reply waiting at the head of its
    /// port's transmit ring holds up every reply queued behind it.
    fn is_guest(&self, addr: IpAddress) -> bool {
        match IpAddr::from(addr) {
            IpAddr::V4(addr) => self.v4.as_ref().is_some_and(|v4| v4.guest == addr),
            IpAddr::V6(addr) => self.v6.as_ref().is_some_and(|v6| v6.guest == addr),
        }
    }
}

/// Which connections to the gateway address the stack carries to the host's
/// loopback, port preserved.
#[derive(Debug, Clone, Default)]
struct HostLoopback {
    /// Every port, from [`NetStackBuilder::host_loopback`].
    all: bool,
    /// The ports named one at a time, from
    /// [`NetStackBuilder::host_loopback_port`].
    ports: BTreeSet<u16>,
}

impl HostLoopback {
    /// Whether a connection to the gateway on `port` maps to host loopback.
    fn admits(&self, port: u16) -> bool {
        self.all || self.ports.contains(&port)
    }
}

/// One guest port published on the host: the stack listens on `host` and
/// carries each connection it accepts to `guest_port` on the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case", deny_unknown_fields)
)]
struct Publication {
    /// The host address to listen on.
    host: SocketAddr,
    /// The guest port each accepted connection is carried to.
    guest_port: u16,
}

/// The IPv4 half of the plan: the guest address the tap carries, and the
/// gateway and nameserver addresses the stack's interface answers for.
#[derive(Debug, Clone)]
struct PlanV4 {
    guest: Ipv4Addr,
    gateway: Ipv4Addr,
    nameserver: Ipv4Addr,
    prefix_len: u8,
}

/// The IPv6 half of the plan.
#[derive(Debug, Clone)]
struct PlanV6 {
    guest: Ipv6Addr,
    gateway: Ipv6Addr,
    nameserver: Ipv6Addr,
    prefix_len: u8,
}

impl NetStack {
    /// Returns a builder holding the default configuration.
    pub fn builder() -> NetStackBuilder {
        NetStackBuilder::default()
    }

    /// Whether the stack carries the guest's traffic over `transport` to
    /// `destination` on to the host.
    ///
    /// This is the forwarding decision every attachment makes, asked of one
    /// destination. It answers `false` for a destination the stack refuses
    /// under any configuration: loopback, link-local, multicast, a cloud's IPv6
    /// instance services, the guest's own subnet, and a protocol the
    /// configuration turns off. It answers `false` too for one the
    /// configuration's [`allow`](NetStackBuilder::allow) and
    /// [`deny`](NetStackBuilder::deny) rules refuse. The gateway address is
    /// carried only on a port [`host_loopback`](NetStackBuilder::host_loopback)
    /// or [`host_loopback_port`](NetStackBuilder::host_loopback_port) admits,
    /// whatever the rules say.
    ///
    /// A caller composing the guest's configuration asks this rather than
    /// restating the rules: one that turns the stack's nameserver off, say, and
    /// gives the guest a resolver of its own to reach through the stack.
    ///
    /// A name rule matches a destination only through the names an
    /// attachment's nameserver resolved to it, and this asks of no attachment,
    /// so it answers by the address rules: a destination a name rule alone
    /// would admit answers `false`, and one a name rule alone would refuse
    /// answers as the address rules have it.
    ///
    /// ```
    /// use ferroday_cage::{NetStack, Transport};
    ///
    /// let stack = NetStack::default();
    /// assert!(stack.forwards(Transport::Udp, "192.0.2.53:53".parse().unwrap()));
    /// // systemd-resolved's stub, and AWS's IPv4 resolver.
    /// assert!(!stack.forwards(Transport::Udp, "127.0.0.53:53".parse().unwrap()));
    /// assert!(!stack.forwards(Transport::Udp, "169.254.169.253:53".parse().unwrap()));
    ///
    /// let bounded = NetStack::builder()
    ///     .allow("tcp:192.0.2.0/24".parse().unwrap())
    ///     .build()
    ///     .unwrap();
    /// assert!(bounded.forwards(Transport::Tcp, "192.0.2.53:53".parse().unwrap()));
    /// assert!(!bounded.forwards(Transport::Udp, "192.0.2.53:53".parse().unwrap()));
    /// ```
    pub fn forwards(&self, transport: Transport, destination: SocketAddr) -> bool {
        pump::host_target(transport, destination.into(), &self.plan, None).is_ok()
    }

    /// The addresses the stack's nameserver answers on, for the sandbox's
    /// `resolv.conf` to name through
    /// [`CageBuilder::nameservers`](crate::CageBuilder::nameservers): host 3 of
    /// each enabled network, `10.0.2.3` and `fd00::3` by default, IPv4 first.
    /// Empty where
    /// [`nameserver(false)`](NetStackBuilder::nameserver) turns the
    /// nameserver off.
    ///
    /// The stack serves these, so [`forwards`](Self::forwards) answers `false`
    /// for them: nothing to them is carried on to the host. The destination
    /// rules do not decide a connection to them, since the nameserver is the
    /// stack's own. They decide the questions it relays instead.
    ///
    /// ```
    /// use ferroday_cage::{NetStack, Transport};
    ///
    /// let stack = NetStack::default();
    /// let named: Vec<String> = stack.nameservers().iter().map(|a| a.to_string()).collect();
    /// assert_eq!(named, ["10.0.2.3", "fd00::3"]);
    /// assert!(!stack.forwards(Transport::Udp, "10.0.2.3:53".parse().unwrap()));
    /// ```
    pub fn nameservers(&self) -> Vec<IpAddr> {
        if !self.plan.nameserver {
            return Vec::new();
        }
        let v4 = self.plan.v4.iter().map(|v4| IpAddr::V4(v4.nameserver));
        let v6 = self.plan.v6.iter().map(|v6| IpAddr::V6(v6.nameserver));
        v4.chain(v6).collect()
    }

    /// Attaches the stack to a pending sandbox launch.
    ///
    /// A forked helper process joins the sandbox's user and network
    /// namespaces through `/proc/<pid>/ns`, creates the tap device, assigns
    /// the guest addresses and default routes, brings the interface up, and
    /// exits. The tap's descriptor comes back to a pump thread in the
    /// caller's process, owned by the returned handle. On return the
    /// sandbox's interface is fully configured, so the caller proceeds
    /// immediately:
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let cage = ferroday_cage::Cage::builder().rootfs("/r").command("/bin/x").build()?;
    /// # let stack = ferroday_cage::NetStack::default();
    /// let pending = cage.spawn_pending()?;
    /// let handle = stack.attach(&pending)?;
    /// let mut running = pending.proceed()?;
    /// let status = running.wait()?;
    /// handle.stop()?;
    /// # let _ = status;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The sandbox must have a private network namespace —
    /// [`Network::Isolated`](crate::Network::Isolated) (the default) or
    /// [`Network::None`](crate::Network::None). A sandbox sharing the host's
    /// namespace ([`Network::Host`](crate::Network::Host)) is refused with
    /// [`NetStackError::SharedNamespace`].
    ///
    /// A sandbox carrying a Landlock network grant, from
    /// `CageBuilder::landlock_net`, is refused with
    /// [`NetStackError::LandlockNetUnenforceable`] where the kernel cannot
    /// enforce the grant: below Landlock ABI 4, or without the LSM. The stack
    /// gives the sandbox outbound TCP, so the grant is then the only bound on
    /// the ports the command reaches through it.
    ///
    /// When the configuration enables IPv6, the guest address is usable
    /// immediately where the stack could disable duplicate address detection
    /// (it tries, through the sandbox's `net.ipv6.conf` sysctls); where it
    /// could not, the kernel holds the address tentative for about a second
    /// after launch, and the guest's first IPv6 connection may stall that
    /// long. IPv4 is never delayed.
    pub fn attach(&self, pending: &Pending<'_>) -> Result<NetStackHandle, NetStackError> {
        #[cfg(feature = "hardening")]
        ensure_net_grant_enforced(
            pending.landlock_net_handled(),
            crate::mechanism::probe_landlock_abi,
        )?;

        // The published ports first, since a host address already in use is the
        // failure a caller is likeliest to meet, and it is better met before a
        // tap exists to be torn down again.
        let listeners = self
            .plan
            .publish
            .iter()
            .map(listen)
            .collect::<Result<Vec<_>, _>>()?;
        let published = listeners.iter().map(|listener| listener.bound).collect();

        // Refuse a sandbox that shares the caller's namespace: attaching
        // would create a tap on the host network, which is never what a
        // caller means.
        if pending.network() == crate::Network::Host {
            return Err(NetStackError::SharedNamespace);
        }
        let namespaces =
            pending
                .namespaces()
                .map_err(|(which, errno)| NetStackError::NamespaceJoin {
                    which,
                    source: Some(errno.into()),
                })?;

        let tap = tap::create(&namespaces, &self.plan)?;

        // What wakes the pump to stop, which stop() and a dropped handle send.
        let (stop, polled) = pump::Stop::new().map_err(|source| NetStackError::Spawn { source })?;
        let running = Arc::new(AtomicBool::new(true));
        let running_pump = Arc::clone(&running);
        let mut plan = self.plan.clone();
        // The host's own networks too, which a name rule admits no address on,
        // as they stand now.
        plan.policy.own = own::networks();
        // The host's resolver is read now, on the caller's thread, so the
        // pump does no file I/O and a stack attached later reads the host's
        // configuration as it stands then.
        let upstream = self
            .plan
            .nameserver
            .then(|| self.plan.upstream.unwrap_or_else(nameserver::host_upstream));
        let (reporter, reports) = report::Reporter::new();
        let pump = std::thread::Builder::new()
            .name("fcage-netstack".to_string())
            .spawn(move || {
                run_caught(
                    || pump::run(tap, polled, plan, listeners, upstream, reporter),
                    &running_pump,
                )
            })
            .map_err(|err| NetStackError::Spawn { source: err })?;

        Ok(NetStackHandle {
            pump: Some(pump),
            stop,
            running,
            published,
            reports: Some(reports),
        })
    }
}

/// Runs a pump on its thread, catching a panic as [`PumpExit::Panicked`], and
/// clears `running` however the pump ends, so the handle's view of the pump is
/// always truthful and [`stop`](NetStackHandle::stop) never rethrows.
fn run_caught(pump: impl FnOnce() -> PumpExit, running: &AtomicBool) -> PumpExit {
    let exit = std::panic::catch_unwind(AssertUnwindSafe(pump));
    running.store(false, Ordering::SeqCst);
    exit.unwrap_or(PumpExit::Panicked)
}

/// Refuses an attachment that would carry the guest's connections past a
/// Landlock network grant the kernel does not enforce.
///
/// Without a stack, the sandbox's network namespace bounds what a network grant
/// governs, so the command stage narrows the grant best-effort on a kernel too
/// old for it. An attached stack gives that namespace outbound TCP to every
/// destination it forwards, and the grant becomes the only bound on the ports
/// the command connects to. `net_handled` is the launch's grant mask, and
/// `landlock_abi` probes the kernel, asked only where there is a grant.
#[cfg(feature = "hardening")]
fn ensure_net_grant_enforced(
    net_handled: u64,
    landlock_abi: impl FnOnce() -> Option<i32>,
) -> Result<(), NetStackError> {
    if net_handled == 0 {
        return Ok(());
    }
    let abi = landlock_abi();
    if crate::mechanism::HardeningPlan::net_grant_unenforced(net_handled, abi) {
        return Err(NetStackError::LandlockNetUnenforceable { abi });
    }
    Ok(())
}

/// A host listener for one published port, bound and ready for the pump.
pub(super) struct Listener {
    /// The listening socket, nonblocking.
    pub(super) socket: OwnedFd,
    /// The address it is bound to, which names the port the kernel chose
    /// where the publication asked for port 0.
    pub(super) bound: SocketAddr,
    /// The guest port each accepted connection is carried to.
    pub(super) guest_port: u16,
}

/// Binds the host listener for one publication.
fn listen(publication: &Publication) -> Result<Listener, NetStackError> {
    let failed = |source| NetStackError::Publish {
        host: publication.host,
        source,
    };
    let listener = std::net::TcpListener::bind(publication.host).map_err(failed)?;
    listener.set_nonblocking(true).map_err(failed)?;
    let bound = listener.local_addr().map_err(failed)?;
    Ok(Listener {
        socket: listener.into(),
        bound,
        guest_port: publication.guest_port,
    })
}

impl Default for NetStack {
    fn default() -> Self {
        NetStackBuilder::default()
            .build()
            .expect("the default network-stack configuration is valid")
    }
}

/// How the pump thread concluded.
enum PumpExit {
    /// The pump stopped because the handle asked it to.
    Clean,
    /// The pump stopped on an unrecoverable error of its own machinery. The
    /// error is absent where the pump stopped on something that was not a
    /// syscall failure, such as a tap that read as ended.
    Failed {
        op: &'static str,
        source: Option<io::Error>,
    },
    /// The pump panicked, and the thread that runs it caught the panic.
    Panicked,
}

/// A handle to one attached network stack.
///
/// Owns the pump thread serving one sandbox's tap device. The intended order
/// is: wait for the sandbox's command, then [`stop`](Self::stop) the stack —
/// the pump holds the sandbox's network namespace open, so it never observes
/// the sandbox's death and does not stop by itself. Dropping the handle stops
/// the pump the same way, discarding its outcome. Stopping or dropping never
/// affects the sandbox: a running command merely loses connectivity.
#[derive(Debug)]
pub struct NetStackHandle {
    /// The pump thread; `None` only after `stop` or `drop` takes it.
    pump: Option<JoinHandle<PumpExit>>,
    /// What stops the pump.
    stop: pump::Stop,
    /// Cleared by the pump on every exit path.
    running: Arc<AtomicBool>,
    /// The host addresses the published ports listen on, in publication
    /// order.
    published: Vec<SocketAddr>,
    /// The receiving end of the pump's reports, until the caller takes it.
    reports: Option<Reports<NetStackReport>>,
}

impl NetStackHandle {
    /// The host addresses the published ports listen on, in the order
    /// [`publish`](NetStackBuilder::publish) named them.
    ///
    /// Each is the address the listener is bound to, so a publication that
    /// asked for port 0 reports the port the kernel chose. Empty for a stack
    /// that publishes nothing.
    pub fn published(&self) -> &[SocketAddr] {
        &self.published
    }

    /// Takes the receiving end of the stack's reports: each decision the stack
    /// takes about a flow the guest opens, carried or refused and why. `None`
    /// once it has been taken.
    ///
    /// The stack reports whether or not the caller takes the reports, and
    /// never waits on a reader: its queue holds 1024 reports, and a report
    /// it has no room for is dropped and counted. A handle whose reports are
    /// never taken therefore holds 1024 at most. Dropping the receiving end
    /// stops the stack making them.
    ///
    /// The reports end once the stack has stopped and every queued report has
    /// been read, so a thread that reads them ends after [`stop`](Self::stop):
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let cage = ferroday_cage::Cage::builder().rootfs("/r").command("/bin/x").build()?;
    /// use ferroday_cage::NetStack;
    ///
    /// let stack = NetStack::builder().allow("tcp:192.0.2.0/24:443".parse()?).build()?;
    /// let pending = cage.spawn_pending()?;
    /// let mut handle = stack.attach(&pending)?;
    /// let reports = handle.take_reports().expect("the reports are not yet taken");
    /// let reader = std::thread::spawn(move || {
    ///     while let Ok(report) = reports.recv() {
    ///         if report.is_refusal() {
    ///             eprintln!("{report}");
    ///         }
    ///     }
    /// });
    /// let mut running = pending.proceed()?;
    /// let status = running.wait()?;
    /// handle.stop()?;
    /// reader.join().expect("the reader finishes");
    /// # let _ = status;
    /// # Ok(())
    /// # }
    /// ```
    pub fn take_reports(&mut self) -> Option<Reports<NetStackReport>> {
        self.reports.take()
    }

    /// Stops the stack and reports how the pump fared.
    ///
    /// Signals the pump, waits for it to exit, and returns the first error
    /// the pump stopped on, if any. A pump that failed earlier — leaving
    /// [`is_running`](Self::is_running) false — still has its outcome
    /// reported here.
    pub fn stop(mut self) -> Result<(), NetStackError> {
        let pump = self
            .pump
            .take()
            .expect("a handle owns its pump thread until stop or drop consumes it");
        self.stop.send();
        match pump.join() {
            Ok(PumpExit::Clean) => Ok(()),
            Ok(PumpExit::Failed { op, source }) => Err(NetStackError::Pump { op, source }),
            // The pump's thread catches its panics; a join error means a panic
            // escaped the catch, which is a panic all the same. Report, not
            // rethrow.
            Ok(PumpExit::Panicked) | Err(_) => Err(NetStackError::PumpPanicked),
        }
    }

    /// Whether the pump thread is still serving the tap device.
    ///
    /// False once the stack has stopped — after [`stop`](Self::stop), or on
    /// its own if the pump hit an unrecoverable error (reported by `stop`).
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

impl Drop for NetStackHandle {
    fn drop(&mut self) {
        self.stop.send();
        // Join so the tap descriptor is closed — and the sandbox's namespace
        // released — before drop returns; the outcome is discarded, stop()
        // being the reporting path.
        if let Some(pump) = self.pump.take() {
            let _ = pump.join();
        }
    }
}

/// Builder for a [`NetStack`].
///
/// The defaults follow the established userspace-networking convention:
/// IPv4 and IPv6 both enabled, the guest at `10.0.2.15/24` and `fd00::15/64`,
/// the gateway — the stack itself — at `10.0.2.2` and `fd00::2`, MTU 1500,
/// interface `tap0`. Within a configured network the stack always places the
/// gateway at host 2 and the guest at host 15.
///
/// With the `serde` feature the builder serializes and deserializes as the
/// stack specification, for embedding in a consumer's own configuration.
/// Keys are kebab-case; unknown keys are rejected; the CIDR fields read and
/// write as strings, and each destination rule as its text. In TOML:
///
/// ```toml
/// ipv4-cidr = "10.0.2.0/24"
/// ipv6 = false
/// mtu = 1500
/// interface = "tap0"
/// host-loopback-ports = [5432]
/// allow = ["192.0.2.0/24", "[2001:db8::/32]:443"]
/// deny = ["192.0.2.7:22"]
///
/// [[publish]]
/// host = "127.0.0.1:8080"
/// guest-port = 80
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(default, rename_all = "kebab-case", deny_unknown_fields)
)]
pub struct NetStackBuilder {
    ipv4: bool,
    ipv6: bool,
    #[cfg_attr(feature = "serde", serde(with = "serde_cidr::v4"))]
    ipv4_cidr: (Ipv4Addr, u8),
    #[cfg_attr(feature = "serde", serde(with = "serde_cidr::v6"))]
    ipv6_cidr: (Ipv6Addr, u8),
    mtu: u16,
    interface: String,
    host_loopback: bool,
    host_loopback_ports: Vec<u16>,
    publish: Vec<Publication>,
    nameserver: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    upstream: Option<SocketAddr>,
    allow: Vec<DestinationRule>,
    deny: Vec<DestinationRule>,
}

impl Default for NetStackBuilder {
    fn default() -> Self {
        NetStackBuilder {
            ipv4: true,
            ipv6: true,
            ipv4_cidr: (Ipv4Addr::new(10, 0, 2, 0), 24),
            ipv6_cidr: (Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0), 64),
            mtu: 1500,
            interface: "tap0".to_string(),
            host_loopback: false,
            host_loopback_ports: Vec::new(),
            publish: Vec::new(),
            nameserver: true,
            upstream: None,
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }
}

impl NetStackBuilder {
    /// Enables or disables IPv4. Enabled by default.
    pub fn ipv4(mut self, enabled: bool) -> Self {
        self.ipv4 = enabled;
        self
    }

    /// Enables or disables IPv6. Enabled by default.
    pub fn ipv6(mut self, enabled: bool) -> Self {
        self.ipv6 = enabled;
        self
    }

    /// Sets the IPv4 network. The default is `10.0.2.0/24`.
    ///
    /// `network` must be the network address itself — no bits set past the
    /// prefix — and the prefix length must be between 1 and 27, leaving room
    /// for the gateway at host 2 and the guest at host 15. Validated by
    /// [`build`](Self::build).
    pub fn ipv4_cidr(mut self, network: Ipv4Addr, prefix_len: u8) -> Self {
        self.ipv4_cidr = (network, prefix_len);
        self
    }

    /// Sets the IPv6 network. The default is `fd00::/64`.
    ///
    /// `network` must be the network address itself and the prefix length
    /// must be between 1 and 120, leaving the address plan the final byte.
    /// Validated by [`build`](Self::build).
    pub fn ipv6_cidr(mut self, network: Ipv6Addr, prefix_len: u8) -> Self {
        self.ipv6_cidr = (network, prefix_len);
        self
    }

    /// Sets the tap interface's MTU. The default is 1500.
    ///
    /// The minimum is 576, or 1280 while IPv6 is enabled. Validated by
    /// [`build`](Self::build).
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Names the tap interface inside the sandbox. The default is `tap0`.
    ///
    /// The name must satisfy the kernel's interface-name rules: 1 to 15
    /// bytes, not `.` or `..`, and free of `/`, `:`, and whitespace as the
    /// kernel reads it, which includes the vertical tab and the byte `0xA0`.
    /// It must be free of `%` too. The kernel reads a name holding one, such as
    /// `tap%d`, as a template for a name of its own choosing, while the stack
    /// configures the interface by the name given here. Validated by
    /// [`build`](Self::build).
    pub fn interface(mut self, name: impl Into<String>) -> Self {
        self.interface = name.into();
        self
    }

    /// Maps connections to the gateway address onto host loopback, on every
    /// port. Off by default.
    ///
    /// The stack never forwards guest traffic to the host's loopback
    /// addresses: `127.0.0.0/8` and `::1` destinations are refused
    /// outright. With this option, a connection to the *gateway* address
    /// (`10.0.2.2` and `fd00::2` by default) is instead forwarded to
    /// `127.0.0.1` or `::1` on the host, port preserved — the conventional
    /// way to reach a host-local service from inside the sandbox, granted
    /// deliberately rather than by making the whole loopback range
    /// reachable. TCP and UDP are mapped alike.
    ///
    /// [`host_loopback_port`](Self::host_loopback_port) grants the same
    /// mapping one port at a time, which is the narrower answer where the
    /// command needs one host service rather than all of them.
    pub fn host_loopback(mut self, enabled: bool) -> Self {
        self.host_loopback = enabled;
        self
    }

    /// Maps connections to the gateway address on `port` alone onto host
    /// loopback. Repeatable; none by default.
    ///
    /// The mapping [`host_loopback`](Self::host_loopback) grants for every
    /// port, granted for one: a connection to the gateway on `port` is
    /// forwarded to `127.0.0.1` or `::1` on the host, port preserved, and a
    /// connection to any other port of the gateway is refused. TCP and UDP are
    /// mapped alike. The ports named here and `host_loopback(true)` combine,
    /// so with both every port maps.
    pub fn host_loopback_port(mut self, port: u16) -> Self {
        self.host_loopback_ports.push(port);
        self
    }

    /// Publishes a TCP port of the guest on the host. Repeatable; none by
    /// default.
    ///
    /// [`attach`](NetStack::attach) listens on `host`, and each connection it
    /// accepts there is carried to `guest_port` on the guest's address of the
    /// same family, arriving from the gateway address. That is how a server
    /// inside the sandbox, a development web server say, is reached from the
    /// host. A connection the guest refuses, because nothing listens on the
    /// port, is reset on the host side.
    ///
    /// At most 128 published connections are carried at once, a budget apart
    /// from the guest's own connections, so neither kind can crowd out the
    /// other. A connection past it is reset on the host side as well.
    ///
    /// `host` is the caller's to choose, and it decides who else can connect.
    /// `127.0.0.1` admits the host's own processes, every local user's
    /// included. `0.0.0.0` or `::` admits whatever reaches the host over the
    /// network. Port 0 has the kernel choose a free port, which
    /// [`NetStackHandle::published`] reports. The family of `host` has to be
    /// enabled, since it decides which of the guest's addresses the
    /// connection is carried to. Validated by [`build`](Self::build), and the
    /// listener is bound by `attach`.
    pub fn publish(mut self, host: SocketAddr, guest_port: u16) -> Self {
        self.publish.push(Publication { host, guest_port });
        self
    }

    /// Serves the guest's DNS from the stack itself. On by default.
    ///
    /// The nameserver answers on port 53, over UDP and TCP, at host 3 of each
    /// enabled network: `10.0.2.3` and `fd00::3` by default, the addresses
    /// [`NetStack::nameservers`] names. It relays each query to the host's own
    /// resolver, or to [`upstream`](Self::upstream)'s, and the answer back. The
    /// sandbox's `resolv.conf` has to name it for the guest to ask it, which
    /// [`CageBuilder::nameservers`](crate::CageBuilder::nameservers) arranges.
    ///
    /// The stack does not fragment, so an answer longer than one packet cannot
    /// go back over UDP. The nameserver sends a truncated answer in its place,
    /// and the guest's resolver asks again over TCP, as it does of any resolver
    /// that truncates.
    ///
    /// Under destination rules the nameserver answers a question for a name the
    /// rules refuse itself, and the names it resolves are what a name rule
    /// admits a flow by; see [`allow`](Self::allow).
    ///
    /// Off, host 3 is an address of the guest's subnet like any other, refused
    /// as the rest of it is, and the guest resolves through whatever its
    /// `resolv.conf` names that the stack forwards to. An allow name rule then
    /// has no addresses to admit, so [`build`](Self::build) refuses one. A deny
    /// name rule still refuses the server a TCP flow's first bytes ask for; see
    /// [`deny`](Self::deny).
    pub fn nameserver(mut self, enabled: bool) -> Self {
        self.nameserver = enabled;
        self
    }

    /// Names the resolver the stack's nameserver asks, in place of the host's.
    ///
    /// By default the nameserver asks the first nameserver the host's
    /// `/etc/resolv.conf` names when the stack attaches, on port 53, or
    /// `127.0.0.1` where it names none, as the host's C library takes such a
    /// file. The stack's sockets are the host's, so a resolver on the host's
    /// loopback is reached, systemd-resolved's stub at `127.0.0.53` among them,
    /// although the guest's own connections to loopback are refused. The port
    /// is the caller's to give, which is how a resolver on another port is
    /// reached.
    ///
    /// [`build`](Self::build) refuses port 0, the unspecified address, and an
    /// upstream for a nameserver [`nameserver(false)`](Self::nameserver) turns
    /// off.
    pub fn upstream(mut self, resolver: SocketAddr) -> Self {
        self.upstream = Some(resolver);
        self
    }

    /// Admits the destinations `rule` matches. Repeatable; none by default.
    ///
    /// Once any allow rule is given, the stack refuses every destination no
    /// allow rule admits, so the allow rules name everything the guest's flows
    /// may reach: an allow rule of `192.0.2.0/24` reads as "only
    /// `192.0.2.0/24`". A
    /// [`deny`](Self::deny) rule that matches refuses a destination whatever
    /// an allow rule says.
    ///
    /// A name rule, `example.com` or `*.example.com`, works through the stack's
    /// [nameserver](Self::nameserver). Once any allow rule is given, the
    /// nameserver answers a question for a name no allow name rule admits with
    /// NXDOMAIN, and relays nothing; an address rule admits no name. Each
    /// address the upstream's answers give an admitted name is pinned to that
    /// name for the attachment's life, past the record's own, and the rule
    /// admits a TCP flow to it. A name rule admits no UDP flow, no address in a
    /// private range, and no address the guest learned other than through the
    /// nameserver: an address rule admits those. Under any name rule the
    /// nameserver answers a question for a name's HTTPS or SVCB records with
    /// none.
    ///
    /// Many sites share an address on a content network, and the name a client
    /// sends picks the site. So a TCP flow an allow name rule admits forwards
    /// nothing the guest sends until the stack has read the server its first
    /// bytes ask for: the server name of a TLS ClientHello, or the host of an
    /// HTTP/1 request. An allow name rule must admit that server on the flow's
    /// port too. A flow an address rule admits is not held to the allow rules
    /// this way, since the address is the grant. A refusal there is answered in
    /// the flow's own protocol, a TLS alert or an HTTP `403`, before the flow
    /// is closed. First bytes that are neither TLS nor HTTP are carried as they
    /// stand, and so is a ClientHello or a request naming no server. Inside TLS
    /// the stack sees nothing after the ClientHello, the HTTP host included, so
    /// a client that names an admitted server and asks it for another site
    /// reaches that site wherever the content network routes such a request.
    ///
    /// The rules decide the destinations the stack would otherwise carry.
    /// Those it refuses under any configuration, loopback and link-local among
    /// them, stay refused, and no rule admits them. The gateway's
    /// [loopback mapping](Self::host_loopback) and the
    /// [published ports](Self::publish) are grants of their own, which the rules
    /// do not decide.
    ///
    /// The stack reports each flow and each question it decides, naming the
    /// rule that admitted or refused it; see [`NetStackHandle::take_reports`].
    ///
    /// [`build`](Self::build) refuses `*`, and a wildcard over the names under
    /// one label such as `*.com`, as an allow rule, since either admits nearly
    /// every name. It refuses an allow name rule where the nameserver is turned
    /// off, with [`NetStackError::RuleInvalid`].
    ///
    /// ```
    /// use ferroday_cage::{NetStack, Transport};
    ///
    /// let stack = NetStack::builder()
    ///     .allow("192.0.2.0/24".parse()?)
    ///     .allow("[2001:db8::/32]:443".parse()?)
    ///     .allow("*.example.com:443".parse()?)
    ///     .deny("192.0.2.7:22".parse()?)
    ///     .build()?;
    /// assert!(stack.forwards(Transport::Tcp, "192.0.2.8:22".parse()?));
    /// assert!(!stack.forwards(Transport::Tcp, "192.0.2.7:22".parse()?));
    /// assert!(!stack.forwards(Transport::Tcp, "[2001:db8::1]:80".parse()?));
    /// assert!(!stack.forwards(Transport::Tcp, "203.0.113.9:443".parse()?));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn allow(mut self, rule: DestinationRule) -> Self {
        self.allow.push(rule);
        self
    }

    /// Refuses the destinations `rule` matches, whatever an
    /// [`allow`](Self::allow) rule admits. Repeatable; none by default.
    ///
    /// With deny rules alone, the stack carries every destination no deny rule
    /// refuses: a deny rule of `192.168.0.0/16` reads as "everything but
    /// `192.168.0.0/16`".
    ///
    /// A deny name rule without ports has the nameserver answer a question for
    /// a name it matches with NXDOMAIN. With ports or without, it refuses a
    /// flow on its ports to an address the nameserver resolved such a name to,
    /// over either transport unless `tcp:` qualifies it, and a TCP flow on its
    /// ports whose first bytes ask for such a name as their server, as
    /// [`allow`](Self::allow) describes. Under deny rules alone a flow to an
    /// address the guest learned other than through the nameserver is carried,
    /// so a name deny holds only where the guest resolves through the stack or
    /// names the server in its first bytes. It holds there with the nameserver
    /// turned off too.
    ///
    /// What the rules decide, and what they leave to grants of their own, is
    /// as [`allow`](Self::allow) describes.
    pub fn deny(mut self, rule: DestinationRule) -> Self {
        self.deny.push(rule);
        self
    }

    /// Whether IPv4 is enabled; see [`ipv4`](Self::ipv4).
    pub fn get_ipv4(&self) -> bool {
        self.ipv4
    }

    /// Whether IPv6 is enabled; see [`ipv6`](Self::ipv6).
    pub fn get_ipv6(&self) -> bool {
        self.ipv6
    }

    /// The IPv4 network and its prefix length; see [`ipv4_cidr`](Self::ipv4_cidr).
    pub fn get_ipv4_cidr(&self) -> (Ipv4Addr, u8) {
        self.ipv4_cidr
    }

    /// The IPv6 network and its prefix length; see [`ipv6_cidr`](Self::ipv6_cidr).
    pub fn get_ipv6_cidr(&self) -> (Ipv6Addr, u8) {
        self.ipv6_cidr
    }

    /// The tap interface's MTU; see [`mtu`](Self::mtu).
    pub fn get_mtu(&self) -> u16 {
        self.mtu
    }

    /// The tap interface's name; see [`interface`](Self::interface).
    pub fn get_interface(&self) -> &str {
        &self.interface
    }

    /// Whether every port of the gateway maps onto host loopback; see
    /// [`host_loopback`](Self::host_loopback).
    pub fn get_host_loopback(&self) -> bool {
        self.host_loopback
    }

    /// The ports of the gateway mapped onto host loopback one at a time, in the
    /// order they were named; see [`host_loopback_port`](Self::host_loopback_port).
    pub fn get_host_loopback_ports(&self) -> &[u16] {
        &self.host_loopback_ports
    }

    /// The published ports, each the host address listened on and the guest
    /// port its connections are carried to, in the order they were published.
    ///
    /// [`NetStackHandle::published`] reports the address each listener is bound
    /// to, in the same order, which is how a caller learns the port the kernel
    /// chose for a publication on port 0.
    pub fn get_publications(&self) -> impl Iterator<Item = (SocketAddr, u16)> + '_ {
        self.publish
            .iter()
            .map(|publication| (publication.host, publication.guest_port))
    }

    /// Whether the stack serves the guest's DNS; see
    /// [`nameserver`](Self::nameserver).
    pub fn get_nameserver(&self) -> bool {
        self.nameserver
    }

    /// The resolver the nameserver asks in place of the host's, where one is
    /// named; see [`upstream`](Self::upstream).
    pub fn get_upstream(&self) -> Option<SocketAddr> {
        self.upstream
    }

    /// The allow rules, in the order they were given; see
    /// [`allow`](Self::allow).
    pub fn get_allow(&self) -> &[DestinationRule] {
        &self.allow
    }

    /// The deny rules, in the order they were given; see [`deny`](Self::deny).
    pub fn get_deny(&self) -> &[DestinationRule] {
        &self.deny
    }

    /// Validates the configuration and freezes it into a [`NetStack`].
    pub fn build(self) -> Result<NetStack, NetStackError> {
        if !self.ipv4 && !self.ipv6 {
            return Err(NetStackError::NoProtocols);
        }
        let v4 = self
            .ipv4
            .then(|| {
                let (network, prefix_len) = self.ipv4_cidr;
                let invalid = |reason| NetStackError::PrefixInvalid {
                    network: IpAddr::V4(network),
                    prefix_len,
                    reason,
                };
                if prefix_len == 0 || prefix_len > MAX_PREFIX_V4 {
                    return Err(invalid("the IPv4 prefix length must be between 1 and 27"));
                }
                let base = u32::from(network);
                if !prefix::is_network(IpAddr::V4(network), prefix_len) {
                    return Err(invalid("the address has bits set past the prefix"));
                }
                if network.is_loopback()
                    || network.is_multicast()
                    || network.is_broadcast()
                    || network.is_link_local()
                    || network.octets()[0] == 0
                {
                    return Err(invalid("the network must be an ordinary unicast range"));
                }
                Ok(PlanV4 {
                    guest: Ipv4Addr::from(base | GUEST_HOST_V4),
                    gateway: Ipv4Addr::from(base | GATEWAY_HOST_V4),
                    nameserver: Ipv4Addr::from(base | NAMESERVER_HOST_V4),
                    prefix_len,
                })
            })
            .transpose()?;
        let v6 = self
            .ipv6
            .then(|| {
                let (network, prefix_len) = self.ipv6_cidr;
                let invalid = |reason| NetStackError::PrefixInvalid {
                    network: IpAddr::V6(network),
                    prefix_len,
                    reason,
                };
                if prefix_len == 0 || prefix_len > MAX_PREFIX_V6 {
                    return Err(invalid("the IPv6 prefix length must be between 1 and 120"));
                }
                let base = u128::from(network);
                if !prefix::is_network(IpAddr::V6(network), prefix_len) {
                    return Err(invalid("the address has bits set past the prefix"));
                }
                if base == 0 || network.is_multicast() || (network.segments()[0] & 0xffc0) == 0xfe80
                {
                    return Err(invalid("the network must be an ordinary unicast range"));
                }
                Ok(PlanV6 {
                    guest: Ipv6Addr::from(base | GUEST_HOST_V6),
                    gateway: Ipv6Addr::from(base | GATEWAY_HOST_V6),
                    nameserver: Ipv6Addr::from(base | NAMESERVER_HOST_V6),
                    prefix_len,
                })
            })
            .transpose()?;
        let minimum = if self.ipv6 { MIN_MTU_V6 } else { MIN_MTU_V4 };
        if self.mtu < minimum {
            return Err(NetStackError::MtuInvalid {
                mtu: self.mtu,
                minimum,
            });
        }
        if !interface_name_valid(&self.interface) {
            return Err(NetStackError::InterfaceNameInvalid {
                name: self.interface,
            });
        }
        for publication in &self.publish {
            let refused = |reason| NetStackError::PublishInvalid {
                host: publication.host,
                guest_port: publication.guest_port,
                reason,
            };
            if publication.guest_port == 0 {
                return Err(refused("the guest port must not be 0"));
            }
            let family_enabled = match publication.host {
                SocketAddr::V4(_) => v4.is_some(),
                SocketAddr::V6(_) => v6.is_some(),
            };
            if !family_enabled {
                return Err(refused(
                    "the host address's family is disabled, so the guest has no address of it to \
                     carry the connection to",
                ));
            }
        }
        if let Some(upstream) = self.upstream {
            let refused = |reason| NetStackError::UpstreamInvalid { upstream, reason };
            if !self.nameserver {
                return Err(refused(
                    "the nameserver is turned off, so nothing would ask the resolver",
                ));
            }
            if upstream.port() == 0 {
                return Err(refused("port 0 names no resolver"));
            }
            if upstream.ip().is_unspecified() {
                return Err(refused("the unspecified address names no resolver"));
            }
        }
        for rule in &self.allow {
            if rule.is_broad_wildcard() {
                return Err(NetStackError::RuleInvalid {
                    rule: rule.clone(),
                    reason: "an allow rule over every name, or every name under one label, \
                             admits nearly every destination",
                });
            }
        }
        if !self.nameserver
            && let Some(rule) = self.allow.iter().find(|rule| rule.is_name())
        {
            return Err(NetStackError::RuleInvalid {
                rule: rule.clone(),
                reason: "the stack's nameserver is turned off, and an allow name rule admits only \
                         the addresses it resolves names to",
            });
        }
        Ok(NetStack {
            plan: Plan {
                v4,
                v6,
                mtu: self.mtu,
                interface: self.interface,
                host_loopback: HostLoopback {
                    all: self.host_loopback,
                    ports: self.host_loopback_ports.into_iter().collect(),
                },
                publish: self.publish,
                nameserver: self.nameserver,
                upstream: self.upstream,
                policy: policy::Policy {
                    allow: self.allow,
                    deny: self.deny,
                    own: Vec::new(),
                },
            },
        })
    }
}

/// Mirrors the kernel's `dev_valid_name`: 1 to 15 bytes (`IFNAMSIZ` minus
/// the terminator), not `.` or `..`, and free of `/`, `:`, and every byte the
/// kernel's `isspace` accepts. NUL is additionally rejected so the name embeds
/// cleanly in the NUL-terminated kernel requests.
///
/// `%` is refused as well, though `dev_valid_name` accepts it. Creating the
/// tap expands a name holding one as a template, `tap%d` to `tap0`, and the
/// configuration requests that follow name the interface as configured, a name
/// no interface has. A valid name is therefore the interface's exact name.
fn interface_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 16
        && name != "."
        && name != ".."
        && !name.bytes().any(|byte| {
            byte == b'/' || byte == b':' || byte == b'%' || byte == 0 || kernel_isspace(byte)
        })
}

/// The kernel's `isspace`, which its `_ctype` table defines over bytes: tab,
/// line feed, vertical tab, form feed, carriage return, space, and `0xA0`, the
/// Latin-1 no-break space.
///
/// Wider than [`u8::is_ascii_whitespace`] by the vertical tab and `0xA0`. The
/// kernel tests the name byte by byte, so `0xA0` refuses every UTF-8 sequence
/// that ends in it, `à` (`C3 A0`) among them.
fn kernel_isspace(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | 0x0B | 0x0C | b'\r' | b' ' | 0xA0)
}

/// An error from building or running a network stack.
///
/// Never a [`crate::Error`]: the stack is an attachment to a sandbox, not
/// part of launching one, and its failures are its own. A failed
/// [`attach`](NetStack::attach) leaves the pending launch untouched — the
/// caller may still proceed (without connectivity) or drop it.
#[derive(Debug)]
#[non_exhaustive]
pub enum NetStackError {
    /// A configured network cannot hold the stack's address plan.
    #[non_exhaustive]
    PrefixInvalid {
        /// The network address as it was given to the builder.
        network: IpAddr,
        /// The prefix length as it was given to the builder.
        prefix_len: u8,
        /// What makes the pair unusable.
        reason: &'static str,
    },
    /// The MTU is below the minimum for the enabled protocols.
    #[non_exhaustive]
    MtuInvalid {
        /// The MTU as it was given to the builder.
        mtu: u16,
        /// The minimum the enabled protocols require.
        minimum: u16,
    },
    /// The interface name does not satisfy the kernel's rules.
    #[non_exhaustive]
    InterfaceNameInvalid {
        /// The name as it was given to the builder.
        name: String,
    },
    /// The configuration enables neither IPv4 nor IPv6.
    NoProtocols,
    /// A published port cannot be carried to the guest as configured.
    #[non_exhaustive]
    PublishInvalid {
        /// The host address the publication named.
        host: SocketAddr,
        /// The guest port the publication named.
        guest_port: u16,
        /// What makes the publication unusable.
        reason: &'static str,
    },
    /// The host listener for a published port could not be established:
    /// binding its address failed, most often because something else holds
    /// it.
    #[non_exhaustive]
    Publish {
        /// The host address the listener was to bind.
        host: SocketAddr,
        /// The underlying error.
        source: io::Error,
    },
    /// The sandbox shares the caller's network namespace, where a stack
    /// must not attach. Sandboxes built with
    /// [`Network::Host`](crate::Network::Host) are refused with this error.
    SharedNamespace,
    /// The sandbox carries a Landlock network grant the kernel cannot
    /// enforce, which the stack would carry the command's connections past.
    ///
    /// An attached stack gives the sandbox's network namespace outbound TCP,
    /// so a grant from `CageBuilder::landlock_net` is the only bound on the
    /// ports the command connects to through it. Network rights first appear
    /// in Landlock ABI 4. On an older kernel, or one without the LSM, the grant
    /// governs nothing, so the attachment is refused rather than made.
    #[non_exhaustive]
    LandlockNetUnenforceable {
        /// The kernel's supported Landlock ABI, or `None` when the LSM is
        /// absent.
        abi: Option<i32>,
    },
    /// The sandbox's network namespace could not be examined or joined.
    #[non_exhaustive]
    NamespaceJoin {
        /// The step that failed.
        which: &'static str,
        /// The underlying error, absent where the failure carried none.
        source: Option<io::Error>,
    },
    /// `/dev/net/tun` could not be opened.
    ///
    /// The tun device is compiled into every mainstream kernel but a host
    /// may omit the module or restrict the device node; the stack cannot
    /// run there.
    #[non_exhaustive]
    TapOpen {
        /// The underlying error.
        source: io::Error,
    },
    /// The tap interface could not be created.
    #[non_exhaustive]
    TapCreate {
        /// The interface name the creation was asked for.
        name: String,
        /// The underlying error.
        source: io::Error,
    },
    /// The tap interface was created but could not be configured.
    #[non_exhaustive]
    TapConfigure {
        /// The configuration step that failed.
        detail: &'static str,
        /// The underlying error.
        source: io::Error,
    },
    /// The tap was created and configured, but its descriptor could not be
    /// handed back to the caller.
    ///
    /// Distinct from [`TapConfigure`](NetStackError::TapConfigure): nothing is
    /// wrong with the interface, only with the handoff, and the tap is
    /// destroyed with the helper that made it.
    #[non_exhaustive]
    TapHandoff {
        /// The underlying error.
        source: io::Error,
    },
    /// The stack's helper process or pump thread could not be started.
    #[non_exhaustive]
    Spawn {
        /// The underlying error.
        source: io::Error,
    },
    /// The tap helper exited without delivering a result.
    ///
    /// The helper always reports an outcome — the tap descriptor or a typed
    /// failure — before it exits; silence means it was killed from outside
    /// or its result could not be read.
    HelperLost,
    /// The pump stopped on an error of its own machinery, reported by
    /// [`NetStackHandle::stop`].
    #[non_exhaustive]
    Pump {
        /// The operation the pump failed at.
        op: &'static str,
        /// The underlying error, absent where the pump stopped on something
        /// that was not a syscall failure.
        source: Option<io::Error>,
    },
    /// The pump panicked, reported by [`NetStackHandle::stop`].
    ///
    /// The panic is caught on the pump's own thread, so it ends the stack and
    /// nothing else: the sandbox runs on without connectivity, and the caller's
    /// process is unaffected.
    PumpPanicked,
    /// The resolver named for the stack's nameserver to ask cannot be asked;
    /// see [`NetStackBuilder::upstream`].
    #[non_exhaustive]
    UpstreamInvalid {
        /// The resolver as it was given to the builder.
        upstream: SocketAddr,
        /// What makes it unusable.
        reason: &'static str,
    },
    /// A destination rule given to [`NetStackBuilder::allow`] or
    /// [`NetStackBuilder::deny`] cannot be used as it was given.
    #[non_exhaustive]
    RuleInvalid {
        /// The rule as it was given to the builder.
        rule: DestinationRule,
        /// What makes it unusable.
        reason: &'static str,
    },
}

impl fmt::Display for NetStackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetStackError::PrefixInvalid {
                network,
                prefix_len,
                reason,
            } => write!(
                f,
                "the network {network}/{prefix_len} is unusable: {reason}"
            ),
            NetStackError::MtuInvalid { mtu, minimum } => write!(
                f,
                "the MTU {mtu} is below {minimum}, the minimum for the enabled protocols",
            ),
            NetStackError::InterfaceNameInvalid { name } => {
                write!(f, "{name:?} is not a valid interface name")
            }
            NetStackError::NoProtocols => {
                f.write_str("the configuration enables neither IPv4 nor IPv6")
            }
            NetStackError::PublishInvalid {
                host,
                guest_port,
                reason,
            } => write!(
                f,
                "cannot publish the guest's port {guest_port} on {host}: {reason}"
            ),
            NetStackError::Publish { host, .. } => {
                write!(
                    f,
                    "could not listen on {host} to publish a port of the sandbox"
                )
            }
            NetStackError::SharedNamespace => f.write_str(
                "the sandbox shares the caller's network namespace; a network stack \
                 attaches only to a private one",
            ),
            NetStackError::LandlockNetUnenforceable { abi } => match abi {
                Some(abi) => write!(
                    f,
                    "the sandbox's Landlock network grant needs Landlock ABI 4, and the kernel \
                     supports ABI {abi}; an attached network stack would carry its connections \
                     to every port"
                ),
                None => f.write_str(
                    "the sandbox requests a Landlock network grant, but the kernel offers no \
                     Landlock LSM to enforce it; an attached network stack would carry its \
                     connections to every port",
                ),
            },
            NetStackError::NamespaceJoin { which, .. } => write!(
                f,
                "could not join the sandbox's network namespace while {which}"
            ),
            NetStackError::TapOpen { .. } => f.write_str("could not open /dev/net/tun"),
            NetStackError::TapCreate { name, .. } => {
                write!(f, "could not create the tap interface {name:?}")
            }
            NetStackError::TapConfigure { detail, .. } => {
                write!(f, "could not configure the tap interface while {detail}")
            }
            NetStackError::TapHandoff { .. } => f.write_str(
                "could not send the tap descriptor back from the network stack's helper",
            ),
            NetStackError::Spawn { .. } => {
                f.write_str("could not start the network stack's helper or pump")
            }
            NetStackError::HelperLost => {
                f.write_str("the network stack's tap helper exited without delivering a result")
            }
            NetStackError::Pump { op, .. } => write!(f, "the network stack pump failed while {op}"),
            NetStackError::PumpPanicked => f.write_str(
                "the network stack pump panicked; the stack caught the panic and stopped \
                 serving the sandbox",
            ),
            NetStackError::UpstreamInvalid { upstream, reason } => {
                write!(f, "cannot ask {upstream} for the sandbox's DNS: {reason}")
            }
            NetStackError::RuleInvalid { rule, reason } => {
                write!(f, "cannot use the destination rule {rule}: {reason}")
            }
        }
    }
}

impl std::error::Error for NetStackError {
    /// The OS failure underneath, where there is one.
    ///
    /// The configuration refusals — an unusable prefix, an MTU below the
    /// minimum, an invalid interface name, no protocols, an unusable
    /// publication, upstream or rule, a shared namespace, an unenforceable
    /// network grant — carry no inner error: nothing failed, the request was
    /// refused.
    /// [`HelperLost`](Self::HelperLost) carries none either: the helper's
    /// silence is the failure. Nor does [`PumpPanicked`](Self::PumpPanicked):
    /// the panic is the failure, and its message went to the panic hook.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NetStackError::NamespaceJoin { source, .. } | NetStackError::Pump { source, .. } => {
                source
                    .as_ref()
                    .map(|source| source as &(dyn std::error::Error + 'static))
            }
            NetStackError::TapOpen { source }
            | NetStackError::TapCreate { source, .. }
            | NetStackError::TapConfigure { source, .. }
            | NetStackError::TapHandoff { source }
            | NetStackError::Publish { source, .. }
            | NetStackError::Spawn { source } => Some(source),
            _ => None,
        }
    }
}

/// Serde adapters presenting the CIDR fields as `"address/len"` strings, the
/// reviewable form for profile files.
#[cfg(feature = "serde")]
mod serde_cidr {
    use std::fmt;
    use std::marker::PhantomData;
    use std::str::FromStr;

    use serde::de::{self, Visitor};
    use serde::{Deserializer, Serializer};

    /// Serializes an `(address, prefix_len)` pair as `"address/len"`.
    fn serialize_pair<A: fmt::Display, S: Serializer>(
        (address, len): &(A, u8),
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{address}/{len}"))
    }

    /// Deserializes `"address/len"` into an `(address, prefix_len)` pair.
    fn deserialize_pair<'de, A, D>(
        deserializer: D,
        family: &'static str,
    ) -> Result<(A, u8), D::Error>
    where
        A: FromStr,
        D: Deserializer<'de>,
    {
        struct CidrVisitor<A> {
            family: &'static str,
            marker: PhantomData<A>,
        }

        impl<A: FromStr> Visitor<'_> for CidrVisitor<A> {
            type Value = (A, u8);

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "an {} network in \"address/len\" form", self.family)
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                let (address, len) = value
                    .split_once('/')
                    .ok_or_else(|| E::custom(format!("{value:?} has no '/' separator")))?;
                let address = address.parse().map_err(|_| {
                    E::custom(format!("{address:?} is not an {} address", self.family))
                })?;
                let len = len
                    .parse()
                    .map_err(|_| E::custom(format!("{len:?} is not a prefix length")))?;
                Ok((address, len))
            }
        }

        deserializer.deserialize_str(CidrVisitor {
            family,
            marker: PhantomData,
        })
    }

    pub(super) mod v4 {
        use std::net::Ipv4Addr;

        use serde::{Deserializer, Serializer};

        pub(crate) fn serialize<S: Serializer>(
            pair: &(Ipv4Addr, u8),
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            super::serialize_pair(pair, serializer)
        }

        pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<(Ipv4Addr, u8), D::Error> {
            super::deserialize_pair(deserializer, "IPv4")
        }
    }

    pub(super) mod v6 {
        use std::net::Ipv6Addr;

        use serde::{Deserializer, Serializer};

        pub(crate) fn serialize<S: Serializer>(
            pair: &(Ipv6Addr, u8),
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            super::serialize_pair(pair, serializer)
        }

        pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<(Ipv6Addr, u8), D::Error> {
            super::deserialize_pair(deserializer, "IPv6")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_configuration_builds() {
        let stack = NetStack::builder().build().expect("the defaults are valid");
        let v4 = stack.plan.v4.expect("IPv4 is on by default");
        assert_eq!(v4.guest, Ipv4Addr::new(10, 0, 2, 15));
        assert_eq!(v4.gateway, Ipv4Addr::new(10, 0, 2, 2));
        assert_eq!(v4.prefix_len, 24);
        let v6 = stack.plan.v6.expect("IPv6 is on by default");
        assert_eq!(v6.guest, "fd00::15".parse::<Ipv6Addr>().unwrap());
        assert_eq!(v6.gateway, "fd00::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(v6.prefix_len, 64);
        assert_eq!(stack.plan.mtu, 1500);
        assert_eq!(stack.plan.interface, "tap0");
    }

    #[test]
    fn the_nameserver_is_host_3_of_each_enabled_network() {
        let stack = NetStack::default();
        assert_eq!(
            stack.nameservers(),
            [
                IpAddr::from([10, 0, 2, 3]),
                "fd00::3".parse::<IpAddr>().unwrap()
            ],
        );
        let custom = NetStack::builder()
            .ipv4_cidr(Ipv4Addr::new(192, 168, 100, 0), 24)
            .ipv6(false)
            .build()
            .expect("a valid custom network");
        assert_eq!(custom.nameservers(), [IpAddr::from([192, 168, 100, 3])]);
        let off = NetStack::builder()
            .nameserver(false)
            .build()
            .expect("a stack without a nameserver");
        assert!(off.nameservers().is_empty());
    }

    #[test]
    fn the_plan_holds_and_serves_the_nameserver_only_where_it_is_on() {
        let on = NetStack::default().plan;
        let held: Vec<IpAddr> = on.held().map(|(address, _)| address).collect();
        assert_eq!(
            held,
            [
                IpAddr::from([10, 0, 2, 2]),
                IpAddr::from([10, 0, 2, 3]),
                "fd00::2".parse().unwrap(),
                "fd00::3".parse().unwrap(),
            ],
            "the gateway first in each family",
        );
        let server =
            |address: &str, port| IpEndpoint::new(address.parse::<IpAddr>().unwrap().into(), port);
        assert!(on.serves(server("10.0.2.3", 53)));
        assert!(on.serves(server("fd00::3", 53)));
        assert!(!on.serves(server("10.0.2.3", 54)), "port 53 alone");
        assert!(
            !on.serves(server("10.0.2.2", 53)),
            "the gateway is not the nameserver"
        );

        let off = NetStack::builder().nameserver(false).build().unwrap().plan;
        assert_eq!(off.held().count(), 2, "the two gateways alone");
        assert!(!off.serves(server("10.0.2.3", 53)));
    }

    #[test]
    fn an_upstream_that_cannot_be_asked_is_refused() {
        for (builder, said) in [
            (
                NetStack::builder().upstream("127.0.0.53:0".parse().unwrap()),
                "port 0",
            ),
            (
                NetStack::builder().upstream("0.0.0.0:53".parse().unwrap()),
                "unspecified",
            ),
            (
                NetStack::builder()
                    .nameserver(false)
                    .upstream("127.0.0.53:53".parse().unwrap()),
                "turned off",
            ),
        ] {
            let err = builder.build().expect_err("an unusable upstream");
            assert!(
                matches!(err, NetStackError::UpstreamInvalid { .. }),
                "{err}"
            );
            assert!(err.to_string().contains(said), "{err}");
        }
        NetStack::builder()
            .upstream("127.0.0.53:53".parse().unwrap())
            .build()
            .expect("a loopback resolver is the stack's to ask");
    }

    #[test]
    fn the_destination_rules_reach_the_plan_in_order() {
        let stack = NetStack::builder()
            .allow("192.0.2.0/24".parse().unwrap())
            .deny("192.0.2.7".parse().unwrap())
            .allow("198.51.100.0/24:443".parse().unwrap())
            .build()
            .expect("address rules build");
        let written = |rules: &[DestinationRule]| -> Vec<String> {
            rules.iter().map(ToString::to_string).collect()
        };
        assert_eq!(
            written(&stack.plan.policy.allow),
            ["192.0.2.0/24", "198.51.100.0/24:443"]
        );
        assert_eq!(written(&stack.plan.policy.deny), ["192.0.2.7"]);
        let open = NetStack::default().plan.policy;
        assert!(open.allow.is_empty() && open.deny.is_empty());
    }

    #[test]
    fn a_rule_the_stack_cannot_use_is_refused() {
        let rule = |text: &str| text.parse::<DestinationRule>().unwrap();
        for (builder, refused, said) in [
            // An allow rule that admits nearly everything, as a rule of any
            // kind would be refused where the stack matched names.
            (NetStack::builder().allow(rule("*")), "*", "every name"),
            (
                NetStack::builder().allow(rule("tcp:*.com:443")),
                "tcp:*.com:443",
                "every name",
            ),
            // A name rule, allow or deny, with no nameserver to resolve its
            // names.
            (
                NetStack::builder()
                    .nameserver(false)
                    .allow(rule("example.com")),
                "example.com",
                "turned off",
            ),
        ] {
            let err = builder.build().expect_err(refused);
            match &err {
                NetStackError::RuleInvalid { rule, .. } => assert_eq!(rule.to_string(), refused),
                other => panic!("{refused}: {other}"),
            }
            assert!(err.to_string().contains(said), "{err}");
            assert!(err.to_string().contains(refused), "{err}");
        }
        // A name rule the nameserver resolves for builds, a deny over every
        // name among them, and a deny name rule builds without the
        // nameserver, since the server a flow's first bytes ask for gives it
        // names to match.
        for builder in [
            NetStack::builder().allow(rule("example.com")),
            NetStack::builder()
                .allow(rule("192.0.2.0/24"))
                .deny(rule("*.example.com")),
            NetStack::builder().deny(rule("*")).deny(rule("*.com")),
            NetStack::builder()
                .nameserver(false)
                .allow(rule("192.0.2.0/24"))
                .deny(rule("*.example.com")),
        ] {
            builder
                .build()
                .expect("a name rule something gives names to match");
        }
    }

    #[test]
    fn a_custom_network_places_the_plan_within_it() {
        let stack = NetStack::builder()
            .ipv4_cidr(Ipv4Addr::new(192, 168, 100, 0), 24)
            .ipv6_cidr("fdab:cd::".parse().unwrap(), 64)
            .build()
            .expect("a valid custom network");
        let v4 = stack.plan.v4.expect("IPv4 is on");
        assert_eq!(v4.guest, Ipv4Addr::new(192, 168, 100, 15));
        assert_eq!(v4.gateway, Ipv4Addr::new(192, 168, 100, 2));
        let v6 = stack.plan.v6.expect("IPv6 is on");
        assert_eq!(v6.guest, "fdab:cd::15".parse::<Ipv6Addr>().unwrap());
        assert_eq!(v6.gateway, "fdab:cd::2".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn disabling_both_protocols_is_refused() {
        let err = NetStack::builder()
            .ipv4(false)
            .ipv6(false)
            .build()
            .expect_err("no protocols is invalid");
        assert!(matches!(err, NetStackError::NoProtocols), "{err}");
    }

    #[test]
    fn a_prefix_too_long_for_the_address_plan_is_refused() {
        let err = NetStack::builder()
            .ipv4_cidr(Ipv4Addr::new(10, 0, 2, 0), 28)
            .build()
            .expect_err("/28 cannot hold host 15 below broadcast");
        assert!(matches!(err, NetStackError::PrefixInvalid { .. }), "{err}");

        let err = NetStack::builder()
            .ipv6_cidr("fd00::".parse().unwrap(), 121)
            .build()
            .expect_err("/121 does not leave the final byte");
        assert!(matches!(err, NetStackError::PrefixInvalid { .. }), "{err}");
    }

    #[test]
    fn host_bits_past_the_prefix_are_refused() {
        let err = NetStack::builder()
            .ipv4_cidr(Ipv4Addr::new(10, 0, 2, 5), 24)
            .build()
            .expect_err("10.0.2.5 is not a /24 network address");
        assert!(matches!(err, NetStackError::PrefixInvalid { .. }), "{err}");

        let err = NetStack::builder()
            .ipv6_cidr("fd00::1".parse().unwrap(), 64)
            .build()
            .expect_err("fd00::1 is not a /64 network address");
        assert!(matches!(err, NetStackError::PrefixInvalid { .. }), "{err}");
    }

    #[test]
    fn the_mtu_floor_follows_the_enabled_protocols() {
        let err = NetStack::builder()
            .mtu(1279)
            .build()
            .expect_err("1279 is below the IPv6 minimum");
        assert!(
            matches!(err, NetStackError::MtuInvalid { minimum: 1280, .. }),
            "{err}"
        );

        NetStack::builder()
            .ipv6(false)
            .mtu(576)
            .build()
            .expect("576 suffices for IPv4 alone");

        let err = NetStack::builder()
            .ipv6(false)
            .mtu(575)
            .build()
            .expect_err("575 is below the IPv4 minimum");
        assert!(
            matches!(err, NetStackError::MtuInvalid { minimum: 576, .. }),
            "{err}"
        );
    }

    /// An attachment carries the guest's connections past a network grant
    /// only where the kernel enforces the grant: from Landlock ABI 4, with the
    /// LSM present. The kernel is asked only about a launch with a grant.
    #[cfg(feature = "hardening")]
    #[test]
    fn a_network_grant_the_kernel_cannot_enforce_refuses_the_attachment() {
        use crate::hardening::net_access;

        for abi in [None, Some(1), Some(3)] {
            let refused = ensure_net_grant_enforced(net_access::CONNECT_TCP, || abi);
            assert!(
                matches!(
                    refused,
                    Err(NetStackError::LandlockNetUnenforceable { abi: reported }) if reported == abi
                ),
                "{abi:?}: {refused:?}",
            );
        }
        for abi in [4, 9] {
            ensure_net_grant_enforced(net_access::ALL, || Some(abi))
                .expect("a kernel at ABI 4 or later enforces the grant");
        }
        ensure_net_grant_enforced(0, || panic!("a launch without a grant probes nothing"))
            .expect("a launch without a grant is not the check's to refuse");
    }

    #[test]
    fn interface_names_follow_the_kernel_rules() {
        for name in [
            "",
            ".",
            "..",
            "a/b",
            "a:b",
            "a b",
            "sixteen-byte-name",
            // The two the kernel's `isspace` adds to ASCII whitespace: the
            // vertical tab, and 0xA0 as a byte of any UTF-8 sequence.
            "a\u{b}b",
            "a\u{a0}b",
            "\u{e0}",
            // Valid to the kernel, which reads it as a template and names the
            // interface itself.
            "tap%d",
            "a%b",
        ] {
            let err = NetStack::builder()
                .interface(name)
                .build()
                .expect_err("an invalid interface name is refused");
            assert!(
                matches!(err, NetStackError::InterfaceNameInvalid { .. }),
                "{name:?}: {err}"
            );
        }
        NetStack::builder()
            .interface("fifteen-byte-nm")
            .build()
            .expect("a 15-byte name is the longest valid one");
        // Other bytes past ASCII are names to the kernel.
        NetStack::builder()
            .interface("\u{e9}th0")
            .build()
            .expect("a name the kernel accepts");
    }

    #[test]
    fn a_pump_that_panics_is_reported_as_a_panic_the_stack_caught() {
        let running = Arc::new(AtomicBool::new(true));
        let running_pump = Arc::clone(&running);
        let (stop, _polled) = pump::Stop::new().expect("an eventfd");
        let handle = NetStackHandle {
            pump: Some(std::thread::spawn(move || {
                run_caught(|| panic!("a pump that panics"), &running_pump)
            })),
            stop,
            running,
            published: Vec::new(),
            reports: None,
        };
        let reported = handle.stop().expect_err("a panicked pump is reported");
        assert!(
            matches!(reported, NetStackError::PumpPanicked),
            "{reported:?}"
        );
        let said = reported.to_string();
        assert!(said.contains("panicked"), "{said}");
        assert!(!said.contains("failed while"), "{said}");
    }

    #[test]
    fn an_interface_name_is_rendered_escaped() {
        // The kernel's alphabet for a name admits control characters, so a
        // name that failed to be created is named with them escaped.
        let hostile = &crate::failure::hostile::TEXT[..12];
        NetStack::builder()
            .interface(hostile)
            .build()
            .expect("a name the kernel accepts");
        let refused = NetStackError::TapCreate {
            name: hostile.to_string(),
            source: io::Error::from_raw_os_error(1),
        };
        crate::failure::hostile::assert_escaped(&refused.to_string());
    }

    #[test]
    fn a_publication_needs_a_guest_port_and_an_enabled_family() {
        let err = NetStack::builder()
            .publish("127.0.0.1:8080".parse().unwrap(), 0)
            .build()
            .expect_err("guest port 0 names nothing to connect to");
        assert!(matches!(err, NetStackError::PublishInvalid { .. }), "{err}");

        let err = NetStack::builder()
            .ipv6(false)
            .publish("[::1]:8080".parse().unwrap(), 80)
            .build()
            .expect_err("an IPv6 listener has no guest address to reach");
        assert!(matches!(err, NetStackError::PublishInvalid { .. }), "{err}");

        let stack = NetStack::builder()
            .publish("127.0.0.1:0".parse().unwrap(), 80)
            .publish("[::1]:0".parse().unwrap(), 443)
            .build()
            .expect("a publication in each enabled family");
        assert_eq!(stack.plan.publish.len(), 2, "both are kept, in order");
        assert_eq!(stack.plan.publish[1].guest_port, 443);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn the_builder_round_trips_through_serde() {
        let toml = "ipv4-cidr = \"192.168.7.0/24\"\nipv6 = false\ninterface = \"net0\"\n";
        let builder: NetStackBuilder = toml::from_str(toml).expect("the profile parses");
        assert_eq!(builder.ipv4_cidr, (Ipv4Addr::new(192, 168, 7, 0), 24));
        assert!(!builder.ipv6);
        assert_eq!(builder.interface, "net0");
        assert_eq!(builder.mtu, 1500, "unset keys keep their defaults");

        let serialized = toml::to_string(&builder).expect("the builder serializes");
        let reparsed: NetStackBuilder = toml::from_str(&serialized).expect("and round-trips");
        assert_eq!(reparsed.ipv4_cidr, builder.ipv4_cidr);
        assert_eq!(reparsed.ipv6_cidr, builder.ipv6_cidr);

        // The two repeatable settings: a list of ports, and an array of
        // publication tables, each with its own keys.
        let toml = "host-loopback-ports = [5432, 6379]\n\n\
                    [[publish]]\nhost = \"127.0.0.1:8080\"\nguest-port = 80\n";
        let builder: NetStackBuilder = toml::from_str(toml).expect("the profile parses");
        assert_eq!(builder.host_loopback_ports, [5432, 6379]);
        assert_eq!(
            builder.publish,
            [Publication {
                host: "127.0.0.1:8080".parse().unwrap(),
                guest_port: 80,
            }],
        );
        let serialized = toml::to_string(&builder).expect("the builder serializes");
        let reparsed: NetStackBuilder = toml::from_str(&serialized).expect("and round-trips");
        assert_eq!(reparsed.publish, builder.publish);
        assert_eq!(reparsed.host_loopback_ports, builder.host_loopback_ports);

        let err = toml::from_str::<NetStackBuilder>(
            "[[publish]]\nhost = \"127.0.0.1:8080\"\nguest-port = 80\nexpose = true\n",
        )
        .expect_err("a publication's unknown keys are refused");
        assert!(err.to_string().contains("expose"), "{err}");

        let err = toml::from_str::<NetStackBuilder>("ipv4-cidr = \"10.0.2.0\"")
            .expect_err("a CIDR without a length is refused");
        assert!(err.to_string().contains("separator"), "{err}");

        let err = toml::from_str::<NetStackBuilder>("gateway = \"10.0.2.1\"")
            .expect_err("unknown keys are refused");
        assert!(err.to_string().contains("gateway"), "{err}");

        // The nameserver's two keys: a switch, and the resolver as a string.
        let builder: NetStackBuilder =
            toml::from_str("nameserver = true\nupstream = \"[::1]:5353\"\n")
                .expect("the profile parses");
        assert_eq!(builder.upstream, Some("[::1]:5353".parse().unwrap()));
        let serialized = toml::to_string(&builder).expect("the builder serializes");
        let reparsed: NetStackBuilder = toml::from_str(&serialized).expect("and round-trips");
        assert_eq!(reparsed.upstream, builder.upstream);
        assert!(reparsed.nameserver);
        let unset = toml::to_string(&NetStack::builder()).expect("the defaults serialize");
        assert!(
            !unset.contains("upstream"),
            "an unset upstream is left out: {unset}"
        );

        // The destination rules: each a string in the rule grammar, written
        // back in its one spelling.
        let builder: NetStackBuilder = toml::from_str(
            "allow = [\"192.0.2.0/24\", \"[2001:DB8::/32]:443\"]\ndeny = [\"udp:192.0.2.7\"]\n\n\
             [[publish]]\nhost = \"127.0.0.1:8080\"\nguest-port = 80\n",
        )
        .expect("the profile parses");
        assert_eq!(
            builder.allow,
            [
                "192.0.2.0/24".parse::<DestinationRule>().unwrap(),
                "[2001:db8::/32]:443".parse().unwrap(),
            ],
        );
        assert_eq!(builder.deny, ["udp:192.0.2.7".parse().unwrap()]);
        let serialized = toml::to_string(&builder).expect("the builder serializes");
        assert!(
            serialized.contains("\"[2001:db8::/32]:443\""),
            "a rule renders as its text: {serialized}"
        );
        let reparsed: NetStackBuilder = toml::from_str(&serialized).expect("and round-trips");
        assert_eq!(reparsed.allow, builder.allow);
        assert_eq!(reparsed.deny, builder.deny);
        let err = toml::from_str::<NetStackBuilder>("allow = [\"example.com:0\"]")
            .expect_err("a rule outside the grammar is refused");
        assert!(err.to_string().contains("port 0"), "{err}");
    }

    /// Every key the builder's serde format can carry, pinned as the profile
    /// format's are: the format is the one a consumer embeds in a document of
    /// its own, and a field rename or a new setting would move a key silently.
    #[cfg(feature = "serde")]
    #[test]
    fn the_builder_format_keys_are_what_they_are() {
        let builder = NetStack::builder()
            .host_loopback(true)
            .host_loopback_port(5432)
            .publish("127.0.0.1:8080".parse().unwrap(), 80)
            .upstream("127.0.0.53:53".parse().unwrap())
            .allow("192.0.2.0/24".parse().unwrap())
            .deny("192.0.2.7".parse().unwrap());
        let rendered = toml::to_string(&builder).expect("the builder serializes");
        assert_eq!(
            crate::spec::serde_tests::profile_keys(&rendered),
            [
                "allow",
                "deny",
                "host-loopback",
                "host-loopback-ports",
                "interface",
                "ipv4",
                "ipv4-cidr",
                "ipv6",
                "ipv6-cidr",
                "mtu",
                "nameserver",
                "publish",
                "publish[].guest-port",
                "publish[].host",
                "upstream",
            ],
            "the network stack's format keys moved",
        );
    }

    #[test]
    fn each_getter_reads_back_its_setting() {
        let defaults = NetStack::builder();
        assert!(defaults.get_ipv4() && defaults.get_ipv6());
        assert_eq!(defaults.get_ipv4_cidr(), (Ipv4Addr::new(10, 0, 2, 0), 24));
        assert_eq!(
            defaults.get_ipv6_cidr(),
            (Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0), 64)
        );
        assert_eq!(defaults.get_mtu(), 1500);
        assert_eq!(defaults.get_interface(), "tap0");
        assert!(!defaults.get_host_loopback());
        assert!(defaults.get_host_loopback_ports().is_empty());
        assert_eq!(defaults.get_publications().count(), 0);
        assert!(defaults.get_nameserver());
        assert_eq!(defaults.get_upstream(), None);
        assert!(defaults.get_allow().is_empty() && defaults.get_deny().is_empty());

        let allow: DestinationRule = "example.com:443".parse().unwrap();
        let deny: DestinationRule = "192.0.2.7".parse().unwrap();
        let set = NetStack::builder()
            .ipv4(false)
            .ipv6(false)
            .ipv4_cidr(Ipv4Addr::new(192, 168, 7, 0), 24)
            .ipv6_cidr(Ipv6Addr::new(0xfd00, 7, 0, 0, 0, 0, 0, 0), 64)
            .mtu(1400)
            .interface("net0")
            .host_loopback(true)
            .host_loopback_port(5432)
            .host_loopback_port(6379)
            .publish("127.0.0.1:0".parse().unwrap(), 80)
            .publish("[::1]:8443".parse().unwrap(), 443)
            .nameserver(false)
            .upstream("127.0.0.53:53".parse().unwrap())
            .allow(allow.clone())
            .deny(deny.clone());
        assert!(!set.get_ipv4() && !set.get_ipv6());
        assert_eq!(set.get_ipv4_cidr(), (Ipv4Addr::new(192, 168, 7, 0), 24));
        assert_eq!(
            set.get_ipv6_cidr(),
            (Ipv6Addr::new(0xfd00, 7, 0, 0, 0, 0, 0, 0), 64)
        );
        assert_eq!(set.get_mtu(), 1400);
        assert_eq!(set.get_interface(), "net0");
        assert!(set.get_host_loopback());
        assert_eq!(set.get_host_loopback_ports(), [5432, 6379]);
        assert_eq!(
            set.get_publications().collect::<Vec<_>>(),
            [
                ("127.0.0.1:0".parse().unwrap(), 80),
                ("[::1]:8443".parse().unwrap(), 443),
            ]
        );
        assert!(!set.get_nameserver());
        assert_eq!(set.get_upstream(), Some("127.0.0.53:53".parse().unwrap()));
        assert_eq!(set.get_allow(), [allow]);
        assert_eq!(set.get_deny(), [deny]);
    }
}
