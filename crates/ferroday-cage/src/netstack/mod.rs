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
//! cloud metadata services. AWS's IPv6 instance services, `fd00:ec2::/32` with
//! the metadata service at `fd00:ec2::254`, are refused too. A caller that must
//! bound egress further confines it outside the stack. One exception is
//! deliberate: [`host_loopback`](NetStackBuilder::host_loopback) and
//! [`host_loopback_port`](NetStackBuilder::host_loopback_port) map connections
//! to the gateway address onto the host's loopback. A refused TCP connection is
//! answered with a reset, with one exception: the guest's own subnet is
//! on-link from the guest's point of view, so it resolves a hardware address
//! before it sends a segment, and the stack answers address resolution only
//! for the gateway. Those destinations fail when the guest's own resolution
//! gives up rather than on a reset. A refused UDP datagram is dropped, and
//! whether the guest also receives an ICMP port-unreachable depends on
//! whether the stack happens to hold a socket on that port for some other
//! destination, so a caller must not read anything into either outcome.
//!
//! Connections run the other way only where the caller publishes a port:
//! [`publish`](NetStackBuilder::publish) has the stack listen on a host address
//! and carry each connection it accepts to a TCP port of the guest's.
//!
//! Only TCP and UDP are forwarded, and only from the guest's own address: a
//! segment or datagram from any other source is dropped, since nothing sent
//! back to it could be delivered. The stack answers ICMP echo for the
//! gateway address and for nothing else, so a ping inside the guest tells the
//! guest that its gateway is up and says nothing at all about the destination
//! — a reachable address does not answer, and neither does a refused one.
//! Reachability is what a connection reports.
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

use rustix::fs::{Mode, OFlags};
use rustix::pipe::{self, PipeFlags};
use smoltcp::wire::IpAddress;

use crate::running::Pending;

mod device;
mod pump;
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
}

impl Plan {
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

/// The IPv4 half of the plan: the guest address the tap carries and the
/// gateway address the stack's interface answers for.
#[derive(Debug, Clone)]
struct PlanV4 {
    guest: Ipv4Addr,
    gateway: Ipv4Addr,
    prefix_len: u8,
}

/// The IPv6 half of the plan.
#[derive(Debug, Clone)]
struct PlanV6 {
    guest: Ipv6Addr,
    gateway: Ipv6Addr,
    prefix_len: u8,
}

impl NetStack {
    /// Returns a builder holding the default configuration.
    pub fn builder() -> NetStackBuilder {
        NetStackBuilder::default()
    }

    /// Whether the stack carries the guest's traffic to `destination` on to the
    /// host.
    ///
    /// This is the forwarding policy every attachment applies, asked of one
    /// destination, TCP and UDP alike. It answers `false` for a destination the
    /// stack refuses: loopback, link-local, multicast, AWS's IPv6 instance
    /// services, the guest's own subnet, and a protocol the configuration turns
    /// off. The gateway address is carried only on a port
    /// [`host_loopback`](NetStackBuilder::host_loopback) or
    /// [`host_loopback_port`](NetStackBuilder::host_loopback_port) admits.
    ///
    /// A caller composing the guest's configuration asks this rather than
    /// restating the rules. `fcage --netstack` binds the host's `resolv.conf`
    /// only where it names a nameserver the stack forwards to on port 53.
    ///
    /// ```
    /// use ferroday_cage::NetStack;
    ///
    /// let stack = NetStack::default();
    /// assert!(stack.forwards("192.0.2.53:53".parse().unwrap()));
    /// // systemd-resolved's stub, and AWS's IPv4 resolver.
    /// assert!(!stack.forwards("127.0.0.53:53".parse().unwrap()));
    /// assert!(!stack.forwards("169.254.169.253:53".parse().unwrap()));
    /// ```
    pub fn forwards(&self, destination: SocketAddr) -> bool {
        pump::host_target(destination.into(), &self.plan).is_some()
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
    /// `CageBuilder::landlock_net`, is refused with [`NetStackError::LandlockNetUnenforceable`] where the
    /// kernel cannot enforce the grant: below Landlock ABI 4, or without the
    /// LSM. The stack gives the sandbox outbound TCP, so the grant is then the
    /// only bound on the ports the command reaches through it.
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

        let pid = pending.netns_pid();
        let target = format!("/proc/{pid}/ns/net");

        // Refuse a sandbox that shares the caller's namespace: attaching
        // would create a tap on the host network, which is never what a
        // caller means. The namespace links compare equal exactly when the
        // namespaces are the same.
        let caller = std::fs::read_link("/proc/self/ns/net").map_err(|err| {
            NetStackError::NamespaceJoin {
                which: "reading the caller's namespace link",
                source: err.raw_os_error().is_some().then_some(err),
            }
        })?;
        let sandbox = std::fs::read_link(&target).map_err(|err| NetStackError::NamespaceJoin {
            which: "reading the sandbox's namespace link",
            source: err.raw_os_error().is_some().then_some(err),
        })?;
        if caller == sandbox {
            return Err(NetStackError::SharedNamespace);
        }

        // The Pending handle keeps the supervisor alive, so the pid cannot
        // be recycled while these descriptors are being opened. The user
        // namespace is joined for its capabilities; the network namespace
        // is where the tap is created.
        let netns = rustix::fs::open(&target, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .map_err(|errno| NetStackError::NamespaceJoin {
                which: "opening the sandbox's network namespace",
                source: Some(errno.into()),
            })?;
        let userns = rustix::fs::open(
            format!("/proc/{pid}/ns/user"),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| NetStackError::NamespaceJoin {
            which: "opening the sandbox's user namespace",
            source: Some(errno.into()),
        })?;

        let tap = tap::create(userns, netns, &self.plan)?;

        // The stop pipe wakes the pump: stop() writes a byte, and a dropped
        // handle closes the write end, which the pump sees as a hangup.
        let (stop_read, stop_write) =
            pipe::pipe_with(PipeFlags::CLOEXEC).map_err(|errno| NetStackError::Spawn {
                source: errno.into(),
            })?;
        let running = Arc::new(AtomicBool::new(true));
        let running_pump = Arc::clone(&running);
        let plan = self.plan.clone();
        let pump = std::thread::Builder::new()
            .name("fcage-netstack".to_string())
            .spawn(move || {
                // Panics are converted into a failed exit and the running
                // flag is cleared on every path, so the handle's view of the
                // pump is always truthful and stop() never rethrows.
                let exit = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    pump::run(tap, stop_read, plan, listeners)
                }));
                running_pump.store(false, Ordering::SeqCst);
                exit.unwrap_or(PumpExit::Failed {
                    op: "recovering from a panic",
                    source: None,
                })
            })
            .map_err(|err| NetStackError::Spawn { source: err })?;

        Ok(NetStackHandle {
            pump: Some(pump),
            stop: Some(stop_write),
            running,
            published,
        })
    }
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
    /// syscall failure — a panic it recovered from.
    Failed {
        op: &'static str,
        source: Option<io::Error>,
    },
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
    /// Write end of the stop pipe; closing it is itself a stop signal.
    stop: Option<OwnedFd>,
    /// Cleared by the pump on every exit path.
    running: Arc<AtomicBool>,
    /// The host addresses the published ports listen on, in publication
    /// order.
    published: Vec<SocketAddr>,
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
        // Closing the stop pipe's write end wakes the pump's poll with a
        // hangup, which is the whole stop signal. Dropping the descriptor here
        // closes it. A byte-write would also wake the pump, but a pump that
        // exited on its own has closed the read end, so the write could raise
        // SIGPIPE; the close cannot.
        drop(self.stop.take());
        match pump.join() {
            Ok(PumpExit::Clean) => Ok(()),
            Ok(PumpExit::Failed { op, source }) => Err(NetStackError::Pump { op, source }),
            // The pump converts its panics into a failed exit; a join error
            // means that conversion itself was bypassed. Report, not rethrow.
            Err(_) => Err(NetStackError::Pump {
                op: "recovering from a panic",
                source: None,
            }),
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
        // Closing the stop pipe's write end hangs up the pump's read end,
        // which the pump treats as a stop request. Join so the tap descriptor
        // is closed — and the sandbox's namespace released — before drop
        // returns; the outcome is discarded, stop() being the reporting path.
        drop(self.stop.take());
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
/// write as strings. In TOML:
///
/// ```toml
/// ipv4-cidr = "10.0.2.0/24"
/// ipv6 = false
/// mtu = 1500
/// interface = "tap0"
/// host-loopback-ports = [5432]
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
    /// Validated by [`build`](Self::build).
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
    /// other. A connection past it is closed on the host side as well.
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
                if base & !(u32::MAX << (32 - prefix_len)) != 0 {
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
                if base & !(u128::MAX << (128 - prefix_len)) != 0 {
                    return Err(invalid("the address has bits set past the prefix"));
                }
                if base == 0 || network.is_multicast() || (network.segments()[0] & 0xffc0) == 0xfe80
                {
                    return Err(invalid("the network must be an ordinary unicast range"));
                }
                Ok(PlanV6 {
                    guest: Ipv6Addr::from(base | GUEST_HOST_V6),
                    gateway: Ipv6Addr::from(base | GATEWAY_HOST_V6),
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
            },
        })
    }
}

/// Mirrors the kernel's `dev_valid_name`: 1 to 15 bytes (`IFNAMSIZ` minus
/// the terminator), not `.` or `..`, and free of `/`, `:`, and every byte the
/// kernel's `isspace` accepts. NUL is additionally rejected so the name embeds
/// cleanly in the NUL-terminated kernel requests.
fn interface_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 16
        && name != "."
        && name != ".."
        && !name
            .bytes()
            .any(|byte| byte == b'/' || byte == b':' || byte == 0 || kernel_isspace(byte))
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
                write!(f, "could not create the tap interface {name}")
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
        }
    }
}

impl std::error::Error for NetStackError {
    /// The OS failure underneath, where there is one.
    ///
    /// The configuration refusals — an unusable prefix, an MTU below the
    /// minimum, an invalid interface name, no protocols, an unusable
    /// publication, a shared namespace, an unenforceable network grant — carry
    /// no inner error: nothing failed, the request was refused.
    /// [`HelperLost`](Self::HelperLost) carries none either: the helper's
    /// silence is the failure.
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
            .publish("127.0.0.1:8080".parse().unwrap(), 80);
        let rendered = toml::to_string(&builder).expect("the builder serializes");
        assert_eq!(
            crate::spec::serde_tests::profile_keys(&rendered),
            [
                "host-loopback",
                "host-loopback-ports",
                "interface",
                "ipv4",
                "ipv4-cidr",
                "ipv6",
                "ipv6-cidr",
                "mtu",
                "publish",
                "publish[].guest-port",
                "publish[].host",
            ],
            "the network stack's format keys moved",
        );
    }
}
