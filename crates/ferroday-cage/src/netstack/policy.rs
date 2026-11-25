//! The stack's destination policy: the rules a caller allows and denies the
//! guest's destinations by, and the decision they make together.
//!
//! [`DestinationRule`] is the one grammar the builder, the stack's profile
//! format and `fcage` share. [`Policy`] holds a configuration's allow and deny
//! rules and decides by them: a flow, after the refusals no rule overrides
//! ([`host_target`](super::pump::host_target)), a question the stack's
//! nameserver would relay, and the server a TCP flow's first bytes ask for
//! ([`server_name`](super::server_name)).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use super::report::{FlowAdmission, FlowRefusal};
use super::server_name::Host;
use super::{dns, own, prefix};

/// A transport the stack carries the guest's traffic over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Transport {
    /// TCP: each connection the guest opens.
    Tcp,
    /// UDP: each flow of datagrams between a guest port and a destination.
    Udp,
}

impl Transport {
    /// The spelling of the transport in a rule, `tcp` or `udp`.
    fn spelling(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        }
    }
}

/// A transport writes as a rule spells it, `tcp` or `udp`.
impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.spelling())
    }
}

/// One rule of a network stack's destination policy, as
/// [`NetStackBuilder::allow`](super::NetStackBuilder::allow) and
/// [`deny`](super::NetStackBuilder::deny) take it.
///
/// A rule is parsed from text, the one form the builder, the stack's profile
/// format and `fcage` share, and [`Display`](fmt::Display) writes it back:
///
/// | Rule | Matches |
/// | --- | --- |
/// | `192.0.2.7`, `2001:db8::1` | the address |
/// | `192.0.2.0/24`, `2001:db8::/32` | every address in the network |
/// | `example.com` | the name |
/// | `*.example.com` | every name below `example.com`, at any depth, and not `example.com` itself |
/// | `*` | every name |
/// | `RULE:443`, `RULE:80,443`, `RULE:8000-8999` | the rule, on those ports alone |
/// | `tcp:RULE`, `udp:RULE` | the rule, over that transport alone |
///
/// An IPv6 address or network with ports is bracketed, as `[2001:db8::1]:443`
/// and `[2001:db8::/32]:443` are, since its own colons would otherwise read as
/// a port's. Unbracketed it carries no ports, so `2001:db8::1:443` is one
/// address. An address rule covers TCP and UDP unless a transport says
/// otherwise. A name rule admits TCP alone, so `udp:` does not qualify one.
///
/// A name rule matches the names the guest asks the stack's nameserver about,
/// and a flow to an address the nameserver resolved such a name to; see
/// [`NetStackBuilder::allow`](super::NetStackBuilder::allow). A name is compared
/// without regard to ASCII case and without a trailing dot, and is written back
/// in lower case without one. A rule written with a network's full width,
/// `192.0.2.7/32`, is written back as the address.
///
/// Parsing refuses a port of 0, a range of ports that runs backwards, a prefix
/// longer than its family's width, and a network with bits set past its
/// prefix. It refuses `udp:` on a name, a wildcard anywhere but as a whole first
/// label, and a name not in its ASCII form, which for an internationalized name
/// is its `xn--` spelling. It refuses a name whose last label is a number,
/// `2130706433`, `127.1` or `0x7f`, since a resolver may read such a name as an
/// address.
///
/// ```
/// use ferroday_cage::DestinationRule;
///
/// let rule: DestinationRule = "TCP:[2001:DB8::/32]:443,8000-8999".parse().unwrap();
/// assert_eq!(rule.to_string(), "tcp:[2001:db8::/32]:443,8000-8999");
/// let rule: DestinationRule = "192.0.2.7/32".parse().unwrap();
/// assert_eq!(rule.to_string(), "192.0.2.7");
/// assert!("udp:example.com".parse::<DestinationRule>().is_err());
/// assert!("127.1".parse::<DestinationRule>().is_err());
/// ```
// A rule's parts are shared rather than owned, so a clone costs no allocation:
// the stack clones the rule that decides a flow into the flow's report, and it
// decides a flow at each datagram the guest sends.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DestinationRule {
    /// The transport the rule covers, or `None` for every transport its target
    /// can be reached over.
    transport: Option<Transport>,
    /// What the rule matches.
    target: Target,
    /// The ports the rule covers, in the order given, or none for every port.
    ports: Arc<[Ports]>,
}

/// What a rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Target {
    /// One name, exactly: lower case, with no trailing dot.
    Name(Arc<str>),
    /// Every name below this one, at any depth, and not the name itself. Empty
    /// for the root, below which every name is.
    Below(Arc<str>),
    /// Every address in a network.
    Network {
        /// The network's address, with no bit set past the prefix.
        network: IpAddr,
        /// The prefix length, at most the family's width.
        prefix_len: u8,
    },
}

/// A range of ports, both ends included and neither 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Ports {
    first: u16,
    last: u16,
}

impl DestinationRule {
    /// Whether the rule covers a flow over `transport` on `port`, whatever its
    /// destination: the rule names that transport or none, and that port or
    /// none.
    fn covers(&self, transport: Transport, port: u16) -> bool {
        self.transport.is_none_or(|covered| covered == transport)
            && (self.ports.is_empty()
                || self
                    .ports
                    .iter()
                    .any(|ports| (ports.first..=ports.last).contains(&port)))
    }

    /// Whether the rule matches a flow over `transport` to `address` on
    /// `port` by its address. A name rule matches no address.
    fn matches_address(&self, transport: Transport, address: IpAddr, port: u16) -> bool {
        let Target::Network {
            network,
            prefix_len,
        } = self.target
        else {
            return false;
        };
        self.covers(transport, port) && prefix::contains(network, prefix_len, address)
    }

    /// Whether the rule matches `name`, a name's text as the stack's nameserver
    /// writes it, whatever the transport and port. An address rule matches no
    /// name.
    ///
    /// The text holds a dot only between two labels (see the
    /// [`dns`](super::dns) module), so a name is below `example.com` exactly
    /// where its text ends in `.example.com`, whatever its other labels hold. A
    /// rule's name holds letters, digits, `-` and `_` alone, so no name whose
    /// text carries an escape equals one, and `*` matches every name but the
    /// root, `.`.
    fn matches_name(&self, name: &str) -> bool {
        match &self.target {
            Target::Name(exact) => name == &**exact,
            Target::Below(base) if base.is_empty() => name != ".",
            Target::Below(base) => name
                .strip_suffix(&**base)
                .is_some_and(|above| above.len() > 1 && above.ends_with('.')),
            Target::Network { .. } => false,
        }
    }

    /// Whether the rule matches names rather than addresses.
    pub(super) fn is_name(&self) -> bool {
        matches!(self.target, Target::Name(_) | Target::Below(_))
    }

    /// Whether the rule is a wildcard over every name, or over every name
    /// below a single label: `*`, or `*.com`.
    pub(super) fn is_broad_wildcard(&self) -> bool {
        matches!(&self.target, Target::Below(base) if !base.contains('.'))
    }
}

impl FromStr for DestinationRule {
    type Err = ParseDestinationRuleError;

    /// Parses a rule from the grammar [`DestinationRule`] describes.
    fn from_str(text: &str) -> Result<DestinationRule, ParseDestinationRuleError> {
        let refused = |reason| ParseDestinationRuleError {
            text: text.to_string(),
            reason,
        };
        let (transport, rest) = split_transport(text);
        let (target, ports) = split_ports(rest).map_err(refused)?;
        let target = parse_target(target).map_err(refused)?;
        let ports = match ports {
            Some(ports) => parse_ports(ports).map_err(refused)?.into(),
            None => Arc::from([]),
        };
        if transport == Some(Transport::Udp) && matches!(target, Target::Name(_) | Target::Below(_))
        {
            return Err(refused(
                "a name rule covers TCP alone, so `udp:` cannot qualify one",
            ));
        }
        Ok(DestinationRule {
            transport,
            target,
            ports,
        })
    }
}

/// Splits a leading `tcp:` or `udp:`, in any case, from the rest of a rule.
///
/// Compared as bytes: a rule is text a caller supplies, and a character that
/// is not ASCII can straddle where a spelling would end.
fn split_transport(text: &str) -> (Option<Transport>, &str) {
    let bytes = text.as_bytes();
    for transport in [Transport::Tcp, Transport::Udp] {
        let spelling = transport.spelling().as_bytes();
        if let Some(prefix) = bytes.get(..spelling.len())
            && prefix.eq_ignore_ascii_case(spelling)
            && bytes.get(spelling.len()) == Some(&b':')
        {
            // The byte before the cut is an ASCII colon, so the cut falls
            // between two characters.
            return (Some(transport), &text[spelling.len() + 1..]);
        }
    }
    (None, text)
}

/// Splits a rule's target from its ports, where it has any: after the closing
/// bracket of a bracketed target, and otherwise after the one colon a name or
/// an IPv4 target can hold. Text with more colons than that is an unbracketed
/// IPv6 target, which carries no ports.
///
/// A bracketed target comes back with its brackets, which tell
/// [`parse_target`] it may only be IPv6.
fn split_ports(text: &str) -> Result<(&str, Option<&str>), &'static str> {
    if text.is_empty() {
        return Err("it names no destination");
    }
    if text.starts_with('[') {
        let close = text.find(']').ok_or("an opening `[` has no closing `]`")?;
        let (target, after) = text.split_at(close + 1);
        return match after {
            "" => Ok((target, None)),
            _ => match after.strip_prefix(':') {
                Some(ports) => Ok((target, Some(ports))),
                None => Err("only `:PORTS` may follow a bracketed address"),
            },
        };
    }
    match text.matches(':').count() {
        1 => Ok(text
            .split_once(':')
            .map(|(target, ports)| (target, Some(ports)))
            .expect("the text holds a colon")),
        _ => Ok((text, None)),
    }
}

/// Parses a rule's target: a network, an address, a bracketed IPv6 one of
/// either, or a name.
fn parse_target(text: &str) -> Result<Target, &'static str> {
    if let Some(inner) = text.strip_prefix('[') {
        let inner = inner.strip_suffix(']').unwrap_or(inner);
        return match parse_network(inner) {
            Some(Ok(
                target @ Target::Network {
                    network: IpAddr::V6(_),
                    ..
                },
            )) => Ok(target),
            Some(Err(reason)) => Err(reason),
            _ => Err("only an IPv6 address or network is bracketed"),
        };
    }
    if let Some(network) = parse_network(text) {
        return network;
    }
    if text.contains(':') {
        return Err(
            "it is neither an address nor a name; an IPv6 address with ports is bracketed, \
             as in `[2001:db8::1]:443`",
        );
    }
    parse_name(text)
}

/// Parses `ADDRESS` or `ADDRESS/LEN` as a network, or answers `None` where the
/// text before any `/` is not an address, so the text may yet be a name.
fn parse_network(text: &str) -> Option<Result<Target, &'static str>> {
    let (address, prefix_len) = match text.split_once('/') {
        Some((address, prefix_len)) => (address, Some(prefix_len)),
        None => (text, None),
    };
    let Ok(network) = address.parse::<IpAddr>() else {
        return prefix_len.map(|_| Err("the text before `/` is not an address"));
    };
    let width = prefix::width(network);
    let prefix_len = match prefix_len {
        None => width,
        Some(text) => match text.parse::<u8>() {
            Ok(prefix_len) if prefix_len <= width => prefix_len,
            Ok(_) => return Some(Err("the prefix is longer than the address family's width")),
            Err(_) => return Some(Err("the text after `/` is not a prefix length")),
        },
    };
    if !prefix::is_network(network, prefix_len) {
        return Some(Err(
            "the address has bits set past its prefix, so it names no network",
        ));
    }
    Some(Ok(Target::Network {
        network,
        prefix_len,
    }))
}

/// Parses a name, or a wildcard over the names below one, lowering its case
/// and dropping one trailing dot.
fn parse_name(text: &str) -> Result<Target, &'static str> {
    if !text.is_ascii() {
        return Err("an internationalized name is written in its ASCII `xn--` form");
    }
    let lowered = text.to_ascii_lowercase();
    let name = lowered.strip_suffix('.').unwrap_or(&lowered);
    if name == "*" {
        return Ok(Target::Below(Arc::from("")));
    }
    let (below, name) = match name.strip_prefix("*.") {
        Some(base) => (true, base),
        None => (false, name),
    };
    validate_name(name)?;
    Ok(match below {
        true => Target::Below(name.into()),
        false => Target::Name(name.into()),
    })
}

/// Checks a lowered name with no trailing dot: a host name
/// ([`dns::host_name_flaw`]) without a wildcard in it, whose last label is not
/// a number.
fn validate_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("it names no destination");
    }
    if name.contains('*') {
        return Err("a wildcard is a whole first label, as in `*.example.com`");
    }
    if let Some(flaw) = dns::host_name_flaw(name) {
        return Err(flaw);
    }
    let last = name.rsplit('.').next().unwrap_or(name);
    if is_number(last) {
        return Err("the name's last label is a number, which a resolver may read as an address");
    }
    Ok(())
}

/// Whether a lowered label reads as a number to a resolver that takes a numeric
/// host for an address: all decimal digits, or `0x` and hexadecimal digits.
///
/// This is the URL standard's test of a host that "ends in a number", which
/// it then parses as an IPv4 address. `inet_aton` reads the same spellings:
/// `2130706433`, `127.1` and `0x7f.1` are all `127.0.0.1` to it.
fn is_number(label: &str) -> bool {
    match label.strip_prefix("0x") {
        Some(hex) => hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
        None => label.bytes().all(|byte| byte.is_ascii_digit()),
    }
}

/// Parses a comma-separated list of ports and inclusive ranges.
fn parse_ports(text: &str) -> Result<Vec<Ports>, &'static str> {
    let port = |text: &str| match text.parse::<u16>() {
        Ok(0) => Err("port 0 names no port"),
        Ok(port) => Ok(port),
        Err(_) => Err("a port is a number from 1 to 65535"),
    };
    text.split(',')
        .map(|entry| {
            let (first, last) = match entry.split_once('-') {
                Some((first, last)) => (port(first)?, port(last)?),
                None => {
                    let single = port(entry)?;
                    (single, single)
                }
            };
            if first > last {
                return Err("a range of ports runs backwards");
            }
            Ok(Ports { first, last })
        })
        .collect()
}

impl fmt::Display for DestinationRule {
    /// Writes the rule in the grammar it parses from: a transport where one
    /// was given, the target, and the ports, an IPv6 target bracketed where
    /// ports follow it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(transport) = self.transport {
            write!(f, "{transport}:")?;
        }
        let bracketed = !self.ports.is_empty()
            && matches!(
                self.target,
                Target::Network {
                    network: IpAddr::V6(_),
                    ..
                }
            );
        if bracketed {
            f.write_str("[")?;
        }
        match &self.target {
            Target::Name(name) => f.write_str(name)?,
            Target::Below(base) if base.is_empty() => f.write_str("*")?,
            Target::Below(base) => write!(f, "*.{base}")?,
            Target::Network {
                network,
                prefix_len,
            } => {
                write!(f, "{network}")?;
                if *prefix_len != prefix::width(*network) {
                    write!(f, "/{prefix_len}")?;
                }
            }
        }
        if bracketed {
            f.write_str("]")?;
        }
        for (index, ports) in self.ports.iter().enumerate() {
            f.write_str(if index == 0 { ":" } else { "," })?;
            write!(f, "{}", ports.first)?;
            if ports.last != ports.first {
                write!(f, "-{}", ports.last)?;
            }
        }
        Ok(())
    }
}

/// A rule renders as its text.
#[cfg(feature = "serde")]
impl serde::Serialize for DestinationRule {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Accepts the text a rule renders as.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for DestinationRule {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(DestinationRuleVisitor)
    }
}

#[cfg(feature = "serde")]
struct DestinationRuleVisitor;

#[cfg(feature = "serde")]
impl serde::de::Visitor<'_> for DestinationRuleVisitor {
    type Value = DestinationRule;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a destination rule: an address, a network or a name, with optional ports")
    }

    fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<DestinationRule, E> {
        text.parse().map_err(E::custom)
    }
}

/// The error from parsing a [`DestinationRule`] outside its grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDestinationRuleError {
    text: String,
    reason: &'static str,
}

impl ParseDestinationRuleError {
    /// The unparsed text, as it was given.
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for ParseDestinationRuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} is not a destination rule: {}",
            self.text, self.reason
        )
    }
}

impl std::error::Error for ParseDestinationRuleError {}

/// What the destination rules hold a TCP flow's first bytes to: the server a
/// TLS ClientHello or an HTTP request asks for
/// ([`server_name`](super::server_name)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Hold {
    /// The flow was admitted by a name the stack resolved to its address, so
    /// an allow name rule must admit the server too, and no deny rule refuse
    /// it.
    AllowRules,
    /// The flow was admitted by an address rule or by default, so a deny name
    /// rule alone refuses the server.
    DenyRules,
}

/// A configuration's allow and deny rules, which decide each destination the
/// stack would otherwise carry.
#[derive(Debug, Clone, Default)]
pub(super) struct Policy {
    /// The rules that admit, in the order given.
    pub(super) allow: Vec<DestinationRule>,
    /// The rules that refuse, in the order given.
    pub(super) deny: Vec<DestinationRule>,
    /// The host's own networks, read when the stack attaches, which a name
    /// rule admits no address on; see [`own`](super::own).
    pub(super) own: Vec<(IpAddr, u8)>,
}

/// The private ranges a name rule does not admit an address in: RFC 1918's
/// three, the shared address space of RFC 6598, and IPv6's unique local
/// addresses.
const PRIVATE: [(IpAddr, u8); 5] = [
    (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
    (IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12),
    (IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16),
    (IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10),
    (IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)), 7),
];

/// The IPv4 address `address` reaches through NAT64's well-known prefix, where
/// it is under that prefix ([`prefix::nat64_embedded`]).
fn translated(address: IpAddr) -> Option<IpAddr> {
    match address {
        IpAddr::V6(address) => prefix::nat64_embedded(address).map(IpAddr::V4),
        IpAddr::V4(_) => None,
    }
}

/// Whether `address` is in one of the [`PRIVATE`] ranges, as itself or as the
/// IPv4 address it reaches through NAT64.
fn is_private(address: IpAddr) -> bool {
    let embedded = translated(address);
    PRIVATE.iter().any(|&(network, prefix_len)| {
        prefix::contains(network, prefix_len, address)
            || embedded.is_some_and(|embedded| prefix::contains(network, prefix_len, embedded))
    })
}

impl Policy {
    /// Whether any rule, allow or deny, is a name rule.
    pub(super) fn has_names(&self) -> bool {
        self.allow
            .iter()
            .chain(&self.deny)
            .any(DestinationRule::is_name)
    }

    /// What the rules decide of a question for `name`, a name's text as the
    /// stack's nameserver writes it, and which rule decided it.
    ///
    /// A deny name rule without ports that matches the name refuses it,
    /// whatever else matches. One with ports leaves the question to the other
    /// rules and refuses the flows to the name on its ports. Otherwise a policy
    /// with any allow rule admits a name an allow name rule matches, whatever
    /// that rule's ports, and refuses the rest, since an address rule admits no
    /// name. One without admits every name by default.
    pub(super) fn decide_question(&self, name: &str) -> Result<FlowAdmission, FlowRefusal> {
        if let Some(rule) = self
            .deny
            .iter()
            .find(|rule| rule.ports.is_empty() && rule.matches_name(name))
        {
            return Err(FlowRefusal::Denied { rule: rule.clone() });
        }
        if self.allow.is_empty() {
            return Ok(FlowAdmission::Default);
        }
        match self.allow.iter().find(|rule| rule.matches_name(name)) {
            Some(rule) => Ok(FlowAdmission::Allowed { rule: rule.clone() }),
            None => Err(FlowRefusal::NotAllowed),
        }
    }

    /// What the rules decide of a flow over `transport` to `address` on `port`,
    /// which the stack's nameserver resolved `names` to, the most recently
    /// resolved first, and which rule decided it. Where a name rule decided, the
    /// name it matched comes back beside the decision.
    ///
    /// A deny rule that matches refuses, whatever else matches, and the first
    /// that matches is the one named. A deny name rule matches a flow to any of
    /// `names` over either transport, unless `tcp:` qualifies it. Otherwise a
    /// policy with any allow rule admits what an allow rule matches and refuses
    /// the rest, and one without admits everything by default. The allow rule
    /// named is the first address rule that matches, and only where none does,
    /// the first name rule: an address rule is the exact grant, and a flow it
    /// admits is not held to the server its first bytes ask for
    /// ([`hold`](Self::hold)). The destinations no rule can admit are the
    /// caller's to refuse first.
    ///
    /// An allow name rule admits a TCP flow to an address one of `names` it
    /// matches was resolved to, and two flows it would otherwise admit are
    /// refused, unless an address rule admits them: a UDP flow, since a name
    /// rule admits TCP alone, and a flow to an address in a private range,
    /// since a name anyone can register could be resolved to the host's own
    /// network. A flow to an address no allow rule admits, which the nameserver
    /// resolved no name to, is refused as [`FlowRefusal::NotResolved`] where
    /// the policy has an allow name rule: the guest learned the address
    /// elsewhere.
    ///
    /// An address under NAT64's well-known prefix is matched as itself and as
    /// the IPv4 address it embeds, since a translator carries the flow to that
    /// address ([`prefix::nat64_embedded`]). An IPv4 rule therefore covers the
    /// address's translated spelling as well, and a deny rule cannot be passed
    /// by way of the translator.
    pub(super) fn decide<'a>(
        &self,
        transport: Transport,
        address: IpAddr,
        port: u16,
        names: impl Iterator<Item = &'a Arc<str>> + Clone,
    ) -> (Result<FlowAdmission, FlowRefusal>, Option<&'a Arc<str>>) {
        let embedded = translated(address);
        let by_address = |rule: &DestinationRule| {
            rule.matches_address(transport, address, port)
                || embedded.is_some_and(|embedded| rule.matches_address(transport, embedded, port))
        };
        let by_name = |rule: &DestinationRule| names.clone().find(|name| rule.matches_name(name));
        for rule in &self.deny {
            if by_address(rule) {
                return (Err(FlowRefusal::Denied { rule: rule.clone() }), None);
            }
            if rule.covers(transport, port)
                && let Some(name) = by_name(rule)
            {
                return (Err(FlowRefusal::Denied { rule: rule.clone() }), Some(name));
            }
        }
        if self.allow.is_empty() {
            return (Ok(FlowAdmission::Default), None);
        }
        if let Some(rule) = self.allow.iter().find(|rule| by_address(rule)) {
            return (Ok(FlowAdmission::Allowed { rule: rule.clone() }), None);
        }
        // A name rule that matches and does not admit is remembered, and its
        // reason given where no later name rule admits the flow.
        let mut withheld = None;
        for rule in &self.allow {
            let Some(name) = rule
                .covers(Transport::Tcp, port)
                .then(|| by_name(rule))
                .flatten()
            else {
                continue;
            };
            let rule = rule.clone();
            let refusal = if transport == Transport::Udp {
                FlowRefusal::NameOverUdp { rule }
            } else if is_private(address)
                || own::holds(&self.own, address)
                || embedded.is_some_and(|embedded| own::holds(&self.own, embedded))
            {
                FlowRefusal::PrivateBehindName { rule }
            } else {
                return (Ok(FlowAdmission::Allowed { rule }), Some(name));
            };
            withheld.get_or_insert((refusal, name));
        }
        if let Some((refusal, name)) = withheld {
            return (Err(refusal), Some(name));
        }
        let unresolved =
            names.clone().next().is_none() && self.allow.iter().any(DestinationRule::is_name);
        match unresolved {
            true => (Err(FlowRefusal::NotResolved), None),
            false => (Err(FlowRefusal::NotAllowed), None),
        }
    }

    /// What the rules hold the first bytes of a TCP flow to `port` to, which
    /// `admission` admitted, or `None` where nothing those bytes could ask for
    /// would refuse the flow.
    ///
    /// On an address many sites share, the name the client sends picks the
    /// site. A flow an allow name rule admitted reached its address through a
    /// name the guest resolved, so the name it sends is held to the allow rules
    /// as that one was. A flow admitted otherwise is held where a deny name rule
    /// covers its port. The gateway's loopback mapping is outside the rules.
    pub(super) fn hold(&self, admission: &FlowAdmission, port: u16) -> Option<Hold> {
        match admission {
            FlowAdmission::Allowed { rule } if rule.is_name() => Some(Hold::AllowRules),
            FlowAdmission::HostLoopback => None,
            FlowAdmission::Default | FlowAdmission::Allowed { .. } => self
                .deny
                .iter()
                .any(|rule| rule.is_name() && rule.covers(Transport::Tcp, port))
                .then_some(Hold::DenyRules),
        }
    }

    /// What the rules decide of `hosts`, the servers the first bytes of a TCP
    /// flow to `destination` on `port` ask for, which `hold` holds them to.
    ///
    /// A deny name rule covering the port that matches a name refuses the
    /// flow. Under [`Hold::AllowRules`] an allow name rule covering the port
    /// must also match each name. An address names no site but itself, so
    /// under [`Hold::AllowRules`] it is the flow's own destination or the flow
    /// is refused, and under [`Hold::DenyRules`] it is passed over. First bytes
    /// that ask for no server are decided at the flow's attempt alone.
    pub(super) fn decide_servers(
        &self,
        hold: Hold,
        destination: IpAddr,
        port: u16,
        hosts: &[Host],
    ) -> Result<(), FlowRefusal> {
        for host in hosts {
            let name = match host {
                Host::Name(name) => name,
                Host::Address(address) if hold == Hold::AllowRules && *address != destination => {
                    return Err(FlowRefusal::ServerNameNotAllowed {
                        name: address.to_string(),
                    });
                }
                Host::Address(_) => continue,
            };
            let matches = |rule: &&DestinationRule| {
                rule.covers(Transport::Tcp, port) && rule.matches_name(name)
            };
            if let Some(rule) = self.deny.iter().find(matches) {
                return Err(FlowRefusal::ServerNameDenied {
                    name: name.clone(),
                    rule: rule.clone(),
                });
            }
            if hold == Hold::AllowRules && !self.allow.iter().any(|rule| matches(&rule)) {
                return Err(FlowRefusal::ServerNameNotAllowed { name: name.clone() });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(text: &str) -> DestinationRule {
        text.parse()
            .unwrap_or_else(|err| panic!("{text:?} parses: {err}"))
    }

    fn refusal(text: &str) -> &'static str {
        text.parse::<DestinationRule>().expect_err(text).reason
    }

    #[test]
    fn each_form_parses_and_writes_back_as_written() {
        for text in [
            "192.0.2.7",
            "192.0.2.0/24",
            "0.0.0.0/0",
            "2001:db8::1",
            "2001:db8::/32",
            "::/0",
            "example.com",
            "*.example.com",
            "*",
            "localhost",
            "_service._tcp.example.com",
            "xn--bcher-kva.example",
            "example.com:443",
            "example.com:80,443",
            "example.com:8000-8999",
            "192.0.2.0/24:22,80,8000-8999",
            "[2001:db8::1]:443",
            "[2001:db8::/32]:443",
            "tcp:example.com",
            "tcp:*.example.com:443",
            "udp:192.0.2.0/24:53",
            "tcp:2001:db8::/32",
            "udp:[2001:db8::53]:53",
            "tcp:*:443",
        ] {
            assert_eq!(rule(text).to_string(), text, "{text}");
        }
    }

    #[test]
    fn a_rule_is_written_back_in_one_spelling() {
        for (given, written) in [
            ("EXAMPLE.Com", "example.com"),
            ("example.com.", "example.com"),
            ("*.Example.COM.", "*.example.com"),
            ("*.", "*"),
            ("TCP:example.com", "tcp:example.com"),
            ("Udp:192.0.2.1", "udp:192.0.2.1"),
            ("192.0.2.7/32", "192.0.2.7"),
            ("2001:DB8::1", "2001:db8::1"),
            ("2001:db8::1/128", "2001:db8::1"),
            ("[2001:db8::1]", "2001:db8::1"),
            ("[2001:db8::/32]", "2001:db8::/32"),
            ("example.com:443-443", "example.com:443"),
        ] {
            let parsed = rule(given);
            assert_eq!(parsed.to_string(), written, "{given}");
            assert_eq!(rule(written), parsed, "{given} reads back as itself");
        }
    }

    #[test]
    fn a_character_straddling_a_transport_s_spelling_is_read_not_sliced() {
        // `é` takes two bytes, so a slice at a spelling's length would cut it.
        for text in [
            "tcé",
            "udé",
            "tcé:example.com",
            "tcpé",
            "TCé:443",
            "tcp:é.example",
        ] {
            assert!(text.parse::<DestinationRule>().is_err(), "{text}");
        }
        assert_eq!(rule("tCp:example.com").to_string(), "tcp:example.com");
    }

    #[test]
    fn an_unbracketed_ipv6_address_carries_no_ports() {
        // Its colons are its own: the last group is part of the address.
        let parsed = rule("2001:db8::1:443");
        assert!(parsed.ports.is_empty());
        assert_eq!(parsed.to_string(), "2001:db8::1:443");
    }

    #[test]
    fn every_spelling_outside_the_grammar_is_refused_with_its_reason() {
        for (text, reason) in [
            ("", "it names no destination"),
            ("tcp:", "it names no destination"),
            ("example.com:0", "port 0 names no port"),
            ("example.com:", "a port is a number from 1 to 65535"),
            ("example.com:80,", "a port is a number from 1 to 65535"),
            ("example.com:65536", "a port is a number from 1 to 65535"),
            ("example.com:http", "a port is a number from 1 to 65535"),
            ("example.com:9000-8000", "a range of ports runs backwards"),
            ("example.com:0-80", "port 0 names no port"),
            (
                "192.0.2.0/33",
                "the prefix is longer than the address family's width",
            ),
            (
                "2001:db8::/129",
                "the prefix is longer than the address family's width",
            ),
            ("192.0.2.0/x", "the text after `/` is not a prefix length"),
            (
                "192.0.2.7/24",
                "the address has bits set past its prefix, so it names no network",
            ),
            ("example.com/24", "the text before `/` is not an address"),
            (
                "udp:example.com",
                "a name rule covers TCP alone, so `udp:` cannot qualify one",
            ),
            (
                "udp:*.example.com:443",
                "a name rule covers TCP alone, so `udp:` cannot qualify one",
            ),
            (
                "*example.com",
                "a wildcard is a whole first label, as in `*.example.com`",
            ),
            (
                "www.*.example.com",
                "a wildcard is a whole first label, as in `*.example.com`",
            ),
            (
                "*.*.example.com",
                "a wildcard is a whole first label, as in `*.example.com`",
            ),
            ("example..com", "the name has an empty label"),
            (".example.com", "the name has an empty label"),
            ("example.com..", "the name has an empty label"),
            (
                "exa mple.com",
                "a name holds letters, digits, `-` and `_` between its dots",
            ),
            (
                "bücher.example",
                "an internationalized name is written in its ASCII `xn--` form",
            ),
            (
                "2130706433",
                "the name's last label is a number, which a resolver may read as an address",
            ),
            (
                "127.1",
                "the name's last label is a number, which a resolver may read as an address",
            ),
            (
                "0x7f.1",
                "the name's last label is a number, which a resolver may read as an address",
            ),
            (
                "0x7f000001",
                "the name's last label is a number, which a resolver may read as an address",
            ),
            (
                // An address with a leading zero, which the address parser
                // refuses, is a name whose last label is a number.
                "192.0.2.07",
                "the name's last label is a number, which a resolver may read as an address",
            ),
            (
                "*.127.1",
                "the name's last label is a number, which a resolver may read as an address",
            ),
            (
                "[192.0.2.1]:80",
                "only an IPv6 address or network is bracketed",
            ),
            (
                "[example.com]:80",
                "only an IPv6 address or network is bracketed",
            ),
            ("[2001:db8::1", "an opening `[` has no closing `]`"),
            (
                "[2001:db8::1]443",
                "only `:PORTS` may follow a bracketed address",
            ),
            (
                "2001:db8::zz",
                "it is neither an address nor a name; an IPv6 address with ports is bracketed, \
                 as in `[2001:db8::1]:443`",
            ),
        ] {
            assert_eq!(refusal(text), reason, "{text:?}");
        }
        // A label and a name at their limits, and one byte past each.
        let label = "a".repeat(63);
        rule(&format!("{label}.example"));
        assert_eq!(
            refusal(&format!("a{label}.example")),
            "a label of the name is longer than 63 characters",
        );
        let name = vec!["a".repeat(61); 4].join(".") + ".example";
        assert_eq!(name.len(), 253 + 2);
        assert_eq!(refusal(&name), "the name is longer than 253 characters");
        rule(&name[2..]);
        // A last label that only starts like a number is a name.
        rule("0xample.com");
        rule("example.123a");
    }

    #[test]
    fn the_error_names_the_text_and_why() {
        let err = "example.com:0".parse::<DestinationRule>().unwrap_err();
        assert_eq!(err.text(), "example.com:0");
        assert_eq!(
            err.to_string(),
            "\"example.com:0\" is not a destination rule: port 0 names no port"
        );
    }

    #[test]
    fn a_wildcard_over_one_label_or_none_is_broad() {
        assert!(rule("*").is_broad_wildcard());
        assert!(rule("*.com").is_broad_wildcard());
        assert!(rule("tcp:*.com:443").is_broad_wildcard());
        assert!(!rule("*.example.com").is_broad_wildcard());
        assert!(!rule("com").is_broad_wildcard());
        assert!(!rule("0.0.0.0/0").is_broad_wildcard());
        assert!(rule("com").is_name());
        assert!(rule("*").is_name());
        assert!(!rule("192.0.2.1").is_name());
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn rules(allow: &[&str], deny: &[&str]) -> Policy {
        Policy {
            own: Vec::new(),
            allow: allow.iter().map(|text| rule(text)).collect(),
            deny: deny.iter().map(|text| rule(text)).collect(),
        }
    }

    impl Policy {
        /// The decision of a flow to an address the nameserver resolved no
        /// name to.
        fn decide_unnamed(
            &self,
            transport: Transport,
            address: IpAddr,
            port: u16,
        ) -> Result<FlowAdmission, FlowRefusal> {
            self.decide(transport, address, port, std::iter::empty()).0
        }

        /// The decision of a flow to an address the nameserver resolved
        /// `names` to, the most recent first, and the name it was taken for.
        fn decide_named(
            &self,
            transport: Transport,
            address: &str,
            port: u16,
            names: &[&str],
        ) -> (Result<FlowAdmission, FlowRefusal>, Option<String>) {
            let names: Vec<Arc<str>> = names.iter().map(|&name| Arc::from(name)).collect();
            let (decision, name) = self.decide(transport, ip(address), port, names.iter());
            (decision, name.map(ToString::to_string))
        }
    }

    #[test]
    fn a_name_rule_matches_its_name_and_a_wildcard_the_names_below() {
        let exact = rule("example.com");
        assert!(exact.matches_name("example.com"));
        assert!(!exact.matches_name("www.example.com"));
        assert!(!exact.matches_name("example.co"));
        let below = rule("*.example.com");
        for name in ["www.example.com", "a.b.example.com", "\\042.example.com"] {
            assert!(below.matches_name(name), "{name}");
        }
        // The apex, a name that only ends in the same letters, and one whose
        // last labels hold an escaped dot rather than a boundary.
        for name in ["example.com", "badexample.com", "x\\046example.com", "."] {
            assert!(!below.matches_name(name), "{name}");
        }
        let every = rule("*");
        assert!(every.matches_name("com") && every.matches_name("www.example.com"));
        assert!(!every.matches_name("."), "the root is below nothing");
        assert!(!rule("192.0.2.0/24").matches_name("example.com"));
    }

    #[test]
    fn a_question_is_held_to_the_name_rules() {
        let open = Policy::default();
        assert_eq!(
            open.decide_question("example.com"),
            Ok(FlowAdmission::Default)
        );
        // Allow rules of either kind admit only the names an allow name rule
        // matches, whatever its ports.
        let allowing = rules(&["192.0.2.0/24", "*.example.com:443"], &[]);
        assert_eq!(
            allowing.decide_question("www.example.com"),
            Ok(FlowAdmission::Allowed {
                rule: rule("*.example.com:443")
            })
        );
        assert_eq!(
            allowing.decide_question("example.com"),
            Err(FlowRefusal::NotAllowed)
        );
        let by_address = rules(&["192.0.2.0/24"], &[]);
        assert_eq!(
            by_address.decide_question("example.com"),
            Err(FlowRefusal::NotAllowed)
        );
        // A deny name rule refuses its names whatever an allow rule admits,
        // unless it names ports, when it refuses flows and leaves the question.
        let denying = rules(
            &["*.example.com"],
            &["tcp:bad.example.com", "*.example.com:25"],
        );
        assert_eq!(
            denying.decide_question("bad.example.com"),
            Err(FlowRefusal::Denied {
                rule: rule("tcp:bad.example.com")
            })
        );
        assert_eq!(
            denying.decide_question("mail.example.com"),
            Ok(FlowAdmission::Allowed {
                rule: rule("*.example.com")
            })
        );
        // Deny rules alone admit every other name, an address deny none.
        let deny_alone = rules(&[], &["bad.example.com", "192.0.2.0/24"]);
        assert!(deny_alone.decide_question("bad.example.com").is_err());
        assert_eq!(
            deny_alone.decide_question("good.example.com"),
            Ok(FlowAdmission::Default)
        );
        assert!(deny_alone.has_names() && allowing.has_names());
        assert!(!by_address.has_names() && !open.has_names());
    }

    #[test]
    fn an_allow_name_rule_admits_tcp_to_a_resolved_address() {
        let policy = rules(&["example.com:443", "*.example.net"], &[]);
        assert_eq!(
            policy.decide_named(Transport::Tcp, "198.51.100.7", 443, &["example.com"]),
            (
                Ok(FlowAdmission::Allowed {
                    rule: rule("example.com:443")
                }),
                Some("example.com".to_string())
            )
        );
        // Another port, or an address resolved for no admitted name.
        assert_eq!(
            policy.decide_named(Transport::Tcp, "198.51.100.7", 80, &["example.com"]),
            (Err(FlowRefusal::NotAllowed), None)
        );
        assert_eq!(
            policy.decide_named(Transport::Tcp, "198.51.100.7", 80, &[]),
            (Err(FlowRefusal::NotResolved), None)
        );
        // Of several names at one address, the one a rule admits is named.
        assert_eq!(
            policy.decide_named(
                Transport::Tcp,
                "198.51.100.7",
                22,
                &["other.example", "www.example.net"]
            ),
            (
                Ok(FlowAdmission::Allowed {
                    rule: rule("*.example.net")
                }),
                Some("www.example.net".to_string())
            )
        );
    }

    #[test]
    fn a_name_rule_admits_no_address_on_the_host_s_own_networks() {
        // A LAN numbered from global addresses, and the host's own public
        // address, read when the stack attached.
        let mut policy = rules(&["example.com"], &[]);
        policy.own = vec![
            ("2001:db8:1:2::".parse().unwrap(), 64),
            ("203.0.113.0".parse().unwrap(), 24),
        ];
        for own in ["2001:db8:1:2::77", "203.0.113.9", "64:ff9b::203.0.113.9"] {
            assert_eq!(
                policy
                    .decide_named(Transport::Tcp, own, 443, &["example.com"])
                    .0,
                Err(FlowRefusal::PrivateBehindName {
                    rule: rule("example.com")
                }),
                "{own}"
            );
        }
        for elsewhere in ["2001:db8:1:3::77", "203.0.114.9"] {
            assert!(
                policy
                    .decide_named(Transport::Tcp, elsewhere, 443, &["example.com"])
                    .0
                    .is_ok(),
                "{elsewhere}"
            );
        }
    }

    #[test]
    fn a_name_rule_admits_neither_udp_nor_a_private_address() {
        let policy = rules(&["example.com"], &[]);
        assert_eq!(
            policy.decide_named(Transport::Udp, "198.51.100.7", 443, &["example.com"]),
            (
                Err(FlowRefusal::NameOverUdp {
                    rule: rule("example.com")
                }),
                Some("example.com".to_string())
            )
        );
        for private in [
            "10.1.2.3",
            "172.31.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "fd12::1",
            "64:ff9b::10.1.2.3",
        ] {
            assert_eq!(
                policy
                    .decide_named(Transport::Tcp, private, 443, &["example.com"])
                    .0,
                Err(FlowRefusal::PrivateBehindName {
                    rule: rule("example.com")
                }),
                "{private}"
            );
        }
        // Next to those ranges, a name admits as it does anywhere.
        for public in [
            "172.32.0.1",
            "100.128.0.1",
            "fe00::1",
            "64:ff9b::198.51.100.7",
        ] {
            assert!(
                policy
                    .decide_named(Transport::Tcp, public, 443, &["example.com"])
                    .0
                    .is_ok(),
                "{public}"
            );
        }
        // An address rule admits either, the name still named.
        let with_address = rules(&["example.com", "192.168.0.0/16", "udp:198.51.100.7"], &[]);
        assert_eq!(
            with_address.decide_named(Transport::Tcp, "192.168.1.1", 443, &["example.com"]),
            (
                Ok(FlowAdmission::Allowed {
                    rule: rule("192.168.0.0/16")
                }),
                None
            )
        );
        assert!(
            with_address
                .decide_named(Transport::Udp, "198.51.100.7", 443, &["example.com"])
                .0
                .is_ok()
        );
    }

    #[test]
    fn a_deny_name_rule_refuses_flows_to_its_names_addresses() {
        let policy = rules(&["*.example.com"], &["mail.example.com:25"]);
        assert_eq!(
            policy.decide_named(Transport::Tcp, "198.51.100.7", 25, &["mail.example.com"]),
            (
                Err(FlowRefusal::Denied {
                    rule: rule("mail.example.com:25")
                }),
                Some("mail.example.com".to_string())
            )
        );
        assert!(
            policy
                .decide_named(Transport::Tcp, "198.51.100.7", 443, &["mail.example.com"])
                .0
                .is_ok()
        );
        // Over either transport, unless the rule names TCP, and under deny
        // rules alone as well.
        let deny_alone = rules(&[], &["mail.example.com:443", "tcp:tcp.example.com"]);
        assert!(
            deny_alone
                .decide_named(Transport::Udp, "198.51.100.7", 443, &["mail.example.com"])
                .0
                .is_err()
        );
        assert_eq!(
            deny_alone
                .decide_named(Transport::Udp, "198.51.100.8", 443, &["tcp.example.com"])
                .0,
            Ok(FlowAdmission::Default)
        );
        assert!(
            deny_alone
                .decide_named(Transport::Tcp, "198.51.100.8", 443, &["tcp.example.com"])
                .0
                .is_err()
        );
    }

    #[test]
    fn no_rules_admit_everything() {
        let open = Policy::default();
        assert!(
            open.decide_unnamed(Transport::Tcp, ip("203.0.113.9"), 443)
                .is_ok()
        );
        assert!(
            open.decide_unnamed(Transport::Udp, ip("2001:db8::1"), 53)
                .is_ok()
        );
    }

    #[test]
    fn any_allow_rule_refuses_what_no_allow_rule_admits() {
        let policy = rules(&["192.0.2.0/24", "[2001:db8::/32]:443"], &[]);
        assert!(
            policy
                .decide_unnamed(Transport::Tcp, ip("192.0.2.7"), 22)
                .is_ok()
        );
        assert!(
            policy
                .decide_unnamed(Transport::Udp, ip("192.0.2.255"), 53)
                .is_ok()
        );
        assert!(
            policy
                .decide_unnamed(Transport::Tcp, ip("192.0.3.1"), 22)
                .is_err()
        );
        assert!(
            policy
                .decide_unnamed(Transport::Tcp, ip("2001:db8::1"), 443)
                .is_ok()
        );
        assert!(
            policy
                .decide_unnamed(Transport::Tcp, ip("2001:db8::1"), 80)
                .is_err()
        );
        assert!(
            policy
                .decide_unnamed(Transport::Tcp, ip("2001:db9::1"), 443)
                .is_err()
        );
    }

    #[test]
    fn deny_rules_alone_admit_what_they_do_not_refuse() {
        let policy = rules(&[], &["192.168.0.0/16", "tcp:203.0.113.9:25"]);
        assert!(
            policy
                .decide_unnamed(Transport::Tcp, ip("192.168.1.1"), 80)
                .is_err()
        );
        assert!(
            policy
                .decide_unnamed(Transport::Udp, ip("192.168.1.1"), 53)
                .is_err()
        );
        assert!(
            policy
                .decide_unnamed(Transport::Tcp, ip("192.169.0.1"), 80)
                .is_ok()
        );
        assert!(
            policy
                .decide_unnamed(Transport::Tcp, ip("203.0.113.9"), 25)
                .is_err()
        );
        assert!(
            policy
                .decide_unnamed(Transport::Udp, ip("203.0.113.9"), 25)
                .is_ok()
        );
        assert!(
            policy
                .decide_unnamed(Transport::Tcp, ip("203.0.113.9"), 26)
                .is_ok()
        );
    }

    #[test]
    fn a_deny_rule_beats_an_allow_rule() {
        let policy = rules(&["192.0.2.0/24"], &["192.0.2.7:22"]);
        assert!(
            policy
                .decide_unnamed(Transport::Tcp, ip("192.0.2.7"), 22)
                .is_err()
        );
        assert!(
            policy
                .decide_unnamed(Transport::Tcp, ip("192.0.2.7"), 23)
                .is_ok()
        );
        assert!(
            policy
                .decide_unnamed(Transport::Tcp, ip("192.0.2.8"), 22)
                .is_ok()
        );
    }

    #[test]
    fn a_transport_qualifies_a_rule_to_itself() {
        let udp = rules(&["udp:192.0.2.53:53"], &[]);
        assert!(
            udp.decide_unnamed(Transport::Udp, ip("192.0.2.53"), 53)
                .is_ok()
        );
        assert!(
            udp.decide_unnamed(Transport::Tcp, ip("192.0.2.53"), 53)
                .is_err()
        );
        let tcp = rules(&["tcp:0.0.0.0/0"], &[]);
        assert!(
            tcp.decide_unnamed(Transport::Tcp, ip("192.0.2.1"), 443)
                .is_ok()
        );
        assert!(
            tcp.decide_unnamed(Transport::Udp, ip("192.0.2.1"), 443)
                .is_err()
        );
    }

    #[test]
    fn a_name_rule_matches_no_address_by_itself() {
        let allow = rules(&["example.com", "*"], &[]);
        assert!(
            allow
                .decide_unnamed(Transport::Tcp, ip("192.0.2.1"), 443)
                .is_err()
        );
        let deny = rules(&[], &["*"]);
        assert!(
            deny.decide_unnamed(Transport::Tcp, ip("192.0.2.1"), 443)
                .is_ok()
        );
    }

    #[test]
    fn a_translated_address_is_held_to_the_ipv4_rules() {
        // Denied as itself, the address is denied under NAT64's prefix too,
        // which the translator would carry it to.
        let deny = rules(&[], &["203.0.113.0/24"]);
        assert!(
            deny.decide_unnamed(Transport::Tcp, ip("64:ff9b::203.0.113.9"), 443)
                .is_err()
        );
        assert!(
            deny.decide_unnamed(Transport::Tcp, ip("64:ff9b::198.51.100.1"), 443)
                .is_ok()
        );
        // Allowed as itself, so it is under the prefix.
        let allow = rules(&["203.0.113.0/24"], &[]);
        assert!(
            allow
                .decide_unnamed(Transport::Tcp, ip("64:ff9b::203.0.113.9"), 443)
                .is_ok()
        );
        assert!(
            allow
                .decide_unnamed(Transport::Tcp, ip("64:ff9b::198.51.100.1"), 443)
                .is_err()
        );
        // Outside the well-known /96 an address embeds nothing.
        assert!(
            allow
                .decide_unnamed(Transport::Tcp, ip("64:ff9b:1::cb00:7109"), 443)
                .is_err()
        );
        // An IPv6 rule over the prefix is a rule like any other, and a deny of
        // the embedded address still beats it.
        let both = rules(&["64:ff9b::/96"], &["203.0.113.9"]);
        assert!(
            both.decide_unnamed(Transport::Tcp, ip("64:ff9b::198.51.100.1"), 443)
                .is_ok()
        );
        assert!(
            both.decide_unnamed(Transport::Tcp, ip("64:ff9b::203.0.113.9"), 443)
                .is_err()
        );
    }

    #[test]
    fn the_first_rule_that_matches_is_the_one_named() {
        let policy = rules(
            &["192.0.2.0/24", "192.0.2.7"],
            &["192.0.2.7:22", "192.0.2.0/24:22"],
        );
        assert_eq!(
            policy.decide_unnamed(Transport::Tcp, ip("192.0.2.7"), 22),
            Err(FlowRefusal::Denied {
                rule: rule("192.0.2.7:22")
            })
        );
        assert_eq!(
            policy.decide_unnamed(Transport::Tcp, ip("192.0.2.8"), 22),
            Err(FlowRefusal::Denied {
                rule: rule("192.0.2.0/24:22")
            })
        );
        assert_eq!(
            policy.decide_unnamed(Transport::Tcp, ip("192.0.2.7"), 80),
            Ok(FlowAdmission::Allowed {
                rule: rule("192.0.2.0/24")
            })
        );
        assert_eq!(
            policy.decide_unnamed(Transport::Tcp, ip("198.51.100.1"), 80),
            Err(FlowRefusal::NotAllowed)
        );
        // An address under NAT64's prefix names the IPv4 rule that matched what
        // it embeds.
        assert_eq!(
            policy.decide_unnamed(Transport::Tcp, ip("64:ff9b::192.0.2.9"), 80),
            Ok(FlowAdmission::Allowed {
                rule: rule("192.0.2.0/24")
            })
        );
    }

    #[test]
    fn an_address_rule_admits_ahead_of_a_name_rule_given_before_it() {
        // The address rule is the exact grant, so it is named whatever the
        // order, and the flow is held to nothing but the deny rules.
        let policy = rules(&["example.com", "198.51.100.0/24"], &[]);
        let (admission, name) =
            policy.decide_named(Transport::Tcp, "198.51.100.7", 443, &["example.com"]);
        assert_eq!(
            admission,
            Ok(FlowAdmission::Allowed {
                rule: rule("198.51.100.0/24")
            })
        );
        assert_eq!(name, None);
        assert_eq!(policy.hold(&admission.unwrap(), 443), None);
    }

    #[test]
    fn a_flow_is_held_to_the_rules_its_admission_leaves_open() {
        let allowed = |text: &str| FlowAdmission::Allowed { rule: rule(text) };
        let policy = rules(&["example.com", "192.0.2.0/24"], &["tcp:*.bad.example:443"]);
        // Admitted by a name: an allow rule must admit the server too.
        assert_eq!(
            policy.hold(&allowed("example.com"), 80),
            Some(Hold::AllowRules)
        );
        // Admitted by an address, or by default: held where a deny name rule
        // covers the port, and nowhere else.
        assert_eq!(
            policy.hold(&allowed("192.0.2.0/24"), 443),
            Some(Hold::DenyRules)
        );
        assert_eq!(policy.hold(&allowed("192.0.2.0/24"), 80), None);
        let deny_alone = rules(&[], &["*.bad.example"]);
        assert_eq!(
            deny_alone.hold(&FlowAdmission::Default, 22),
            Some(Hold::DenyRules)
        );
        assert_eq!(Policy::default().hold(&FlowAdmission::Default, 443), None);
        // The gateway's mapping is outside the rules.
        assert_eq!(deny_alone.hold(&FlowAdmission::HostLoopback, 22), None);
    }

    fn hosts(hosts: &[&str]) -> Vec<Host> {
        hosts
            .iter()
            .map(|host| match host.parse() {
                Ok(address) => Host::Address(address),
                Err(_) => Host::Name(host.to_string()),
            })
            .collect()
    }

    #[test]
    fn the_server_first_bytes_ask_for_is_held_to_the_name_rules() {
        let policy = rules(
            &["example.com:443", "*.cdn.example", "192.0.2.0/24"],
            &["tcp:mail.cdn.example:25", "bad.cdn.example"],
        );
        let destination = ip("198.51.100.7");
        let decide = |hold, port, servers: &[&str]| {
            policy.decide_servers(hold, destination, port, &hosts(servers))
        };
        // Under the allow rules: a server an allow name rule admits on the
        // port, or none at all.
        for (port, servers) in [
            (443, &["example.com"][..]),
            (443, &["img.cdn.example"]),
            (80, &["img.cdn.example"]),
            (443, &[]),
            (443, &["198.51.100.7"]),
        ] {
            assert_eq!(
                decide(Hold::AllowRules, port, servers),
                Ok(()),
                "{servers:?} on {port}"
            );
        }
        for (port, servers, name) in [
            (80, &["example.com"][..], "example.com"),
            (443, &["other.example"], "other.example"),
            (443, &["example.com", "other.example"], "other.example"),
            (443, &["192.0.2.7"], "192.0.2.7"),
        ] {
            assert_eq!(
                decide(Hold::AllowRules, port, servers),
                Err(FlowRefusal::ServerNameNotAllowed {
                    name: name.to_string()
                }),
                "{servers:?} on {port}"
            );
        }
        // A deny name rule on its ports, under either hold.
        for hold in [Hold::AllowRules, Hold::DenyRules] {
            assert_eq!(
                decide(hold, 443, &["bad.cdn.example"]),
                Err(FlowRefusal::ServerNameDenied {
                    name: "bad.cdn.example".to_string(),
                    rule: rule("bad.cdn.example")
                })
            );
            assert_eq!(
                decide(hold, 25, &["mail.cdn.example"]),
                Err(FlowRefusal::ServerNameDenied {
                    name: "mail.cdn.example".to_string(),
                    rule: rule("tcp:mail.cdn.example:25")
                })
            );
        }
        assert_eq!(decide(Hold::AllowRules, 443, &["mail.cdn.example"]), Ok(()));
        // Under the deny rules alone, anything else passes, an address
        // included.
        for servers in [&["other.example"][..], &["192.0.2.7"], &[]] {
            assert_eq!(decide(Hold::DenyRules, 443, servers), Ok(()), "{servers:?}");
        }
    }

    #[test]
    fn without_allow_rules_what_no_deny_rule_refuses_is_admitted_by_default() {
        assert_eq!(
            Policy::default().decide_unnamed(Transport::Tcp, ip("192.0.2.1"), 443),
            Ok(FlowAdmission::Default)
        );
        let deny = rules(&[], &["192.0.2.0/24"]);
        assert_eq!(
            deny.decide_unnamed(Transport::Udp, ip("198.51.100.1"), 53),
            Ok(FlowAdmission::Default)
        );
    }
}
