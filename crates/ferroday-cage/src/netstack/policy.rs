//! The stack's destination policy: the rules a caller allows and denies the
//! guest's destinations by, and the decision they make together.
//!
//! [`DestinationRule`] is the one grammar the builder, the stack's profile
//! format and `fcage` share. [`Policy`] holds a configuration's allow and deny
//! rules and decides a destination by them, after the refusals no rule
//! overrides ([`host_target`](super::pump::host_target)).

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use super::prefix;
use super::report::{FlowAdmission, FlowRefusal};

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
/// otherwise. A name rule covers TCP alone, so `udp:` does not qualify one.
///
/// A name is compared without regard to ASCII case and without a trailing dot,
/// and is written back in lower case without one. A rule written with a
/// network's full width, `192.0.2.7/32`, is written back as the address.
///
/// Parsing refuses a port of 0, a range of ports that runs backwards, a prefix
/// longer than its family's width, and a network with bits set past its
/// prefix. It refuses `udp:` on a name, a wildcard anywhere but as a whole first
/// label, and a name not in its ASCII form, which for an internationalized name
/// is its `xn--` spelling. It refuses a name whose last label is a number,
/// `2130706433`, `127.1` or `0x7f`, since a resolver may read such a name as an
/// address.
///
/// The stack decides a flow by its address, and
/// [`build`](super::NetStackBuilder::build) refuses a name rule.
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
    /// Whether the rule matches a flow over `transport` to `address` on
    /// `port`. A name rule matches no address.
    fn matches(&self, transport: Transport, address: IpAddr, port: u16) -> bool {
        let Target::Network {
            network,
            prefix_len,
        } = self.target
        else {
            return false;
        };
        self.transport.is_none_or(|covered| covered == transport)
            && (self.ports.is_empty()
                || self
                    .ports
                    .iter()
                    .any(|ports| (ports.first..=ports.last).contains(&port)))
            && prefix::contains(network, prefix_len, address)
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
fn split_transport(text: &str) -> (Option<Transport>, &str) {
    for transport in [Transport::Tcp, Transport::Udp] {
        let spelling = transport.spelling();
        if let Some(prefix) = text.get(..spelling.len() + 1)
            && prefix[..spelling.len()].eq_ignore_ascii_case(spelling)
            && prefix.ends_with(':')
        {
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

/// The longest name a rule can hold: 253 characters without a trailing dot,
/// the most a DNS name of 255 bytes on the wire spells.
const MAX_NAME: usize = 253;

/// The longest label of a name.
const MAX_LABEL: usize = 63;

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

/// Checks a lowered name with no trailing dot: within the length limits,
/// labels of letters, digits, `-` and `_`, and a last label that is not a
/// number.
fn validate_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("it names no destination");
    }
    if name.len() > MAX_NAME {
        return Err("the name is longer than 253 characters");
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err("the name has an empty label");
        }
        if label.len() > MAX_LABEL {
            return Err("a label of the name is longer than 63 characters");
        }
        if label.contains('*') {
            return Err("a wildcard is a whole first label, as in `*.example.com`");
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err("a name holds letters, digits, `-` and `_` between its dots");
        }
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

/// A configuration's allow and deny rules, which decide each destination the
/// stack would otherwise carry.
#[derive(Debug, Clone, Default)]
pub(super) struct Policy {
    /// The rules that admit, in the order given.
    pub(super) allow: Vec<DestinationRule>,
    /// The rules that refuse, in the order given.
    pub(super) deny: Vec<DestinationRule>,
}

impl Policy {
    /// What the rules decide of a flow over `transport` to `address` on `port`,
    /// and which rule decided it.
    ///
    /// A deny rule that matches refuses, whatever else matches, and the first
    /// that matches is the one named. Otherwise a policy with any allow rule
    /// admits what an allow rule matches, naming the first, and refuses the
    /// rest, and one without admits everything by default. The destinations no
    /// rule can admit are the caller's to refuse first.
    ///
    /// An address under NAT64's well-known prefix is matched as itself and as
    /// the IPv4 address it embeds, since a translator carries the flow to that
    /// address ([`prefix::nat64_embedded`]). An IPv4 rule therefore covers the
    /// address's translated spelling as well, and a deny rule cannot be passed
    /// by way of the translator.
    pub(super) fn decide(
        &self,
        transport: Transport,
        address: IpAddr,
        port: u16,
    ) -> Result<FlowAdmission, FlowRefusal> {
        let embedded = match address {
            IpAddr::V6(address) => prefix::nat64_embedded(address).map(IpAddr::V4),
            IpAddr::V4(_) => None,
        };
        let matches = |rule: &&DestinationRule| {
            rule.matches(transport, address, port)
                || embedded.is_some_and(|embedded| rule.matches(transport, embedded, port))
        };
        if let Some(rule) = self.deny.iter().find(matches) {
            return Err(FlowRefusal::Denied { rule: rule.clone() });
        }
        if self.allow.is_empty() {
            return Ok(FlowAdmission::Default);
        }
        match self.allow.iter().find(matches) {
            Some(rule) => Ok(FlowAdmission::Allowed { rule: rule.clone() }),
            None => Err(FlowRefusal::NotAllowed),
        }
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
        let label = "a".repeat(MAX_LABEL);
        rule(&format!("{label}.example"));
        assert_eq!(
            refusal(&format!("a{label}.example")),
            "a label of the name is longer than 63 characters",
        );
        let name = vec!["a".repeat(61); 4].join(".") + ".example";
        assert_eq!(name.len(), MAX_NAME + 2);
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
            allow: allow.iter().map(|text| rule(text)).collect(),
            deny: deny.iter().map(|text| rule(text)).collect(),
        }
    }

    #[test]
    fn no_rules_admit_everything() {
        let open = Policy::default();
        assert!(open.decide(Transport::Tcp, ip("203.0.113.9"), 443).is_ok());
        assert!(open.decide(Transport::Udp, ip("2001:db8::1"), 53).is_ok());
    }

    #[test]
    fn any_allow_rule_refuses_what_no_allow_rule_admits() {
        let policy = rules(&["192.0.2.0/24", "[2001:db8::/32]:443"], &[]);
        assert!(policy.decide(Transport::Tcp, ip("192.0.2.7"), 22).is_ok());
        assert!(policy.decide(Transport::Udp, ip("192.0.2.255"), 53).is_ok());
        assert!(policy.decide(Transport::Tcp, ip("192.0.3.1"), 22).is_err());
        assert!(
            policy
                .decide(Transport::Tcp, ip("2001:db8::1"), 443)
                .is_ok()
        );
        assert!(
            policy
                .decide(Transport::Tcp, ip("2001:db8::1"), 80)
                .is_err()
        );
        assert!(
            policy
                .decide(Transport::Tcp, ip("2001:db9::1"), 443)
                .is_err()
        );
    }

    #[test]
    fn deny_rules_alone_admit_what_they_do_not_refuse() {
        let policy = rules(&[], &["192.168.0.0/16", "tcp:203.0.113.9:25"]);
        assert!(
            policy
                .decide(Transport::Tcp, ip("192.168.1.1"), 80)
                .is_err()
        );
        assert!(
            policy
                .decide(Transport::Udp, ip("192.168.1.1"), 53)
                .is_err()
        );
        assert!(policy.decide(Transport::Tcp, ip("192.169.0.1"), 80).is_ok());
        assert!(
            policy
                .decide(Transport::Tcp, ip("203.0.113.9"), 25)
                .is_err()
        );
        assert!(policy.decide(Transport::Udp, ip("203.0.113.9"), 25).is_ok());
        assert!(policy.decide(Transport::Tcp, ip("203.0.113.9"), 26).is_ok());
    }

    #[test]
    fn a_deny_rule_beats_an_allow_rule() {
        let policy = rules(&["192.0.2.0/24"], &["192.0.2.7:22"]);
        assert!(policy.decide(Transport::Tcp, ip("192.0.2.7"), 22).is_err());
        assert!(policy.decide(Transport::Tcp, ip("192.0.2.7"), 23).is_ok());
        assert!(policy.decide(Transport::Tcp, ip("192.0.2.8"), 22).is_ok());
    }

    #[test]
    fn a_transport_qualifies_a_rule_to_itself() {
        let udp = rules(&["udp:192.0.2.53:53"], &[]);
        assert!(udp.decide(Transport::Udp, ip("192.0.2.53"), 53).is_ok());
        assert!(udp.decide(Transport::Tcp, ip("192.0.2.53"), 53).is_err());
        let tcp = rules(&["tcp:0.0.0.0/0"], &[]);
        assert!(tcp.decide(Transport::Tcp, ip("192.0.2.1"), 443).is_ok());
        assert!(tcp.decide(Transport::Udp, ip("192.0.2.1"), 443).is_err());
    }

    #[test]
    fn a_name_rule_matches_no_address() {
        let allow = rules(&["example.com", "*"], &[]);
        assert!(allow.decide(Transport::Tcp, ip("192.0.2.1"), 443).is_err());
        let deny = rules(&[], &["*"]);
        assert!(deny.decide(Transport::Tcp, ip("192.0.2.1"), 443).is_ok());
    }

    #[test]
    fn a_translated_address_is_held_to_the_ipv4_rules() {
        // Denied as itself, the address is denied under NAT64's prefix too,
        // which the translator would carry it to.
        let deny = rules(&[], &["203.0.113.0/24"]);
        assert!(
            deny.decide(Transport::Tcp, ip("64:ff9b::203.0.113.9"), 443)
                .is_err()
        );
        assert!(
            deny.decide(Transport::Tcp, ip("64:ff9b::198.51.100.1"), 443)
                .is_ok()
        );
        // Allowed as itself, so it is under the prefix.
        let allow = rules(&["203.0.113.0/24"], &[]);
        assert!(
            allow
                .decide(Transport::Tcp, ip("64:ff9b::203.0.113.9"), 443)
                .is_ok()
        );
        assert!(
            allow
                .decide(Transport::Tcp, ip("64:ff9b::198.51.100.1"), 443)
                .is_err()
        );
        // Outside the well-known /96 an address embeds nothing.
        assert!(
            allow
                .decide(Transport::Tcp, ip("64:ff9b:1::cb00:7109"), 443)
                .is_err()
        );
        // An IPv6 rule over the prefix is a rule like any other, and a deny of
        // the embedded address still beats it.
        let both = rules(&["64:ff9b::/96"], &["203.0.113.9"]);
        assert!(
            both.decide(Transport::Tcp, ip("64:ff9b::198.51.100.1"), 443)
                .is_ok()
        );
        assert!(
            both.decide(Transport::Tcp, ip("64:ff9b::203.0.113.9"), 443)
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
            policy.decide(Transport::Tcp, ip("192.0.2.7"), 22),
            Err(FlowRefusal::Denied {
                rule: rule("192.0.2.7:22")
            })
        );
        assert_eq!(
            policy.decide(Transport::Tcp, ip("192.0.2.8"), 22),
            Err(FlowRefusal::Denied {
                rule: rule("192.0.2.0/24:22")
            })
        );
        assert_eq!(
            policy.decide(Transport::Tcp, ip("192.0.2.7"), 80),
            Ok(FlowAdmission::Allowed {
                rule: rule("192.0.2.0/24")
            })
        );
        assert_eq!(
            policy.decide(Transport::Tcp, ip("198.51.100.1"), 80),
            Err(FlowRefusal::NotAllowed)
        );
        // An address under NAT64's prefix names the IPv4 rule that matched what
        // it embeds.
        assert_eq!(
            policy.decide(Transport::Tcp, ip("64:ff9b::192.0.2.9"), 80),
            Ok(FlowAdmission::Allowed {
                rule: rule("192.0.2.0/24")
            })
        );
    }

    #[test]
    fn without_allow_rules_what_no_deny_rule_refuses_is_admitted_by_default() {
        assert_eq!(
            Policy::default().decide(Transport::Tcp, ip("192.0.2.1"), 443),
            Ok(FlowAdmission::Default)
        );
        let deny = rules(&[], &["192.0.2.0/24"]);
        assert_eq!(
            deny.decide(Transport::Udp, ip("198.51.100.1"), 53),
            Ok(FlowAdmission::Default)
        );
    }
}
