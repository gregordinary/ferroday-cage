//! A fetch sandbox built on ferroday-cage's native network stack.
//!
//! `fetch-sandbox` provisions an Alpine root filesystem, attaches the library's
//! native userspace network stack to an otherwise isolated sandbox, and runs
//! `wget` inside it to retrieve a URL. The sandbox reaches the network from its
//! own private namespace, through a stack that runs in the caller's process: it
//! creates a tap device inside the sandbox's network namespace and forwards its
//! flows over ordinary host sockets.
//!
//! ```sh
//! fetch-sandbox --rootfs ./alpine --tarball alpine-minirootfs.tar.gz \
//!     http://example.org
//! ```
//!
//! It is the worked example for the `netstack` feature, taking an outbound
//! fetch through a stack's whole life in the order a consumer drives it:
//! [`NetStack::builder`](ferroday_cage::NetStack::builder) to configure the
//! stack, [`spawn_pending`](ferroday_cage::Cage::spawn_pending) to hold the
//! command at the gate, [`attach`](ferroday_cage::NetStack::attach) to stand the
//! network up, [`proceed`](ferroday_cage::Pending::proceed) to release the
//! command once the network is ready, and
//! [`stop`](ferroday_cage::NetStackHandle::stop) to tear the stack down after
//! the command exits. Publishing a port, for a server inside the sandbox, is
//! the guide's to show: a fetch has nothing listening.
//!
//! DNS is the caller's to arrange. The stack refuses loopback and link-local
//! destinations, so a host running systemd-resolved — whose `127.0.0.53` stub is
//! the only entry in `/etc/resolv.conf` — offers the sandbox no working
//! resolver. This example binds the host's `resolv.conf` only when it names a
//! nameserver the stack [forwards](ferroday_cage::NetStack::forwards) to, and
//! otherwise leaves the sandbox to resolve nothing; fetching a literal IP
//! address always works.
//!
//! # Usage
//!
//! ```text
//! fetch-sandbox --rootfs DIR --tarball FILE [OPTIONS] URL
//! ```

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::ExitCode;

use ferroday_cage::provision::{self, Tarball};
use ferroday_cage::{Cage, Error, ErrorChain, NetStack, NetStackError};

mod common;

use common::{failure, string_value, usage_error, value_for};

/// The fetch tool, addressed by absolute path: the cage does not resolve the
/// command against `PATH`.
const WGET: &str = "/usr/bin/wget";

const USAGE: &str = "\
Fetch a URL from inside a sandbox through the native network stack.

Usage:
  fetch-sandbox --rootfs DIR --tarball FILE [OPTIONS] URL

Options:
  --rootfs DIR       Directory to provision and present as the sandbox root
  --tarball FILE     Alpine minirootfs tarball to provision --rootfs from
                     when the directory does not exist yet
  --cidr V4/LEN      IPv4 network for the stack (default 10.0.2.0/24)
  --host-loopback    Map the gateway address onto host loopback, to fetch
                     from a service listening on the host's 127.0.0.1
  -h, --help         Print this help

The URL is fetched with wget and written to standard output. Give a URL with a
literal IP address to sidestep DNS, or ensure the host has a routable
nameserver in /etc/resolv.conf.
";

/// The parsed command line.
struct Options {
    rootfs: PathBuf,
    tarball: PathBuf,
    cidr: Option<(std::net::Ipv4Addr, u8)>,
    host_loopback: bool,
    url: OsString,
}

fn main() -> ExitCode {
    let options = match parse(std::env::args_os().skip(1)) {
        Ok(Some(options)) => options,
        Ok(None) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(message) => return usage_error("fetch-sandbox", &message),
    };

    // Provision the Alpine root from the tarball if it is not already there.
    if let Err(error) = provision::ensure(&options.rootfs, &mut Tarball::new(&options.tarball)) {
        return failure(
            "fetch-sandbox",
            &format!(
                "provisioning the rootfs failed: {}",
                ErrorChain::new(&error)
            ),
        );
    }

    match fetch(&options) {
        Ok(code) => code,
        // The library owns the exit-code conventions, so a sandbox that could
        // not run its command reports through them: 126 for a command that is
        // there and cannot be run, 127 for one that is not there. Only the
        // stack's own failures are this example's, and 125 is what it says
        // about those.
        Err(FetchFailure::Cage(error)) => {
            eprintln!("fetch-sandbox: {}", ErrorChain::new(&error));
            ExitCode::from(error.shell_code())
        }
        Err(FetchFailure::Stack(error)) => failure(
            "fetch-sandbox",
            &format!(
                "the network stack could not be attached: {}",
                ErrorChain::new(&error)
            ),
        ),
    }
}

/// What can stop the run before the command's own exit status is the answer.
///
/// Two kinds, because they report differently. The library's [`Error`] carries
/// the exit-code convention every launcher here follows; a
/// [`NetStackError`] is about the stack this example stood up, which the
/// command never saw, so it is the example's own failure to report.
enum FetchFailure {
    /// The sandbox could not be configured, launched, or waited on.
    Cage(Error),
    /// The stack could not be built or attached.
    Stack(NetStackError),
}

impl From<Error> for FetchFailure {
    fn from(error: Error) -> FetchFailure {
        FetchFailure::Cage(error)
    }
}

impl From<NetStackError> for FetchFailure {
    fn from(error: NetStackError) -> FetchFailure {
        FetchFailure::Stack(error)
    }
}

/// Builds the sandbox, attaches the stack, and runs the fetch, returning the
/// process exit code to propagate.
///
/// Both the sandbox's [`Error`] and the stack's [`NetStackError`] propagate
/// with `?` through [`FetchFailure`], rather than being unwrapped — attaching
/// the stack stands up a tap device and can fail for real reasons.
fn fetch(options: &Options) -> Result<ExitCode, FetchFailure> {
    // Configure the stack. host_loopback lets the sandbox reach a service on
    // the host's own loopback through the gateway address.
    let mut stack = NetStack::builder().host_loopback(options.host_loopback);
    if let Some((network, prefix_len)) = options.cidr {
        stack = stack.ipv4_cidr(network, prefix_len);
    }
    let stack = stack.build()?;

    let mut builder = Cage::builder()
        .rootfs(&options.rootfs)
        .command(WGET)
        .arg("-qO-")
        .arg(&options.url);
    // Give the sandbox the host's DNS only if the stack forwards to one of its
    // nameservers.
    if host_has_forwarded_nameserver(&stack) {
        builder = builder.bind_ro("/etc/resolv.conf", "/etc/resolv.conf");
    }
    let cage = builder.build()?;

    // Hold the command at the gate, stand the network up in the sandbox's
    // namespace, then release the command so it sees the network from its
    // first instruction.
    let pending = cage.spawn_pending()?;
    let handle = stack.attach(&pending)?;
    let mut running = pending.proceed()?;
    let status = running.wait()?;

    // Tear the stack down once the command has exited. A failure here loses
    // no data, so it is a warning rather than the run's outcome.
    if let Err(error) = handle.stop() {
        eprintln!(
            "fetch-sandbox: the network stack did not stop cleanly: {}",
            ErrorChain::new(&error)
        );
    }

    Ok(ExitCode::from(status.shell_code()))
}

/// Whether the host's `resolv.conf` names a nameserver reachable through the
/// stack, by the stack's own [`forwards`](NetStack::forwards).
fn host_has_forwarded_nameserver(stack: &NetStack) -> bool {
    let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") else {
        return false;
    };
    contents.lines().any(|line| {
        let Some(address) = line.trim().strip_prefix("nameserver") else {
            return false;
        };
        // The keyword and its value are separated by whitespace, and glibc
        // ignores a line that runs them together. Reading `nameserver8.8.8.8`
        // as a nameserver would count a line the resolver does not as the
        // reason this host is considered routable.
        if !address.starts_with([' ', '\t']) {
            return false;
        }
        address
            .trim()
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| stack.forwards(std::net::SocketAddr::new(address, 53)))
    })
}

/// Parses the command line, returning `None` when help was requested.
fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Option<Options>, String> {
    let mut rootfs = None;
    let mut tarball = None;
    let mut cidr = None;
    let mut host_loopback = false;
    let mut url = None;

    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            return Ok(None);
        } else if arg == "--rootfs" {
            rootfs = Some(PathBuf::from(value_for("--rootfs", &mut args)?));
        } else if arg == "--tarball" {
            tarball = Some(PathBuf::from(value_for("--tarball", &mut args)?));
        } else if arg == "--cidr" {
            cidr = Some(parse_cidr(&string_value("--cidr", &mut args)?)?);
        } else if arg == "--host-loopback" {
            host_loopback = true;
        } else if arg.as_bytes().starts_with(b"-") && arg != "-" {
            return Err(format!("unrecognized option {}", arg.to_string_lossy()));
        } else if url.is_none() {
            url = Some(arg);
        } else {
            return Err("only one URL may be given".to_string());
        }
    }

    Ok(Some(Options {
        rootfs: rootfs.ok_or("--rootfs is required")?,
        tarball: tarball.ok_or("--tarball is required")?,
        cidr,
        host_loopback,
        url: url.ok_or("a URL is required")?,
    }))
}

/// Parses an IPv4 `address/prefix` for `--cidr`.
fn parse_cidr(value: &str) -> Result<(std::net::Ipv4Addr, u8), String> {
    let (address, len) = value
        .split_once('/')
        .ok_or_else(|| format!("--cidr expects ADDRESS/LEN, not {value:?}"))?;
    let address = address
        .parse()
        .map_err(|_| format!("--cidr: {address:?} is not an IPv4 address"))?;
    let len: u8 = len
        .parse()
        .map_err(|_| format!("--cidr: {len:?} is not a prefix length"))?;
    if len > 32 {
        return Err(format!(
            "--cidr: {len} is not a valid IPv4 prefix length (0 to 32)"
        ));
    }
    Ok((address, len))
}

/// The example runs against the fixture-provisioned root; a smoke check keeps
/// the argument parsing honest.
#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn parse_requires_a_rootfs_tarball_and_url() {
        assert!(parse(["http://x".into()].into_iter()).is_err());
        let options = parse(
            [
                "--rootfs",
                "/r",
                "--tarball",
                "a.tar.gz",
                "--host-loopback",
                "http://10.0.0.1",
            ]
            .into_iter()
            .map(OsString::from),
        )
        .expect("a valid command line")
        .expect("not a help request");
        assert_eq!(options.rootfs, Path::new("/r"));
        assert!(options.host_loopback);
        assert_eq!(options.url, OsString::from("http://10.0.0.1"));
    }

    /// A `--cidr` value is text, and one that is not is refused as such,
    /// naming the option, rather than parsed from a lossy rendering of it.
    #[test]
    fn a_cidr_that_is_not_text_is_refused_by_name() {
        use std::os::unix::ffi::OsStringExt;

        let mut line: Vec<OsString> = ["--rootfs", "/r", "--tarball", "a.tar.gz", "--cidr"]
            .into_iter()
            .map(OsString::from)
            .collect();
        line.push(OsString::from_vec(b"10.0.2.0/\xff".to_vec()));
        line.push(OsString::from("http://10.0.0.1"));
        let Err(message) = parse(line.into_iter()) else {
            panic!("a --cidr that is not UTF-8 is refused");
        };
        assert!(message.contains("--cidr value"), "{message}");
        assert!(message.contains("not valid UTF-8"), "{message}");
    }
}
