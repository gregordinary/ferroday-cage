//! The events `fcage` writes for a program to read.
//!
//! With `--events PATH`, every line `fcage` would write of its own on standard
//! error is written to PATH instead, as an event, and standard error carries
//! the command's output alone. Each event is one JSON object on a line of its
//! own, UTF-8, with no newline inside it.
//!
//! - **Each event names its kind** in its `event` member: `hello`, `started`,
//!   `published`, `network`, `seccomp`, `dropped`, `provision`, `warning`,
//!   `exited` or `failed`.
//! - **A stream begins with `hello`.** Its `protocol` is this vocabulary's
//!   version, [`PROTOCOL`], and its `fcage` is the release that wrote it.
//! - **A reader ignores the members and the kinds it does not know.** Within one
//!   protocol version, events gain members and kinds and lose none. A change
//!   that would break a reader is a kind or a member under a new name.
//! - **An event that has a line for a person carries it as `text`**, as
//!   standard error would have had it. A report the library adds that this
//!   vocabulary does not name yet is still an event: its `report` is `other`,
//!   and its `text` says what it is.
//! - **Bytes that are not UTF-8** are written as `{"base64": "..."}`, and any
//!   other byte string as a JSON string; see [`Bytes`].
//! - **A launch's last event is `exited` or `failed`**, and its `shell-code` is
//!   `fcage`'s exit status. A `failed` follows an `exited` where the command
//!   ended and `fcage` failed after it, as a relay that lost output does. A run
//!   that only provisions ends with neither.
//!
//! The vocabulary is `fcage`'s, mapped here from the library's types rather
//! than serialized from them. The stream is part of `fcage`'s contract, which
//! versions apart from the library, so a name the library changes reaches the
//! stream only through a change here. Two rules name what the library
//! enumerates, and both are the library's variant names in kebab case: a
//! failure's `error` is the [`Error`] variant, written out below, and its
//! `step` is the [`SetupStep`] variant, read from its derived `Debug`, since
//! the library adds steps more often than any other kind of name.

use std::net::SocketAddr;
use std::time::Duration;

use ferroday_cage::provision::Stream;
use ferroday_cage::{
    Error, ExitStatus, FlowAdmission, FlowRefusal, NetStackReport, ResourceUsage, SeccompReport,
    SetupStep, Transport,
};
use serde::Serialize;
use serde::ser::{SerializeMap as _, Serializer};

/// The version of the vocabulary, which every stream's `hello` carries.
pub const PROTOCOL: u32 = 1;

/// Something `fcage` says of its own, as a program reads it.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum Event {
    /// The stream's first event.
    Hello(Hello),
    /// The command was released.
    Started(Started),
    /// A port the network stack publishes was bound on the host.
    Published(Published),
    /// A report of the network stack's.
    Network(Box<Network>),
    /// A report of the seccomp filter's.
    Seccomp(Box<Seccomp>),
    /// Reports were dropped where nothing took them in time.
    Dropped(Dropped),
    /// A provisioning run's progress, or the output of a command it ran.
    Provision(Provision),
    /// A line of `fcage`'s own that is neither a report nor an outcome.
    Warning(Warning),
    /// The command ended, or its timeout expired.
    Exited(Exited),
    /// A failure that decides `fcage`'s exit status.
    Failed(Failed),
}

/// `hello`: the stream's first event.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Hello {
    /// [`PROTOCOL`].
    protocol: u32,
    /// The `fcage` release writing the stream.
    fcage: &'static str,
}

/// `started`: the command was released.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Started {
    /// The host's process id of the process the launch's handle holds: the
    /// sandbox's init where it has a PID namespace, and otherwise the command.
    pid: u32,
}

/// `published`: a port the network stack publishes was bound on the host.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Published {
    /// The sandbox's port.
    guest_port: u16,
    /// The host's address and port it is reached at.
    address: String,
    /// The line standard error carries: only where the kernel chose the port,
    /// since the caller named any other.
    #[serde(skip)]
    line: Option<String>,
}

/// `network`: a report of the network stack's.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Network {
    /// Which report: `flow-admitted`, `flow-refused`, `question-relayed`,
    /// `question-refused`, `question-withheld`, or `other`.
    report: &'static str,
    /// `tcp` or `udp`, for a flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<&'static str>,
    /// The guest's address and port.
    #[serde(skip_serializing_if = "Option::is_none")]
    guest: Option<String>,
    /// The destination's address and port, for a flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    destination: Option<String>,
    /// The name a flow's destination was resolved from, or a question's name.
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    /// A question's record type, as the number DNS gives it.
    #[serde(skip_serializing_if = "Option::is_none")]
    record_type: Option<u16>,
    /// Why the stack carried a flow or relayed a question.
    #[serde(skip_serializing_if = "Option::is_none")]
    admission: Option<&'static str>,
    /// Why the stack refused a flow or a question.
    #[serde(skip_serializing_if = "Option::is_none")]
    refusal: Option<&'static str>,
    /// The destination rule that decided, as a rule is written.
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<String>,
    /// The cloud whose instance services a refused address belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    cloud: Option<&'static str>,
    /// The server a flow's first bytes asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    server_name: Option<String>,
    /// Why a flow's first bytes could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    /// The line standard error carries.
    text: String,
}

/// `seccomp`: a report of the seccomp filter's.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Seccomp {
    /// Which report: `denied`, or `other`.
    report: &'static str,
    /// The syscall's name, where the library knows it.
    #[serde(skip_serializing_if = "Option::is_none")]
    syscall: Option<&'static str>,
    /// The syscall's number, in the architecture it was made in.
    #[serde(skip_serializing_if = "Option::is_none")]
    number: Option<i64>,
    /// That architecture, as the audit architecture value, in hexadecimal.
    #[serde(skip_serializing_if = "Option::is_none")]
    audit_arch: Option<String>,
    /// The thread that made the call, by the host's id for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    thread: Option<u32>,
    /// The thread's command name, where it could be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<String>,
    /// The call's six arguments, in hexadecimal, since most are addresses
    /// beyond the integers a JSON reader is sure to hold exactly.
    #[serde(skip_serializing_if = "Option::is_none")]
    arguments: Option<[String; 6]>,
    /// The errno the call was refused with; see [`errno_name`].
    #[serde(skip_serializing_if = "Option::is_none")]
    errno: Option<String>,
    /// The line standard error carries.
    text: String,
}

/// `dropped`: reports were dropped where nothing took them in time.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Dropped {
    /// Whose reports: `network` for the stack's queue, `seccomp` for the
    /// filter's, and `fcage` for the queue of `fcage`'s own writer.
    source: &'static str,
    /// How many.
    count: u64,
    /// The line standard error carries.
    text: String,
}

/// `provision`: a provisioning run's progress, or what a command it ran wrote.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Provision {
    /// `progress`, or `output`.
    report: &'static str,
    /// A progress line, as standard error carries it.
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    /// Which of the command's streams the output came from: `stdout` or
    /// `stderr`.
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<&'static str>,
    /// The output, as the command wrote it, which need not end a line.
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<Bytes>,
}

/// `warning`: a line of `fcage`'s own that is neither a report nor an outcome.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Warning {
    /// The line standard error carries.
    text: String,
}

/// `exited`: the command ended, or its timeout expired.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Exited {
    /// The command's exit code, where it exited.
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<i32>,
    /// The signal that ended it, by number, where one did.
    #[serde(skip_serializing_if = "Option::is_none")]
    signal: Option<i32>,
    /// Whether that signal left a core dump.
    core_dumped: bool,
    /// Whether `--timeout` expired first. The command's own status is then
    /// left out, whatever became of the command afterwards, as the exit
    /// status is 124 whatever it was.
    timed_out: bool,
    /// `fcage`'s exit status.
    shell_code: u8,
    /// What the command and its descendants used, where anything was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<Usage>,
}

/// What a command used, as `exited` carries it: [`ResourceUsage`], a member
/// for each figure the launch read.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Usage {
    /// Processor time in user mode, in microseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    user_time_us: Option<u64>,
    /// Processor time in the kernel, in microseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    system_time_us: Option<u64>,
    /// The largest resident set of any collected process, in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    peak_rss_bytes: Option<u64>,
    /// The cgroup's processor time in user mode, in microseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    cgroup_user_time_us: Option<u64>,
    /// The cgroup's processor time in the kernel, in microseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    cgroup_system_time_us: Option<u64>,
    /// The cgroup's peak memory, in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    cgroup_peak_memory_bytes: Option<u64>,
    /// The most processes the cgroup held at once.
    #[serde(skip_serializing_if = "Option::is_none")]
    cgroup_peak_processes: Option<u64>,
    /// How many processes the cgroup's memory limit killed.
    #[serde(skip_serializing_if = "Option::is_none")]
    cgroup_oom_kills: Option<u64>,
    /// How many forks the cgroup's process limit refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    cgroup_refused_processes: Option<u64>,
}

/// `failed`: a failure that decides `fcage`'s exit status.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Failed {
    /// What failed; see [`Fault`] for the names.
    error: &'static str,
    /// The setup step that failed, where the failure names one; see
    /// [`step_name`].
    #[serde(skip_serializing_if = "Option::is_none")]
    step: Option<String>,
    /// The errno beneath the failure, where there is one; see
    /// [`errno_name`].
    #[serde(skip_serializing_if = "Option::is_none")]
    errno: Option<String>,
    /// `fcage`'s exit status.
    shell_code: u8,
    /// The line standard error carries.
    text: String,
}

/// What a failure names, for [`Event::failed`]: what failed, the setup step
/// and the errno where it carries them, and its message.
///
/// `error` is one of:
///
/// - the library's [`Error`] variant in kebab case ([`error_kind`]);
/// - `usage`, for a command line `fcage` refuses;
/// - `relay`, for a relay of the command's standard streams or of its
///   terminal that failed;
/// - `reader-gone`, for a reader of what the run writes that went away;
/// - `netstack` and `provision`, for the network stack's and a provisioner's
///   own failures;
/// - `fcage`, for any other failure of `fcage`'s own.
#[derive(Debug, Clone)]
pub struct Fault {
    /// What failed.
    pub error: &'static str,
    /// The setup step, where the failure names one.
    pub step: Option<String>,
    /// The errno's name, where there is one.
    pub errno: Option<String>,
    /// The message, without `fcage: `.
    pub message: String,
}

impl Fault {
    /// A failure of `error`'s kind that names no step or errno.
    pub fn plain(error: &'static str, message: String) -> Fault {
        Fault {
            error,
            step: None,
            errno: None,
            message,
        }
    }

    /// A failure carried by `source`, of `error`'s kind, naming the errno
    /// beneath it where there is one.
    pub fn of(error: &'static str, source: &(dyn std::error::Error + 'static)) -> Fault {
        Fault {
            error,
            step: None,
            errno: errno_in(source),
            message: ferroday_cage::ErrorChain::new(source).to_string(),
        }
    }

    /// A failure of the library's, by its variant, its step, and its errno.
    pub fn of_cage(error: &Error) -> Fault {
        Fault {
            step: step_of(error),
            ..Fault::of(error_kind(error), error)
        }
    }
}

/// A byte string, which a reader takes back exactly.
///
/// Bytes that are valid UTF-8 are a JSON string. Any others are an object,
/// `{"base64": "..."}`, in RFC 4648's standard alphabet with padding, so a
/// path or an output that is not text is neither refused nor changed.
#[derive(Debug, Clone)]
pub struct Bytes(pub Vec<u8>);

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match std::str::from_utf8(&self.0) {
            Ok(text) => serializer.serialize_str(text),
            Err(_) => {
                let mut object = serializer.serialize_map(Some(1))?;
                object.serialize_entry("base64", &base64(&self.0))?;
                object.end()
            }
        }
    }
}

/// `bytes` in base64, as RFC 4648 section 4 defines it: the standard alphabet,
/// padded.
///
/// A second answer to the library's `provision::alpine::base64::encode`, which
/// is private to the Alpine layer: `fcage` is a crate apart, and this is the
/// one encoder its event stream needs. It decodes nothing.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let mut packed = 0u32;
        for (at, byte) in group.iter().enumerate() {
            packed |= u32::from(*byte) << (16 - 8 * at);
        }
        // One character per six bits of input the group holds, and a pad
        // character for each it does not.
        for at in 0..=group.len() {
            out.push(char::from(
                ALPHABET[(packed >> (18 - 6 * at)) as usize & 0x3f],
            ));
        }
        for _ in group.len()..3 {
            out.push('=');
        }
    }
    out
}

impl Event {
    /// `hello`, for the start of a stream.
    pub fn hello() -> Event {
        Event::Hello(Hello {
            protocol: PROTOCOL,
            fcage: env!("CARGO_PKG_VERSION"),
        })
    }

    /// `started`, for a command released with `pid` the handle's process.
    pub fn started(pid: u32) -> Event {
        Event::Started(Started { pid })
    }

    /// `published`, for the sandbox's `guest_port` bound at `address` on the
    /// host. `chosen` says the kernel chose the port, which is the only case
    /// standard error says anything of, since the caller named every other.
    pub fn published(guest_port: u16, address: SocketAddr, chosen: bool) -> Event {
        Event::Published(Published {
            guest_port,
            address: address.to_string(),
            line: chosen
                .then(|| format!("fcage: publishing the sandbox's port {guest_port} on {address}")),
        })
    }

    /// `dropped`: `count` of `source`'s reports, as `text` says.
    pub fn dropped(source: &'static str, count: u64, text: String) -> Event {
        Event::Dropped(Dropped {
            source,
            count,
            text,
        })
    }

    /// `provision`: one line of a provisioning run's progress.
    pub fn progress(text: String) -> Event {
        Event::Provision(Provision {
            report: "progress",
            text: Some(text),
            stream: None,
            output: None,
        })
    }

    /// `provision`: what a command a provisioning run ran wrote to `stream`.
    pub fn command_output(stream: Stream, bytes: &[u8]) -> Event {
        Event::Provision(Provision {
            report: "output",
            text: None,
            stream: Some(match stream {
                Stream::Stdout => "stdout",
                Stream::Stderr => "stderr",
                _ => "other",
            }),
            output: Some(Bytes(bytes.to_vec())),
        })
    }

    /// `warning`: `text`, a line of `fcage`'s own.
    pub fn warning(text: String) -> Event {
        Event::Warning(Warning { text })
    }

    /// `exited`: the command ended with `status`, or with `None` its timeout
    /// expired, `fcage` exits `shell_code`, and the command used `usage`.
    pub fn exited(
        status: Option<ExitStatus>,
        usage: Option<&ResourceUsage>,
        shell_code: u8,
    ) -> Event {
        Event::Exited(Exited {
            code: status.and_then(|status| status.code()),
            signal: status.and_then(|status| status.signal()),
            core_dumped: status.is_some_and(|status| status.core_dumped()),
            timed_out: status.is_none(),
            shell_code,
            usage: usage.map(Usage::of),
        })
    }

    /// `failed`: `failure`, after which `fcage` exits `shell_code`.
    pub fn failed(failure: Fault, shell_code: u8) -> Event {
        Event::Failed(Failed {
            error: failure.error,
            step: failure.step,
            errno: failure.errno,
            shell_code,
            text: format!("fcage: {}", failure.message),
        })
    }

    /// The line standard error carries for the event, where it carries one.
    pub fn text(&self) -> Option<&str> {
        match self {
            Event::Hello(_) | Event::Started(_) | Event::Exited(_) => None,
            Event::Published(published) => published.line.as_deref(),
            Event::Network(network) => Some(&network.text),
            Event::Seccomp(seccomp) => Some(&seccomp.text),
            Event::Dropped(dropped) => Some(&dropped.text),
            Event::Provision(provision) => provision.text.as_deref(),
            Event::Warning(warning) => Some(&warning.text),
            Event::Failed(failed) => Some(&failed.text),
        }
    }

    /// The event as a line of the stream: its JSON, and a newline.
    pub fn line(&self) -> Vec<u8> {
        // Every member is a string, a number, a boolean, or an object of
        // those, under string keys, so writing one to memory cannot fail.
        let mut line = serde_json::to_vec(self).expect("an event is always JSON");
        line.push(b'\n');
        line
    }
}

/// `network`: the network stack's `report`.
pub fn network(report: &NetStackReport) -> Event {
    let mut event = Network {
        report: "other",
        transport: None,
        guest: None,
        destination: None,
        name: None,
        record_type: None,
        admission: None,
        refusal: None,
        rule: None,
        cloud: None,
        server_name: None,
        reason: None,
        text: format!("fcage: the network stack {report}"),
    };
    match report {
        NetStackReport::FlowAdmitted {
            transport,
            guest,
            destination,
            name,
            admission,
            ..
        } => {
            event.report = "flow-admitted";
            event.flow(*transport, *guest, *destination, name.as_deref());
            event.admitted(admission);
        }
        NetStackReport::FlowRefused {
            transport,
            guest,
            destination,
            name,
            refusal,
            ..
        } => {
            event.report = "flow-refused";
            event.flow(*transport, *guest, *destination, name.as_deref());
            event.refused(refusal);
        }
        NetStackReport::QuestionRelayed {
            guest,
            name,
            record_type,
            admission,
            ..
        } => {
            event.report = "question-relayed";
            event.question(*guest, name, *record_type);
            event.admitted(admission);
        }
        NetStackReport::QuestionRefused {
            guest,
            name,
            record_type,
            refusal,
            ..
        } => {
            event.report = "question-refused";
            event.question(*guest, name, *record_type);
            event.refused(refusal);
        }
        NetStackReport::QuestionWithheld {
            guest,
            name,
            record_type,
            ..
        } => {
            event.report = "question-withheld";
            event.question(*guest, name, *record_type);
        }
        _ => {}
    }
    Event::Network(Box::new(event))
}

impl Network {
    /// Fills in a flow's members.
    fn flow(
        &mut self,
        transport: Transport,
        guest: SocketAddr,
        destination: SocketAddr,
        name: Option<&str>,
    ) {
        self.transport = Some(match transport {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
            _ => "other",
        });
        self.guest = Some(guest.to_string());
        self.destination = Some(destination.to_string());
        self.name = name.map(str::to_owned);
    }

    /// Fills in a question's members.
    fn question(&mut self, guest: SocketAddr, name: &str, record_type: u16) {
        self.guest = Some(guest.to_string());
        self.name = Some(name.to_owned());
        self.record_type = Some(record_type);
    }

    /// Names why the stack admitted a flow or a question.
    fn admitted(&mut self, admission: &FlowAdmission) {
        self.admission = Some(match admission {
            FlowAdmission::Default => "default",
            FlowAdmission::Allowed { rule, .. } => {
                self.rule = Some(rule.to_string());
                "allowed"
            }
            FlowAdmission::HostLoopback => "host-loopback",
            _ => "other",
        });
    }

    /// Names why the stack refused a flow or a question, and what the
    /// refusal carries.
    fn refused(&mut self, refusal: &FlowRefusal) {
        self.refusal = Some(match refusal {
            FlowRefusal::NotAllowed => "not-allowed",
            FlowRefusal::Denied { rule, .. } => {
                self.rule = Some(rule.to_string());
                "denied"
            }
            FlowRefusal::Loopback => "loopback",
            FlowRefusal::LinkLocal => "link-local",
            FlowRefusal::Multicast => "multicast",
            FlowRefusal::Broadcast => "broadcast",
            FlowRefusal::Unspecified => "unspecified",
            FlowRefusal::EmbeddedIpv4 => "embedded-ipv4",
            FlowRefusal::InstanceServices { cloud, .. } => {
                self.cloud = Some(*cloud);
                "instance-services"
            }
            FlowRefusal::GuestNetwork => "guest-network",
            FlowRefusal::GatewayUnmapped => "gateway-unmapped",
            FlowRefusal::ProtocolDisabled => "protocol-disabled",
            FlowRefusal::TooManyFlows => "too-many-flows",
            FlowRefusal::NotResolved => "not-resolved",
            FlowRefusal::PrivateBehindName { rule, .. } => {
                self.rule = Some(rule.to_string());
                "private-behind-name"
            }
            FlowRefusal::NameOverUdp { rule, .. } => {
                self.rule = Some(rule.to_string());
                "name-over-udp"
            }
            FlowRefusal::ServerNameNotAllowed { name, .. } => {
                self.server_name = Some(name.clone());
                "server-name-not-allowed"
            }
            FlowRefusal::ServerNameDenied { name, rule, .. } => {
                self.server_name = Some(name.clone());
                self.rule = Some(rule.to_string());
                "server-name-denied"
            }
            FlowRefusal::ServerNameUnfinished => "server-name-unfinished",
            FlowRefusal::ServerNameUnreadable { reason, .. } => {
                self.reason = Some(*reason);
                "server-name-unreadable"
            }
            _ => "other",
        });
    }
}

/// `seccomp`: the seccomp filter's `report`.
pub fn seccomp(report: &SeccompReport) -> Event {
    let mut event = Seccomp {
        report: "other",
        syscall: None,
        number: None,
        audit_arch: None,
        thread: None,
        command: None,
        arguments: None,
        errno: None,
        text: format!("fcage: the seccomp filter {report}"),
    };
    if let SeccompReport::Denied {
        syscall,
        name,
        arch,
        thread,
        command,
        arguments,
        errno,
        ..
    } = report
    {
        event.report = "denied";
        event.syscall = *name;
        event.number = Some(*syscall);
        event.audit_arch = Some(format!("{arch:#x}"));
        event.thread = Some(*thread);
        event.command.clone_from(command);
        event.arguments = Some(arguments.map(|argument| format!("{argument:#x}")));
        event.errno = Some(errno_name(i32::from(*errno)));
    }
    Event::Seccomp(Box::new(event))
}

impl Usage {
    /// The figures `usage` holds.
    fn of(usage: &ResourceUsage) -> Usage {
        let micros = |time: Option<Duration>| {
            time.map(|time| u64::try_from(time.as_micros()).unwrap_or(u64::MAX))
        };
        Usage {
            user_time_us: micros(usage.user_time),
            system_time_us: micros(usage.system_time),
            peak_rss_bytes: usage.peak_rss_bytes,
            cgroup_user_time_us: micros(usage.cgroup_user_time),
            cgroup_system_time_us: micros(usage.cgroup_system_time),
            cgroup_peak_memory_bytes: usage.cgroup_peak_memory_bytes,
            cgroup_peak_processes: usage.cgroup_peak_processes,
            cgroup_oom_kills: usage.cgroup_oom_kills,
            cgroup_refused_processes: usage.cgroup_refused_processes,
        }
    }
}

/// The library's [`Error`] variant, in kebab case, or `other` for one this
/// release of `fcage` does not name.
pub fn error_kind(error: &Error) -> &'static str {
    match error {
        Error::Config(_) => "config",
        Error::UsernsUnavailable { .. } => "userns-unavailable",
        Error::NamespaceLimitReached { .. } => "namespace-limit-reached",
        Error::KeyQuotaExhausted { .. } => "key-quota-exhausted",
        Error::Setup { .. } => "setup",
        Error::Spawn { .. } => "spawn",
        Error::Wait { .. } => "wait",
        Error::SupervisorLost => "supervisor-lost",
        Error::Signal { .. } => "signal",
        Error::KillHandle { .. } => "kill-handle",
        Error::IdentityMap(_) => "identity-map",
        Error::Terminal { .. } => "terminal",
        Error::TerminalsExhausted { .. } => "terminals-exhausted",
        Error::StreamIsDirectory { .. } => "stream-is-directory",
        Error::ListenRefused { .. } => "listen-refused",
        Error::Listen { .. } => "listen",
        Error::ProcfsRefused { .. } => "procfs-refused",
        Error::CgroupRefused { .. } => "cgroup-refused",
        Error::Cgroup { .. } => "cgroup",
        Error::SupervisorUnreceived => "supervisor-unreceived",
        Error::MountRefused { .. } => "mount-refused",
        Error::SeccompListenerHeld { .. } => "seccomp-listener-held",
        Error::SandboxEnded => "sandbox-ended",
        _ => "other",
    }
}

/// The setup step `error` names, where it names one; see [`step_name`].
fn step_of(error: &Error) -> Option<String> {
    match error {
        Error::Setup { step, .. }
        | Error::NamespaceLimitReached { step, .. }
        | Error::MountRefused { step, .. } => Some(step_name(*step)),
        _ => None,
    }
}

/// A setup step's name: its [`SetupStep`] variant in kebab case, as
/// `mount-overlay` names `SetupStep::MountOverlay`.
///
/// Read from the variant's derived `Debug`, which writes a fieldless variant's
/// name and nothing else, so every step the library adds is named without a
/// release of `fcage`. A step's discriminant is no name for it, since the
/// library numbers steps afresh in any release.
pub fn step_name(step: SetupStep) -> String {
    let mut name = String::new();
    for (at, letter) in format!("{step:?}").chars().enumerate() {
        if letter.is_ascii_uppercase() && at > 0 {
            name.push('-');
        }
        name.push(letter.to_ascii_lowercase());
    }
    name
}

/// The errno's name, as `EACCES`, where the kernel's table names it, and its
/// number in decimal otherwise, so a reader gets a string either way.
pub fn errno_name(errno: i32) -> String {
    syscalls::Errno::new(errno)
        .name()
        .map_or_else(|| errno.to_string(), str::to_owned)
}

/// The name of the first errno in `error`'s chain, itself included, where an
/// OS error is one of its causes.
///
/// A second walk of the chain [`ErrorChain`](ferroday_cage::ErrorChain)
/// renders, since this one asks it a different question: which errno lies
/// beneath, rather than how the layers read. It goes `source()` after
/// `source()` as the rendering does, with one step more: an `io::Error` that
/// wraps another error shows that error's message as its own, and its
/// `source()` is the wrapped error's source, so the wrapped error is the layer
/// asked next.
pub fn errno_in(error: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut layer = Some(error);
    while let Some(error) = layer {
        layer = error.source();
        if let Some(io) = error.downcast_ref::<std::io::Error>() {
            if let Some(errno) = io.raw_os_error() {
                return Some(errno_name(errno));
            }
            if let Some(wrapped) = io.get_ref() {
                layer = Some(wrapped);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The members `event` writes, sorted.
    fn members(event: &Event) -> Vec<String> {
        let value: serde_json::Value =
            serde_json::from_slice(&event.line()).expect("the line is JSON");
        value
            .as_object()
            .expect("an event is an object")
            .keys()
            .cloned()
            .collect()
    }

    #[test]
    fn each_kind_writes_the_members_it_names() {
        let address: SocketAddr = "127.0.0.1:41234".parse().expect("an address");
        let cases: Vec<(Event, &[&str])> = vec![
            (Event::hello(), &["event", "fcage", "protocol"]),
            (Event::started(7), &["event", "pid"]),
            (
                Event::published(8080, address, true),
                &["address", "event", "guest-port"],
            ),
            (
                Event::dropped("network", 3, "fcage: dropped".into()),
                &["count", "event", "source", "text"],
            ),
            (
                Event::progress("fcage: fetching".into()),
                &["event", "report", "text"],
            ),
            (
                Event::command_output(Stream::Stderr, b"dpkg says\n"),
                &["event", "output", "report", "stream"],
            ),
            (Event::warning("fcage: careful".into()), &["event", "text"]),
            (
                Event::exited(Some(ExitStatus::exited(3)), None, 3),
                &["code", "core-dumped", "event", "shell-code", "timed-out"],
            ),
            (
                Event::exited(None, None, 124),
                &["core-dumped", "event", "shell-code", "timed-out"],
            ),
            (
                Event::exited(Some(ExitStatus::signaled(9)), None, 137),
                &["core-dumped", "event", "shell-code", "signal", "timed-out"],
            ),
            (
                Event::failed(Fault::plain("usage", "no command".into()), 2),
                &["error", "event", "shell-code", "text"],
            ),
        ];
        for (event, expected) in cases {
            assert_eq!(members(&event), *expected, "{event:?}");
        }
    }

    #[test]
    fn a_kind_and_its_members_are_spelled_in_kebab_case() {
        let line = String::from_utf8(Event::exited(None, None, 124).line()).expect("UTF-8");
        assert_eq!(
            line,
            "{\"event\":\"exited\",\"core-dumped\":false,\"timed-out\":true,\"shell-code\":124}\n"
        );
    }

    #[test]
    fn bytes_are_a_string_where_they_are_text_and_base64_otherwise() {
        let text = serde_json::to_value(Bytes(b"plain text\n".to_vec())).expect("JSON");
        assert_eq!(text, serde_json::json!("plain text\n"));
        let binary = serde_json::to_value(Bytes(b"\xff\xfe\x00name".to_vec())).expect("JSON");
        assert_eq!(binary, serde_json::json!({"base64": "//4AbmFtZQ=="}));
    }

    #[test]
    fn base64_follows_rfc_4648() {
        // RFC 4648 section 10's test vectors.
        let vectors = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (input, encoded) in vectors {
            assert_eq!(base64(input.as_bytes()), encoded, "{input:?}");
        }
    }

    #[test]
    fn a_step_is_named_by_its_variant_in_kebab_case() {
        assert_eq!(step_name(SetupStep::Exec), "exec");
        assert_eq!(step_name(SetupStep::MountOverlay), "mount-overlay");
        assert_eq!(step_name(SetupStep::WriteUidMap), "write-uid-map");
    }

    #[test]
    fn an_errno_is_named_where_the_table_names_it() {
        assert_eq!(errno_name(13), "EACCES");
        assert_eq!(errno_name(4000), "4000");
        let io = std::io::Error::from_raw_os_error(2);
        let wrapped = std::io::Error::other(io);
        assert_eq!(errno_in(&wrapped).as_deref(), Some("ENOENT"));
        assert_eq!(errno_in(&std::io::Error::other("no errno")), None);
    }

    #[test]
    fn a_failure_writes_its_line_as_text() {
        let event = Event::failed(Fault::plain("fcage", "it broke".into()), 125);
        assert_eq!(event.text(), Some("fcage: it broke"));
    }

    #[test]
    fn only_a_port_the_kernel_chose_is_said() {
        let address: SocketAddr = "127.0.0.1:41234".parse().expect("an address");
        assert_eq!(
            Event::published(8080, address, true).text(),
            Some("fcage: publishing the sandbox's port 8080 on 127.0.0.1:41234")
        );
        assert_eq!(Event::published(8080, address, false).text(), None);
    }
}
