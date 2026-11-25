//! DNS messages, as the stack's nameserver reads and writes them.
//!
//! The nameserver relays the guest's queries to the host's resolver and the
//! answers back, so it reads little of a message. Of a query it reads the
//! header, the one question, and whether an OPT record follows: enough to tell
//! a query from anything else, to hold its name to the destination rules, and
//! to answer one it does not relay. Of an answer it reads the address records
//! that answer the question, following its aliases, which is what ties an
//! address to the name the guest asked for. It writes the answers it gives
//! itself: a refusal, a failure, a name refused under the rules, a question
//! answered with no records, and the truncated answer that stands in for one
//! too long for a datagram and sends the guest's resolver to TCP.
//!
//! What it reads comes from the guest, or from the servers the host's resolver
//! asked on the guest's behalf, and is read in the caller's process. Each read
//! is bounded by the message and by the protocol's own limits: a label of at
//! most 63 bytes, a name of at most 255, and a compression pointer that points
//! strictly backwards, which is what makes a walk of pointers end. A message
//! that breaks one is refused rather than read some other way.
//!
//! A name is compared in one spelling, its [text](Query::name): the labels in
//! lower case, joined by dots, with every byte but a letter, a digit, `-` and
//! `_` written as a backslash and three decimal digits, as a zone file writes
//! one. A dot is then always the boundary between two labels, so a name's text
//! ends in `.example.com` exactly where the name is below `example.com`, and
//! the text holds no control character, which lets a report name it bare. The
//! root is `.`.

use std::fmt::Write as _;
use std::net::IpAddr;

/// The length of a message's header.
pub(super) const HEADER: usize = 12;

/// The record types the nameserver reads or writes (RFC 1035, section 3.2.2;
/// RFC 3596; RFC 6891; RFC 9460).
const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;
const TYPE_SVCB: u16 = 64;
const TYPE_HTTPS: u16 = 65;

/// The Internet class, the only one whose address records are read.
const CLASS_IN: u16 = 1;

/// The length of a resource record's fixed fields, between its owner name and
/// its data: type, class, time to live, and the data's length.
const RECORD_FIELDS: usize = 10;

/// The Extended DNS Error a refused name is answered with: 15, "Blocked"
/// (RFC 8914, section 4.16), carried in the OPT record's option of that code.
const EDE_OPTION: u16 = 15;
const EDE_BLOCKED: u16 = 15;

/// The longest reply the nameserver writes itself, and the payload size the
/// OPT record of such a reply states: every resolver takes a message this long,
/// over UDP with EDNS or without (RFC 1035, section 4.2.1; RFC 6891, section
/// 6.2.5), and every interface the stack configures carries one in a packet.
const OWN_REPLY: usize = 512;

/// The longest query the nameserver takes, over either transport.
///
/// A query carries one question, of at most a 255-byte name and four bytes of
/// type and class, and an OPT record whose options are a few dozen bytes in
/// practice. The bound is generous to that and small beside the 65,535 bytes a
/// TCP length prefix can state, which is what it is there to refuse: a guest
/// that announces a message that long holds a session's buffer for nothing.
pub(super) const MAX_QUERY: usize = 4096;

/// The longest name a message may carry, its length bytes included (RFC 1035,
/// section 2.3.4).
const MAX_NAME: usize = 255;

/// The response codes the nameserver writes itself (RFC 1035, section 4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Rcode {
    /// The question is answered, with no records where nothing else is said.
    NoError = 0,
    /// The message could not be read as a query.
    FormatError = 1,
    /// The nameserver could not get an answer from upstream.
    ServerFailure = 2,
    /// The name does not exist (NXDOMAIN).
    NameError = 3,
    /// The query asks for an operation other than a standard query.
    NotImplemented = 4,
}

// Header flag bits, as they sit in the header's third and fourth bytes.
/// Third byte: the message is a response.
const QR: u8 = 0x80;
/// Third byte: the operation code's four bits.
const OPCODE: u8 = 0x78;
/// Third byte: the response was truncated to fit its transport.
const TC: u8 = 0x02;
/// Third byte: the client asks for recursion, which a response repeats.
const RD: u8 = 0x01;
/// Fourth byte: the server offers recursion.
const RA: u8 = 0x80;

/// Why a message is not a query the nameserver relays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
    /// Too short to hold a header, or a response rather than a query. Nothing
    /// is written back: a header is what a reply would repeat, and answering a
    /// response is how two servers come to answer each other forever.
    Unanswerable,
    /// A query the nameserver answers itself, with this code and no question.
    Answer(Rcode),
}

/// A query the nameserver relays: a standard query with exactly one question,
/// read as far as the question's end.
#[derive(Debug, Clone, Copy)]
pub(super) struct Query<'a> {
    /// The whole message, as the guest sent it.
    message: &'a [u8],
    /// Where the question ends, which is where a reply the nameserver writes
    /// itself stops repeating the query.
    question_end: usize,
}

impl<'a> Query<'a> {
    /// The query's transaction id.
    pub(super) fn id(&self) -> u16 {
        u16::from_be_bytes([self.message[0], self.message[1]])
    }

    /// The whole message.
    pub(super) fn message(&self) -> &'a [u8] {
        self.message
    }

    /// The text of the name the question asks about, in the spelling the
    /// [module](self) describes.
    pub(super) fn name(&self) -> String {
        name_text(self.message, HEADER)
            .map(|(text, _)| text)
            .expect("a query's question name read when the query did")
    }

    /// The record type the question asks for.
    pub(super) fn record_type(&self) -> u16 {
        let at = self.question_end - 4;
        u16::from_be_bytes([self.message[at], self.message[at + 1]])
    }

    /// The question's type and class, as they sit in the message.
    fn type_and_class(&self) -> &'a [u8] {
        &self.message[self.question_end - 4..self.question_end]
    }

    /// Whether the query carries an OPT record, which says its resolver reads
    /// EDNS (RFC 6891), and so the options a reply carries in one.
    ///
    /// A record past the question that does not read ends the search, and the
    /// query is taken to carry none.
    pub(super) fn has_opt(&self) -> bool {
        let count =
            |at: usize| usize::from(u16::from_be_bytes([self.message[at], self.message[at + 1]]));
        let before = count(6) + count(8);
        let mut at = self.question_end;
        for index in 0..before + count(10) {
            let Some(record) = read_record(self.message, at) else {
                return false;
            };
            if index >= before && record.kind == TYPE_OPT {
                return true;
            }
            at = record.end;
        }
        false
    }
}

/// Whether `record_type` is SVCB's or HTTPS's (RFC 9460): the records that
/// carry a service's keys for Encrypted Client Hello and its transport hints.
pub(super) fn is_service_binding(record_type: u16) -> bool {
    matches!(record_type, TYPE_SVCB | TYPE_HTTPS)
}

/// The mnemonic a zone file writes `record_type` as, for the types a guest
/// commonly asks for, or `None` for another, which RFC 3597 writes `TYPEn`.
pub(super) fn type_mnemonic(record_type: u16) -> Option<&'static str> {
    Some(match record_type {
        TYPE_A => "A",
        2 => "NS",
        TYPE_CNAME => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        TYPE_AAAA => "AAAA",
        33 => "SRV",
        TYPE_SVCB => "SVCB",
        TYPE_HTTPS => "HTTPS",
        255 => "ANY",
        257 => "CAA",
        _ => return None,
    })
}

/// Reads `message` as a query the nameserver relays.
///
/// It must hold a header, ask (the QR bit clear), be a standard query (opcode
/// 0), and carry exactly one question that reads to its end. Everything after
/// the question, the OPT record among it, is relayed as it stands.
pub(super) fn read_query(message: &[u8]) -> Result<Query<'_>, Refusal> {
    let header = message.get(..HEADER).ok_or(Refusal::Unanswerable)?;
    if header[2] & QR != 0 {
        return Err(Refusal::Unanswerable);
    }
    if header[2] & OPCODE != 0 {
        return Err(Refusal::Answer(Rcode::NotImplemented));
    }
    if message.len() > MAX_QUERY || u16::from_be_bytes([header[4], header[5]]) != 1 {
        return Err(Refusal::Answer(Rcode::FormatError));
    }
    let name_end = skip_name(message, HEADER).ok_or(Refusal::Answer(Rcode::FormatError))?;
    // The question's type and class follow its name.
    let question_end = name_end + 4;
    if question_end > message.len() {
        return Err(Refusal::Answer(Rcode::FormatError));
    }
    Ok(Query {
        message,
        question_end,
    })
}

/// The end of the name that starts at `start` in `message`, or `None` where the
/// name breaks one of the protocol's limits; see [`walk_name`].
fn skip_name(message: &[u8], start: usize) -> Option<usize> {
    walk_name(message, start, |_| {})
}

/// The text of the name that starts at `start` in `message`, in the spelling
/// the [module](self) describes, and the name's end in the message; `None`
/// where the name breaks one of the protocol's limits.
fn name_text(message: &[u8], start: usize) -> Option<(String, usize)> {
    let mut text = String::new();
    let end = walk_name(message, start, |label| {
        if !text.is_empty() {
            text.push('.');
        }
        for byte in label.iter().map(u8::to_ascii_lowercase) {
            if byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' {
                text.push(char::from(byte));
            } else {
                let _ = write!(text, "\\{byte:03}");
            }
        }
    })?;
    if text.is_empty() {
        text.push('.');
    }
    Some((text, end))
}

/// Walks the name that starts at `start` in `message`, handing `label` each of
/// its labels in order, and answers the name's end in the message, or `None`
/// where the name breaks one of the protocol's limits.
///
/// A name is a run of labels ended by an empty one, or by a compression
/// pointer to the rest of the name elsewhere in the message. Its end, in the
/// message, is just past that empty label or that pointer, whatever the pointer
/// leads to. Each pointer must point strictly before itself, so a walk of them
/// ends, and the labels it reaches count toward the 255 bytes a name may hold.
/// A name that breaks a limit may have handed some of its labels over first.
fn walk_name(message: &[u8], start: usize, mut label: impl FnMut(&[u8])) -> Option<usize> {
    let mut at = start;
    // Where the name ends in the message: past its first pointer, or past its
    // final empty label where it holds no pointer.
    let mut end = None;
    let mut length = 0usize;
    loop {
        let byte = *message.get(at)?;
        match byte & 0xc0 {
            0x00 => {
                let len = usize::from(byte);
                length += 1 + len;
                if length > MAX_NAME {
                    return None;
                }
                if len == 0 {
                    return Some(end.unwrap_or(at + 1));
                }
                // A length byte whose top two bits are clear is at most 63,
                // the longest a label may be, so no label here is too long.
                label(message.get(at + 1..at + 1 + len)?);
                at += 1 + len;
            }
            0xc0 => {
                let low = *message.get(at + 1)?;
                let target = usize::from(u16::from_be_bytes([byte & 0x3f, low]));
                if target >= at {
                    return None;
                }
                end.get_or_insert(at + 2);
                at = target;
            }
            // The extended and reserved label types (RFC 6891 section 5, RFC
            // 2673): no resolver sends one, and none can be read here.
            _ => return None,
        }
    }
}

/// One resource record, where [`read_record`] found it in a message.
struct Record {
    /// Where its owner name starts.
    owner: usize,
    /// Its type.
    kind: u16,
    /// Its class.
    class: u16,
    /// Where its data starts and ends.
    data: std::ops::Range<usize>,
    /// Where the record ends, which is where the next one starts.
    end: usize,
}

/// Reads the resource record that starts at `at` in `message`, or `None` where
/// its owner name breaks a limit or the record runs past the message.
fn read_record(message: &[u8], at: usize) -> Option<Record> {
    let fields = skip_name(message, at)?;
    let fixed = message.get(fields..fields + RECORD_FIELDS)?;
    let start = fields + RECORD_FIELDS;
    let end = start + usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
    if end > message.len() {
        return None;
    }
    Some(Record {
        owner: at,
        kind: u16::from_be_bytes([fixed[0], fixed[1]]),
        class: u16::from_be_bytes([fixed[2], fixed[3]]),
        data: start..end,
        end,
    })
}

/// The most aliases an answer's chain is followed through. Resolvers stop
/// following a chain at about this length, and a longer one in an answer is
/// either a loop or written to cost its reader.
const MAX_ALIASES: usize = 16;

/// The addresses `answer` gives for the name `query` asks about: each address
/// record of its answer section on the question's alias chain.
///
/// The chain starts at the name the guest asked about, and each CNAME record
/// whose owner is on it adds its target, so an answer that reaches its addresses
/// through a content network's aliases gives them for the asked name. A record
/// whose owner is not on the chain gives nothing: an answer record for another
/// name, and every record of the authority and additional sections, which are
/// not read. The answer must state no error and repeat the query's question,
/// its name in any case; anything else gives nothing. A record that does not
/// read ends the answer section, and the records before it stand, since they
/// reach the guest as they are.
///
/// That `answer` is a response, and to this query, is [`answers`]'s to settle.
pub(super) fn answer_addresses(query: &Query<'_>, answer: &[u8]) -> Vec<IpAddr> {
    let Some(header) = answer.get(..HEADER) else {
        return Vec::new();
    };
    if header[3] & 0x0f != Rcode::NoError as u8 || u16::from_be_bytes([header[4], header[5]]) != 1 {
        return Vec::new();
    }
    let asked = query.name();
    let Some((name, question)) = name_text(answer, HEADER) else {
        return Vec::new();
    };
    if name != asked || answer.get(question..question + 4) != Some(query.type_and_class()) {
        return Vec::new();
    }
    let mut aliases = Vec::new();
    let mut addresses = Vec::new();
    let mut at = question + 4;
    for _ in 0..u16::from_be_bytes([header[6], header[7]]) {
        let Some(record) = read_record(answer, at) else {
            break;
        };
        at = record.end;
        if record.class != CLASS_IN {
            continue;
        }
        let data = &answer[record.data.clone()];
        match record.kind {
            TYPE_A | TYPE_AAAA => {
                let address = match record.kind {
                    TYPE_A => <[u8; 4]>::try_from(data).ok().map(IpAddr::from),
                    _ => <[u8; 16]>::try_from(data).ok().map(IpAddr::from),
                };
                if let Some(address) = address
                    && let Some((owner, _)) = name_text(answer, record.owner)
                {
                    addresses.push((owner, address));
                }
            }
            TYPE_CNAME => {
                // The target is a name, which may point anywhere before it in
                // the message, and must end where the record's data does.
                if let Some((owner, _)) = name_text(answer, record.owner)
                    && let Some((target, end)) = name_text(answer, record.data.start)
                    && end == record.data.end
                {
                    aliases.push((owner, target));
                }
            }
            _ => {}
        }
    }
    let mut chain = vec![asked];
    while chain.len() <= MAX_ALIASES {
        let last = &chain[chain.len() - 1];
        match aliases.iter().find(|(owner, _)| owner == last) {
            Some((_, target)) if !chain.contains(target) => chain.push(target.clone()),
            _ => break,
        }
    }
    addresses
        .into_iter()
        .filter(|(owner, _)| chain.contains(owner))
        .map(|(_, address)| address)
        .collect()
}

/// A reply the nameserver writes itself to a message `read_query` refused with
/// [`Refusal::Answer`]: the message's own header, marked a response with
/// recursion offered, carrying `rcode`, and no question or records.
///
/// The header is all it repeats, since the question is what failed to read, or
/// belongs to an operation the nameserver does not carry out. `None` where `message` holds no header,
/// which [`read_query`] reports as [`Refusal::Unanswerable`].
pub(super) fn refusal(message: &[u8], rcode: Rcode) -> Option<Vec<u8>> {
    let header = message.get(..HEADER)?;
    let mut reply = header.to_vec();
    reply[2] = QR | (header[2] & (OPCODE | RD));
    reply[3] = RA | rcode as u8;
    reply[4..HEADER].fill(0);
    Some(reply)
}

/// A reply to `query` carrying no records: the query's header and question,
/// marked a response with recursion offered, with the response code `rcode`,
/// and an OPT record of the nameserver's own where the query carries one.
pub(super) fn failure(query: &Query<'_>, rcode: Rcode) -> Vec<u8> {
    own_reply(query, rcode, None)
}

/// The reply to `query` for a name the destination rules refuse: NXDOMAIN,
/// which a resolver takes at once and as final.
///
/// Where the query carries an OPT record, so its resolver reads EDNS, the reply
/// carries Extended DNS Error 15, "Blocked", with `reason` as its text, which a
/// tool such as `dig` shows. The text is left out where it would take the reply
/// past the 512 bytes every resolver accepts.
pub(super) fn blocked(query: &Query<'_>, reason: &str) -> Vec<u8> {
    own_reply(query, Rcode::NameError, Some(reason))
}

/// The reply to `query` that answers it with no records: NOERROR, and nothing
/// of the type asked for.
pub(super) fn no_records(query: &Query<'_>) -> Vec<u8> {
    own_reply(query, Rcode::NoError, None)
}

/// A reply the nameserver writes itself to `query`, which it read whole: the
/// query's header and question, marked a response with recursion offered, with
/// `rcode` and no records.
///
/// A query that carries an OPT record gets one back (RFC 6891, section 7),
/// stating [`OWN_REPLY`] as the payload size, and holding Extended DNS Error 15
/// with `blocked` as its text where that is given.
fn own_reply(query: &Query<'_>, rcode: Rcode, blocked: Option<&str>) -> Vec<u8> {
    let mut reply = query.message[..query.question_end].to_vec();
    reply[2] = QR | (reply[2] & (OPCODE | RD));
    reply[3] = RA | rcode as u8;
    set_counts(&mut reply);
    if !query.has_opt() {
        return reply;
    }
    let mut options = Vec::new();
    if let Some(reason) = blocked {
        // The root owner, the record's fixed fields, and the option's code,
        // length and info code come first.
        let room = OWN_REPLY.saturating_sub(reply.len() + 1 + RECORD_FIELDS + 6);
        let text = if reason.len() <= room {
            reason.as_bytes()
        } else {
            &[]
        };
        options.extend_from_slice(&EDE_OPTION.to_be_bytes());
        options.extend_from_slice(&length_of(2 + text.len()));
        options.extend_from_slice(&EDE_BLOCKED.to_be_bytes());
        options.extend_from_slice(text);
    }
    reply[10..12].copy_from_slice(&1u16.to_be_bytes());
    // The root name, the type, the payload size where a class would be, and an
    // extended response code, version and flags of zero.
    reply.push(0);
    reply.extend_from_slice(&TYPE_OPT.to_be_bytes());
    reply.extend_from_slice(&length_of(OWN_REPLY));
    reply.extend_from_slice(&[0, 0, 0, 0]);
    reply.extend_from_slice(&length_of(options.len()));
    reply.extend_from_slice(&options);
    reply
}

/// A length the nameserver writes, at most [`OWN_REPLY`], as the two bytes a
/// message states it in.
fn length_of(length: usize) -> [u8; 2] {
    u16::try_from(length)
        .expect("a length within one of the nameserver's own replies")
        .to_be_bytes()
}

/// The reply that stands in for `answer` where it is too long for the datagram
/// it would go back in: `query`'s header and question, with `answer`'s flags and
/// response code and the TC bit set, and no records.
///
/// A resolver that receives it asks again over TCP (RFC 1035, section 4.2.1;
/// RFC 7766). The question is the query's, which is what the guest's resolver
/// matches its reply to.
pub(super) fn truncated(query: &Query<'_>, answer: &[u8]) -> Vec<u8> {
    let mut reply = query.message[..query.question_end].to_vec();
    reply[2] = answer[2] | QR | TC;
    reply[3] = answer[3];
    set_counts(&mut reply);
    reply
}

/// Sets a reply's counts to its one question and no records.
fn set_counts(reply: &mut [u8]) {
    reply[4..6].copy_from_slice(&1u16.to_be_bytes());
    reply[6..HEADER].fill(0);
}

/// Whether `message` is the response to the query sent under transaction id
/// `id`: a header with that id and the QR bit set.
///
/// Each query goes upstream on a socket of its own, connected to the resolver,
/// so nothing but that resolver can answer on it. The id is checked as any
/// resolver's client checks it, which keeps a stray datagram from standing in
/// for the answer.
pub(super) fn answers(message: &[u8], id: u16) -> bool {
    message.get(..HEADER).is_some_and(|header| {
        header[2] & QR != 0 && u16::from_be_bytes([header[0], header[1]]) == id
    })
}

/// Runs every reader and writer here over `message`, for a fuzz target: none
/// may panic, and what each returns holds to the shape its caller relies on.
///
/// A query is also read as the answer to itself, and a response as the answer
/// to the query its own header and question make, so the answer reader meets
/// the input whichever way its QR bit falls.
#[cfg(fuzzing)]
pub(super) fn exercise(message: &[u8]) {
    match read_query(message) {
        Ok(query) => {
            assert!(query.question_end > HEADER && query.question_end <= message.len());
            let name = query.name();
            assert!(!name.is_empty() && name.is_ascii() && !name.contains(char::is_control));
            let _ = query.record_type();
            let opt = query.has_opt();
            let long = "x".repeat(OWN_REPLY);
            for reply in [
                failure(&query, Rcode::FormatError),
                failure(&query, Rcode::ServerFailure),
                failure(&query, Rcode::NotImplemented),
                blocked(&query, "the deny rule example.com refuses it"),
                blocked(&query, &long),
                no_records(&query),
            ] {
                assert!(answers(&reply, query.id()));
                assert!(reply.len() <= OWN_REPLY);
                assert_eq!(reply.len() > query.question_end, opt);
                assert_eq!(
                    reply[HEADER..query.question_end],
                    message[HEADER..query.question_end]
                );
            }
            // The message as an answer to itself, whatever its flags say.
            let reply = truncated(&query, message);
            assert_eq!(reply.len(), query.question_end);
            assert!(answers(&reply, query.id()));
            assert_eq!(reply[2] & TC, TC);
            let _ = answer_addresses(&query, message);
        }
        Err(Refusal::Unanswerable) => {
            assert!(message.len() < HEADER || message[2] & QR != 0);
            if message.len() >= HEADER {
                let mut asked = message[..message.len().min(MAX_QUERY)].to_vec();
                asked[2] &= !QR;
                if let Ok(query) = read_query(&asked) {
                    let _ = answer_addresses(&query, message);
                }
            }
        }
        Err(Refusal::Answer(rcode)) => {
            let reply = refusal(message, rcode).expect("an answered refusal has a header");
            assert_eq!(reply.len(), HEADER);
            assert_eq!(reply[..2], message[..2]);
        }
    }
    let _ = answers(message, 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The response code of a message that holds a header.
    fn rcode_of(message: &[u8]) -> u8 {
        message[3] & 0x0f
    }

    /// A query for `name` (dotted, no trailing dot) of type A, id 0x1234, with
    /// recursion desired.
    fn query(name: &str) -> Vec<u8> {
        let mut message = vec![0x12, 0x34, RD, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            message.push(u8::try_from(label.len()).unwrap());
            message.extend_from_slice(label.as_bytes());
        }
        message.extend_from_slice(&[0, 0, 1, 0, 1]);
        message
    }

    #[test]
    fn a_query_reads_to_its_questions_end() {
        let message = query("example.com");
        let read = read_query(&message).expect("a plain query");
        assert_eq!(read.id(), 0x1234);
        assert_eq!(read.question_end, message.len());
    }

    #[test]
    fn what_follows_the_question_is_carried_along() {
        // An OPT record: the root name, type 41, a 1232-byte payload size.
        let mut message = query("example.com");
        message[11] = 1;
        let question_end = message.len();
        message.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        let read = read_query(&message).expect("a query with an OPT record");
        assert_eq!(read.question_end, question_end);
        assert_eq!(read.message(), &message[..]);
    }

    #[test]
    fn a_response_or_a_fragment_of_a_header_is_not_answered() {
        let mut response = query("example.com");
        response[2] |= QR;
        assert_eq!(read_query(&response).unwrap_err(), Refusal::Unanswerable);
        for len in 0..HEADER {
            let message = query("example.com");
            assert_eq!(
                read_query(&message[..len]).unwrap_err(),
                Refusal::Unanswerable,
                "{len} bytes",
            );
            assert_eq!(refusal(&message[..len], Rcode::FormatError), None);
        }
    }

    #[test]
    fn an_operation_other_than_a_query_is_not_implemented() {
        // Opcode 5, an update.
        let mut message = query("example.com");
        message[2] |= 5 << 3;
        assert_eq!(
            read_query(&message).unwrap_err(),
            Refusal::Answer(Rcode::NotImplemented),
        );
        let reply = refusal(&message, Rcode::NotImplemented).expect("a header to repeat");
        assert_eq!(reply.len(), HEADER);
        assert_eq!(reply[..2], [0x12, 0x34]);
        assert_eq!(reply[2], QR | 5 << 3 | RD, "the opcode and RD are repeated");
        assert_eq!(rcode_of(&reply), Rcode::NotImplemented as u8);
        assert!(
            reply[4..].iter().all(|&byte| byte == 0),
            "no question, no records"
        );
    }

    #[test]
    fn a_query_without_exactly_one_question_is_a_format_error() {
        for count in [0u16, 2] {
            let mut message = query("example.com");
            message[4..6].copy_from_slice(&count.to_be_bytes());
            assert_eq!(
                read_query(&message).unwrap_err(),
                Refusal::Answer(Rcode::FormatError),
                "{count} questions",
            );
        }
    }

    #[test]
    fn a_question_cut_short_is_a_format_error() {
        let message = query("example.com");
        for len in HEADER..message.len() {
            assert_eq!(
                read_query(&message[..len]).unwrap_err(),
                Refusal::Answer(Rcode::FormatError),
                "{len} bytes",
            );
        }
    }

    #[test]
    fn a_query_past_the_bound_is_a_format_error() {
        let mut message = query("example.com");
        message.resize(MAX_QUERY + 1, 0);
        assert_eq!(
            read_query(&message).unwrap_err(),
            Refusal::Answer(Rcode::FormatError),
        );
    }

    #[test]
    fn a_name_holds_to_the_protocols_limits() {
        // 255 bytes exactly on the wire: four labels of 62 and one of 1, each
        // with its length byte, and the root's. The dotted form is two shorter.
        let longest = vec!["a".repeat(62); 4].join(".") + ".a";
        assert_eq!(longest.len() + 2, MAX_NAME);
        read_query(&query(&longest)).expect("a name of 255 bytes");
        let over = longest.clone() + "b";
        assert_eq!(
            read_query(&query(&over)).unwrap_err(),
            Refusal::Answer(Rcode::FormatError),
            "a name of 256 bytes",
        );
        // A length byte with the reserved or extended type's bits.
        for kind in [0x40u8, 0x80] {
            let mut message = query("example.com");
            message[HEADER] = kind | 7;
            assert_eq!(
                read_query(&message).unwrap_err(),
                Refusal::Answer(Rcode::FormatError),
                "label type {kind:#x}",
            );
        }
    }

    #[test]
    fn a_pointer_must_point_backwards() {
        // A name made of one pointer to itself, then to just past itself.
        for target in [HEADER as u16, HEADER as u16 + 1] {
            let mut message = vec![0x12, 0x34, RD, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            message.extend_from_slice(&(0xc000 | target).to_be_bytes());
            message.extend_from_slice(&[0, 1, 0, 1, 0]);
            assert_eq!(
                read_query(&message).unwrap_err(),
                Refusal::Answer(Rcode::FormatError),
                "a pointer to {target}",
            );
        }
        // A pointer cut short.
        let mut message = query("example.com");
        message.truncate(HEADER);
        message.push(0xc0);
        assert!(read_query(&message).is_err());
    }

    #[test]
    fn a_pointer_ends_the_name_where_it_stands() {
        // The question's name points back into the header's bytes, which read
        // as the empty name: a query no resolver sends, and one that reads.
        // Byte 7 of the header is a count's low byte, here zero.
        let mut message = vec![0x12, 0x34, RD, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        message.extend_from_slice(&[0xc0, 7, 0, 1, 0, 1]);
        let read = read_query(&message).expect("a name ending at a pointer");
        assert_eq!(read.question_end, message.len());
    }

    #[test]
    fn a_walk_of_pointers_counts_toward_the_names_length() {
        // A chain of labels, each reached by a pointer from after it, whose
        // total runs past 255 bytes while every pointer points backwards.
        let mut message = vec![0x12, 0x34, RD, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        let mut previous: Option<u16> = None;
        for _ in 0..5 {
            let at = u16::try_from(message.len()).unwrap();
            message.push(62);
            message.extend_from_slice(&[b'a'; 62]);
            match previous {
                Some(target) => message.extend_from_slice(&(0xc000u16 | target).to_be_bytes()),
                None => message.push(0),
            }
            previous = Some(at);
        }
        let start = message.len();
        message.extend_from_slice(&(0xc000u16 | previous.unwrap()).to_be_bytes());
        message.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(skip_name(&message, start), None, "five 63-byte labels");
    }

    /// `message` with an OPT record of a 1232-byte payload size added to its
    /// additional section.
    fn with_opt(mut message: Vec<u8>) -> Vec<u8> {
        message[11] += 1;
        message.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        message
    }

    #[test]
    fn a_failure_repeats_the_question_and_carries_no_records() {
        let message = query("example.com");
        let read = read_query(&message).unwrap();
        let reply = failure(&read, Rcode::ServerFailure);
        assert_eq!(reply.len(), read.question_end);
        assert_eq!(reply[..2], [0x12, 0x34]);
        assert_eq!(reply[2], QR | RD);
        assert_eq!(reply[3], RA | Rcode::ServerFailure as u8);
        assert_eq!(reply[4..HEADER], [0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(reply[HEADER..], message[HEADER..read.question_end]);
    }

    #[test]
    fn a_reply_to_a_query_with_an_opt_record_carries_one_of_its_own() {
        let message = with_opt(query("example.com"));
        let read = read_query(&message).unwrap();
        for reply in [failure(&read, Rcode::ServerFailure), no_records(&read)] {
            assert_eq!(
                reply[4..HEADER],
                [0, 1, 0, 0, 0, 0, 0, 1],
                "one additional record"
            );
            // The root, OPT, a 512-byte payload size, no extended code, version
            // or flags, and no options: the guest's own record is not repeated.
            assert_eq!(
                reply[read.question_end..],
                [0, 0, 41, 0x02, 0x00, 0, 0, 0, 0, 0, 0]
            );
        }
    }

    #[test]
    fn a_query_reads_its_name_type_and_opt_record() {
        let mut message = query("Example.COM");
        message[HEADER + 13..HEADER + 15].copy_from_slice(&65u16.to_be_bytes());
        let read = read_query(&message).unwrap();
        assert_eq!(read.name(), "example.com", "lowered");
        assert_eq!(read.record_type(), 65);
        assert!(!read.has_opt());
        let message = with_opt(message);
        assert!(read_query(&message).unwrap().has_opt());
        // An OPT record anywhere but the additional section is not the query's.
        let mut misplaced = message.clone();
        misplaced[7] = 1;
        misplaced[11] = 0;
        assert!(!read_query(&misplaced).unwrap().has_opt());
        // A record that does not read ends the search.
        let mut cut = with_opt(query("example.com"));
        cut.truncate(cut.len() - 3);
        assert!(!read_query(&cut).unwrap().has_opt());
    }

    #[test]
    fn a_name_is_written_in_one_spelling() {
        let text = |labels: &[&[u8]]| {
            let mut message = vec![0; HEADER];
            for label in labels {
                message.push(u8::try_from(label.len()).unwrap());
                message.extend_from_slice(label);
            }
            message.push(0);
            name_text(&message, HEADER).map(|(text, _)| text)
        };
        assert_eq!(
            text(&[b"WWW", b"Example", b"com"]).unwrap(),
            "www.example.com"
        );
        assert_eq!(text(&[b"_dmarc", b"a-b", b"9"]).unwrap(), "_dmarc.a-b.9");
        assert_eq!(text(&[]).unwrap(), ".", "the root");
        // A dot, a space, a star, a backslash and a control byte inside a label
        // are written as escapes, so a dot is only ever a boundary.
        assert_eq!(text(&[b"x.example", b"com"]).unwrap(), "x\\046example.com");
        assert_eq!(
            text(&[b"a b", b"*", b"\\", b"\x07"]).unwrap(),
            "a\\032b.\\042.\\092.\\007"
        );
        // A name past its limit has no text.
        assert_eq!(
            text(&[&[b'a'; 63], &[b'a'; 63], &[b'a'; 63], &[b'a'; 63]]),
            None
        );
    }

    #[test]
    fn a_name_read_through_a_pointer_is_read_whole() {
        // The question's name, then a name made of a label and a pointer back
        // into the question's.
        let mut message = query("example.com");
        let start = message.len();
        message.extend_from_slice(&[3, b'W', b'w', b'W', 0xc0, 12]);
        assert_eq!(
            name_text(&message, start),
            Some(("www.example.com".to_string(), message.len()))
        );
    }

    #[test]
    fn a_blocked_name_is_answered_nxdomain_with_its_reason_where_edns_is_read() {
        // Without an OPT record, the code alone.
        let message = query("example.com");
        let read = read_query(&message).unwrap();
        let reply = blocked(&read, "the deny rule example.com refuses it");
        assert_eq!(reply.len(), read.question_end);
        assert_eq!(reply[3], RA | Rcode::NameError as u8);
        assert!(answers(&reply, 0x1234));

        // With one, Extended DNS Error 15 and the reason as its text.
        let message = with_opt(query("example.com"));
        let read = read_query(&message).unwrap();
        let reason = "the deny rule example.com refuses it";
        let reply = blocked(&read, reason);
        assert_eq!(reply[3], RA | Rcode::NameError as u8);
        assert_eq!(reply[4..HEADER], [0, 1, 0, 0, 0, 0, 0, 1]);
        let opt = &reply[read.question_end..];
        assert_eq!(opt[..9], [0, 0, 41, 0x02, 0x00, 0, 0, 0, 0]);
        let length = 4 + 2 + reason.len();
        assert_eq!(opt[9..11], u16::try_from(length).unwrap().to_be_bytes());
        assert_eq!(opt[11..13], [0, 15], "the Extended DNS Error option");
        assert_eq!(
            opt[13..15],
            u16::try_from(2 + reason.len()).unwrap().to_be_bytes()
        );
        assert_eq!(opt[15..17], [0, 15], "Blocked");
        assert_eq!(&opt[17..], reason.as_bytes());

        // A reason too long for 512 bytes is left out, and the code stays.
        let long = "x".repeat(OWN_REPLY);
        let reply = blocked(&read, &long);
        assert!(reply.len() <= OWN_REPLY);
        let opt = &reply[read.question_end..];
        assert_eq!(opt[9..], [0, 6, 0, 15, 0, 2, 0, 15]);
    }

    /// The wire form of a dotted name.
    fn wire(name: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for label in name.split('.').filter(|label| !label.is_empty()) {
            bytes.push(u8::try_from(label.len()).unwrap());
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes
    }

    /// An answer to `query`, stating `rcode`, with `records` in its answer
    /// section: each an owner, a type, a class, and its data.
    fn answer_with(query: &[u8], rcode: u8, records: &[(Vec<u8>, u16, u16, Vec<u8>)]) -> Vec<u8> {
        let read = read_query(query).unwrap();
        let mut answer = query[..read.question_end].to_vec();
        answer[2] |= QR;
        answer[3] = RA | rcode;
        answer[6..8].copy_from_slice(&u16::try_from(records.len()).unwrap().to_be_bytes());
        answer[8..HEADER].fill(0);
        for (owner, kind, class, data) in records {
            answer.extend_from_slice(owner);
            answer.extend_from_slice(&kind.to_be_bytes());
            answer.extend_from_slice(&class.to_be_bytes());
            answer.extend_from_slice(&60u32.to_be_bytes());
            answer.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            answer.extend_from_slice(data);
        }
        answer
    }

    fn a(owner: &str, octets: [u8; 4]) -> (Vec<u8>, u16, u16, Vec<u8>) {
        (wire(owner), TYPE_A, CLASS_IN, octets.to_vec())
    }

    fn aaaa(owner: &str, address: &str) -> (Vec<u8>, u16, u16, Vec<u8>) {
        let address: std::net::Ipv6Addr = address.parse().unwrap();
        (wire(owner), TYPE_AAAA, CLASS_IN, address.octets().to_vec())
    }

    fn cname(owner: &str, target: &str) -> (Vec<u8>, u16, u16, Vec<u8>) {
        (wire(owner), TYPE_CNAME, CLASS_IN, wire(target))
    }

    fn addresses(query: &[u8], answer: &[u8]) -> Vec<String> {
        answer_addresses(&read_query(query).unwrap(), answer)
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn an_answer_gives_the_addresses_of_the_asked_name() {
        let asked = query("example.com");
        let answer = answer_with(
            &asked,
            0,
            &[
                a("example.com", [192, 0, 2, 1]),
                a("EXAMPLE.com", [192, 0, 2, 2]),
            ],
        );
        assert_eq!(addresses(&asked, &answer), ["192.0.2.1", "192.0.2.2"]);
        // A record of an address's length the type does not take gives nothing.
        let answer = answer_with(
            &asked,
            0,
            &[
                (wire("example.com"), TYPE_A, CLASS_IN, vec![192, 0, 2, 1, 0]),
                aaaa("example.com", "2001:db8::1"),
                (wire("example.com"), TYPE_AAAA, CLASS_IN, vec![192, 0, 2, 3]),
            ],
        );
        assert_eq!(addresses(&asked, &answer), ["2001:db8::1"]);
    }

    #[test]
    fn an_alias_chain_gives_its_addresses_for_the_asked_name() {
        let asked = query("www.example.com");
        let answer = answer_with(
            &asked,
            0,
            &[
                // Out of order, as an answer may be.
                a("edge.cdn.example", [198, 51, 100, 7]),
                cname("www.example.com", "example.cdn.example"),
                cname("example.cdn.example", "edge.cdn.example"),
                // Records for names off the chain.
                a("stray.example", [203, 0, 113, 9]),
                cname("other.example", "edge.cdn.example"),
                a("other.example", [203, 0, 113, 10]),
            ],
        );
        assert_eq!(addresses(&asked, &answer), ["198.51.100.7"]);
    }

    #[test]
    fn an_alias_written_through_a_pointer_is_followed() {
        let asked = query("www.example.com");
        // The CNAME's target is `cdn` and a pointer to `example.com` in the
        // question, which starts at byte 16.
        let answer = answer_with(
            &asked,
            0,
            &[
                (
                    vec![0xc0, 12],
                    TYPE_CNAME,
                    CLASS_IN,
                    vec![3, b'c', b'd', b'n', 0xc0, 16],
                ),
                a("cdn.example.com", [192, 0, 2, 9]),
            ],
        );
        assert_eq!(addresses(&asked, &answer), ["192.0.2.9"]);
        // A target that runs past the record's data is no alias.
        let answer = answer_with(
            &asked,
            0,
            &[
                (
                    vec![0xc0, 12],
                    TYPE_CNAME,
                    CLASS_IN,
                    vec![3, b'c', b'd', b'n'],
                ),
                (vec![0xc0, 16], TYPE_A, CLASS_IN, vec![192, 0, 2, 9]),
            ],
        );
        assert!(addresses(&asked, &answer).is_empty());
    }

    #[test]
    fn a_looping_or_endless_chain_ends() {
        let asked = query("a.example");
        let answer = answer_with(
            &asked,
            0,
            &[
                cname("a.example", "b.example"),
                cname("b.example", "a.example"),
                a("b.example", [192, 0, 2, 1]),
            ],
        );
        assert_eq!(addresses(&asked, &answer), ["192.0.2.1"]);
        // A chain past the aliases a resolver follows reaches no further.
        let mut records: Vec<_> = (0..=MAX_ALIASES)
            .map(|step| {
                cname(
                    &format!("n{step}.example"),
                    &format!("n{}.example", step + 1),
                )
            })
            .collect();
        let asked = query("n0.example");
        records.push(a(&format!("n{MAX_ALIASES}.example"), [192, 0, 2, 1]));
        records.push(a(&format!("n{}.example", MAX_ALIASES + 1), [192, 0, 2, 2]));
        assert_eq!(
            addresses(&asked, &answer_with(&asked, 0, &records)),
            ["192.0.2.1"]
        );
    }

    #[test]
    fn an_answer_that_is_not_to_the_question_gives_nothing() {
        let asked = query("example.com");
        let record = [a("example.com", [192, 0, 2, 1])];
        // An error, a question for another name, and one of another type.
        assert!(addresses(&asked, &answer_with(&asked, 3, &record)).is_empty());
        let other = query("example.net");
        let mut answer = answer_with(&other, 0, &[a("example.net", [192, 0, 2, 1])]);
        answer[..2].copy_from_slice(&[0x12, 0x34]);
        assert!(addresses(&asked, &answer).is_empty());
        let mut typed = query("example.com");
        typed[HEADER + 14] = 28;
        assert!(addresses(&asked, &answer_with(&typed, 0, &record)).is_empty());
        // A record of another class.
        let chaos = [(wire("example.com"), TYPE_A, 3, vec![192, 0, 2, 1])];
        assert!(addresses(&asked, &answer_with(&asked, 0, &chaos)).is_empty());
        // The question's name in another case is the same question.
        let mut shouted = answer_with(&asked, 0, &record);
        shouted[HEADER + 1..HEADER + 8].copy_from_slice(b"EXAMPLE");
        assert_eq!(addresses(&asked, &shouted), ["192.0.2.1"]);
    }

    #[test]
    fn a_record_that_does_not_read_ends_the_answer_section() {
        let asked = query("example.com");
        let mut answer = answer_with(
            &asked,
            0,
            &[
                a("example.com", [192, 0, 2, 1]),
                a("example.com", [192, 0, 2, 2]),
            ],
        );
        answer.truncate(answer.len() - 1);
        assert_eq!(addresses(&asked, &answer), ["192.0.2.1"]);
        // A count that overruns the message reads what is there.
        answer[7] = 200;
        assert_eq!(addresses(&asked, &answer), ["192.0.2.1"]);
    }

    #[test]
    fn a_type_is_named_as_a_zone_file_names_it() {
        assert_eq!(type_mnemonic(1), Some("A"));
        assert_eq!(type_mnemonic(28), Some("AAAA"));
        assert_eq!(type_mnemonic(65), Some("HTTPS"));
        assert_eq!(type_mnemonic(99), None);
        assert!(is_service_binding(64) && is_service_binding(65));
        assert!(!is_service_binding(1));
    }

    #[test]
    fn a_truncated_reply_keeps_the_answers_flags_and_sets_tc() {
        let message = query("example.com");
        let read = read_query(&message).unwrap();
        // An answer under the upstream's id: authoritative, recursion offered,
        // authenticated data, NXDOMAIN, one answer record's worth of bytes.
        let mut answer = message.clone();
        answer[..2].copy_from_slice(&[0xab, 0xcd]);
        answer[2] = QR | 0x04 | RD;
        answer[3] = RA | 0x20 | 3;
        answer[6..8].copy_from_slice(&1u16.to_be_bytes());
        answer.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
        let reply = truncated(&read, &answer);
        assert_eq!(reply.len(), read.question_end);
        assert_eq!(
            reply[..2],
            [0x12, 0x34],
            "the guest's id, not the upstream's"
        );
        assert_eq!(reply[2], QR | 0x04 | TC | RD);
        assert_eq!(reply[3], RA | 0x20 | 3);
        assert_eq!(reply[4..HEADER], [0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn an_answer_is_matched_by_its_id_and_its_qr_bit() {
        let mut answer = query("example.com");
        assert!(!answers(&answer, 0x1234), "a query is no answer");
        answer[2] |= QR;
        assert!(answers(&answer, 0x1234));
        assert!(!answers(&answer, 0x1235));
        assert!(!answers(&answer[..HEADER - 1], 0x1234));
    }
}
