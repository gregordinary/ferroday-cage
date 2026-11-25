//! DNS messages, as the stack's nameserver reads and writes them.
//!
//! The nameserver relays the guest's queries to the host's resolver and the
//! answers back, so it reads little of a message: the header, and the one
//! question a query carries. That is enough to tell a query from anything else,
//! to answer one it does not relay, and to stand in for an answer too long for
//! one datagram with a truncated one, which sends the guest's resolver to TCP.
//!
//! What it reads comes from the guest and is read in the caller's process. Each
//! read is bounded by the message and by the protocol's own limits: a label of
//! at most 63 bytes, a name of at most 255, and a compression pointer that
//! points strictly backwards, which is what makes a walk of pointers end. A
//! message that breaks one is refused rather than read some other way.

/// The length of a message's header.
pub(super) const HEADER: usize = 12;

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
    /// The message could not be read as a query.
    FormatError = 1,
    /// The nameserver could not get an answer from upstream.
    ServerFailure = 2,
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
/// name breaks one of the protocol's limits.
///
/// A name is a run of labels ended by an empty one, or by a compression
/// pointer to the rest of the name elsewhere in the message. Its end, in the
/// message, is just past that empty label or that pointer, whatever the pointer
/// leads to. The pointers are followed only to hold the name to its limits: each
/// must point strictly before itself, so a walk of them ends, and the labels it
/// reaches count toward the 255 bytes a name may hold.
fn skip_name(message: &[u8], start: usize) -> Option<usize> {
    let mut at = start;
    // Where the name ends in the message: past its first pointer, or past its
    // final empty label where it holds no pointer.
    let mut end = None;
    let mut length = 0usize;
    loop {
        let byte = *message.get(at)?;
        match byte & 0xc0 {
            0x00 => {
                let label = usize::from(byte);
                length += 1 + label;
                if length > MAX_NAME {
                    return None;
                }
                if label == 0 {
                    return Some(end.unwrap_or(at + 1));
                }
                // A length byte whose top two bits are clear is at most 63,
                // the longest a label may be, so no label here is too long.
                if at + 1 + label > message.len() {
                    return None;
                }
                at += 1 + label;
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
/// marked a response with recursion offered, with the response code `rcode`.
pub(super) fn failure(query: &Query<'_>, rcode: Rcode) -> Vec<u8> {
    let mut reply = query.message[..query.question_end].to_vec();
    reply[2] = QR | (reply[2] & (OPCODE | RD));
    reply[3] = RA | rcode as u8;
    set_counts(&mut reply);
    reply
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
#[cfg(fuzzing)]
pub(super) fn exercise(message: &[u8]) {
    match read_query(message) {
        Ok(query) => {
            assert!(query.question_end > HEADER && query.question_end <= message.len());
            for rcode in [
                Rcode::FormatError,
                Rcode::ServerFailure,
                Rcode::NotImplemented,
            ] {
                let reply = failure(&query, rcode);
                assert_eq!(reply.len(), query.question_end);
                assert!(answers(&reply, query.id()));
            }
            // The message as an answer to itself, whatever its flags say.
            let reply = truncated(&query, message);
            assert_eq!(reply.len(), query.question_end);
            assert!(answers(&reply, query.id()));
            assert_eq!(reply[2] & TC, TC);
        }
        Err(Refusal::Unanswerable) => {
            assert!(message.len() < HEADER || message[2] & QR != 0);
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

    #[test]
    fn a_failure_repeats_the_question_and_carries_no_records() {
        let mut message = query("example.com");
        message[11] = 1;
        message.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        let read = read_query(&message).unwrap();
        let reply = failure(&read, Rcode::ServerFailure);
        assert_eq!(
            reply.len(),
            read.question_end,
            "the OPT record is not repeated"
        );
        assert_eq!(reply[..2], [0x12, 0x34]);
        assert_eq!(reply[2], QR | RD);
        assert_eq!(reply[3], RA | Rcode::ServerFailure as u8);
        assert_eq!(reply[4..HEADER], [0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(reply[HEADER..], message[HEADER..read.question_end]);
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
