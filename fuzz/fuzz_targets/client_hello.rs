//! A TCP flow's first bytes, as the network stack reads them for the server
//! they ask for, framed as a TLS ClientHello whose body is arbitrary input: no
//! panic, a reading that does not change as more bytes arrive, and the same
//! reading in records of any size.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| ferroday_cage::fuzzing::client_hello(input));
