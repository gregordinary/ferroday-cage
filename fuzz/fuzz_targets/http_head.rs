//! A TCP flow's first bytes, as the network stack reads them for the server
//! they ask for, over arbitrary input: no panic, a reading that does not change
//! as more bytes arrive, and lines that read the same ended by a line feed
//! alone or by a carriage return and one.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| ferroday_cage::fuzzing::http_head(bytes));
