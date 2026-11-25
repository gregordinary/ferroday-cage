//! A field-and-stanza document, as an index, a release, or a plan states one,
//! over arbitrary input: no panic, and every field a stanza lists is one it
//! answers for by name.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| ferroday_cage::fuzzing::stanza_document(bytes));
