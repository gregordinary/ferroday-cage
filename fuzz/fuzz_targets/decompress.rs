//! A compressed stream, named by its leading bytes, and a bare LZMA stream,
//! over arbitrary input: no panic, and each decoded to a bound.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| ferroday_cage::fuzzing::decompress(bytes));
