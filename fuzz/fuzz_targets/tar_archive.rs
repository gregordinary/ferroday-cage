//! A tar archive, as an extraction reads one, over arbitrary input: no panic,
//! and every entry read whole within a bound until the reader ends or refuses.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| ferroday_cage::fuzzing::tar_archive(bytes));
