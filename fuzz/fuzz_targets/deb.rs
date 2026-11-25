//! A `.deb`'s `ar` container over arbitrary input: its control member read,
//! and its data member reached, without a panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| ferroday_cage::fuzzing::deb(bytes));
