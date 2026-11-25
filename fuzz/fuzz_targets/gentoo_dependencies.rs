//! A Gentoo runtime dependency class, as an index record or a database entry
//! states one, over arbitrary input: no panic, and no more atoms than bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| ferroday_cage::fuzzing::gentoo_dependencies(bytes));
