//! An `.apk`, its gzip segments and its file tree, over arbitrary input: no
//! panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| ferroday_cage::fuzzing::apk_package(bytes));
