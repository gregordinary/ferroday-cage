//! A Gentoo binary package container, its members and its metadata archive,
//! over arbitrary input: no panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| ferroday_cage::fuzzing::gpkg(bytes));
