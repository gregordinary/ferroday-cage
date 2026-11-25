//! An access control list, as an attribute's value and as a `SCHILY.acl.*`
//! record's text, over arbitrary input: no panic, and a list the attribute's
//! reader admits renders as text the text's reader reads back.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| ferroday_cage::fuzzing::acl(bytes));
