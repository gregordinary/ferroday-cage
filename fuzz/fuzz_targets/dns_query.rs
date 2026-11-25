//! A guest's DNS message, as the network stack's nameserver reads it, over
//! arbitrary input: no panic, a query reads no further than the message, and
//! each reply the nameserver writes itself has the shape its sender relies on.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|message: &[u8]| ferroday_cage::fuzzing::dns_query(message));
