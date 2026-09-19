#![no_main]
//! A whole device, probed and then sniffed.
//!
//! This crate runs before anything about a disk has been established,
//! and this is the target that reaches all of it: deciding whether the
//! table is MBR or GPT, walking the GPT entry array whose length is the
//! product of two header fields, following an extended-partition chain
//! whose every link is a sector number off the disk, and falling back
//! to the backup header when the primary does not parse.
//!
//! An extended chain that points back at itself is the cheapest way to
//! turn a probe into a hang, which is why the walk is budgeted.
use libfuzzer_sys::fuzz_target;
use partitions_fuzz::walk;

fuzz_target!(|data: &[u8]| {
    walk(data);
});
