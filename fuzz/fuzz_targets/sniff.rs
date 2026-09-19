#![no_main]
//! The filesystem sniffer, over the window it reads.
//!
//! `classify` looks as far as the ISO 9660 descriptor at 0x8001, and
//! every check before that is an offset into a buffer whose length it
//! does not control. A window shorter than the offset it wants is the
//! ordinary case, not the exotic one: a partition can be smaller than
//! the furthest magic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = partitions::sniff::classify(data);
});
