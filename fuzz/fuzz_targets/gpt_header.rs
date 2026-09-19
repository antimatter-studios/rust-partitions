#![no_main]
//! The GPT header.
//!
//! It declares how many partition entries there are and how long each
//! one is, and the product of those two sizes a read. It also declares
//! where its own entry array lives, where the backup header is, and the
//! usable range every entry is checked against -- all of it before any
//! of it has been believed.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut sector = [0u8; partitions::SECTOR_SIZE_USIZE];
    let take = data.len().min(sector.len());
    sector[..take].copy_from_slice(&data[..take]);

    let _ = partitions::gpt::parse_header(&sector);
});
