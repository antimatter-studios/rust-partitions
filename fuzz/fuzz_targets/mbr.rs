#![no_main]
//! Sector zero, as an MBR.
//!
//! Four sixteen-byte entries, each declaring a start LBA and a length
//! whose sum is used as a range, plus a type byte that decides whether
//! the entry is a partition, an extended container, or a GPT
//! protective marker.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut sector = [0u8; partitions::SECTOR_SIZE_USIZE];
    let take = data.len().min(sector.len());
    sector[..take].copy_from_slice(&data[..take]);

    let _ = partitions::mbr::parse(&sector);
    let _ = partitions::mbr::is_protective(&sector);
    let _ = partitions::mbr::has_gpt_marker(&sector);
});
