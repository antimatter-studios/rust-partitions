//! GPT writer.
//!
//! Serialises a list of [`Partition`]s back to disk as a fully-formed GPT —
//! protective MBR at LBA 0, primary header at LBA 1, primary entry array at
//! LBA 2..33, backup entry array at LBA (last-32)..(last-1), backup header
//! at the last LBA. CRCs are computed per the partition-table spec.
//!
//! Layout assumptions:
//!
//! - 512-byte logical sectors (matches what [`gpt::parse`] assumes).
//! - 128 partition entries × 128 bytes = 16 KiB array (the canonical shape).
//! - First usable LBA = 34, last usable LBA = `last_lba - 33`.
//!
//! The writer does not preserve any pre-existing bootloader code in the
//! protective MBR's first 446 bytes — those are zeroed. A future
//! `with_boot_code` variant can carry caller-supplied boot code through.
//! TODO: expose that variant once a caller wants legacy BIOS boot support.
//!
//! CRC pitfalls baked in here:
//! - Header CRC is computed with the four CRC bytes (offset 16..20) zeroed.
//! - Entry-array CRC covers the entire 16 KiB, including unused (zeroed)
//!   slots, not just the populated entries.

use crate::error::{Error, Result};
use crate::gpt::{type_guids, SECTOR_SIZE, SIGNATURE};
use crate::probe::{Partition, PartitionKind};
use fs_core::BlockDevice;

/// Canonical entry counts. The spec allows other values; this writer pins
/// them so every commit produces a byte-identical layout shape.
const NUM_ENTRIES: u32 = 128;
const ENTRY_SIZE: u32 = 128;
const ENTRY_ARRAY_BYTES: u64 = (NUM_ENTRIES as u64) * (ENTRY_SIZE as u64); // 16384
const ENTRY_ARRAY_SECTORS: u64 = ENTRY_ARRAY_BYTES / SECTOR_SIZE; // 32
const FIRST_USABLE_LBA: u64 = 2 + ENTRY_ARRAY_SECTORS; // 34
const HEADER_SIZE: u32 = 92;

/// Write a complete GPT to `dev`. The caller owns the partition list and the
/// disk GUID; this function does not mutate either.
///
/// Validation:
/// - Each partition must carry a [`PartitionKind::Gpt`] type GUID. Any
///   non-GPT entry is rejected with [`Error::Invalid`].
/// - Each partition must have a UUID. Callers building a fresh table can
///   mint one through the public helpers in [`crate::mutation`].
/// - All start/length pairs must lie within the usable range (LBA 34 ..=
///   last_lba - 33), be sector-aligned, and not overlap each other.
/// - At most [`NUM_ENTRIES`] partitions are accepted.
pub fn write_gpt(
    dev: &dyn BlockDevice,
    partitions: &[Partition],
    disk_guid: [u8; 16],
) -> Result<()> {
    if !dev.is_writable() {
        return Err(Error::Block(fs_core::Error::ReadOnly));
    }

    let total_bytes = dev.size_bytes();
    if total_bytes < (FIRST_USABLE_LBA + ENTRY_ARRAY_SECTORS + 1) * SECTOR_SIZE {
        return Err(Error::DeviceTooSmall);
    }
    let total_sectors = total_bytes / SECTOR_SIZE;
    let last_lba = total_sectors - 1;
    let last_usable_lba = last_lba - ENTRY_ARRAY_SECTORS - 1; // = last_lba - 33

    if partitions.len() > NUM_ENTRIES as usize {
        return Err(Error::Invalid("too many partitions for canonical 128-slot table"));
    }

    // Sort copy by start LBA so overlap detection is one linear pass.
    let mut sorted: Vec<(usize, &Partition)> = partitions.iter().enumerate().collect();
    sorted.sort_by_key(|(_, p)| p.start);
    let mut prev_end_lba: Option<u64> = None;
    for (_, p) in &sorted {
        validate_partition(p, FIRST_USABLE_LBA, last_usable_lba)?;
        let start_lba = p.start / SECTOR_SIZE;
        let end_lba = (p.start + p.length) / SECTOR_SIZE - 1;
        if let Some(prev) = prev_end_lba {
            if start_lba <= prev {
                return Err(Error::Invalid("partitions overlap"));
            }
        }
        prev_end_lba = Some(end_lba);
    }

    // --- Build the entry array (16 KiB, all zeros + populated slots). ---
    let mut array = vec![0u8; ENTRY_ARRAY_BYTES as usize];
    for (idx, p) in partitions.iter().enumerate() {
        let off = idx * ENTRY_SIZE as usize;
        let type_guid = match p.kind {
            PartitionKind::Gpt { type_guid } => type_guid,
            _ => return Err(Error::Invalid("non-GPT partition kind in GPT write")),
        };
        let uuid = p
            .uuid
            .ok_or(Error::Invalid("GPT partition missing UUID"))?;
        let start_lba = p.start / SECTOR_SIZE;
        let end_lba = (p.start + p.length) / SECTOR_SIZE - 1;

        array[off..off + 16].copy_from_slice(&type_guid);
        array[off + 16..off + 32].copy_from_slice(&uuid);
        array[off + 32..off + 40].copy_from_slice(&start_lba.to_le_bytes());
        array[off + 40..off + 48].copy_from_slice(&end_lba.to_le_bytes());
        // attributes (8 bytes) left zero
        if let Some(label) = &p.label {
            // 72 bytes UTF-16 LE, zero-padded; truncate at 36 code units.
            let name_off = off + 56;
            for (j, c) in label.encode_utf16().enumerate() {
                if j * 2 + 2 > 72 {
                    break;
                }
                array[name_off + j * 2..name_off + j * 2 + 2].copy_from_slice(&c.to_le_bytes());
            }
        }
    }
    let entry_array_crc = crc32fast::hash(&array);

    // --- Protective MBR at LBA 0. ---
    let mut mbr = [0u8; 512];
    // Partition 1 (offset 446): 0xEE spanning the disk.
    mbr[446] = 0x00; // boot indicator
    // CHS first sector — write the canonical 0x00 0x02 0x00 trio meaning
    // "head 0, sector 2, cylinder 0".
    mbr[447] = 0x00;
    mbr[448] = 0x02;
    mbr[449] = 0x00;
    mbr[450] = 0xEE; // type byte
    // CHS last sector — set to 0xFF 0xFF 0xFF (max) per the legacy convention
    // when the LBA range exceeds what CHS can express.
    mbr[451] = 0xFF;
    mbr[452] = 0xFF;
    mbr[453] = 0xFF;
    // starting LBA = 1
    mbr[454..458].copy_from_slice(&1u32.to_le_bytes());
    // size in sectors = min(disk_sectors - 1, 0xFFFFFFFF). Per the spec, the
    // protective entry caps at 0xFFFFFFFF for >2 TiB devices.
    let prot_sectors = (total_sectors - 1).min(0xFFFF_FFFF) as u32;
    mbr[458..462].copy_from_slice(&prot_sectors.to_le_bytes());
    // boot signature
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    dev.write_at(0, &mbr)?;

    // --- Primary header at LBA 1. ---
    let primary = build_header(
        /* my_lba */ 1,
        /* alternate_lba */ last_lba,
        /* entry_lba */ 2,
        /* first_usable */ FIRST_USABLE_LBA,
        /* last_usable */ last_usable_lba,
        disk_guid,
        entry_array_crc,
    );
    dev.write_at(SECTOR_SIZE, &primary)?;

    // --- Primary entry array at LBA 2 ---
    dev.write_at(2 * SECTOR_SIZE, &array)?;

    // --- Backup entry array at LBA (last_lba - 32) ---
    let backup_entries_lba = last_lba - ENTRY_ARRAY_SECTORS;
    dev.write_at(backup_entries_lba * SECTOR_SIZE, &array)?;

    // --- Backup header at last LBA. ---
    let backup = build_header(
        /* my_lba */ last_lba,
        /* alternate_lba */ 1,
        /* entry_lba */ backup_entries_lba,
        /* first_usable */ FIRST_USABLE_LBA,
        /* last_usable */ last_usable_lba,
        disk_guid,
        entry_array_crc,
    );
    dev.write_at(last_lba * SECTOR_SIZE, &backup)?;

    Ok(())
}

fn validate_partition(p: &Partition, first_usable: u64, last_usable: u64) -> Result<()> {
    if !matches!(p.kind, PartitionKind::Gpt { .. }) {
        return Err(Error::Invalid("non-GPT partition kind in GPT write"));
    }
    if p.length == 0 {
        return Err(Error::Invalid("partition has zero length"));
    }
    if !p.start.is_multiple_of(SECTOR_SIZE) || !p.length.is_multiple_of(SECTOR_SIZE) {
        return Err(Error::Invalid("partition not sector-aligned"));
    }
    let start_lba = p.start / SECTOR_SIZE;
    let end_lba = (p.start + p.length) / SECTOR_SIZE - 1;
    if start_lba < first_usable {
        return Err(Error::Invalid("partition starts before first usable LBA"));
    }
    if end_lba > last_usable {
        return Err(Error::Invalid("partition ends past last usable LBA"));
    }
    if let PartitionKind::Gpt { type_guid } = p.kind {
        if type_guid == type_guids::UNUSED {
            return Err(Error::Invalid("partition type GUID is the unused sentinel"));
        }
    }
    Ok(())
}

fn build_header(
    my_lba: u64,
    alternate_lba: u64,
    entry_lba: u64,
    first_usable: u64,
    last_usable: u64,
    disk_guid: [u8; 16],
    entry_array_crc: u32,
) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[0..8].copy_from_slice(SIGNATURE);
    h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // revision 1.0
    h[12..16].copy_from_slice(&HEADER_SIZE.to_le_bytes());
    // 16..20 header_crc — left zero for the compute pass, written below.
    // 20..24 reserved
    h[24..32].copy_from_slice(&my_lba.to_le_bytes());
    h[32..40].copy_from_slice(&alternate_lba.to_le_bytes());
    h[40..48].copy_from_slice(&first_usable.to_le_bytes());
    h[48..56].copy_from_slice(&last_usable.to_le_bytes());
    h[56..72].copy_from_slice(&disk_guid);
    h[72..80].copy_from_slice(&entry_lba.to_le_bytes());
    h[80..84].copy_from_slice(&NUM_ENTRIES.to_le_bytes());
    h[84..88].copy_from_slice(&ENTRY_SIZE.to_le_bytes());
    h[88..92].copy_from_slice(&entry_array_crc.to_le_bytes());

    let header_crc = crc32fast::hash(&h[..HEADER_SIZE as usize]);
    h[16..20].copy_from_slice(&header_crc.to_le_bytes());
    h
}
