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

use crate::gpt;
use crate::gpt_layout::{
    ENTRY_ARRAY_SECTORS, ENTRY_SIZE, FIRST_USABLE_LBA, HEADER_SIZE, NUM_ENTRIES,
};
const ENTRY_ARRAY_BYTES: u64 = (NUM_ENTRIES as u64) * (ENTRY_SIZE as u64);

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
        return Err(Error::Invalid(
            "too many partitions for canonical 128-slot table",
        ));
    }

    // Sort copy by start LBA so overlap detection is one linear pass.
    let mut sorted: Vec<(usize, &Partition)> = partitions.iter().enumerate().collect();
    sorted.sort_by_key(|(_, p)| p.start);
    let mut prev_end_lba: Option<u64> = None;
    for (_, p) in &sorted {
        validate_partition(p, FIRST_USABLE_LBA, last_usable_lba)?;
        let (start_lba, end_lba) = p.sector_span()?;
        if let Some(prev) = prev_end_lba {
            if start_lba <= prev {
                return Err(Error::Invalid("partitions overlap"));
            }
        }
        prev_end_lba = Some(end_lba);
    }

    // --- Build the entry array (16 KiB, all zeros + populated slots). ---
    let slots = assign_slots(partitions, NUM_ENTRIES)?;
    let mut array = vec![0u8; ENTRY_ARRAY_BYTES as usize];
    for (p, slot) in partitions.iter().zip(&slots) {
        let off = (*slot as usize) * ENTRY_SIZE as usize;
        let (type_guid, attributes) = match p.kind {
            PartitionKind::Gpt {
                type_guid,
                attributes,
            } => (type_guid, attributes),
            _ => return Err(Error::Invalid("non-GPT partition kind in GPT write")),
        };
        let uuid = p.uuid.ok_or(Error::Invalid("GPT partition missing UUID"))?;
        let (start_lba, end_lba) = p.sector_span()?;

        array[off..off + 16].copy_from_slice(&type_guid);
        array[off + 16..off + 32].copy_from_slice(&uuid);
        array[off + 32..off + 40].copy_from_slice(&start_lba.to_le_bytes());
        array[off + 40..off + 48].copy_from_slice(&end_lba.to_le_bytes());
        array[off + 48..off + 56].copy_from_slice(&attributes.to_le_bytes());
        if let Some(label) = &p.label {
            // 72 bytes UTF-16 LE, zero-padded.
            //
            // TRUNCATED BY CHARACTER, NOT BY CODE UNIT. The field holds
            // 36 UTF-16 units and a character outside the basic
            // multilingual plane takes two of them, so cutting at 36
            // units can leave a lone high surrogate on disk. That is not
            // a shortened label: it is not valid UTF-16 at all, and a
            // reader that decodes strictly answers "no label" — the name
            // disappears rather than losing its last character.
            let name_off = off + 56;
            let mut written = 0usize;
            for c in label.chars() {
                let units = c.len_utf16();
                if (written + units) * 2 > 72 {
                    break;
                }
                let mut buf = [0u16; 2];
                for (k, u) in c.encode_utf16(&mut buf).iter().enumerate() {
                    let at = name_off + (written + k) * 2;
                    array[at..at + 2].copy_from_slice(&u.to_le_bytes());
                }
                written += units;
            }
        }
    }
    let entry_array_crc = crc32fast::hash(&array);

    // --- Protective MBR at LBA 0. ---
    let mut mbr = [0u8; crate::SECTOR_SIZE_USIZE];
    // Partition 1 (offset 446): 0xEE spanning the disk.
    mbr[446] = 0x00; // boot indicator
                     // CHS first sector — write the canonical 0x00 0x02 0x00 trio meaning
                     // "head 0, sector 2, cylinder 0".
    mbr[447] = 0x00;
    mbr[448] = 0x02;
    mbr[449] = 0x00;
    mbr[450] = crate::mbr::types::GPT_PROTECTIVE;
    // CHS last sector — set to 0xFF 0xFF 0xFF (max) per the legacy convention
    // when the LBA range exceeds what CHS can express.
    mbr[451] = 0xFF;
    mbr[452] = 0xFF;
    mbr[453] = 0xFF;
    // starting LBA = 1
    mbr[454..458].copy_from_slice(&1u32.to_le_bytes());
    // size in sectors = min(disk_sectors - 1, 0xFFFFFFFF). Per the spec, the
    // protective entry caps at 0xFFFFFFFF for >2 TiB devices.
    let prot_sectors = (total_sectors - 1).min(crate::MBR_LBA_MAX) as u32;
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

/// Which table slot each partition is written into.
///
/// A partition's slot is its identity to everything above this crate —
/// the `3` in `/dev/sda3` — so a partition that came off a disk goes
/// back into the slot it came from. Writing each one into the slot
/// matching its position in the `Vec`, which is what this used to do,
/// compacts a table with a hole in it and renumbers every partition
/// after the hole: a probe, an unrelated edit and a commit were enough
/// to break every fstab entry and boot-loader config that named one by
/// number, with the operation reporting success.
///
/// A partition with no slot has never been in a table, so it takes the
/// lowest free one. Two partitions claiming the same slot is refused:
/// one would be written over the other and the table would silently
/// lose a partition.
pub(crate) fn assign_slots(partitions: &[Partition], num_entries: u32) -> Result<Vec<u32>> {
    let mut taken = vec![false; num_entries as usize];
    for p in partitions {
        let Some(slot) = p.slot else { continue };
        let seat = taken
            .get_mut(slot as usize)
            .ok_or(Error::Invalid("partition slot past the end of the table"))?;
        if *seat {
            return Err(Error::Invalid("two partitions claim the same table slot"));
        }
        *seat = true;
    }

    let mut next_free = 0usize;
    let mut out = Vec::with_capacity(partitions.len());
    for p in partitions {
        match p.slot {
            Some(slot) => out.push(slot),
            None => {
                while next_free < taken.len() && taken[next_free] {
                    next_free += 1;
                }
                if next_free == taken.len() {
                    return Err(Error::Invalid("no free slot left in the table"));
                }
                taken[next_free] = true;
                out.push(next_free as u32);
            }
        }
    }
    Ok(out)
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
    let (start_lba, end_lba) = p.sector_span()?;
    if start_lba < first_usable {
        return Err(Error::Invalid("partition starts before first usable LBA"));
    }
    // The start needs its own upper bound, not just the end's. Without
    // it the only thing keeping an absurd `start` out of the table is
    // the end check, and a `start` far enough out makes the end wrap to
    // something small -- which that check then waves through. A refusal
    // by name beats one that depends on the arithmetic not wrapping.
    if start_lba > last_usable {
        return Err(Error::Invalid("partition starts past last usable LBA"));
    }
    if end_lba > last_usable {
        return Err(Error::Invalid("partition ends past last usable LBA"));
    }
    if let PartitionKind::Gpt { type_guid, .. } = p.kind {
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
) -> [u8; crate::SECTOR_SIZE_USIZE] {
    let mut h = [0u8; crate::SECTOR_SIZE_USIZE];
    h[0..8].copy_from_slice(SIGNATURE);
    h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // revision 1.0
    h[12..16].copy_from_slice(&HEADER_SIZE.to_le_bytes());
    // 16..20 header_crc — left zero for the compute pass, written below.
    // 20..24 reserved
    h[gpt::header_offsets::MY_LBA..gpt::header_offsets::MY_LBA + 8]
        .copy_from_slice(&my_lba.to_le_bytes());
    h[32..40].copy_from_slice(&alternate_lba.to_le_bytes());
    h[40..48].copy_from_slice(&first_usable.to_le_bytes());
    h[48..56].copy_from_slice(&last_usable.to_le_bytes());
    h[56..72].copy_from_slice(&disk_guid);
    h[gpt::header_offsets::PARTITION_ENTRY_LBA..gpt::header_offsets::PARTITION_ENTRY_LBA + 8]
        .copy_from_slice(&entry_lba.to_le_bytes());
    h[gpt::header_offsets::NUM_PARTITION_ENTRIES..gpt::header_offsets::NUM_PARTITION_ENTRIES + 4]
        .copy_from_slice(&NUM_ENTRIES.to_le_bytes());
    h[gpt::header_offsets::PARTITION_ENTRY_SIZE..gpt::header_offsets::PARTITION_ENTRY_SIZE + 4]
        .copy_from_slice(&ENTRY_SIZE.to_le_bytes());
    h[88..92].copy_from_slice(&entry_array_crc.to_le_bytes());

    let header_crc = crc32fast::hash(&h[..HEADER_SIZE as usize]);
    h[16..20].copy_from_slice(&header_crc.to_le_bytes());
    h
}
