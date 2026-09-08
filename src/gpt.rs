//! GPT (GUID Partition Table) primary header + partition entry array.
//!
//! Layout (sector-size = 512):
//!
//! ```text
//!   LBA 0   Protective MBR (one 0xEE entry spanning the disk)
//!   LBA 1   GPT header (92 bytes used, rest of sector zero)
//!   LBA 2..(2 + entries_size/512)  Partition entry array
//!   ...
//!   LBA (n-32)..(n-1)  Backup entry array
//!   LBA n-1  Backup GPT header
//! ```
//!
//! Header fields (offsets within LBA 1):
//!
//! ```text
//!    0..8    "EFI PART"
//!    8..12   revision (1.0 = 0x00010000)
//!   12..16   header_size  (typically 92)
//!   16..20   header_crc32 (zeroed during compute)
//!   20..24   reserved (must be zero)
//!   24..32   my_lba  (= 1 for primary)
//!   32..40   alternate_lba (backup header LBA)
//!   40..48   first_usable_lba
//!   48..56   last_usable_lba
//!   56..72   disk_guid
//!   72..80   partition_entry_lba (= 2 for primary)
//!   80..84   num_partition_entries (typically 128)
//!   84..88   partition_entry_size  (typically 128)
//!   88..92   partition_entry_array_crc32
//! ```
//!
//! Entry layout (offsets within each entry):
//!
//! ```text
//!    0..16   partition_type_guid
//!   16..32   unique_partition_guid
//!   32..40   starting_lba
//!   40..48   ending_lba (inclusive)
//!   48..56   attributes
//!   56..128  partition_name (UTF-16 LE, zero-padded)
//! ```
//!
//! All multi-byte integers are little-endian. GUIDs are stored mixed-endian:
//! the first three fields are little-endian, the last two big-endian. We
//! treat them as opaque 16-byte blobs for matching — readers comparing
//! against canonical strings need to convert (see `match_guid`).

use crate::error::{Error, Result};
use crate::probe::{Partition, PartitionKind};
use crate::BlockRead;

pub const SIGNATURE: &[u8; 8] = b"EFI PART";
/// Re-exported so `gpt::SECTOR_SIZE` keeps working; the definition
/// is [`crate::SECTOR_SIZE`].
pub use crate::SECTOR_SIZE;

/// Byte offsets within the 92-byte GPT header.
///
/// The header was transcribed by hand in `gpt::parse_header` and again
/// in `gpt_write::build_header` — two descriptions of one layout,
/// agreeing only because both were written from the same table on the
/// same afternoon. A wrong offset in either produces a header the other
/// half of this crate cannot read.
pub mod header_offsets {
    /// `Signature` — `EFI PART`.
    pub const SIGNATURE: usize = 0;
    /// `Revision`.
    pub const REVISION: usize = 8;
    /// `HeaderSize`.
    pub const HEADER_SIZE: usize = 12;
    /// `HeaderCRC32`, computed with these four bytes zeroed.
    pub const HEADER_CRC32: usize = 16;
    /// `MyLBA` — the LBA this header itself sits at.
    pub const MY_LBA: usize = 24;
    /// `AlternateLBA` — where the other copy sits.
    pub const ALTERNATE_LBA: usize = 32;
    /// `FirstUsableLBA`.
    pub const FIRST_USABLE_LBA: usize = 40;
    /// `LastUsableLBA`.
    pub const LAST_USABLE_LBA: usize = 48;
    /// `DiskGUID`.
    pub const DISK_GUID: usize = 56;
    /// `PartitionEntryLBA`.
    pub const PARTITION_ENTRY_LBA: usize = 72;
    /// `NumberOfPartitionEntries`.
    pub const NUM_PARTITION_ENTRIES: usize = 80;
    /// `SizeOfPartitionEntry`.
    pub const PARTITION_ENTRY_SIZE: usize = 84;
    /// `PartitionEntryArrayCRC32`.
    pub const PARTITION_ENTRY_ARRAY_CRC32: usize = 88;
}

/// Named bits inside the 64-bit partition attributes field (entry offset
/// +48). Bits 0..47 are defined by the partition-table spec; bits 48..63 are
/// reserved for "partition-type-specific" use and are commonly hijacked by
/// Microsoft (read-only / shadow / hidden / no-automount on basic-data
/// partitions). Callers can `(attributes & attr::LEGACY_BIOS_BOOTABLE) != 0`
/// to test a single bit.
pub mod attr {
    /// Bit 0: "Required Partition" — system depends on it; OS installers
    /// should not delete or move it.
    pub const REQUIRED_PARTITION: u64 = 1 << 0;
    /// Bit 1: "No Block IO Protocol" — UEFI firmware should not expose a
    /// block I/O protocol on this partition. Rarely set.
    pub const NO_BLOCK_IO_PROTOCOL: u64 = 1 << 1;
    /// Bit 2: "Legacy BIOS Bootable" — the partition contains a legacy
    /// (non-UEFI) bootloader and is meant to be booted on BIOS systems.
    /// Distro install ISOs that boot on both BIOS and UEFI typically set
    /// this on the BIOS-boot or root partition in addition to providing
    /// an ESP.
    pub const LEGACY_BIOS_BOOTABLE: u64 = 1 << 2;
    /// Bit 60: Microsoft "Read-Only" attribute on basic-data partitions.
    pub const MS_READ_ONLY: u64 = 1 << 60;
    /// Bit 61: Microsoft "Shadow Copy" attribute.
    pub const MS_SHADOW_COPY: u64 = 1 << 61;
    /// Bit 62: Microsoft "Hidden" attribute.
    pub const MS_HIDDEN: u64 = 1 << 62;
    /// Bit 63: Microsoft "No Drive Letter / No Automount" attribute.
    pub const MS_NO_AUTOMOUNT: u64 = 1 << 63;
}

/// Type GUIDs for partitions we can match (binary form, mixed-endian as on
/// disk). Useful for callers that want to filter without re-deriving them.
pub mod type_guids {
    /// 0x00000000-0000-0000-0000-000000000000 — unused entry.
    pub const UNUSED: [u8; 16] = [0u8; 16];

    /// EFI System Partition (FAT32, "C12A7328-F81F-11D2-BA4B-00A0C93EC93B").
    pub const EFI_SYSTEM: [u8; 16] = [
        0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9,
        0x3B,
    ];

    /// Microsoft basic data ("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"); also
    /// what most Windows installs use for NTFS/exFAT data partitions.
    pub const MICROSOFT_BASIC_DATA: [u8; 16] = [
        0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99,
        0xC7,
    ];

    /// Linux filesystem ("0FC63DAF-8483-4772-8E79-3D69D8477DE4").
    pub const LINUX_FILESYSTEM: [u8; 16] = [
        0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D,
        0xE4,
    ];

    /// Linux swap ("0657FD6D-A4AB-43C4-84E5-0933C84B4F4F").
    pub const LINUX_SWAP: [u8; 16] = [
        0x6D, 0xFD, 0x57, 0x06, 0xAB, 0xA4, 0xC4, 0x43, 0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F,
        0x4F,
    ];

    /// Apple HFS+ ("48465300-0000-11AA-AA11-00306543ECAC").
    pub const APPLE_HFS_PLUS: [u8; 16] = [
        0x00, 0x53, 0x46, 0x48, 0x00, 0x00, 0xAA, 0x11, 0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC,
        0xAC,
    ];

    /// Apple APFS ("7C3457EF-0000-11AA-AA11-00306543ECAC").
    pub const APPLE_APFS: [u8; 16] = [
        0xEF, 0x57, 0x34, 0x7C, 0x00, 0x00, 0xAA, 0x11, 0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC,
        0xAC,
    ];
}

/// Decoded GPT header fields. Used internally by both the primary and backup
/// parsers, and surfaced through [`Header`] so callers comparing the two
/// halves can inspect them.
#[derive(Debug, Clone)]
pub struct Header {
    pub my_lba: u64,
    pub alternate_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub disk_guid: [u8; 16],
    pub partition_entry_lba: u64,
    pub num_partition_entries: u32,
    pub partition_entry_size: u32,
    pub partition_entry_array_crc32: u32,
    pub header_crc32: u32,
    pub header_size: u32,
}

/// The rules a GPT entry has to satisfy, named so that a caller can be
/// told which one an entry breaks.
///
/// These existed once, in the writer. `gpt_write` refused a partition
/// starting before `first_usable_lba` or ending past `last_usable_lba`,
/// and refused an overlapping pair; the reader applied neither, so the
/// two disagreed about what a legal table is. `probe` handed back
/// entries that `commit` then refused, and a user could not edit such a
/// disk at all without first working out which entries were illegal —
/// with nothing telling them which. Measured on a table holding an
/// overlapping pair and an entry on LBA 1..33:
///
/// ```text
/// remove the overlapping entry  -> commit Err("partition starts before first usable LBA")
/// remove the on-top-of-GPT one  -> commit Err("partitions overlap")
/// remove both                   -> commit Ok(())
/// ```
///
/// So the rules live here now and both sides call them.
pub mod entry_issue {
    /// The entry breaks none of the rules.
    pub const NONE: u32 = 0;
    /// Starts before the header's `first_usable_lba` — inside the
    /// protective MBR, the header itself, or the entry array.
    pub const BEFORE_FIRST_USABLE: u32 = 1 << 0;
    /// Ends past the header's `last_usable_lba` — inside the backup
    /// entry array or the backup header.
    pub const PAST_LAST_USABLE: u32 = 1 << 1;
    /// Shares at least one sector with another entry in the same table.
    pub const OVERLAPS_ANOTHER: u32 = 1 << 2;

    /// Every bit this crate defines. A bit outside this is not one of
    /// ours.
    pub const ALL: u32 = BEFORE_FIRST_USABLE | PAST_LAST_USABLE | OVERLAPS_ANOTHER;

    /// The rules `issues` breaks, in words, for an error message a
    /// person reads.
    pub fn describe(issues: u32) -> String {
        let mut parts = Vec::new();
        if issues & BEFORE_FIRST_USABLE != 0 {
            parts.push("starts before the first usable LBA");
        }
        if issues & PAST_LAST_USABLE != 0 {
            parts.push("ends past the last usable LBA");
        }
        if issues & OVERLAPS_ANOTHER != 0 {
            parts.push("overlaps another partition");
        }
        if parts.is_empty() {
            return "no issues".to_string();
        }
        parts.join(", ")
    }
}

/// Which of the header's usable-range rules the inclusive LBA span
/// `[start_lba, end_lba]` breaks.
pub fn range_issues(start_lba: u64, end_lba: u64, first_usable: u64, last_usable: u64) -> u32 {
    let mut issues = entry_issue::NONE;
    if start_lba < first_usable {
        issues |= entry_issue::BEFORE_FIRST_USABLE;
    }
    // The start needs its own upper bound, not only the end's: a start
    // far enough out makes the end wrap to something small, which the
    // end test would then wave through.
    if start_lba > last_usable || end_lba > last_usable {
        issues |= entry_issue::PAST_LAST_USABLE;
    }
    issues
}

/// Which entries in `spans` share a sector with another entry.
///
/// `spans` are inclusive `(first_lba, last_lba)` pairs in the order the
/// entries appear in the table; the returned vector is in the same
/// order. One sort of the indices, one linear pass.
pub fn mark_overlaps(spans: &[(u64, u64)]) -> Vec<bool> {
    let mut flags = vec![false; spans.len()];
    let mut order: Vec<usize> = (0..spans.len()).collect();
    order.sort_by_key(|&i| spans[i].0);
    // One pass, carrying the highest end seen so far.
    //
    // A sorted-neighbour comparison is not enough on its own — a short
    // entry entirely swallowed by a long one two places back is
    // invisible to it — and this pass subsumes it, so there used to be
    // two where one does the work.
    //
    // Why it subsumes it: take a neighbouring pair `(a, b)` in sorted
    // order with `spans[b].0 <= spans[a].1`. By the time `b` is
    // reached, `highest_end` covers every entry before it, so
    // `end >= spans[a].1 >= spans[b].0` and `b` is flagged. Its partner
    // is flagged too, though it may be some earlier `j` rather than
    // `a`: if `j` is not `a` then `j` precedes `a` with
    // `spans[j].1 >= spans[a].1`, so `spans[a].0 <= spans[j].1` and `a`
    // was already flagged when `a` itself came round. No input reaches
    // a verdict here that the neighbour pass would have reached first.
    let mut highest_end: Option<(usize, u64)> = None;
    for &i in &order {
        if let Some((j, end)) = highest_end {
            if spans[i].0 <= end {
                flags[i] = true;
                flags[j] = true;
            }
        }
        match highest_end {
            Some((_, end)) if end >= spans[i].1 => {}
            _ => highest_end = Some((i, spans[i].1)),
        }
    }
    flags
}

/// Parse and CRC-validate a GPT header sector. Does not touch the entry array.
pub fn parse_header(sector: &[u8; crate::SECTOR_SIZE_USIZE]) -> Result<Header> {
    if &sector[header_offsets::SIGNATURE..header_offsets::SIGNATURE + 8] != SIGNATURE {
        return Err(Error::GptCorrupt("missing EFI PART signature"));
    }
    let header_size = u32::from_le_bytes(sector[12..16].try_into().unwrap());
    if !(92..=512).contains(&header_size) {
        return Err(Error::GptCorrupt("header_size out of range"));
    }

    let stored_header_crc = u32::from_le_bytes(
        sector[header_offsets::HEADER_CRC32..header_offsets::HEADER_CRC32 + 4]
            .try_into()
            .unwrap(),
    );
    let mut header_for_crc = [0u8; crate::SECTOR_SIZE_USIZE];
    header_for_crc[..header_size as usize].copy_from_slice(&sector[..header_size as usize]);
    header_for_crc[header_offsets::HEADER_CRC32..header_offsets::HEADER_CRC32 + 4].fill(0);
    let computed_header_crc = crc32fast::hash(&header_for_crc[..header_size as usize]);
    if computed_header_crc != stored_header_crc {
        return Err(Error::GptHeaderCrc);
    }

    let my_lba = u64::from_le_bytes(
        sector[header_offsets::MY_LBA..header_offsets::MY_LBA + 8]
            .try_into()
            .unwrap(),
    );
    let alternate_lba = u64::from_le_bytes(
        sector[header_offsets::ALTERNATE_LBA..header_offsets::ALTERNATE_LBA + 8]
            .try_into()
            .unwrap(),
    );
    let first_usable_lba = u64::from_le_bytes(
        sector[header_offsets::FIRST_USABLE_LBA..header_offsets::FIRST_USABLE_LBA + 8]
            .try_into()
            .unwrap(),
    );
    let last_usable_lba = u64::from_le_bytes(sector[48..56].try_into().unwrap());
    let disk_guid: [u8; 16] = sector[56..72].try_into().unwrap();
    let partition_entry_lba = u64::from_le_bytes(
        sector[header_offsets::PARTITION_ENTRY_LBA..header_offsets::PARTITION_ENTRY_LBA + 8]
            .try_into()
            .unwrap(),
    );
    let num_partition_entries = u32::from_le_bytes(
        sector[header_offsets::NUM_PARTITION_ENTRIES..header_offsets::NUM_PARTITION_ENTRIES + 4]
            .try_into()
            .unwrap(),
    );
    let partition_entry_size = u32::from_le_bytes(
        sector[header_offsets::PARTITION_ENTRY_SIZE..header_offsets::PARTITION_ENTRY_SIZE + 4]
            .try_into()
            .unwrap(),
    );
    let partition_entry_array_crc32 = u32::from_le_bytes(
        sector[header_offsets::PARTITION_ENTRY_ARRAY_CRC32
            ..header_offsets::PARTITION_ENTRY_ARRAY_CRC32 + 4]
            .try_into()
            .unwrap(),
    );

    if !(128..=4096).contains(&partition_entry_size) {
        return Err(Error::GptCorrupt("partition_entry_size out of range"));
    }
    if num_partition_entries > 4096 {
        return Err(Error::GptCorrupt("num_partition_entries > 4096"));
    }

    Ok(Header {
        my_lba,
        alternate_lba,
        first_usable_lba,
        last_usable_lba,
        disk_guid,
        partition_entry_lba,
        num_partition_entries,
        partition_entry_size,
        partition_entry_array_crc32,
        header_crc32: stored_header_crc,
        header_size,
    })
}

fn parse_entry_array(dev: &dyn BlockRead, header: &Header) -> Result<(Vec<Partition>, Vec<u8>)> {
    let total_array_bytes =
        (header.num_partition_entries as u64) * (header.partition_entry_size as u64);
    // Checked, for the same reason `starting_lba` below is: the LBA
    // comes straight off the disk, and the header CRC is a checksum
    // rather than a signature, so anyone who can set the field can
    // restamp the CRC over it. A random header reaches this on the
    // first try.
    let array_offset =
        header
            .partition_entry_lba
            .checked_mul(SECTOR_SIZE)
            .ok_or(Error::GptCorrupt(
                "partition_entry_lba overflows a byte offset",
            ))?;
    // The array cannot be inside a device that does not reach it. This
    // is also what keeps the allocation above honest: the size fields
    // are bounded (4096 entries of at most 4096 bytes), but 16 MiB per
    // probe of a 4 KiB device is still work nobody asked for.
    let array_end = array_offset
        .checked_add(total_array_bytes)
        .ok_or(Error::GptCorrupt("partition entry array overflows"))?;
    if array_end > dev.size_bytes() {
        return Err(Error::GptCorrupt(
            "partition entry array reaches past the end of the device",
        ));
    }
    let mut array = vec![0u8; total_array_bytes as usize];
    dev.read_at(array_offset, &mut array)?;

    let computed_entries_crc = crc32fast::hash(&array);
    if computed_entries_crc != header.partition_entry_array_crc32 {
        return Err(Error::GptEntriesCrc);
    }

    let entry_size = header.partition_entry_size as usize;
    let mut out = Vec::new();
    let mut spans: Vec<(u64, u64)> = Vec::new();
    for i in 0..header.num_partition_entries as usize {
        let off = i * entry_size;
        let type_guid: [u8; 16] = array[off..off + 16].try_into().unwrap();
        if type_guid == type_guids::UNUSED {
            continue;
        }
        let unique_guid: [u8; 16] = array[off + 16..off + 32].try_into().unwrap();
        let start_lba = u64::from_le_bytes(array[off + 32..off + 40].try_into().unwrap());
        let end_lba = u64::from_le_bytes(array[off + 40..off + 48].try_into().unwrap());
        if end_lba < start_lba {
            return Err(Error::GptCorrupt("ending_lba < starting_lba"));
        }
        let attributes = u64::from_le_bytes(array[off + 48..off + 56].try_into().unwrap());

        // Checked. Both LBAs come straight off the disk and the only
        // guard above is their relative ordering, so either
        // multiplication can overflow a u64 — a panic in debug, a silent
        // wrap in release, which is the worse of the two: a wrapped
        // `start` names a byte offset the caller then reads from.
        let start = start_lba
            .checked_mul(SECTOR_SIZE)
            .ok_or(Error::GptCorrupt("starting_lba overflows a byte offset"))?;
        let sectors = end_lba
            .checked_sub(start_lba)
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::GptCorrupt("partition sector count overflows"))?;
        let length = sectors
            .checked_mul(SECTOR_SIZE)
            .ok_or(Error::GptCorrupt("partition length overflows a byte count"))?;

        let name_bytes = &array[off + 56..off + 128];
        let label = parse_utf16_label(name_bytes);

        out.push(Partition {
            start,
            length,
            kind: PartitionKind::Gpt {
                type_guid,
                attributes,
            },
            label,
            uuid: Some(unique_guid),
            slot: Some(i as u32),
            // Filled in below, once every entry has been read: the
            // overlap rule is about the set, not the entry.
            issues: entry_issue::NONE,
        });
        spans.push((start_lba, end_lba));
    }

    // The header's own usable range, and the entries against each other.
    //
    // Reported rather than refused. Refusing the whole table would make
    // a damaged disk unreadable as well as uneditable, which is the
    // opposite of what somebody looking at one needs; per-entry flags
    // keep `probe` total and let a caller say which entry is wrong and
    // about what. What stops a caller acting on one unknowingly is
    // `partitions_open_slice`, which refuses to hand out a slice for an
    // entry with issues.
    for (p, span) in out.iter_mut().zip(&spans) {
        p.issues = range_issues(
            span.0,
            span.1,
            header.first_usable_lba,
            header.last_usable_lba,
        );
    }
    for (p, overlaps) in out.iter_mut().zip(mark_overlaps(&spans)) {
        if overlaps {
            p.issues |= entry_issue::OVERLAPS_ANOTHER;
        }
    }

    Ok((out, array))
}

/// Parse the GPT given the LBA-1 sector and a device for fetching the entry
/// array. Validates header CRC and entry-array CRC.
pub fn parse(dev: &dyn BlockRead, lba1: &[u8; crate::SECTOR_SIZE_USIZE]) -> Result<Vec<Partition>> {
    let header = parse_header(lba1)?;
    let (parts, _) = parse_entry_array(dev, &header)?;
    Ok(parts)
}

/// Outcome of validating the backup GPT header against the primary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupStatus {
    /// Backup header parsed, CRC-validated, and reports an identical
    /// partition list to the primary (after sorting by `starting_lba`).
    Ok,
    /// Backup header is missing, unreadable, or fails its own CRC. The reason
    /// string is short and stable. Many real-world disks have stale or zero
    /// backup tables, so the probe path treats this as advisory rather than
    /// fatal.
    Mismatch(&'static str),
}

/// Parse the GPT backup header (last LBA) and return the partition list it
/// describes. The backup entry array sits in the 32 sectors immediately
/// preceding the backup header. Per the partition-table spec, the backup
/// header mirrors the primary with `my_lba` and `alternate_lba` swapped.
///
/// Returns `Err` only on hard parse failures (bad signature, CRC fail,
/// out-of-range fields). Use [`validate_backup`] for a friendlier shape that
/// reports a primary/backup mismatch as a status enum instead.
pub fn parse_backup(dev: &dyn BlockRead) -> Result<Vec<Partition>> {
    let total = dev.size_bytes();
    if total < 2 * SECTOR_SIZE {
        return Err(Error::GptCorrupt("device too small for GPT backup"));
    }
    let last_lba = total / SECTOR_SIZE - 1;
    let mut sector = [0u8; crate::SECTOR_SIZE_USIZE];
    dev.read_at(last_lba * SECTOR_SIZE, &mut sector)?;
    let header = parse_header(&sector)?;
    if header.my_lba != last_lba {
        return Err(Error::GptCorrupt("backup my_lba != last LBA"));
    }
    let (parts, _) = parse_entry_array(dev, &header)?;
    Ok(parts)
}

/// Validate the backup against a list of primary partitions. Returns
/// [`BackupStatus::Ok`] when every primary entry has a matching backup entry
/// (same UUID, type GUID, and byte range), and [`BackupStatus::Mismatch`]
/// otherwise. A read or CRC failure becomes a `Mismatch` rather than an
/// error, because a stale backup is the most common reason to see one.
pub fn validate_backup(dev: &dyn BlockRead, primary: &[Partition]) -> BackupStatus {
    let backup = match parse_backup(dev) {
        Ok(b) => b,
        Err(Error::GptCorrupt(_)) => return BackupStatus::Mismatch("backup header corrupt"),
        Err(Error::GptHeaderCrc) => return BackupStatus::Mismatch("backup header CRC"),
        Err(Error::GptEntriesCrc) => return BackupStatus::Mismatch("backup entries CRC"),
        Err(_) => return BackupStatus::Mismatch("backup unreadable"),
    };
    if backup.len() != primary.len() {
        return BackupStatus::Mismatch("partition count differs");
    }
    // Sort both by start so insertion order doesn't matter.
    let mut a = primary.to_vec();
    let mut b = backup;
    a.sort_by_key(|p| p.start);
    b.sort_by_key(|p| p.start);
    for (pa, pb) in a.iter().zip(b.iter()) {
        if pa.start != pb.start || pa.length != pb.length {
            return BackupStatus::Mismatch("partition range differs");
        }
        if pa.uuid != pb.uuid {
            return BackupStatus::Mismatch("partition uuid differs");
        }
        if pa.kind != pb.kind {
            return BackupStatus::Mismatch("partition type differs");
        }
    }
    BackupStatus::Ok
}

fn parse_utf16_label(bytes: &[u8]) -> Option<String> {
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for c in bytes.chunks_exact(2) {
        let u = u16::from_le_bytes([c[0], c[1]]);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    if units.is_empty() {
        return None;
    }
    // Lossy, deliberately.
    //
    // A label is display text, and the only thing that can be wrong with
    // it here is an unpaired surrogate — which is what a writer that cut
    // the field at 36 code units without regard for surrogate pairs
    // leaves behind, including this crate's own writer until recently.
    // Decoding strictly and dropping the result on failure answered "no
    // label" for a name that is almost entirely readable, and said
    // nothing about why. One replacement character in the last position
    // tells a user more than an empty name does, and nothing computes on
    // a partition label.
    Some(String::from_utf16_lossy(&units))
}

#[cfg(test)]
mod rule_tests {
    /// `mark_overlaps` agrees with the definition of overlapping, on
    /// every span set of three inside a small coordinate space.
    ///
    /// The function used to make two passes, and the second subsumed
    /// the first — the argument for that is in the comment on the
    /// function. An argument is worth having and is not evidence, and
    /// "the suite stayed green" is evidence about the tests rather than
    /// about the function.
    ///
    /// So this compares the pass that remains against the definition
    /// itself: `i` overlaps something iff some other `j` shares a byte
    /// with it. Ten spans over four coordinates, taken three at a time,
    /// is a thousand cases and covers the shapes the passes disagreed
    /// about — touching at a boundary, nesting, and one entry swallowed
    /// by another two places back in sorted order.
    ///
    /// It also outlives the deletion: it is what a future edit to the
    /// remaining pass is measured against.
    #[test]
    fn overlap_marking_agrees_with_the_definition_on_every_small_case() {
        let spans: Vec<(u64, u64)> = (0..4u64)
            .flat_map(|s| (s..4u64).map(move |e| (s, e)))
            .collect();
        assert_eq!(spans.len(), 10, "the coordinate space changed");

        let mut checked = 0usize;
        let mut with_an_overlap = 0usize;
        for &a in &spans {
            for &b in &spans {
                for &c in &spans {
                    let set = [a, b, c];
                    let got = mark_overlaps(&set);
                    let want: Vec<bool> = (0..set.len())
                        .map(|i| {
                            (0..set.len())
                                .any(|j| j != i && set[i].0 <= set[j].1 && set[j].0 <= set[i].1)
                        })
                        .collect();
                    assert_eq!(got, want, "spans {set:?}");
                    checked += 1;
                    if want.iter().any(|&f| f) {
                        with_an_overlap += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 1000);
        assert!(
            with_an_overlap > 0 && with_an_overlap < checked,
            "the case space is degenerate: {with_an_overlap} of {checked} overlap"
        );
    }

    /// The case the deleted pass could not see, kept as a case with a
    /// name rather than only as one of a thousand.
    ///
    /// A short entry entirely swallowed by a long one two places back
    /// is invisible to a sorted-neighbour comparison, which is why the
    /// second pass existed. It is the first pass that went.
    #[test]
    fn an_entry_swallowed_by_one_two_places_back_is_marked() {
        // Sorted by start: (0, 100), (10, 20), (30, 40).
        // (30, 40) neighbours (10, 20), which it does not touch, and
        // sits inside (0, 100), which it does.
        let flags = mark_overlaps(&[(0, 100), (10, 20), (30, 40)]);
        assert_eq!(flags, vec![true, true, true]);
    }

    use super::{entry_issue, mark_overlaps, range_issues};

    /// The usable-range rule, at both edges.
    ///
    /// The integration fixtures reach the outside cases; a bound is only
    /// pinned by the last value it accepts and the first it refuses, and
    /// those are here where they can be stated without building a disk
    /// around them.
    #[test]
    fn the_usable_range_is_inclusive_at_both_ends() {
        // Exactly on each edge: legal.
        assert_eq!(range_issues(34, 2014, 34, 2014), entry_issue::NONE);
        // One sector outside each edge: not.
        assert_eq!(
            range_issues(33, 2014, 34, 2014),
            entry_issue::BEFORE_FIRST_USABLE
        );
        assert_eq!(
            range_issues(34, 2015, 34, 2014),
            entry_issue::PAST_LAST_USABLE
        );
        // Both at once.
        assert_eq!(
            range_issues(33, 2015, 34, 2014),
            entry_issue::BEFORE_FIRST_USABLE | entry_issue::PAST_LAST_USABLE
        );
    }

    /// The start is bounded above as well as below, and this is the only
    /// test that says so.
    ///
    /// Both of this function's callers establish `end >= start` before
    /// they get here — the reader refuses `ending_lba < starting_lba`
    /// outright, and the writer's length is a non-zero multiple of a
    /// sector — so a start past the last usable LBA always drags its end
    /// past it too, and no fixture can isolate this clause. It is kept
    /// because the function's contract is about a span, not about what
    /// its callers happen to have checked first: a caller that has not
    /// established the ordering, or a `sector_span` whose arithmetic
    /// wrapped, hands over a span whose end is small and whose start is
    /// absurd, and the end test alone waves it through.
    #[test]
    fn a_start_past_the_last_usable_lba_is_reported_even_when_the_end_is_not() {
        assert_eq!(
            range_issues(9_000, 10, 34, 2014),
            entry_issue::PAST_LAST_USABLE,
            "the end is inside the disk; the start is not"
        );
    }

    /// Overlap is about sharing a sector, so touching by one sector
    /// counts and abutting does not.
    #[test]
    fn overlap_is_bounded_at_the_shared_sector() {
        // Share exactly one sector.
        assert_eq!(mark_overlaps(&[(100, 200), (200, 300)]), vec![true, true]);
        // Abut: the normal shape of a partitioned disk.
        assert_eq!(mark_overlaps(&[(100, 200), (201, 300)]), vec![false, false]);
        // Nothing at all.
        assert_eq!(
            mark_overlaps(&[(100, 200), (900, 1000)]),
            vec![false, false]
        );
    }

    /// An entry wholly inside another is an overlap even when the two
    /// are not neighbours once sorted by start.
    ///
    /// Sorted, these are X(100..10000), Y(200..300), Z(9000..9100). The
    /// neighbour pairs are (X, Y) — overlapping — and (Y, Z), which do
    /// not overlap, since 9000 is past 300. Z is nonetheless wholly
    /// inside X. A single-pass sorted-neighbour scan reports
    /// `[true, true, false]` and calls the nested entry clean, which is
    /// why the second pass carries the highest end seen so far rather
    /// than only the previous one.
    #[test]
    fn an_entry_nested_inside_a_longer_one_is_an_overlap() {
        assert_eq!(
            mark_overlaps(&[(100, 10_000), (200, 300), (9_000, 9_100)]),
            vec![true, true, true]
        );
    }

    /// Order in the table does not change the answer.
    ///
    /// `mark_overlaps` sorts indices rather than spans, so the returned
    /// flags are in the caller's order. Reversing the input must reverse
    /// the output and nothing else.
    #[test]
    fn the_answer_does_not_depend_on_the_order_of_the_entries() {
        assert_eq!(
            mark_overlaps(&[(9_000, 9_100), (200, 300), (100, 10_000)]),
            vec![true, true, true]
        );
        assert_eq!(mark_overlaps(&[(201, 300), (100, 200)]), vec![false, false]);
    }

    /// A table with nothing in it, and a table with one entry, have no
    /// overlaps — the windows(2) pass has no pairs to look at.
    #[test]
    fn a_table_too_small_to_have_a_pair_has_no_overlaps() {
        assert_eq!(mark_overlaps(&[]), Vec::<bool>::new());
        assert_eq!(mark_overlaps(&[(100, 200)]), vec![false]);
    }
}
