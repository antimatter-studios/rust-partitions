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
pub const SECTOR_SIZE: u64 = 512;

/// Type GUIDs for partitions we can match (binary form, mixed-endian as on
/// disk). Useful for callers that want to filter without re-deriving them.
pub mod type_guids {
    /// 0x00000000-0000-0000-0000-000000000000 — unused entry.
    pub const UNUSED: [u8; 16] = [0u8; 16];

    /// EFI System Partition (FAT32, "C12A7328-F81F-11D2-BA4B-00A0C93EC93B").
    pub const EFI_SYSTEM: [u8; 16] = [
        0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
        0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
    ];

    /// Microsoft basic data ("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"); also
    /// what most Windows installs use for NTFS/exFAT data partitions.
    pub const MICROSOFT_BASIC_DATA: [u8; 16] = [
        0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
        0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
    ];

    /// Linux filesystem ("0FC63DAF-8483-4772-8E79-3D69D8477DE4").
    pub const LINUX_FILESYSTEM: [u8; 16] = [
        0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
        0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
    ];

    /// Linux swap ("0657FD6D-A4AB-43C4-84E5-0933C84B4F4F").
    pub const LINUX_SWAP: [u8; 16] = [
        0x6D, 0xFD, 0x57, 0x06, 0xAB, 0xA4, 0xC4, 0x43,
        0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F, 0x4F,
    ];

    /// Apple HFS+ ("48465300-0000-11AA-AA11-00306543ECAC").
    pub const APPLE_HFS_PLUS: [u8; 16] = [
        0x00, 0x53, 0x46, 0x48, 0x00, 0x00, 0xAA, 0x11,
        0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC,
    ];

    /// Apple APFS ("7C3457EF-0000-11AA-AA11-00306543ECAC").
    pub const APPLE_APFS: [u8; 16] = [
        0xEF, 0x57, 0x34, 0x7C, 0x00, 0x00, 0xAA, 0x11,
        0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC,
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

/// Parse and CRC-validate a GPT header sector. Does not touch the entry array.
pub fn parse_header(sector: &[u8; 512]) -> Result<Header> {
    if &sector[0..8] != SIGNATURE {
        return Err(Error::GptCorrupt("missing EFI PART signature"));
    }
    let header_size = u32::from_le_bytes(sector[12..16].try_into().unwrap());
    if !(92..=512).contains(&header_size) {
        return Err(Error::GptCorrupt("header_size out of range"));
    }

    let stored_header_crc = u32::from_le_bytes(sector[16..20].try_into().unwrap());
    let mut header_for_crc = [0u8; 512];
    header_for_crc[..header_size as usize].copy_from_slice(&sector[..header_size as usize]);
    header_for_crc[16..20].fill(0);
    let computed_header_crc = crc32fast::hash(&header_for_crc[..header_size as usize]);
    if computed_header_crc != stored_header_crc {
        return Err(Error::GptHeaderCrc);
    }

    let my_lba = u64::from_le_bytes(sector[24..32].try_into().unwrap());
    let alternate_lba = u64::from_le_bytes(sector[32..40].try_into().unwrap());
    let first_usable_lba = u64::from_le_bytes(sector[40..48].try_into().unwrap());
    let last_usable_lba = u64::from_le_bytes(sector[48..56].try_into().unwrap());
    let disk_guid: [u8; 16] = sector[56..72].try_into().unwrap();
    let partition_entry_lba = u64::from_le_bytes(sector[72..80].try_into().unwrap());
    let num_partition_entries = u32::from_le_bytes(sector[80..84].try_into().unwrap());
    let partition_entry_size = u32::from_le_bytes(sector[84..88].try_into().unwrap());
    let partition_entry_array_crc32 = u32::from_le_bytes(sector[88..92].try_into().unwrap());

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

fn parse_entry_array(
    dev: &dyn BlockRead,
    header: &Header,
) -> Result<(Vec<Partition>, Vec<u8>)> {
    let total_array_bytes =
        (header.num_partition_entries as u64) * (header.partition_entry_size as u64);
    let mut array = vec![0u8; total_array_bytes as usize];
    dev.read_at(header.partition_entry_lba * SECTOR_SIZE, &mut array)?;

    let computed_entries_crc = crc32fast::hash(&array);
    if computed_entries_crc != header.partition_entry_array_crc32 {
        return Err(Error::GptEntriesCrc);
    }

    let entry_size = header.partition_entry_size as usize;
    let mut out = Vec::new();
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
        let start = start_lba * SECTOR_SIZE;
        let length = (end_lba - start_lba + 1) * SECTOR_SIZE;

        let name_bytes = &array[off + 56..off + 128];
        let label = parse_utf16_label(name_bytes);

        out.push(Partition {
            start,
            length,
            kind: PartitionKind::Gpt { type_guid },
            label,
            uuid: Some(unique_guid),
        });
    }
    Ok((out, array))
}

/// Parse the GPT given the LBA-1 sector and a device for fetching the entry
/// array. Validates header CRC and entry-array CRC.
pub fn parse(dev: &dyn BlockRead, lba1: &[u8; 512]) -> Result<Vec<Partition>> {
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
    let mut sector = [0u8; 512];
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
        None
    } else {
        String::from_utf16(&units).ok()
    }
}
