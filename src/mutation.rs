//! Partition-table mutation API.
//!
//! Builds an in-memory partition set from a probe (or from scratch), lets
//! callers add / remove / resize entries with 1 MiB alignment and a
//! first-fit free-space finder, and serialises the result on `commit`.
//!
//! The C ABI surface in [`crate::capi`] does not yet cover this module — the
//! current FFI handle the C side knows about is read-only. A follow-up pass
//! will add a writable handle. Keeping the C ABI frozen for this change
//! avoids reshuffling consumer integrations while the Rust API settles.

use crate::error::{Error, Result};
use crate::gpt::{self, type_guids};
use crate::mbr::{self, types as mbr_types};
use crate::probe::{Partition, PartitionKind, TableKind};
use fs_core::{BlockDevice, BlockRead};

/// Spec-mandated GPT slot count.
const GPT_FIRST_USABLE_LBA: u64 = 34;
const GPT_BACKUP_RESERVE_SECTORS: u64 = 33; // entry array (32) + backup header (1)
const SECTOR_SIZE: u64 = 512;
/// 1 MiB alignment in 512-byte sectors. Most partition-table editors use
/// this as the default and Windows / macOS treat it as a soft requirement.
const ALIGNMENT_SECTORS: u64 = 2048;
/// MBR LBAs are 32-bit. Cap any computed range at this.
const MBR_LBA_MAX: u64 = 0xFFFF_FFFF;

/// Cross-table-format identifier for "what kind of partition is this?". The
/// caller picks a logical role and the mutation API translates it to the
/// right on-disk encoding (GPT type GUID or MBR type byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionTypeId {
    EfiSystem,
    MicrosoftBasicData,
    LinuxFilesystem,
    LinuxSwap,
    AppleHfsPlus,
    AppleApfs,
    /// Escape hatch: a raw type GUID. MBR tables reject this with
    /// [`Error::Invalid`].
    GptCustom([u8; 16]),
    /// Escape hatch: a raw MBR type byte. GPT tables reject this with
    /// [`Error::Invalid`].
    MbrCustom(u8),
}

impl PartitionTypeId {
    fn to_gpt_guid(self) -> Result<[u8; 16]> {
        Ok(match self {
            PartitionTypeId::EfiSystem => type_guids::EFI_SYSTEM,
            PartitionTypeId::MicrosoftBasicData => type_guids::MICROSOFT_BASIC_DATA,
            PartitionTypeId::LinuxFilesystem => type_guids::LINUX_FILESYSTEM,
            PartitionTypeId::LinuxSwap => type_guids::LINUX_SWAP,
            PartitionTypeId::AppleHfsPlus => type_guids::APPLE_HFS_PLUS,
            PartitionTypeId::AppleApfs => type_guids::APPLE_APFS,
            PartitionTypeId::GptCustom(g) => g,
            PartitionTypeId::MbrCustom(_) => {
                return Err(Error::Invalid("MBR type byte used in GPT context"))
            }
        })
    }
    fn to_mbr_byte(self) -> Result<u8> {
        Ok(match self {
            PartitionTypeId::EfiSystem => mbr_types::EFI_SYSTEM,
            PartitionTypeId::MicrosoftBasicData => mbr_types::NTFS_OR_EXFAT,
            PartitionTypeId::LinuxFilesystem => mbr_types::LINUX,
            PartitionTypeId::LinuxSwap => mbr_types::LINUX_SWAP,
            PartitionTypeId::AppleHfsPlus => mbr_types::HFS_PLUS,
            // No legacy MBR encoding for APFS — callers should use GPT.
            PartitionTypeId::AppleApfs => {
                return Err(Error::Invalid("APFS has no MBR type byte; use GPT"));
            }
            PartitionTypeId::MbrCustom(b) => b,
            PartitionTypeId::GptCustom(_) => {
                return Err(Error::Invalid("GPT type GUID used in MBR context"))
            }
        })
    }
}

/// How callers identify a partition for `remove` / `resize`. Index is
/// always accepted; UUID is GPT-only.
#[derive(Debug, Clone, Copy)]
pub enum PartitionRef {
    Index(usize),
    Uuid([u8; 16]),
}

/// In-memory mutable partition set. All edits stay in this struct until
/// `commit` writes them back.
#[derive(Debug, Clone)]
pub struct PartitionSet {
    pub table_kind: TableKind,
    pub partitions: Vec<Partition>,
    pub disk_size: u64,
    /// Disk GUID for the GPT header. Ignored when `table_kind == Mbr`.
    pub disk_guid: [u8; 16],
}

impl PartitionSet {
    /// Probe the device and return its current partition set, ready for
    /// editing. The disk GUID for GPT is read from the on-disk header; for
    /// MBR it is left at all-zeros and unused.
    pub fn from_probe(dev: &dyn BlockRead) -> Result<Self> {
        let (table_kind, partitions) = crate::probe(dev)?;
        let disk_size = dev.size_bytes();
        let disk_guid = if table_kind == TableKind::Gpt {
            // Re-read LBA 1 to pull the disk GUID out.
            let mut sector = [0u8; 512];
            dev.read_at(SECTOR_SIZE, &mut sector)?;
            gpt::parse_header(&sector)?.disk_guid
        } else {
            [0u8; 16]
        };
        Ok(PartitionSet {
            table_kind,
            partitions,
            disk_size,
            disk_guid,
        })
    }

    /// Empty GPT table sized for `disk_size` bytes. Generates a v4 disk GUID.
    pub fn empty_gpt(disk_size: u64) -> Self {
        PartitionSet {
            table_kind: TableKind::Gpt,
            partitions: Vec::new(),
            disk_size,
            disk_guid: random_uuid(),
        }
    }

    /// Empty MBR table sized for `disk_size` bytes.
    pub fn empty_mbr(disk_size: u64) -> Self {
        PartitionSet {
            table_kind: TableKind::Mbr,
            partitions: Vec::new(),
            disk_size,
            disk_guid: [0u8; 16],
        }
    }

    /// Add a partition. `start_hint = None` triggers a first-fit search at
    /// 1 MiB alignment. A non-`None` hint that isn't already aligned is
    /// rounded up to the next 1 MiB boundary, and `length` is rounded up to
    /// the next sector if it isn't already a multiple of 512.
    ///
    /// Returns the index of the newly added partition.
    pub fn add(
        &mut self,
        start_hint: Option<u64>,
        length: u64,
        type_id: PartitionTypeId,
        label: Option<String>,
    ) -> Result<usize> {
        if length == 0 {
            return Err(Error::Invalid("zero length"));
        }
        if self.table_kind == TableKind::Mbr && self.partitions.len() >= 4 {
            return Err(Error::Invalid("MBR primary table is full (4 entries)"));
        }
        if self.table_kind == TableKind::Gpt && self.partitions.len() >= 128 {
            return Err(Error::Invalid("GPT canonical table is full (128 entries)"));
        }

        // Round length up to a sector multiple.
        let length_sectors = length.div_ceil(SECTOR_SIZE);
        // Round length up to alignment too — trailing tail bytes inside an
        // unaligned region are unreachable to most consumers, so it is
        // friendlier to grow than to leave a dangling stub.
        let length_sectors = align_up(length_sectors, ALIGNMENT_SECTORS);

        let (first_usable_lba, last_usable_lba) = self.usable_range();
        if first_usable_lba > last_usable_lba {
            return Err(Error::DeviceTooSmall);
        }

        let start_lba = match start_hint {
            Some(byte) => {
                let raw_sectors = byte / SECTOR_SIZE + if byte % SECTOR_SIZE != 0 { 1 } else { 0 };
                let aligned = align_up(raw_sectors.max(first_usable_lba), ALIGNMENT_SECTORS);
                if aligned < first_usable_lba {
                    return Err(Error::Invalid("hinted start before first usable LBA"));
                }
                aligned
            }
            None => self.find_free(length_sectors, first_usable_lba, last_usable_lba)?,
        };

        let end_lba = start_lba
            .checked_add(length_sectors - 1)
            .ok_or(Error::Invalid("partition end overflows"))?;
        if end_lba > last_usable_lba {
            return Err(Error::Invalid("partition extends past last usable LBA"));
        }
        if self.table_kind == TableKind::Mbr
            && (start_lba > MBR_LBA_MAX || length_sectors > MBR_LBA_MAX)
        {
            return Err(Error::Invalid("partition exceeds MBR 32-bit LBA range"));
        }

        // Overlap check against existing partitions.
        for p in &self.partitions {
            let p_start = p.start / SECTOR_SIZE;
            let p_end = (p.start + p.length) / SECTOR_SIZE - 1;
            if start_lba <= p_end && end_lba >= p_start {
                return Err(Error::Invalid("partition overlaps existing entry"));
            }
        }

        // New partitions default to non-bootable / no special attributes.
        // Callers that want to mark an active partition or set GPT
        // attribute bits should mutate the partition kind in-place after
        // the add() call.
        let kind = match self.table_kind {
            TableKind::Gpt => PartitionKind::Gpt {
                type_guid: type_id.to_gpt_guid()?,
                attributes: 0,
            },
            TableKind::Mbr => PartitionKind::Mbr {
                type_byte: type_id.to_mbr_byte()?,
                active: false,
            },
        };
        let uuid = if self.table_kind == TableKind::Gpt {
            Some(random_uuid())
        } else {
            None
        };

        let part = Partition {
            start: start_lba * SECTOR_SIZE,
            length: length_sectors * SECTOR_SIZE,
            kind,
            label,
            uuid,
        };
        let idx = self.partitions.len();
        self.partitions.push(part);
        Ok(idx)
    }

    /// Remove a partition. Returns [`Error::Invalid`] if the ref doesn't
    /// match anything.
    pub fn remove(&mut self, target: PartitionRef) -> Result<()> {
        let idx = self.resolve(target)?;
        self.partitions.remove(idx);
        Ok(())
    }

    /// Resize a partition. The new length is rounded up to a sector multiple
    /// and re-validated against the device bounds and other partitions.
    pub fn resize(&mut self, target: PartitionRef, new_length: u64) -> Result<()> {
        if new_length == 0 {
            return Err(Error::Invalid("zero length"));
        }
        let idx = self.resolve(target)?;
        let new_length_sectors = align_up(new_length.div_ceil(SECTOR_SIZE), ALIGNMENT_SECTORS);
        let (_, last_usable_lba) = self.usable_range();

        let start_lba = self.partitions[idx].start / SECTOR_SIZE;
        let new_end_lba = start_lba
            .checked_add(new_length_sectors - 1)
            .ok_or(Error::Invalid("partition end overflows"))?;
        if new_end_lba > last_usable_lba {
            return Err(Error::Invalid("resize extends past last usable LBA"));
        }
        if self.table_kind == TableKind::Mbr && new_length_sectors > MBR_LBA_MAX {
            return Err(Error::Invalid("resize exceeds MBR 32-bit LBA range"));
        }

        // Overlap check excluding self.
        for (j, p) in self.partitions.iter().enumerate() {
            if j == idx {
                continue;
            }
            let p_start = p.start / SECTOR_SIZE;
            let p_end = (p.start + p.length) / SECTOR_SIZE - 1;
            if start_lba <= p_end && new_end_lba >= p_start {
                return Err(Error::Invalid("resize would overlap another partition"));
            }
        }
        self.partitions[idx].length = new_length_sectors * SECTOR_SIZE;
        Ok(())
    }

    /// Serialise to disk. Dispatches to the GPT or MBR writer depending on
    /// `table_kind`, then flushes the device.
    pub fn commit(&self, dev: &dyn BlockDevice) -> Result<()> {
        match self.table_kind {
            TableKind::Gpt => {
                crate::gpt_write::write_gpt(dev, &self.partitions, self.disk_guid)?;
            }
            TableKind::Mbr => {
                mbr::write_mbr(dev, &self.partitions)?;
            }
        }
        dev.flush()?;
        Ok(())
    }

    // --- helpers -----------------------------------------------------------

    fn usable_range(&self) -> (u64, u64) {
        let total_sectors = self.disk_size / SECTOR_SIZE;
        match self.table_kind {
            TableKind::Gpt => {
                if total_sectors < GPT_FIRST_USABLE_LBA + GPT_BACKUP_RESERVE_SECTORS + 1 {
                    return (GPT_FIRST_USABLE_LBA, GPT_FIRST_USABLE_LBA - 1);
                }
                let last = total_sectors - 1 - GPT_BACKUP_RESERVE_SECTORS;
                (GPT_FIRST_USABLE_LBA, last)
            }
            TableKind::Mbr => {
                if total_sectors < 2 {
                    return (1, 0);
                }
                let last = (total_sectors - 1).min(MBR_LBA_MAX);
                (1, last)
            }
        }
    }

    fn resolve(&self, target: PartitionRef) -> Result<usize> {
        match target {
            PartitionRef::Index(i) => {
                if i >= self.partitions.len() {
                    return Err(Error::Invalid("index out of range"));
                }
                Ok(i)
            }
            PartitionRef::Uuid(u) => self
                .partitions
                .iter()
                .position(|p| p.uuid == Some(u))
                .ok_or(Error::Invalid("uuid not found")),
        }
    }

    /// First-fit free-space finder, walking partitions sorted by start LBA.
    fn find_free(&self, length_sectors: u64, first_usable: u64, last_usable: u64) -> Result<u64> {
        let mut sorted: Vec<&Partition> = self.partitions.iter().collect();
        sorted.sort_by_key(|p| p.start);

        let mut cursor = align_up(first_usable, ALIGNMENT_SECTORS);
        for p in &sorted {
            let p_start = p.start / SECTOR_SIZE;
            let p_end = (p.start + p.length) / SECTOR_SIZE - 1;
            if cursor + length_sectors - 1 < p_start {
                // Gap before this partition is big enough.
                if cursor + length_sectors - 1 <= last_usable {
                    return Ok(cursor);
                }
            }
            // Move cursor past this partition, re-aligned.
            cursor = align_up(p_end + 1, ALIGNMENT_SECTORS);
        }
        if cursor + length_sectors - 1 <= last_usable {
            Ok(cursor)
        } else {
            Err(Error::Invalid("no free space large enough"))
        }
    }
}

/// Round `value` up to the next multiple of `align`. `align` must be > 0.
fn align_up(value: u64, align: u64) -> u64 {
    debug_assert!(align > 0);
    let rem = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}

// ---------------------------------------------------------------------------
// Random UUID generator
// ---------------------------------------------------------------------------
//
// Mints RFC 4122 v4 (random) UUIDs without pulling in `uuid` or `rand`.
// Strategy:
//   1. Try `/dev/urandom` on Unix-like systems — every POSIX kernel exposes
//      it, and a single 16-byte read is unhindered by buffering or
//      locale.
//   2. Fall back to a small xorshift64 PRNG seeded from `SystemTime` and
//      `ProcessId`. This branch is only meant for non-Unix (Windows) and is
//      not cryptographically strong, but UUIDs only need to be unique
//      within a partition table, not unguessable.
//
// The version (high nibble of byte 7) and variant (high two bits of byte 8)
// are stamped per RFC 4122 §4.4.

pub(crate) fn random_uuid() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    if !fill_from_urandom(&mut bytes) {
        fill_from_prng(&mut bytes);
    }
    // Version 4 (random): high nibble of byte 7.
    bytes[7] = (bytes[7] & 0x0F) | 0x40;
    // Variant 10xxxxxx: high two bits of byte 8.
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    bytes
}

#[cfg(unix)]
fn fill_from_urandom(buf: &mut [u8]) -> bool {
    use std::io::Read;
    match std::fs::File::open("/dev/urandom") {
        Ok(mut f) => f.read_exact(buf).is_ok(),
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn fill_from_urandom(_buf: &mut [u8]) -> bool {
    false
}

fn fill_from_prng(buf: &mut [u8]) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15);
    let pid = std::process::id() as u64;
    let mut state = nanos.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(pid);
    if state == 0 {
        state = 0x9E37_79B9_7F4A_7C15;
    }
    for chunk in buf.chunks_mut(8) {
        // xorshift64
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let b = state.to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
}
