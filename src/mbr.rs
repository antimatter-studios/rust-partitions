//! MBR (Master Boot Record) partition table.
//!
//! Layout:
//!
//! ```text
//!   0..446    bootloader code
//!   446..510  4 partition entries × 16 bytes
//!   510..512  signature 0x55 0xAA
//! ```
//!
//! Each partition entry:
//!
//! ```text
//!   0       boot indicator
//!   1..4    starting CHS (legacy, ignored)
//!   4       partition type byte
//!   5..8    ending CHS (legacy, ignored)
//!   8..12   starting LBA  (u32 little-endian)
//!   12..16  number of sectors  (u32 little-endian)
//! ```
//!
//! Sector size is assumed to be 512 bytes. Real-world hardware with 4K
//! sectors stores LBAs in 512-byte units in the MBR for compatibility, so
//! this assumption holds.

use crate::error::{Error, Result};
use crate::probe::{Partition, PartitionKind};
use fs_core::BlockDevice;

use crate::MBR_LBA_MAX;
use crate::SECTOR_SIZE;

/// The MBR partition table's layout.
///
/// `446 + i * 16` appeared at three sites and the per-entry field
/// offsets at two more. One description instead of five, so a reader
/// checks the table once.
pub mod layout {
    /// First byte of the partition table — the bootloader code ends here.
    pub const TABLE_START: usize = 446;
    /// Bytes per entry.
    pub const ENTRY_SIZE: usize = 16;
    /// Entries in the table. MBR has exactly four; more needs an
    /// extended partition, which this crate does not write.
    pub const ENTRY_COUNT: usize = 4;

    /// Byte offset of entry `i` within the sector.
    pub const fn entry_at(i: usize) -> usize {
        TABLE_START + i * ENTRY_SIZE
    }

    /// `status` — 0x80 for the active/bootable entry.
    pub const STATUS: usize = 0;
    /// `partition type` byte.
    pub const TYPE_BYTE: usize = 4;
    /// `first LBA`, four bytes little-endian.
    pub const START_LBA: usize = 8;
    /// `sector count`, four bytes little-endian.
    pub const SECTOR_COUNT: usize = 12;
}

/// One 0xEE entry that spans the whole disk = protective MBR (GPT lives here).
///
/// The same byte as [`types::GPT_PROTECTIVE`], which is the spelling
/// callers are meant to match on; this one is what the module's own
/// `is_protective` uses. Kept as an alias rather than removed because
/// both are `pub` and published.
pub const TYPE_GPT_PROTECTIVE: u8 = types::GPT_PROTECTIVE;

/// Common MBR partition-type byte values, exported so callers can match.
pub mod types {
    pub const EMPTY: u8 = 0x00;
    pub const FAT12: u8 = 0x01;
    pub const FAT16_SMALL: u8 = 0x04;
    pub const EXTENDED_CHS: u8 = 0x05;
    pub const FAT16: u8 = 0x06;
    pub const NTFS_OR_EXFAT: u8 = 0x07;
    pub const FAT32_CHS: u8 = 0x0B;
    pub const FAT32_LBA: u8 = 0x0C;
    pub const FAT16_LBA: u8 = 0x0E;
    pub const EXTENDED_LBA: u8 = 0x0F;
    pub const LINUX_SWAP: u8 = 0x82;
    pub const LINUX: u8 = 0x83;
    pub const LINUX_LVM: u8 = 0x8E;
    pub const HFS_PLUS: u8 = 0xAF;
    pub const SOLARIS: u8 = 0xBF;
    pub const FREEBSD: u8 = 0xA5;
    pub const OPENBSD: u8 = 0xA6;
    pub const NETBSD: u8 = 0xA9;
    pub const GPT_PROTECTIVE: u8 = 0xEE;
    pub const EFI_SYSTEM: u8 = 0xEF;
}

/// True when the MBR is "protective" — exactly one non-empty entry of type
/// 0xEE. Real GPT lives at LBA 1 in this case.
pub fn is_protective(lba0: &[u8; crate::SECTOR_SIZE_USIZE]) -> bool {
    let mut nonempty = 0;
    let mut all_protective = true;
    for i in 0..layout::ENTRY_COUNT {
        let off = layout::entry_at(i);
        let type_byte = lba0[off + layout::TYPE_BYTE];
        if type_byte != types::EMPTY {
            nonempty += 1;
            if type_byte != TYPE_GPT_PROTECTIVE {
                all_protective = false;
            }
        }
    }
    nonempty == 1 && all_protective
}

/// MBR active/boot flag mask. The "status byte" at offset +0 of each entry
/// holds this in its high bit; legacy BIOS firmware boots from the partition
/// where this bit is set.
pub const STATUS_ACTIVE: u8 = 0x80;

/// Parse the four primary entries. Empty entries are skipped. Extended-LBA
/// entries are reported as-is — chain walking is not yet implemented.
pub fn parse(lba0: &[u8; crate::SECTOR_SIZE_USIZE]) -> Result<Vec<Partition>> {
    let mut out = Vec::new();
    for i in 0..layout::ENTRY_COUNT {
        let off = layout::entry_at(i);
        let status = lba0[off];
        let type_byte = lba0[off + layout::TYPE_BYTE];
        if type_byte == types::EMPTY {
            continue;
        }
        let starting_lba =
            u32::from_le_bytes([lba0[off + 8], lba0[off + 9], lba0[off + 10], lba0[off + 11]]);
        let sectors = u32::from_le_bytes([
            lba0[off + 12],
            lba0[off + 13],
            lba0[off + 14],
            lba0[off + 15],
        ]);
        if sectors == 0 {
            continue;
        }
        let start = (starting_lba as u64) * SECTOR_SIZE;
        let length = (sectors as u64) * SECTOR_SIZE;
        let active = (status & STATUS_ACTIVE) != 0;
        out.push(Partition {
            start,
            length,
            kind: PartitionKind::Mbr { type_byte, active },
            label: None,
            uuid: None,
        });
    }
    Ok(out)
}

/// Write a fresh MBR sector with up to four primary entries. The bootloader
/// region (offset 0..446) is zeroed — there is no provision for preserving
/// existing boot code. A future `with_boot_code` variant can carry caller-
/// supplied boot code through. TODO: add that variant when a caller wants
/// legacy BIOS boot support.
///
/// Validation:
/// - At most four partitions (extended chains aren't written here).
/// - Every partition must carry a [`PartitionKind::Mbr`] type byte.
/// - Every partition must be sector-aligned, non-empty, and fit inside the
///   32-bit LBA range MBR uses.
/// - Partitions must not overlap.
pub fn write_mbr(dev: &dyn BlockDevice, partitions: &[Partition]) -> Result<()> {
    if !dev.is_writable() {
        return Err(Error::Block(fs_core::Error::ReadOnly));
    }
    if partitions.len() > 4 {
        return Err(Error::Invalid("MBR supports at most 4 primary partitions"));
    }
    let total_bytes = dev.size_bytes();
    if total_bytes < SECTOR_SIZE {
        return Err(Error::DeviceTooSmall);
    }

    // Overlap check on a sorted-by-start view.
    let mut sorted: Vec<&Partition> = partitions.iter().collect();
    sorted.sort_by_key(|p| p.start);
    let mut prev_end_lba: Option<u64> = None;
    for p in &sorted {
        validate_mbr_partition(p, total_bytes)?;
        let (start_lba, end_lba) = p.sector_span()?;
        if let Some(prev) = prev_end_lba {
            if start_lba <= prev {
                return Err(Error::Invalid("partitions overlap"));
            }
        }
        prev_end_lba = Some(end_lba);
    }

    let mut sector = [0u8; crate::SECTOR_SIZE_USIZE];
    for (i, p) in partitions.iter().enumerate() {
        let off = layout::entry_at(i);
        let (type_byte, active) = match p.kind {
            PartitionKind::Mbr { type_byte, active } => (type_byte, active),
            _ => return Err(Error::Invalid("non-MBR partition kind in MBR write")),
        };
        let start_lba = (p.start / SECTOR_SIZE) as u32;
        let sectors = (p.length / SECTOR_SIZE) as u32;

        sector[off] = if active { STATUS_ACTIVE } else { 0x00 };
        // CHS first/last left as zeros — modern OSes ignore CHS once LBA is
        // present, and the legacy fields can't faithfully describe most
        // modern geometry anyway.
        sector[off + layout::TYPE_BYTE] = type_byte;
        sector[off + layout::START_LBA..off + layout::START_LBA + 4]
            .copy_from_slice(&start_lba.to_le_bytes());
        sector[off + layout::SECTOR_COUNT..off + layout::SECTOR_COUNT + 4]
            .copy_from_slice(&sectors.to_le_bytes());
    }
    sector[510] = 0x55;
    sector[511] = 0xAA;
    dev.write_at(0, &sector)?;
    Ok(())
}

fn validate_mbr_partition(p: &Partition, total_bytes: u64) -> Result<()> {
    if !matches!(p.kind, PartitionKind::Mbr { .. }) {
        return Err(Error::Invalid("non-MBR partition kind in MBR write"));
    }
    if p.length == 0 {
        return Err(Error::Invalid("partition has zero length"));
    }
    if !p.start.is_multiple_of(SECTOR_SIZE) || !p.length.is_multiple_of(SECTOR_SIZE) {
        return Err(Error::Invalid("partition not sector-aligned"));
    }
    // Derived through the checked helper rather than inline: the cap
    // below happens to reject everything that would wrap, which is a
    // coincidence of two unrelated bounds -- the cap is about the
    // 32-bit on-disk field, not about u64 arithmetic -- and not
    // something the next edit should have to know.
    let (start_lba, _) = p.sector_span()?;
    let sectors = p.length / SECTOR_SIZE;
    if start_lba > MBR_LBA_MAX || sectors > MBR_LBA_MAX {
        return Err(Error::Invalid("partition exceeds MBR 32-bit LBA range"));
    }
    // First sector reserved for the MBR itself.
    if start_lba < 1 {
        return Err(Error::Invalid("MBR partition cannot start at LBA 0"));
    }
    let end = p.start.checked_add(p.length).ok_or(Error::Invalid(
        "a partition's start and length overflow a u64",
    ))?;
    if end > total_bytes {
        return Err(Error::Invalid("partition extends past device end"));
    }
    Ok(())
}
