//! Top-level probe: try GPT first, fall back to MBR. Logical (extended-MBR)
//! chains are not walked yet — the four primary entries are reported as-is.

use crate::error::{Error, Result};
use crate::gpt;
use crate::mbr;
use crate::BlockRead;

/// Which on-disk partition table produced a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableKind {
    Gpt,
    Mbr,
}

/// One partition. `start`/`length` are byte values relative to the start of
/// the whole device.
#[derive(Debug, Clone)]
pub struct Partition {
    pub start: u64,
    pub length: u64,
    pub kind: PartitionKind,
    pub label: Option<String>,
    pub uuid: Option<[u8; 16]>,
}

/// The on-disk type-tag for the partition. For GPT this is the type GUID +
/// the 64-bit attributes field; for MBR it's the one-byte type code + the
/// active/boot flag. `Whole` is reserved for the (future) "no partition
/// table" probe result.
///
/// Callers that only need a "did the firmware mark this as bootable?" answer
/// should use [`Partition::is_bootable`] instead of inspecting bits directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionKind {
    /// `type_guid`: 16-byte on-disk partition type GUID.
    /// `attributes`: 64-bit attributes field from entry offset +48. Bit 0 =
    ///   required partition, bit 2 = legacy BIOS bootable; see
    ///   [`crate::gpt::attr`] for the full set of named bits.
    Gpt {
        type_guid: [u8; 16],
        attributes: u64,
    },
    /// `type_byte`: MBR partition type code.
    /// `active`: bit 0x80 of the entry's status byte (offset +0). Marks the
    ///   "active" / "bootable" partition that legacy BIOS firmware boots.
    Mbr {
        type_byte: u8,
        active: bool,
    },
    Whole,
}

impl Partition {
    /// True when this partition is marked bootable in the on-disk table.
    ///
    /// - MBR: the active flag is set on the entry (legacy BIOS boots from
    ///   the active partition).
    /// - GPT: the type GUID is the EFI System Partition GUID *or* the
    ///   `LEGACY_BIOS_BOOTABLE` attribute bit is set.
    /// - Whole: never (no firmware-level bootability for table-less media).
    pub fn is_bootable(&self) -> bool {
        match self.kind {
            PartitionKind::Mbr { active, .. } => active,
            PartitionKind::Gpt {
                type_guid,
                attributes,
            } => {
                type_guid == crate::gpt::type_guids::EFI_SYSTEM
                    || (attributes & crate::gpt::attr::LEGACY_BIOS_BOOTABLE) != 0
            }
            PartitionKind::Whole => false,
        }
    }
}

/// Probe the device. Returns `(table_kind, partitions)` on success.
///
/// Order of attempts:
///  1. GPT primary header at LBA 1. If signature matches and CRC validates,
///     parse the entry array.
///  2. MBR at LBA 0. The protective-MBR case (single 0xEE entry) means GPT
///     was supposed to be there but its parse failed — propagate the GPT
///     error rather than reporting a single GPT-protective MBR partition.
pub fn probe(dev: &dyn BlockRead) -> Result<(TableKind, Vec<Partition>)> {
    // --- LBA 0 + LBA 1: enough to decide which table type ---
    let mut lba0 = [0u8; 512];
    let mut lba1 = [0u8; 512];
    dev.read_at(0, &mut lba0)?;
    if dev.size_bytes() >= 1024 {
        dev.read_at(512, &mut lba1)?;
    }

    let has_mbr_sig = lba0[510] == 0x55 && lba0[511] == 0xAA;
    let gpt_sig = &lba1[0..8];
    let has_gpt_sig = gpt_sig == gpt::SIGNATURE;

    if has_gpt_sig {
        let parts = gpt::parse(dev, &lba1)?;
        return Ok((TableKind::Gpt, parts));
    }

    if has_mbr_sig {
        // Detect protective-MBR (single 0xEE entry). Per the spec this means
        // the disk *should* be GPT — but GPT signature was missing, so the
        // table is broken. Surface that explicitly.
        if mbr::is_protective(&lba0) {
            return Err(Error::GptCorrupt(
                "protective MBR present but no GPT signature",
            ));
        }
        let parts = mbr::parse(&lba0)?;
        return Ok((TableKind::Mbr, parts));
    }

    Err(Error::NoPartitionTable)
}
