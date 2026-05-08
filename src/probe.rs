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

/// The on-disk type-tag for the partition. For GPT this is the type GUID; for
/// MBR it's the one-byte type code. `Whole` is reserved for the (future)
/// "no partition table" probe result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionKind {
    Gpt { type_guid: [u8; 16] },
    Mbr { type_byte: u8 },
    Whole,
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
