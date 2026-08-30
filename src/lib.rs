//! Partition-table probe (GPT/MBR) and filesystem-magic sniffer over any
//! random-access block source.
//!
//! See the crate-level [`README`](https://github.com/antimatter-studios/rust-partitions)
//! for design and scope.
//!
//! Block-device abstractions come from
//! [`fs_core`](https://github.com/antimatter-studios/rust-fs-core); this
//! crate re-exports the bits most consumers will use so callers can `use
//! partitions::BlockRead;` without an extra dependency line.

#![deny(unsafe_op_in_unsafe_fn)]

/// Bytes in a logical sector.
///
/// This crate reads and writes partition tables in 512-byte units
/// throughout, which is what both table formats specify their LBAs in.
/// It is deliberately not a parameter: a table on a 4Kn device still
/// counts its LBAs in the device's own sectors, and supporting that
/// would mean threading a sector size through every offset calculation
/// rather than changing this number.
///
/// It used to be declared three times — `gpt`, `mbr` and `mutation`
/// each had their own — with the literal `512` written out at eight
/// more places on top.
pub const SECTOR_SIZE: u64 = 512;

/// [`SECTOR_SIZE`] where an array length or a slice index needs it.
///
/// Rust will not take a `u64` const as an array length, which is what
/// made the eight bare `[0u8; 512]` buffers bare in the first place.
pub const SECTOR_SIZE_USIZE: usize = SECTOR_SIZE as usize;

/// One sector's worth of bytes.
///
/// `[0u8; SECTOR_SIZE_USIZE]` replaces the eight bare `[0u8; 512]`
/// buffers, so one that is meant to hold a sector says so. The alias is
/// here for signatures that want to name the type.
pub type Sector = [u8; SECTOR_SIZE_USIZE];

/// The largest LBA an MBR entry can name.
///
/// MBR LBAs are 32-bit, so one primary entry describes at most
/// `2^32 - 1` sectors — 2 TiB less 512 bytes at this sector size. The
/// writer rejects anything larger.
///
/// Declared twice before, in `mbr` and `mutation`.
pub const MBR_LBA_MAX: u64 = 0xFFFF_FFFF;

pub mod capi;
pub mod error;
pub mod gpt;
pub mod gpt_write;
pub mod mbr;
pub mod mutation;
pub mod probe;
pub mod sniff;

pub use error::{Error, Result};
pub use mutation::{PartitionRef, PartitionSet, PartitionTypeId};
pub use probe::{probe, Partition, PartitionKind, TableKind};
pub use sniff::{sniff, FsKind};

// Re-export the core block-device pieces so consumers don't have to depend
// on fs-core directly for the common cases. SliceReader / OwnedSlice
// originally lived here but moved to fs-core in v0.2 — they're generic
// block-layer types, not partition-specific. Re-exported to keep
// existing `partitions::SliceReader` callers working.
pub use fs_core::{BlockDevice, BlockRead, FileDevice as FileBlock, OwnedSlice, SliceReader};

#[cfg(test)]
mod sector_size_tests {
    use super::*;

    /// The two spellings of one number cannot drift.
    ///
    /// Rust will not take a `u64` const as an array length, which is
    /// why there has to be a second spelling at all — and why the eight
    /// buffers were bare `[0u8; 512]` before. This is the assertion
    /// that keeps the second spelling honest.
    #[test]
    fn the_two_spellings_of_a_sector_agree() {
        assert_eq!(SECTOR_SIZE, SECTOR_SIZE_USIZE as u64);
        assert_eq!(std::mem::size_of::<Sector>(), SECTOR_SIZE_USIZE);
        assert_eq!(std::mem::size_of::<Sector>() as u64, SECTOR_SIZE);
    }

    /// `MBR_LBA_MAX` is what a 32-bit LBA field can hold, not a number
    /// somebody typed.
    ///
    /// It was declared twice, in `mbr` and `mutation`, and a third
    /// literal `0xFFFF_FFFF` sat in `gpt_write`'s protective-MBR
    /// sizing.
    #[test]
    fn the_mbr_lba_ceiling_is_the_field_it_describes() {
        assert_eq!(MBR_LBA_MAX, u64::from(u32::MAX));
        // 2 TiB less one sector, which is the limit the doc claims.
        assert_eq!(
            MBR_LBA_MAX * SECTOR_SIZE,
            2 * 1024 * 1024 * 1024 * 1024 - SECTOR_SIZE
        );
    }
}
