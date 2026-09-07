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
/// throughout. That is the *logical* sector size of a 512n or 512e
/// disk, which is the large majority of them, and it is what both
/// table formats count their LBAs in on such a disk.
///
/// It is deliberately not a parameter. A table on a 4Kn disk — 4096-byte
/// logical sectors — counts its LBAs in 4096-byte units, and reading
/// one properly would mean threading a sector size through every offset
/// calculation rather than changing this number.
///
/// The consequence, stated rather than implied, because the two halves
/// differ:
///
/// * A **4Kn GPT** disk is refused by name.
///   [`probe`](crate::probe) looks for a valid GPT header at byte 4096
///   and returns [`Error::UnsupportedSectorSize`](crate::Error) when it
///   finds one, because without that check the disk was reported as
///   `GptCorrupt("protective MBR present but no GPT signature")` — a
///   healthy disk described as a broken table.
/// * A **4Kn MBR** disk cannot be detected at all. An MBR carries
///   nothing that says what its LBAs count in, so the entries are read
///   as 512-byte indices and every offset comes out eight times too
///   small, with no complaint. Measured on a 4Kn entry naming LBA 2048:
///   reported at byte 1048576, where the truth is 8388608. That is the
///   worse of the two failures and there is no fix for it short of the
///   sector size being threaded through — or a caller that knows its
///   disk's geometry telling this crate.
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

/// The GPT layout this crate reads and writes.
///
/// Every number here was previously stated twice: `gpt_write` derived
/// its geometry from the entry array, `mutation` wrote `34` and `33` as
/// literals, and the two agreed only because somebody checked. Changing
/// either alone produced a writer and a planner that disagreed about
/// where a partition may start — and **no test noticed**: setting
/// `mutation`'s first-usable LBA to 40 left the whole suite green.
pub mod gpt_layout {
    use super::SECTOR_SIZE;

    /// Entries in the partition array. The spec allows other values;
    /// this crate pins one so every commit produces the same shape.
    pub const NUM_ENTRIES: u32 = 128;
    /// Bytes per entry, likewise pinned.
    pub const ENTRY_SIZE: u32 = 128;
    /// Sectors the entry array occupies.
    pub const ENTRY_ARRAY_SECTORS: u64 = (NUM_ENTRIES as u64) * (ENTRY_SIZE as u64) / SECTOR_SIZE;

    /// First LBA a partition may occupy: the protective MBR, the
    /// primary header, and the entry array.
    ///
    /// Derived rather than written as `34`, so it stays correct if the
    /// pinned entry count ever changes.
    pub const FIRST_USABLE_LBA: u64 = 2 + ENTRY_ARRAY_SECTORS;

    /// Sectors reserved at the end of the disk: the backup entry array
    /// and the backup header.
    pub const BACKUP_RESERVE_SECTORS: u64 = ENTRY_ARRAY_SECTORS + 1;

    /// Bytes of the GPT header that the header CRC covers.
    pub const HEADER_SIZE: u32 = 92;
}

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

    /// The GPT geometry is derived from the entry array, not typed.
    ///
    /// `gpt_write` computed it and `mutation` wrote `34` and `33` as
    /// literals. They agreed only because somebody checked — and
    /// **nothing would have noticed if they stopped**: setting
    /// `mutation`'s first-usable LBA to 40 left the whole suite green,
    /// leaving a writer and a planner that disagree about where a
    /// partition may start.
    #[test]
    fn the_gpt_geometry_follows_from_the_entry_array() {
        use gpt_layout::*;
        assert_eq!(
            ENTRY_ARRAY_SECTORS,
            u64::from(NUM_ENTRIES) * u64::from(ENTRY_SIZE) / SECTOR_SIZE,
            "the array is the entries, laid out"
        );
        assert_eq!(
            FIRST_USABLE_LBA,
            2 + ENTRY_ARRAY_SECTORS,
            "protective MBR + primary header + the array"
        );
        assert_eq!(
            BACKUP_RESERVE_SECTORS,
            ENTRY_ARRAY_SECTORS + 1,
            "the backup array + the backup header"
        );
        // And the values the spec's common case produces, so a change
        // to the pinned entry count is visible rather than silent.
        assert_eq!(
            (
                ENTRY_ARRAY_SECTORS,
                FIRST_USABLE_LBA,
                BACKUP_RESERVE_SECTORS
            ),
            (32, 34, 33)
        );
    }

    /// The MBR table is four 16-byte entries after 446 bytes of code.
    #[test]
    fn the_mbr_table_starts_where_the_bootloader_ends() {
        use mbr::layout::*;
        assert_eq!(TABLE_START, 446);
        assert_eq!(ENTRY_SIZE, 16);
        assert_eq!(ENTRY_COUNT, 4);
        assert_eq!(entry_at(0), 446);
        assert_eq!(entry_at(3), 446 + 3 * 16);
        // The four entries end exactly at the 0x55AA signature.
        assert_eq!(
            entry_at(ENTRY_COUNT - 1) + ENTRY_SIZE,
            SECTOR_SIZE_USIZE - 2,
            "the table must end where the boot signature begins"
        );
    }

    /// Every GPT header field lies inside the CRC'd region.
    #[test]
    fn the_gpt_header_fields_fit_inside_the_header() {
        use gpt::header_offsets::*;
        for (name, off, len) in [
            ("signature", SIGNATURE, 8),
            ("revision", REVISION, 4),
            ("header_size", HEADER_SIZE, 4),
            ("header_crc32", HEADER_CRC32, 4),
            ("my_lba", MY_LBA, 8),
            ("alternate_lba", ALTERNATE_LBA, 8),
            ("first_usable_lba", FIRST_USABLE_LBA, 8),
            ("last_usable_lba", LAST_USABLE_LBA, 8),
            ("disk_guid", DISK_GUID, 16),
            ("partition_entry_lba", PARTITION_ENTRY_LBA, 8),
            ("num_partition_entries", NUM_PARTITION_ENTRIES, 4),
            ("partition_entry_size", PARTITION_ENTRY_SIZE, 4),
            ("array_crc32", PARTITION_ENTRY_ARRAY_CRC32, 4),
        ] {
            assert!(
                off + len <= gpt_layout::HEADER_SIZE as usize,
                "{name} at {off}..{} runs past the {}-byte header",
                off + len,
                gpt_layout::HEADER_SIZE
            );
        }
    }

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
