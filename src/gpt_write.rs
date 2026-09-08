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
use crate::gpt_layout::{ENTRY_SIZE, HEADER_SIZE, NUM_ENTRIES};

/// The largest LBA whose byte offset fits in a `u64`.
///
/// A sector number this crate accepts has to be multipliable by
/// [`SECTOR_SIZE`] without wrapping, because that product is the offset
/// every read and write is issued at.
const MAX_LBA: u64 = u64::MAX / SECTOR_SIZE;

/// The shape of a GPT's entry array, and the usable range that follows
/// from it.
///
/// The spec allows any entry count whose array fits, and some firmware
/// and array controllers write tables that are not the canonical 128.
/// This crate used to pin the shape in constants and rebuild every
/// table to it, so a 256-entry disk came back as a 128-entry disk with
/// no diagnostic — half its partition slots gone, and the old backup
/// array stranded inside what the new header calls usable space, where
/// the next partition created can be placed on top of it. A 64-entry
/// disk went the other way and was refused, with a message blaming a
/// partition that was perfectly legal.
///
/// So the geometry travels with the set: a table that came off a disk
/// is written back in the shape it was found in, and a table being
/// created gets the canonical one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GptGeometry {
    /// Entries the array holds.
    pub num_entries: u32,
    /// Bytes per entry.
    pub entry_size: u32,
    /// LBA the primary entry array starts at. 2 on every table this
    /// crate writes, and read from the disk for one it did not.
    pub entry_lba: u64,
    /// The usable range the disk declares, for a geometry that came
    /// off a disk.
    ///
    /// `None` for a table being created, where the range follows from
    /// the device's size. Kept rather than re-derived because a disk
    /// may reserve more than the minimum — an alignment gap before the
    /// first partition is ordinary — and re-deriving would hand that
    /// reserved space out to the next partition added.
    pub declared_usable: Option<(u64, u64)>,
}

impl GptGeometry {
    /// The canonical shape: 128 entries of 128 bytes at LBA 2.
    pub const fn canonical() -> Self {
        GptGeometry {
            num_entries: NUM_ENTRIES,
            entry_size: ENTRY_SIZE,
            entry_lba: 2,
            declared_usable: None,
        }
    }

    /// The shape a disk's header describes, including the usable range
    /// it declares.
    pub fn from_header(h: &gpt::Header) -> Self {
        GptGeometry {
            num_entries: h.num_partition_entries,
            entry_size: h.partition_entry_size,
            entry_lba: h.partition_entry_lba,
            declared_usable: Some((h.first_usable_lba, h.last_usable_lba)),
        }
    }

    /// Bytes the entry array occupies.
    pub fn array_bytes(&self) -> u64 {
        u64::from(self.num_entries) * u64::from(self.entry_size)
    }

    /// Sectors the entry array occupies, rounded up: an array that does
    /// not fill its last sector still owns it.
    pub fn array_sectors(&self) -> u64 {
        self.array_bytes().div_ceil(SECTOR_SIZE)
    }

    /// Sectors reserved at the end of the disk: the backup array and
    /// the backup header.
    pub fn backup_reserve_sectors(&self) -> u64 {
        self.array_sectors() + 1
    }

    /// The shape itself has to be one a table can have, whatever disk
    /// it is going on.
    ///
    /// Checked before the geometry is used for arithmetic, so a header
    /// carrying nonsense is refused as a geometry rather than turned
    /// into an absurd usable range.
    fn check_shape(&self) -> Result<()> {
        if self.num_entries == 0 {
            return Err(Error::Invalid("a GPT with no entry slots"));
        }
        if self.entry_size < ENTRY_SIZE || !self.entry_size.is_multiple_of(8) {
            return Err(Error::Invalid(
                "a GPT entry size below 128 bytes or not a multiple of 8",
            ));
        }
        if self.entry_lba < 2 {
            return Err(Error::Invalid(
                "a GPT entry array starting at or before the header",
            ));
        }
        // Every LBA this geometry names has to have a byte offset.
        //
        // This is the bound that makes the arithmetic below total, and
        // it is here — in the shape check, before anything is written —
        // rather than as a checked add at each site, because *where the
        // refusal happens* is the defect rather than *whether* it
        // happens.
        //
        // `write_gpt_with_geometry` writes the protective MBR at LBA 0
        // and the primary header at LBA 1 before it ever touches the
        // entry array. With `entry_lba` near `u64::MAX` the sum below
        // wraps in a release build, the `DeviceTooSmall` refusal is
        // stepped over, and the failure arrives later — after those two
        // sectors have been rewritten. The caller is handed an `Err`
        // and a torn table, which is worse than either a clean refusal
        // or a clean write. Checked arithmetic at the point of use
        // would turn the wrap into an error and leave that ordering
        // exactly as it is.
        //
        // Not reachable from a disk: `gpt::parse_entry_array` multiplies
        // `partition_entry_lba` through `checked_mul` and refuses an
        // array reaching past the device, so `from_probe` cannot build
        // such a geometry. The exposure is a directly-constructed one,
        // which the public fields permit.
        if self.entry_lba > MAX_LBA {
            return Err(Error::Invalid(
                "a GPT entry array at an LBA whose byte offset does not fit a u64",
            ));
        }
        let array_sectors = self.array_sectors();
        if array_sectors > MAX_LBA {
            return Err(Error::Invalid(
                "a GPT entry array longer than any device could hold",
            ));
        }
        // The two together, because the first usable LBA is their sum
        // and the backup reserve is one more than the array.
        // `>` and not `>=`: an array ending exactly at `MAX_LBA` names
        // no LBA whose byte offset is unrepresentable, so refusing it
        // would be one sector too strict. The two differ at exactly one
        // value and there is a test at it.
        if self
            .entry_lba
            .checked_add(array_sectors)
            .is_none_or(|first| first > MAX_LBA)
        {
            return Err(Error::Invalid(
                "a GPT whose entry array ends past the last addressable LBA",
            ));
        }
        Ok(())
    }

    /// The usable range on a device of `total_sectors`, or why this
    /// geometry does not fit it.
    ///
    /// A declared range is checked rather than trusted: it must start
    /// no earlier than the entry array ends and finish no later than
    /// the backup reserve begins, or the table would describe usable
    /// space on top of its own metadata.
    pub fn usable_range(&self, total_sectors: u64) -> Result<(u64, u64)> {
        // `check_shape` is what makes the arithmetic here total: it
        // bounds `entry_lba`, the array's sectors, and their sum below
        // `MAX_LBA`, so neither this sum nor the reserve can wrap.
        self.check_shape()?;
        let first_possible = self.entry_lba + self.array_sectors();
        let reserve = self.backup_reserve_sectors();
        if total_sectors <= first_possible + reserve {
            return Err(Error::DeviceTooSmall);
        }
        let last_possible = total_sectors - 1 - reserve;
        match self.declared_usable {
            None => Ok((first_possible, last_possible)),
            Some((first, last)) => {
                if first < first_possible {
                    return Err(Error::Invalid(
                        "the table's first usable LBA is inside its own entry array",
                    ));
                }
                if last > last_possible {
                    return Err(Error::Invalid(
                        "the table's last usable LBA is inside the space the backup copy needs",
                    ));
                }
                if first > last {
                    return Err(Error::Invalid("the table's usable range runs backwards"));
                }
                Ok((first, last))
            }
        }
    }
}

/// Write a complete GPT to `dev`. The caller owns the partition list and the
/// disk GUID; this function does not mutate either.
///
/// Validation:
/// - Each partition must carry a [`PartitionKind::Gpt`] type GUID. Any
///   non-GPT entry is rejected with [`Error::Invalid`].
/// - Each partition must have a UUID. Callers building a fresh table can
///   mint one through the public helpers in [`crate::mutation`].
/// - All start/length pairs must lie within the table's usable range, be
///   sector-aligned, and not overlap each other.
/// - At most as many partitions as the table has entry slots.
pub fn write_gpt(
    dev: &dyn BlockDevice,
    partitions: &[Partition],
    disk_guid: [u8; 16],
) -> Result<()> {
    write_gpt_with_geometry(dev, partitions, disk_guid, GptGeometry::canonical())
}

/// As [`write_gpt`], in the entry-array shape `geometry` describes.
///
/// A table read off a disk is written back the shape it was found in.
/// Rebuilding every table to the canonical 128 entries silently halved
/// a 256-entry disk's partition capacity and left its old backup array
/// stranded inside the new usable range; it also refused a legal
/// 64-entry disk, blaming a partition rather than the geometry the
/// crate had discarded.
pub fn write_gpt_with_geometry(
    dev: &dyn BlockDevice,
    partitions: &[Partition],
    disk_guid: [u8; 16],
    geometry: GptGeometry,
) -> Result<()> {
    write_gpt_preserving_tails(
        dev,
        partitions,
        disk_guid,
        geometry,
        &gpt::EntryTails::new(),
    )
}

/// As [`write_gpt_with_geometry`], carrying each entry's tail bytes.
///
/// The specification fixes the first 128 bytes of an entry and lets a
/// table declare a larger `partition_entry_size`. This writer builds a
/// fresh array of zeros and fills in those 128 bytes, so on a disk
/// whose entries are larger, a probe-then-commit that changed nothing
/// zeroed the rest of every entry — vendor or future-format payload
/// that nothing in this crate can reconstruct.
///
/// Refusing such a disk instead would be worse than the loss it
/// prevents: this writer exists to put a table back in the shape it was
/// found in, and a disk that cannot be committed is a disk that cannot
/// be edited at all.
///
/// `tails` is keyed by the partition's own UUID rather than by slot,
/// and that is the whole of the care needed here. [`assign_slots`]
/// re-uses a seat a removed partition vacated, so a tail carried by
/// position would be handed to whichever partition next sat there — a
/// stranger's vendor bytes on somebody else's partition, and a removed
/// partition's payload outliving it. A partition with no entry in the
/// map — one just created — gets zeros, which is right for a table
/// being made rather than rewritten.
pub fn write_gpt_preserving_tails(
    dev: &dyn BlockDevice,
    partitions: &[Partition],
    disk_guid: [u8; 16],
    geometry: GptGeometry,
    tails: &gpt::EntryTails,
) -> Result<()> {
    if !dev.is_writable() {
        return Err(Error::Block(fs_core::Error::ReadOnly));
    }

    let total_bytes = dev.size_bytes();
    let total_sectors = total_bytes / SECTOR_SIZE;
    let (first_usable_lba, last_usable_lba) = geometry.usable_range(total_sectors)?;
    let last_lba = total_sectors - 1;
    let array_sectors = geometry.array_sectors();

    if partitions.len() > geometry.num_entries as usize {
        return Err(Error::Invalid(
            "more partitions than the table has entry slots",
        ));
    }

    // The usable-range and overlap rules are the reader's too, so both
    // sides call `gpt::range_issues` and `gpt::mark_overlaps` rather
    // than each carrying its own copy. They disagreed before: the
    // writer refused what the reader had just handed the caller.
    let mut spans: Vec<(u64, u64)> = Vec::with_capacity(partitions.len());
    for p in partitions {
        validate_partition(p, first_usable_lba, last_usable_lba)?;
        spans.push(p.sector_span()?);
    }
    if gpt::mark_overlaps(&spans).iter().any(|&o| o) {
        return Err(Error::Invalid("partitions overlap"));
    }

    // --- Build the entry array (16 KiB, all zeros + populated slots). ---
    let slots = assign_slots(partitions, geometry.num_entries)?;
    let mut array = vec![0u8; geometry.array_bytes() as usize];
    for (p, slot) in partitions.iter().zip(&slots) {
        let off = (*slot as usize) * geometry.entry_size as usize;
        let (type_guid, attributes) = match p.kind {
            PartitionKind::Gpt {
                type_guid,
                attributes,
            } => (type_guid, attributes),
            _ => return Err(Error::Invalid("non-GPT partition kind in GPT write")),
        };
        let uuid = p.uuid.ok_or(Error::Invalid("GPT partition missing UUID"))?;
        let (start_lba, end_lba) = p.sector_span()?;

        // The partition's own tail, before the standard bytes are laid
        // over the front of it. Truncated or zero-padded to this
        // table's entry size, because the geometry being written is not
        // required to be the one the tail came off.
        if geometry.entry_size as usize > gpt::ENTRY_STANDARD_BYTES {
            let room = geometry.entry_size as usize - gpt::ENTRY_STANDARD_BYTES;
            if let Some(tail) = tails.get(&uuid) {
                let take = tail.len().min(room);
                let at = off + gpt::ENTRY_STANDARD_BYTES;
                array[at..at + take].copy_from_slice(&tail[..take]);
            }
        }

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
        /* entry_lba */ geometry.entry_lba,
        /* usable */ (first_usable_lba, last_usable_lba),
        disk_guid,
        entry_array_crc,
        geometry,
    );
    dev.write_at(SECTOR_SIZE, &primary)?;

    // --- Primary entry array where the header says it is ---
    dev.write_at(geometry.entry_lba * SECTOR_SIZE, &array)?;

    // --- Backup entry array, immediately before the backup header ---
    let backup_entries_lba = last_lba - array_sectors;
    dev.write_at(backup_entries_lba * SECTOR_SIZE, &array)?;

    // --- Backup header at last LBA. ---
    let backup = build_header(
        /* my_lba */ last_lba,
        /* alternate_lba */ 1,
        /* entry_lba */ backup_entries_lba,
        /* usable */ (first_usable_lba, last_usable_lba),
        disk_guid,
        entry_array_crc,
        geometry,
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
    assign_slots_with_taken(partitions, num_entries, &[])
}

/// As [`assign_slots`], with `pre_taken` naming slots that are already
/// spoken for by something that is not in `partitions`.
///
/// The MBR writer has such entries: the extended container and the
/// hybrid `0xEE` marker are in the table but are not volumes, so they
/// never appear in the partition list, and a slot search that cannot
/// see them hands one of their slots to the next partition added.
pub(crate) fn assign_slots_with_taken(
    partitions: &[Partition],
    num_entries: u32,
    pre_taken: &[u32],
) -> Result<Vec<u32>> {
    let mut taken = vec![false; num_entries as usize];
    for slot in pre_taken {
        let seat = taken.get_mut(*slot as usize).ok_or(Error::Invalid(
            "reserved entry slot past the end of the table",
        ))?;
        if *seat {
            return Err(Error::Invalid("two entries claim the same table slot"));
        }
        *seat = true;
    }
    for p in partitions {
        let Some(slot) = p.slot else { continue };
        let seat = taken
            .get_mut(slot as usize)
            .ok_or(Error::Invalid("partition slot past the end of the table"))?;
        if *seat {
            return Err(Error::Invalid("two entries claim the same table slot"));
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
    // The same statement of the usable-range rules the reader applies.
    // The start needs its own upper bound, not just the end's, and
    // `range_issues` carries that reasoning.
    let issues = gpt::range_issues(start_lba, end_lba, first_usable, last_usable);
    if issues & gpt::entry_issue::BEFORE_FIRST_USABLE != 0 {
        return Err(Error::Invalid("partition starts before first usable LBA"));
    }
    if issues & gpt::entry_issue::PAST_LAST_USABLE != 0 {
        return Err(Error::Invalid("partition runs past last usable LBA"));
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
    // The two ends travel together: they are one range, and splitting
    // them into two parameters was the eighth argument.
    usable: (u64, u64),
    disk_guid: [u8; 16],
    entry_array_crc: u32,
    geometry: GptGeometry,
) -> [u8; crate::SECTOR_SIZE_USIZE] {
    let (first_usable, last_usable) = usable;
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
        .copy_from_slice(&geometry.num_entries.to_le_bytes());
    h[gpt::header_offsets::PARTITION_ENTRY_SIZE..gpt::header_offsets::PARTITION_ENTRY_SIZE + 4]
        .copy_from_slice(&geometry.entry_size.to_le_bytes());
    h[88..92].copy_from_slice(&entry_array_crc.to_le_bytes());

    let header_crc = crc32fast::hash(&h[..HEADER_SIZE as usize]);
    h[16..20].copy_from_slice(&header_crc.to_le_bytes());
    h
}

#[cfg(test)]
mod geometry_tests {
    use super::*;

    /// A 64 MiB disk, in sectors.
    const SECTORS: u64 = 64 * 1024 * 1024 / 512;

    fn canonical() -> GptGeometry {
        GptGeometry::canonical()
    }

    /// The canonical shape gives the numbers this crate has always
    /// used, which is what says the general form did not move them.
    #[test]
    fn the_canonical_geometry_is_the_34_and_33_this_crate_had_pinned() {
        let g = canonical();
        assert_eq!(g.array_sectors(), 32);
        assert_eq!(g.backup_reserve_sectors(), 33);
        assert_eq!(g.usable_range(SECTORS).unwrap(), (34, SECTORS - 34));
    }

    /// A bigger array pushes the first usable LBA out and pulls the
    /// last one in, by the same amount at each end.
    #[test]
    fn a_256_entry_array_moves_both_ends_of_the_usable_range() {
        let g = GptGeometry {
            num_entries: 256,
            ..canonical()
        };
        assert_eq!(g.array_sectors(), 64);
        assert_eq!(g.usable_range(SECTORS).unwrap(), (66, SECTORS - 66));
    }

    /// An array that does not fill its last sector still owns it.
    ///
    /// 3 entries of 128 bytes is 384 bytes — most of a sector, and no
    /// partition may start in the rest of it.
    #[test]
    fn an_array_shorter_than_a_sector_still_occupies_one() {
        let g = GptGeometry {
            num_entries: 3,
            ..canonical()
        };
        assert_eq!(g.array_sectors(), 1);
        assert_eq!(g.usable_range(SECTORS).unwrap(), (3, SECTORS - 3));
    }

    /// A declared range narrower than the minimum is kept, because a
    /// disk may reserve more than the metadata needs.
    #[test]
    fn a_declared_range_narrower_than_the_minimum_is_kept() {
        let g = GptGeometry {
            declared_usable: Some((2048, SECTORS - 2048)),
            ..canonical()
        };
        assert_eq!(g.usable_range(SECTORS).unwrap(), (2048, SECTORS - 2048));
    }

    /// A geometry whose LBAs have no byte offset is refused, and the
    /// bound has both ends.
    ///
    /// `MAX_LBA` is the largest sector number whose byte offset fits a
    /// `u64`, so it is the last value that must be accepted and
    /// `MAX_LBA + 1` the first that must be refused. A bound written
    /// one either way passes one of these and fails the other.
    ///
    /// The accepted case is checked through `check_shape` rather than
    /// through `usable_range`, because no device is that large: the
    /// range would be refused as `DeviceTooSmall`, which is the right
    /// answer for a different reason and would hide this one.
    #[test]
    fn the_addressable_lba_bound_is_checked_at_both_ends() {
        let at_the_limit = GptGeometry {
            entry_lba: MAX_LBA - 33,
            ..canonical()
        };
        at_the_limit
            .check_shape()
            .expect("the last LBA with a byte offset is addressable");

        let past_it = GptGeometry {
            entry_lba: MAX_LBA + 1,
            ..canonical()
        };
        match past_it.check_shape() {
            Err(Error::Invalid(m)) => assert!(
                m.contains("byte offset does not fit"),
                "refused, but not for the offset: {m}"
            ),
            other => panic!("an LBA past the addressable range gave {other:?}"),
        }
    }

    /// An entry array whose end runs past the addressable range is
    /// refused even when its start does not, and the bound has both
    /// ends.
    ///
    /// `entry_lba` alone is inside the bound in both cases here; it is
    /// the array that pushes the sum. An array ending *exactly* at
    /// `MAX_LBA` names no LBA whose byte offset is unrepresentable, so
    /// it must be accepted — a check written `>=` refuses it, which is
    /// one sector too strict and the failure that arrives as "this tool
    /// will not write my disk".
    ///
    /// The accepted case goes through `check_shape` rather than
    /// `usable_range` because no device is that large: the range would
    /// come back `DeviceTooSmall`, which is right for another reason
    /// and would hide this one.
    #[test]
    fn the_arrays_end_is_bounded_at_both_ends() {
        let canonical_array = canonical().array_sectors();

        let ends_exactly_at_the_limit = GptGeometry {
            entry_lba: MAX_LBA - canonical_array,
            ..canonical()
        };
        assert_eq!(
            ends_exactly_at_the_limit.entry_lba + canonical_array,
            MAX_LBA,
            "the fixture does not end where this test says it does"
        );
        ends_exactly_at_the_limit
            .check_shape()
            .expect("an array ending at the last addressable LBA is addressable");

        let one_past = GptGeometry {
            entry_lba: MAX_LBA - canonical_array + 1,
            ..canonical()
        };
        match one_past.check_shape() {
            Err(Error::Invalid(m)) => assert!(
                m.contains("ends past the last addressable LBA"),
                "refused, but not for the array's end: {m}"
            ),
            other => panic!("an array ending one past the range gave {other:?}"),
        }
    }

    /// The arithmetic that used to wrap now cannot be reached with the
    /// values that wrapped it.
    ///
    /// `entry_lba: u64::MAX` panicked in a debug build and, in release,
    /// wrapped `entry_lba + array_sectors` to 31 — which is below the
    /// device's sector count, so the `DeviceTooSmall` refusal was
    /// stepped over and the writer carried on.
    #[test]
    fn the_geometry_that_wrapped_is_refused_rather_than_wrapping() {
        let g = GptGeometry {
            entry_lba: u64::MAX,
            ..canonical()
        };
        assert!(g.usable_range(131_072).is_err());
        assert!(
            g.check_shape().is_err(),
            "the refusal is in the shape check"
        );
    }

    /// Each way a geometry can fail to describe a table, refused with
    /// the reason that names it.
    ///
    /// One case per clause: a check that is never the only reason a
    /// geometry is refused is a check nothing would notice losing.
    #[test]
    fn a_geometry_that_cannot_describe_a_table_is_refused() {
        let cases: &[(GptGeometry, &str)] = &[
            (
                GptGeometry {
                    num_entries: 0,
                    ..canonical()
                },
                "no entry slots",
            ),
            (
                GptGeometry {
                    entry_size: 64,
                    ..canonical()
                },
                "below 128 bytes",
            ),
            (
                GptGeometry {
                    entry_size: 132,
                    ..canonical()
                },
                "multiple of 8",
            ),
            (
                GptGeometry {
                    entry_lba: 1,
                    ..canonical()
                },
                "before the header",
            ),
            (
                GptGeometry {
                    declared_usable: Some((33, SECTORS - 34)),
                    ..canonical()
                },
                "inside its own entry array",
            ),
            (
                GptGeometry {
                    declared_usable: Some((34, SECTORS - 33)),
                    ..canonical()
                },
                "the backup copy needs",
            ),
            (
                GptGeometry {
                    declared_usable: Some((100, 99)),
                    ..canonical()
                },
                "runs backwards",
            ),
        ];
        for (geometry, expected) in cases {
            match geometry.usable_range(SECTORS) {
                Err(Error::Invalid(m)) => assert!(
                    m.contains(expected),
                    "refused for the wrong reason: wanted {expected:?}, got {m:?}"
                ),
                other => panic!("{geometry:?} gave {other:?}, wanted {expected:?}"),
            }
        }
    }

    /// A disk with no room for the table's own metadata is too small,
    /// and says so rather than producing a backwards range.
    #[test]
    fn a_disk_too_small_for_the_geometry_is_refused_as_too_small() {
        let g = canonical();
        // 34 for the front, 33 for the back, and at least one usable.
        assert!(g.usable_range(68).is_ok());
        match g.usable_range(67) {
            Err(Error::DeviceTooSmall) => {}
            other => panic!("a disk one sector too small gave {other:?}"),
        }
    }
}
