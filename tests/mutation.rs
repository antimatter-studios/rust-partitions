//! Round-trip tests for the write side: mutate → commit → re-probe.

use partitions::gpt::{type_guids, BackupStatus};
use partitions::{
    gpt, probe, BlockDevice, BlockRead, Error, Partition, PartitionKind, PartitionRef,
    PartitionSet, PartitionTypeId, TableKind,
};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// In-memory BlockDevice for tests.
// ---------------------------------------------------------------------------

struct MemDev(Mutex<Vec<u8>>);

impl MemDev {
    fn new(size: usize) -> Self {
        Self(Mutex::new(vec![0u8; size]))
    }
}

impl BlockRead for MemDev {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_core::Result<()> {
        let b = self.0.lock().unwrap();
        let start = offset as usize;
        let end = start + buf.len();
        if end > b.len() {
            return Err(fs_core::Error::ShortRead {
                offset,
                want: buf.len(),
                got: b.len().saturating_sub(start),
            });
        }
        buf.copy_from_slice(&b[start..end]);
        Ok(())
    }
    fn size_bytes(&self) -> u64 {
        self.0.lock().unwrap().len() as u64
    }
}

impl BlockDevice for MemDev {
    fn write_at(&self, offset: u64, buf: &[u8]) -> fs_core::Result<()> {
        let mut b = self.0.lock().unwrap();
        let start = offset as usize;
        let end = start + buf.len();
        if end > b.len() {
            return Err(fs_core::Error::OutOfBounds {
                offset,
                len: buf.len() as u64,
                size: b.len() as u64,
            });
        }
        b[start..end].copy_from_slice(buf);
        Ok(())
    }
    fn flush(&self) -> fs_core::Result<()> {
        Ok(())
    }
    fn is_writable(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// GPT round-trips
// ---------------------------------------------------------------------------

const ONE_MIB: u64 = 1024 * 1024;
const DISK_64M: u64 = 64 * ONE_MIB;

#[test]
fn gpt_round_trip_two_partitions() {
    let dev = MemDev::new(DISK_64M as usize);
    let mut set = PartitionSet::empty_gpt(DISK_64M);

    let i0 = set
        .add(
            None,
            8 * ONE_MIB,
            PartitionTypeId::EfiSystem,
            Some("EFI".into()),
        )
        .unwrap();
    let i1 = set
        .add(
            None,
            16 * ONE_MIB,
            PartitionTypeId::LinuxFilesystem,
            Some("rootfs".into()),
        )
        .unwrap();
    assert_eq!(i0, 0);
    assert_eq!(i1, 1);

    set.commit(&dev).unwrap();

    let (kind, parts) = probe(&dev).unwrap();
    assert_eq!(kind, TableKind::Gpt);
    assert_eq!(parts.len(), 2);
    // Sort by start so order is stable.
    let mut parts = parts;
    parts.sort_by_key(|p| p.start);
    assert_eq!(parts[0].length, 8 * ONE_MIB);
    assert_eq!(parts[0].label.as_deref(), Some("EFI"));
    if let PartitionKind::Gpt { type_guid, .. } = parts[0].kind {
        assert_eq!(type_guid, type_guids::EFI_SYSTEM);
    } else {
        panic!("expected GPT kind");
    }
    assert_eq!(parts[1].length, 16 * ONE_MIB);
    assert_eq!(parts[1].label.as_deref(), Some("rootfs"));
}

#[test]
fn gpt_alignment_preserved() {
    let dev = MemDev::new(DISK_64M as usize);
    let mut set = PartitionSet::empty_gpt(DISK_64M);
    set.add(None, 4 * ONE_MIB, PartitionTypeId::LinuxFilesystem, None)
        .unwrap();
    set.add(None, 4 * ONE_MIB, PartitionTypeId::LinuxFilesystem, None)
        .unwrap();
    set.commit(&dev).unwrap();

    let (_, parts) = probe(&dev).unwrap();
    for p in &parts {
        assert_eq!(p.start % ONE_MIB, 0, "start not 1 MiB aligned: {}", p.start);
        assert_eq!(
            p.length % ONE_MIB,
            0,
            "length not 1 MiB aligned: {}",
            p.length
        );
    }
}

#[test]
fn gpt_unaligned_hint_silently_aligned() {
    let dev = MemDev::new(DISK_64M as usize);
    let mut set = PartitionSet::empty_gpt(DISK_64M);
    // Hint is at 1.5 MiB which is not 1 MiB aligned — should snap up to 2 MiB.
    let idx = set
        .add(
            Some(ONE_MIB + ONE_MIB / 2),
            4 * ONE_MIB,
            PartitionTypeId::LinuxFilesystem,
            None,
        )
        .unwrap();
    let p = &set.partitions[idx];
    assert_eq!(
        p.start,
        2 * ONE_MIB,
        "expected snap to 2 MiB, got {}",
        p.start
    );
    set.commit(&dev).unwrap();
    let (_, parts) = probe(&dev).unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].start, 2 * ONE_MIB);
}

#[test]
fn gpt_overlap_rejected() {
    let mut set = PartitionSet::empty_gpt(DISK_64M);
    set.add(
        Some(ONE_MIB),
        8 * ONE_MIB,
        PartitionTypeId::LinuxFilesystem,
        None,
    )
    .unwrap();
    // Try to add another that overlaps.
    let result = set.add(
        Some(2 * ONE_MIB),
        4 * ONE_MIB,
        PartitionTypeId::LinuxFilesystem,
        None,
    );
    match result {
        Err(Error::Invalid(_)) => {}
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn gpt_remove_round_trip() {
    let dev = MemDev::new(DISK_64M as usize);
    let mut set = PartitionSet::empty_gpt(DISK_64M);
    set.add(
        None,
        4 * ONE_MIB,
        PartitionTypeId::LinuxFilesystem,
        Some("a".into()),
    )
    .unwrap();
    let idx = set
        .add(
            None,
            4 * ONE_MIB,
            PartitionTypeId::LinuxFilesystem,
            Some("b".into()),
        )
        .unwrap();
    set.remove(PartitionRef::Index(idx)).unwrap();
    set.commit(&dev).unwrap();

    let (kind, parts) = probe(&dev).unwrap();
    assert_eq!(kind, TableKind::Gpt);
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].label.as_deref(), Some("a"));
}

#[test]
fn gpt_remove_by_uuid() {
    let mut set = PartitionSet::empty_gpt(DISK_64M);
    set.add(None, 4 * ONE_MIB, PartitionTypeId::LinuxFilesystem, None)
        .unwrap();
    set.add(None, 4 * ONE_MIB, PartitionTypeId::LinuxFilesystem, None)
        .unwrap();
    let uuid = set.partitions[1].uuid.unwrap();
    set.remove(PartitionRef::Uuid(uuid)).unwrap();
    assert_eq!(set.partitions.len(), 1);
}

#[test]
fn gpt_resize_round_trip() {
    let dev = MemDev::new(DISK_64M as usize);
    let mut set = PartitionSet::empty_gpt(DISK_64M);
    let idx = set
        .add(None, 4 * ONE_MIB, PartitionTypeId::LinuxFilesystem, None)
        .unwrap();
    set.resize(PartitionRef::Index(idx), 12 * ONE_MIB).unwrap();
    set.commit(&dev).unwrap();
    let (_, parts) = probe(&dev).unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].length, 12 * ONE_MIB);
}

#[test]
fn gpt_primary_and_backup_match_after_commit() {
    let dev = MemDev::new(DISK_64M as usize);
    let mut set = PartitionSet::empty_gpt(DISK_64M);
    set.add(
        None,
        4 * ONE_MIB,
        PartitionTypeId::EfiSystem,
        Some("EFI".into()),
    )
    .unwrap();
    set.add(
        None,
        8 * ONE_MIB,
        PartitionTypeId::LinuxFilesystem,
        Some("root".into()),
    )
    .unwrap();
    set.commit(&dev).unwrap();

    // Primary path.
    let (kind, primary) = probe(&dev).unwrap();
    assert_eq!(kind, TableKind::Gpt);

    // Backup path.
    let backup = gpt::parse_backup(&dev).unwrap();
    assert_eq!(primary.len(), backup.len());
    let mut p = primary.clone();
    let mut b = backup;
    p.sort_by_key(|x| x.start);
    b.sort_by_key(|x| x.start);
    for (pa, pb) in p.iter().zip(b.iter()) {
        assert_eq!(pa.start, pb.start);
        assert_eq!(pa.length, pb.length);
        assert_eq!(pa.uuid, pb.uuid);
        assert_eq!(pa.kind, pb.kind);
    }

    // validate_backup is the friendly shape.
    assert_eq!(gpt::validate_backup(&dev, &primary), BackupStatus::Ok);
}

#[test]
fn gpt_backup_mismatch_detected() {
    let dev = MemDev::new(DISK_64M as usize);
    let mut set = PartitionSet::empty_gpt(DISK_64M);
    set.add(None, 4 * ONE_MIB, PartitionTypeId::LinuxFilesystem, None)
        .unwrap();
    set.commit(&dev).unwrap();

    // Corrupt one byte inside the backup entry array.
    let total = dev.size_bytes();
    let last_lba = total / 512 - 1;
    let backup_array_off = (last_lba - 32) * 512;
    let mut zap = [0u8; 1];
    dev.read_at(backup_array_off, &mut zap).unwrap();
    zap[0] ^= 0xFF;
    dev.write_at(backup_array_off, &zap).unwrap();

    let (_, primary) = probe(&dev).unwrap();
    match gpt::validate_backup(&dev, &primary) {
        BackupStatus::Mismatch(_) => {}
        BackupStatus::Ok => panic!("expected backup mismatch"),
    }
}

#[test]
fn gpt_from_probe_then_mutate_then_commit() {
    let dev = MemDev::new(DISK_64M as usize);
    let mut set = PartitionSet::empty_gpt(DISK_64M);
    set.add(
        None,
        4 * ONE_MIB,
        PartitionTypeId::LinuxFilesystem,
        Some("a".into()),
    )
    .unwrap();
    set.commit(&dev).unwrap();

    let mut reloaded = PartitionSet::from_probe(&dev).unwrap();
    assert_eq!(reloaded.partitions.len(), 1);
    reloaded
        .add(
            None,
            4 * ONE_MIB,
            PartitionTypeId::LinuxFilesystem,
            Some("b".into()),
        )
        .unwrap();
    reloaded.commit(&dev).unwrap();

    let (_, parts) = probe(&dev).unwrap();
    assert_eq!(parts.len(), 2);
    let labels: Vec<_> = {
        let mut v: Vec<&Partition> = parts.iter().collect();
        v.sort_by_key(|p| p.start);
        v.iter().filter_map(|p| p.label.clone()).collect()
    };
    assert_eq!(labels, vec!["a", "b"]);
}

// ---------------------------------------------------------------------------
// MBR round-trips
// ---------------------------------------------------------------------------

#[test]
fn mbr_round_trip_two_partitions() {
    let dev = MemDev::new(DISK_64M as usize);
    let mut set = PartitionSet::empty_mbr(DISK_64M);
    set.add(None, 4 * ONE_MIB, PartitionTypeId::LinuxFilesystem, None)
        .unwrap();
    set.add(None, 4 * ONE_MIB, PartitionTypeId::LinuxSwap, None)
        .unwrap();
    set.commit(&dev).unwrap();

    let (kind, parts) = probe(&dev).unwrap();
    assert_eq!(kind, TableKind::Mbr);
    assert_eq!(parts.len(), 2);
    let mut parts = parts;
    parts.sort_by_key(|p| p.start);
    assert!(matches!(
        parts[0].kind,
        PartitionKind::Mbr {
            type_byte: 0x83,
            active: _
        }
    ));
    assert!(matches!(
        parts[1].kind,
        PartitionKind::Mbr {
            type_byte: 0x82,
            active: _
        }
    ));
    for p in &parts {
        assert_eq!(p.start % ONE_MIB, 0);
        assert_eq!(p.length, 4 * ONE_MIB);
    }
}

#[test]
fn mbr_full_table_rejects_fifth() {
    let mut set = PartitionSet::empty_mbr(DISK_64M);
    for _ in 0..4 {
        set.add(None, ONE_MIB, PartitionTypeId::LinuxFilesystem, None)
            .unwrap();
    }
    let r = set.add(None, ONE_MIB, PartitionTypeId::LinuxFilesystem, None);
    match r {
        Err(Error::Invalid(_)) => {}
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn mbr_apfs_type_rejected() {
    let mut set = PartitionSet::empty_mbr(DISK_64M);
    let r = set.add(None, ONE_MIB, PartitionTypeId::AppleApfs, None);
    match r {
        Err(Error::Invalid(_)) => {}
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn random_uuid_v4_bits_set() {
    // Add a partition; check the v4 / variant bits per RFC 4122.
    let mut set = PartitionSet::empty_gpt(DISK_64M);
    set.add(None, ONE_MIB, PartitionTypeId::LinuxFilesystem, None)
        .unwrap();
    let uuid = set.partitions[0].uuid.unwrap();
    assert_eq!(uuid[7] & 0xF0, 0x40, "version nibble != 4: {:x}", uuid[7]);
    assert_eq!(uuid[8] & 0xC0, 0x80, "variant bits != 10: {:x}", uuid[8]);
    // disk_guid too
    assert_eq!(set.disk_guid[7] & 0xF0, 0x40);
    assert_eq!(set.disk_guid[8] & 0xC0, 0x80);
}

/// The overlap checks and the free-space finder all asked where an
/// existing partition ends, by adding its start to its length. Both
/// numbers come from the partition table, which comes off the disk, so
/// the addition can leave a `u64` -- and in release, where these crates
/// ship with `overflow-checks` off, it wrapped rather than panicked.
///
/// A wrapped end makes an overlap check answer "no overlap" about a
/// partition that does overlap, which places a new partition on top of
/// an existing one. A GPT entry of `starting_lba = 2^54` and
/// `ending_lba = 2^55` produces exactly this pair.
#[test]
fn a_partition_whose_start_and_length_overflow_is_refused_not_wrapped() {
    let mut set = PartitionSet::empty_gpt(DISK_64M);
    set.partitions.push(Partition {
        start: 1 << 63,
        length: (1 << 63) + 512,
        kind: PartitionKind::Gpt {
            type_guid: type_guids::LINUX_FILESYSTEM,
            attributes: 0,
        },
        label: Some("overflowing".into()),
        uuid: Some([7u8; 16]),
        slot: None,
    });

    match set.add(None, ONE_MIB, PartitionTypeId::LinuxFilesystem, None) {
        Err(Error::Invalid(_)) => {}
        other => panic!(
            "adding beside a partition whose span leaves a u64 gave {other:?}, \
             which means the wrapped end was used as a real one"
        ),
    }
}

/// The same span, with the length zero rather than overflowing: a
/// partition with no last sector. `end / SECTOR_SIZE - 1` underflows.
#[test]
fn a_zero_length_partition_is_refused_not_underflowed() {
    let mut set = PartitionSet::empty_gpt(DISK_64M);
    set.partitions.push(Partition {
        start: 0,
        length: 0,
        kind: PartitionKind::Gpt {
            type_guid: type_guids::LINUX_FILESYSTEM,
            attributes: 0,
        },
        label: None,
        uuid: Some([8u8; 16]),
        slot: None,
    });

    match set.add(None, ONE_MIB, PartitionTypeId::LinuxFilesystem, None) {
        Err(Error::Invalid(_)) => {}
        other => panic!("adding beside a zero-length partition gave {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The same arithmetic, in the place that writes it to disk
// ---------------------------------------------------------------------------

/// A partition whose `start + length` leaves a `u64`, chosen so the
/// wrapped sum lands somewhere the surrounding checks accept.
///
/// `start` is the last sector of the 64-bit address space and `length`
/// is two sectors, so the sum wraps to 512 and the derived end LBA to
/// zero: below `last_usable`, so the "ends past last usable LBA" test
/// passes, and below `start_lba`, which is exactly the shape no reader
/// will accept. A sum that wrapped to something large would have been
/// caught by that test — accidentally, and only for some inputs.
///
/// `Partition`'s fields are all `pub` and `PartitionSet.partitions` is a
/// `pub Vec`, so a caller can hand these numbers straight to the writers
/// without going through `add`, which bounds them.
fn overflowing_gpt_partition() -> Partition {
    Partition {
        // 2^64 - 512: the last whole sector a u64 can address.
        start: u64::MAX - 511,
        length: 1024,
        kind: PartitionKind::Gpt {
            type_guid: type_guids::LINUX_FILESYSTEM,
            attributes: 0,
        },
        label: Some("overflowing".into()),
        uuid: Some([9u8; 16]),
        slot: None,
    }
}

/// `write_gpt` derived a partition's ending LBA with `(start + length)
/// / SECTOR_SIZE - 1`, unchecked, at three separate sites.
///
/// `mutation.rs` had already fixed this expression once, with a comment
/// saying why: in release, where these crates ship with
/// `overflow-checks` off, it wraps. The copies in the code that writes
/// the table to disk were not updated, and `validate_partition`'s
/// `end_lba > last_usable` test passes trivially once the value has
/// wrapped to something small.
///
/// So in release the crate wrote a table it then refused to read —
/// `ending_lba` below `starting_lba`, both CRCs valid, backup written,
/// and success reported. In debug it panicked. This test fails in both
/// configurations before the fix and passes in both after it, which is
/// the point: the two builds must not disagree.
#[test]
fn write_gpt_refuses_a_span_that_leaves_a_u64_rather_than_wrapping_it() {
    let dev = MemDev::new(DISK_64M as usize);
    match partitions::gpt_write::write_gpt(&dev, &[overflowing_gpt_partition()], [1u8; 16]) {
        Err(Error::Invalid(_)) => {}
        other => panic!(
            "write_gpt gave {other:?} for a partition whose span leaves a u64 — \
             in release that is a committed table with ending_lba < starting_lba"
        ),
    }

    // And nothing reached the disk. A refusal that had already written
    // the header would leave the caller with a half-committed table.
    let mut lba1 = [0u8; 8];
    dev.read_at(512, &mut lba1).unwrap();
    assert_eq!(
        &lba1, b"\0\0\0\0\0\0\0\0",
        "a GPT header was written anyway"
    );
}

/// The overlap pass runs before the entry array is built, and derives
/// the same end. A wrapped end there answers "no overlap" about a
/// partition that does overlap.
#[test]
fn write_gpt_refuses_an_overflowing_span_beside_a_real_partition() {
    let dev = MemDev::new(DISK_64M as usize);
    let sound = Partition {
        start: ONE_MIB,
        length: 4 * ONE_MIB,
        kind: PartitionKind::Gpt {
            type_guid: type_guids::LINUX_FILESYSTEM,
            attributes: 0,
        },
        label: None,
        uuid: Some([3u8; 16]),
        slot: None,
    };
    match partitions::gpt_write::write_gpt(&dev, &[sound, overflowing_gpt_partition()], [1u8; 16]) {
        Err(Error::Invalid(_)) => {}
        other => panic!("write_gpt gave {other:?} for an overflowing span"),
    }
}

/// `write_mbr` carries the same expression. Its `MBR_LBA_MAX` cap
/// happens to reject the inputs that would wrap before the expression
/// runs, so this is a guard against that accident being relied on
/// rather than a live defect — the cap is about the 32-bit on-disk
/// field, not about `u64` arithmetic, and the two are only incidentally
/// aligned.
#[test]
fn write_mbr_refuses_a_span_that_leaves_a_u64() {
    let dev = MemDev::new(DISK_64M as usize);
    let p = Partition {
        start: u64::MAX - 511,
        length: 1024,
        kind: PartitionKind::Mbr {
            type_byte: 0x83,
            active: false,
        },
        label: None,
        uuid: None,
        slot: None,
    };
    match partitions::mbr::write_mbr(&dev, &[p]) {
        Err(Error::Invalid(_)) => {}
        other => panic!("write_mbr gave {other:?} for a partition whose span leaves a u64"),
    }
}

// ---------------------------------------------------------------------------
// A partition's slot in the table is its identity
// ---------------------------------------------------------------------------

/// A partition's slot in the on-disk table is its identity to the rest
/// of the system — the `3` in `/dev/sda3`, the `s3` in `disk4s3`. A GPT
/// with a hole in it is routine: it is what a deletion leaves, and it is
/// the normal state of a macOS disk, where slot numbering is not
/// compacted.
///
/// `write_gpt` wrote each partition into the slot matching its position
/// in the `Vec`, so probe → commit compacted a sparse table into slots
/// 0..n. Nothing about the surviving partitions changed except their
/// numbers, and every fstab entry, boot-loader config and bookmark that
/// named one by number then pointed at a different volume — with the
/// operation reporting success.
#[test]
fn committing_an_unchanged_table_leaves_every_partition_in_its_slot() {
    let dev = MemDev::new(DISK_64M as usize);
    let a = gpt_partition(4 * ONE_MIB, 4 * ONE_MIB, "a", 1, Some(0));
    let c = gpt_partition(16 * ONE_MIB, 4 * ONE_MIB, "c", 3, Some(2));
    partitions::gpt_write::write_gpt(&dev, &[a, c], [5u8; 16]).unwrap();

    let (_, parts) = probe(&dev).unwrap();
    assert_eq!(
        parts.iter().map(|p| p.slot).collect::<Vec<_>>(),
        vec![Some(0), Some(2)],
        "probe must report the slot each entry came from"
    );

    // Round-trip it unchanged.
    let set = PartitionSet::from_probe(&dev).unwrap();
    set.commit(&dev).unwrap();

    let (_, after) = probe(&dev).unwrap();
    assert_eq!(
        after.iter().map(|p| p.slot).collect::<Vec<_>>(),
        vec![Some(0), Some(2)],
        "a commit that changed nothing renumbered the disk"
    );
    let labels: Vec<_> = after.iter().filter_map(|p| p.label.clone()).collect();
    assert_eq!(labels, vec!["a", "c"]);
}

/// Removing a partition must not move the ones after it. `Vec::remove`
/// shifts, and with the slot derived from vector position that shift
/// reached the disk: delete partition 2 of four and 3 and 4 became 2
/// and 3.
#[test]
fn removing_a_partition_does_not_renumber_the_ones_after_it() {
    let dev = MemDev::new(DISK_64M as usize);
    let parts = vec![
        gpt_partition(4 * ONE_MIB, 4 * ONE_MIB, "a", 1, Some(0)),
        gpt_partition(12 * ONE_MIB, 4 * ONE_MIB, "b", 2, Some(1)),
        gpt_partition(20 * ONE_MIB, 4 * ONE_MIB, "c", 3, Some(2)),
    ];
    partitions::gpt_write::write_gpt(&dev, &parts, [5u8; 16]).unwrap();

    let mut set = PartitionSet::from_probe(&dev).unwrap();
    set.remove(PartitionRef::Index(1)).unwrap();
    set.commit(&dev).unwrap();

    let (_, after) = probe(&dev).unwrap();
    let by_label: Vec<(String, Option<u32>)> = after
        .iter()
        .map(|p| (p.label.clone().unwrap_or_default(), p.slot))
        .collect();
    assert_eq!(
        by_label,
        vec![("a".to_string(), Some(0)), ("c".to_string(), Some(2))],
        "deleting the middle partition moved the last one's number"
    );
}

/// A partition that has never been on a disk has no slot, and gets the
/// lowest free one — not the one matching its position in the vector,
/// which is what would collide with an existing entry's number.
#[test]
fn a_new_partition_takes_the_lowest_free_slot() {
    let dev = MemDev::new(DISK_64M as usize);
    let occupied = gpt_partition(20 * ONE_MIB, 4 * ONE_MIB, "kept", 1, Some(2));
    partitions::gpt_write::write_gpt(&dev, &[occupied], [5u8; 16]).unwrap();

    let mut set = PartitionSet::from_probe(&dev).unwrap();
    set.add(
        None,
        4 * ONE_MIB,
        PartitionTypeId::LinuxFilesystem,
        Some("new".into()),
    )
    .unwrap();
    set.commit(&dev).unwrap();

    let (_, after) = probe(&dev).unwrap();
    let mut by_label: Vec<(String, Option<u32>)> = after
        .iter()
        .map(|p| (p.label.clone().unwrap_or_default(), p.slot))
        .collect();
    by_label.sort();
    assert_eq!(
        by_label,
        vec![("kept".to_string(), Some(2)), ("new".to_string(), Some(0))]
    );
}

/// Two partitions cannot claim the same slot: one of them would be
/// written over the other and the table would silently lose a
/// partition.
#[test]
fn two_partitions_claiming_one_slot_are_refused() {
    let dev = MemDev::new(DISK_64M as usize);
    let a = gpt_partition(4 * ONE_MIB, 4 * ONE_MIB, "a", 1, Some(1));
    let b = gpt_partition(12 * ONE_MIB, 4 * ONE_MIB, "b", 2, Some(1));
    match partitions::gpt_write::write_gpt(&dev, &[a, b], [5u8; 16]) {
        Err(Error::Invalid(_)) => {}
        other => panic!("two partitions in slot 1 gave {other:?}"),
    }
}

fn gpt_partition(start: u64, length: u64, label: &str, uuid: u8, slot: Option<u32>) -> Partition {
    Partition {
        start,
        length,
        kind: PartitionKind::Gpt {
            type_guid: type_guids::LINUX_FILESYSTEM,
            attributes: 0,
        },
        label: Some(label.into()),
        uuid: Some([uuid; 16]),
        slot,
    }
}

// ---------------------------------------------------------------------------
// Labels made of more than the basic multilingual plane
// ---------------------------------------------------------------------------

/// A GPT label is 72 bytes of UTF-16, so 36 code units, and a character
/// outside the basic multilingual plane takes two of them. Truncating at
/// 36 units without regard for that leaves a lone high surrogate on
/// disk, and the reader answers `String::from_utf16(..).ok()` — which is
/// `None` for an unpaired surrogate.
///
/// So the label does not come back shortened. It comes back **absent**:
/// a caller that wrote a 35-character name ending in an emoji reads a
/// partition with no name at all, and nothing says why.
#[test]
fn a_label_that_would_split_a_surrogate_pair_is_not_lost() {
    let dev = MemDev::new(DISK_64M as usize);
    // 35 BMP characters, then one that needs a surrogate pair: the pair
    // straddles the 36-unit boundary.
    let label: String = "a".repeat(35) + "\u{1F600}";
    assert_eq!(label.encode_utf16().count(), 37);

    let mut set = PartitionSet::empty_gpt(DISK_64M);
    set.add(
        None,
        4 * ONE_MIB,
        PartitionTypeId::LinuxFilesystem,
        Some(label.clone()),
    )
    .unwrap();
    set.commit(&dev).unwrap();

    let (_, parts) = probe(&dev).unwrap();
    let got = parts[0]
        .label
        .clone()
        .expect("the label was dropped entirely, not shortened");
    assert_eq!(
        got,
        "a".repeat(35),
        "a label must be cut at a character boundary, not inside one"
    );
}

/// A whole astral character fits when there is room for both of its
/// units, and must survive.
#[test]
fn a_label_whose_surrogate_pair_fits_survives_whole() {
    let dev = MemDev::new(DISK_64M as usize);
    let label: String = "a".repeat(34) + "\u{1F600}";
    assert_eq!(label.encode_utf16().count(), 36);

    let mut set = PartitionSet::empty_gpt(DISK_64M);
    set.add(
        None,
        4 * ONE_MIB,
        PartitionTypeId::LinuxFilesystem,
        Some(label.clone()),
    )
    .unwrap();
    set.commit(&dev).unwrap();

    let (_, parts) = probe(&dev).unwrap();
    assert_eq!(parts[0].label.as_deref(), Some(label.as_str()));
}

/// A table another tool wrote can still carry an unpaired surrogate.
/// Showing the rest of the name with one replacement character tells a
/// user more than showing no name at all, so the reader stops throwing
/// the whole label away.
#[test]
fn a_label_another_writer_truncated_mid_pair_is_still_shown() {
    let dev = MemDev::new(DISK_64M as usize);
    let mut set = PartitionSet::empty_gpt(DISK_64M);
    set.add(
        None,
        4 * ONE_MIB,
        PartitionTypeId::LinuxFilesystem,
        Some("data".into()),
    )
    .unwrap();
    set.commit(&dev).unwrap();

    // Overwrite the entry's name with "da" + a lone high surrogate, and
    // repair the CRCs so the table is otherwise valid.
    let entry_array_lba = 2u64;
    let name_off = (entry_array_lba * 512) as usize + 56;
    let mut units: Vec<u16> = "da".encode_utf16().collect();
    units.push(0xD83D); // high surrogate with no low half
    let mut name = vec![0u8; 72];
    for (i, u) in units.iter().enumerate() {
        name[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
    }
    patch_entry_name_and_repair_crcs(&dev, name_off, &name);

    let (_, parts) = probe(&dev).unwrap();
    let got = parts[0].label.clone().expect("the label was dropped");
    assert!(
        got.starts_with("da"),
        "the readable part of the name must survive, got {got:?}"
    );
}

/// Write `name` at `name_off` and recompute the entry-array CRC and the
/// primary header CRC so the table stays valid.
fn patch_entry_name_and_repair_crcs(dev: &MemDev, name_off: usize, name: &[u8]) {
    let mut b = dev.0.lock().unwrap();
    b[name_off..name_off + name.len()].copy_from_slice(name);

    // Header at LBA 1; entry array at the LBA it names.
    let array_lba = u64::from_le_bytes(b[512 + 72..512 + 80].try_into().unwrap()) as usize;
    let count = u32::from_le_bytes(b[512 + 80..512 + 84].try_into().unwrap()) as usize;
    let size = u32::from_le_bytes(b[512 + 84..512 + 88].try_into().unwrap()) as usize;
    let array = &b[array_lba * 512..array_lba * 512 + count * size];
    let array_crc = crc32fast::hash(array);
    b[512 + 88..512 + 92].copy_from_slice(&array_crc.to_le_bytes());

    let header_size = u32::from_le_bytes(b[512 + 12..512 + 16].try_into().unwrap()) as usize;
    b[512 + 16..512 + 20].fill(0);
    let header_crc = crc32fast::hash(&b[512..512 + header_size]);
    b[512 + 16..512 + 20].copy_from_slice(&header_crc.to_le_bytes());
}
