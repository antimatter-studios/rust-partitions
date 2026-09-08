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
        issues: 0,
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
        issues: 0,
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
        issues: 0,
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
        issues: 0,
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
        issues: 0,
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
        issues: 0,
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

// ---------------------------------------------------------------------------
// A commit that changed nothing must leave the table it read alone
// ---------------------------------------------------------------------------

/// Plant one primary entry directly in LBA 0, the way a disk that this
/// crate did not write carries it.
fn plant_mbr_entry(dev: &MemDev, slot: usize, type_byte: u8, start_lba: u32, sectors: u32) {
    let mut b = dev.0.lock().unwrap();
    let off = 446 + slot * 16;
    b[off + 4] = type_byte;
    b[off + 8..off + 12].copy_from_slice(&start_lba.to_le_bytes());
    b[off + 12..off + 16].copy_from_slice(&sectors.to_le_bytes());
    b[510] = 0x55;
    b[511] = 0xAA;
}

/// The four entries as they are on disk: 446..510, the bytes a commit is
/// allowed to rewrite and not allowed to lose.
fn mbr_table(dev: &MemDev) -> [u8; 64] {
    let mut out = [0u8; 64];
    dev.read_at(446, &mut out).unwrap();
    out
}

/// A round trip that changes nothing must change nothing on disk.
///
/// `probe` returns the volumes, deliberately leaving out the extended
/// container: it is a chain of partition tables rather than a
/// filesystem, and reporting it as a volume made sniffing read an EBR
/// and call it an unknown filesystem. `commit` then builds a fresh,
/// all-zero sector and writes only the partitions it was handed, so the
/// entry the filter dropped is not written back. The container's slot
/// comes back as type `0x00`, the EBR chain behind it is still on disk
/// with nothing pointing at it, and every logical partition on the disk
/// is gone as far as any tool is concerned. `commit` returns `Ok(())`.
///
/// Measured before the fix:
///
/// ```text
/// slot1 type before = 0x0f
/// from_probe saw 1 partitions
/// slot1 type after  = 0x00
/// ```
#[test]
fn a_commit_that_changed_nothing_keeps_the_extended_container() {
    let dev = MemDev::new(DISK_64M as usize);
    plant_mbr_entry(&dev, 0, 0x83, 2048, 2048);
    // 0x0F: an extended container, LBA-addressed. Its contents are EBRs.
    plant_mbr_entry(&dev, 1, 0x0F, 8192, 16384);

    let before = mbr_table(&dev);
    let set = PartitionSet::from_probe(&dev).unwrap();
    set.commit(&dev).unwrap();
    let after = mbr_table(&dev);

    assert_eq!(
        after,
        before,
        "a commit that changed nothing rewrote the table; \
         slot 1 type is {:#04x} where it was {:#04x}",
        after[16 + 4],
        before[16 + 4]
    );
}

/// The same round trip on a hybrid MBR, which is what a bootable
/// macOS/Windows USB and most Linux live images carry: a `0xEE` marker
/// beside real entries. Losing it stops firmware taking the hybrid path
/// from seeing the disk as GPT-backed.
///
/// The marker is in slot 0 here and the container above was in slot 1,
/// so between them the entry that has to survive is neither always the
/// first nor always after the volumes.
#[test]
fn a_commit_that_changed_nothing_keeps_a_hybrid_mbrs_marker() {
    let dev = MemDev::new(DISK_64M as usize);
    let total_sectors = (DISK_64M / 512) as u32;
    plant_mbr_entry(&dev, 0, 0xEE, 1, total_sectors - 1);
    plant_mbr_entry(&dev, 1, 0x83, 2048, 2048);
    plant_mbr_entry(&dev, 2, 0xAF, 4096, 2048);

    let before = mbr_table(&dev);
    let set = PartitionSet::from_probe(&dev).unwrap();
    set.commit(&dev).unwrap();
    let after = mbr_table(&dev);

    assert_eq!(
        after, before,
        "a commit that changed nothing rewrote the table; \
         slot 0 type is {:#04x} where it was {:#04x}",
        after[4], before[4]
    );
}

/// An entry `parse` skipped as junk is still not this crate's to erase.
///
/// A type byte that says "volume" with a sector count of zero describes
/// nothing, so the probe drops it — and a commit built only from what
/// the probe returned then zeroes its slot. The rule the writer works
/// to is "put back what the probe did not report", which covers this
/// without anyone having to enumerate the kinds of junk a table can
/// hold; a rule written as "put back containers and markers" would
/// have missed it.
#[test]
fn a_commit_that_changed_nothing_keeps_an_entry_the_probe_skipped() {
    let dev = MemDev::new(DISK_64M as usize);
    plant_mbr_entry(&dev, 0, 0x83, 2048, 2048);
    plant_mbr_entry(&dev, 1, 0x83, 8192, 0);

    let before = mbr_table(&dev);
    let set = PartitionSet::from_probe(&dev).unwrap();
    assert_eq!(
        set.partitions.len(),
        1,
        "the zero-length entry was reported"
    );
    set.commit(&dev).unwrap();

    assert_eq!(
        mbr_table(&dev),
        before,
        "a commit that changed nothing erased the zero-length entry in slot 1"
    );
}

/// A partition added to a probed table does not get given the
/// container's slot.
///
/// The slot search sees the volumes; the container is not one, so a
/// search that is not told about it hands out slot 0 and the new
/// partition is written over the container. This is the compounding
/// half of the same defect: the entry is not merely dropped, its seat
/// is handed to somebody else.
#[test]
fn a_partition_added_to_a_probed_table_does_not_take_the_containers_slot() {
    let dev = MemDev::new(DISK_64M as usize);
    // The container is in slot 0, so the first free slot a search finds
    // without knowing about it is the container's.
    plant_mbr_entry(&dev, 0, 0x0F, 8192, 16384);
    plant_mbr_entry(&dev, 1, 0x83, 2048, 2048);

    let before = mbr_table(&dev);
    let mut set = PartitionSet::from_probe(&dev).unwrap();
    set.add(
        Some(32 * ONE_MIB),
        4 * ONE_MIB,
        PartitionTypeId::LinuxFilesystem,
        None,
    )
    .unwrap();
    set.commit(&dev).unwrap();

    let after = mbr_table(&dev);
    assert_eq!(
        &after[0..16],
        &before[0..16],
        "the added partition was written into the container's slot"
    );
    // And it did land somewhere: slot 2 is the first one free.
    assert_eq!(
        after[2 * 16 + 4],
        0x83,
        "the added partition was not written"
    );
}

/// A table holding a container and three volumes is full, and `add`
/// says so rather than letting `commit` discover it.
///
/// Counting only the volumes makes a fourth one look like it fits. The
/// caller then finishes editing, calls `commit`, and is told there is
/// no free slot — after the work, and in a place that cannot say which
/// partition is the problem.
#[test]
fn a_probed_table_with_a_container_is_full_at_three_volumes() {
    let dev = MemDev::new(DISK_64M as usize);
    plant_mbr_entry(&dev, 0, 0x0F, 2048, 2048);
    plant_mbr_entry(&dev, 1, 0x83, 8192, 2048);
    plant_mbr_entry(&dev, 2, 0x83, 12288, 2048);
    plant_mbr_entry(&dev, 3, 0x83, 16384, 2048);

    let mut set = PartitionSet::from_probe(&dev).unwrap();
    assert_eq!(set.partitions.len(), 3);
    match set.add(None, ONE_MIB, PartitionTypeId::LinuxFilesystem, None) {
        Err(Error::Invalid(m)) => assert!(
            m.contains("full"),
            "the fourth volume was refused for the wrong reason: {m}"
        ),
        other => panic!("a fourth volume beside a container gave {other:?}"),
    }
}

/// The writer counts the preserved entries against the four slots too,
/// and says which limit was hit.
///
/// `assign_slots` would also refuse this, one layer down and as "no
/// free slot left in the table". The count is checked here so the
/// caller is told the table is full rather than told about slots, so
/// the message is asserted and not just the refusal.
#[test]
fn the_mbr_writer_counts_preserved_entries_against_the_four_slots() {
    let dev = MemDev::new(DISK_64M as usize);
    let reserved = [partitions::mbr::ReservedEntry {
        slot: 3,
        bytes: [0u8; 16],
    }];
    let mut parts = Vec::new();
    for i in 0..4u64 {
        parts.push(Partition {
            start: (2 + i) * ONE_MIB,
            length: ONE_MIB,
            kind: PartitionKind::Mbr {
                type_byte: 0x83,
                active: false,
            },
            label: None,
            uuid: None,
            slot: None,
            issues: 0,
        });
    }
    match partitions::mbr::write_mbr_preserving(&dev, &parts, &reserved) {
        Err(Error::Invalid(m)) => assert!(
            m.contains("at most 4 primary partitions"),
            "refused, but not as a full table: {m}"
        ),
        other => panic!("four volumes beside a preserved entry gave {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The table's shape survives a round trip
// ---------------------------------------------------------------------------

use partitions::gpt_write::{self, write_gpt_with_geometry, GptGeometry};

/// The header fields that describe the table's shape.
fn gpt_shape(dev: &MemDev) -> (u32, u32, u64, u64, u64) {
    let mut sector = [0u8; 512];
    dev.read_at(512, &mut sector).unwrap();
    let h = gpt::parse_header(&sector).unwrap();
    (
        h.num_partition_entries,
        h.partition_entry_size,
        h.partition_entry_lba,
        h.first_usable_lba,
        h.last_usable_lba,
    )
}

/// Lay down a GPT in `geometry`'s shape with one partition in it, and
/// assert the header really says so before any test depends on it.
///
/// The fixture is written through the writer's own geometry path rather
/// than by hand. That is worth stating plainly: it means a change that
/// stopped the writer honouring a geometry would show up here as a
/// fixture that is not the shape it asked for, which the assertion
/// below catches — not as a test that quietly checks 128 against 128.
fn build_gpt_shaped(dev: &MemDev, geometry: GptGeometry, start_lba: u64) {
    let p = Partition {
        start: start_lba * 512,
        length: 4 * ONE_MIB,
        kind: PartitionKind::Gpt {
            type_guid: type_guids::LINUX_FILESYSTEM,
            attributes: 0,
        },
        label: Some("data".into()),
        uuid: Some([0x5Au8; 16]),
        slot: Some(0),
        issues: 0,
    };
    write_gpt_with_geometry(dev, &[p], [0x11u8; 16], geometry).unwrap();

    let (entries, size, entry_lba, first, _last) = gpt_shape(dev);
    assert_eq!(entries, geometry.num_entries, "fixture entry count");
    assert_eq!(size, geometry.entry_size, "fixture entry size");
    assert_eq!(entry_lba, geometry.entry_lba, "fixture entry array LBA");
    assert_eq!(
        first,
        geometry.entry_lba + geometry.array_sectors(),
        "fixture first usable LBA"
    );
}

/// A round trip that changes nothing leaves a 256-entry table with 256
/// entries.
///
/// `from_probe` took the disk GUID out of the header and dropped the
/// rest, and `commit` rebuilt the table from pinned constants. A
/// 256-entry disk came back as a 128-entry disk, `Ok(())`, with no
/// diagnostic: half its partition slots gone, and its old backup array
/// stranded inside what the new header calls usable space, where the
/// next partition created can be placed on top of it.
#[test]
fn a_commit_that_changed_nothing_keeps_a_256_entry_table() {
    let dev = MemDev::new(DISK_64M as usize);
    let geometry = GptGeometry {
        num_entries: 256,
        ..GptGeometry::canonical()
    };
    build_gpt_shaped(&dev, geometry, 2048);

    let before = gpt_shape(&dev);
    assert_eq!(before.0, 256);
    assert_eq!(before.3, 66, "a 256-entry array ends at LBA 65");

    let set = PartitionSet::from_probe(&dev).unwrap();
    set.commit(&dev).unwrap();

    assert_eq!(
        gpt_shape(&dev),
        before,
        "a commit that changed nothing reshaped the table"
    );
    let (_, parts) = probe(&dev).unwrap();
    assert_eq!(
        parts.len(),
        1,
        "the partition did not survive the round trip"
    );
}

/// The same round trip on a table smaller than the canonical one, which
/// failed loudly rather than quietly.
///
/// A 64-entry array is 16 sectors, so the first usable LBA is 18 and a
/// partition may legally start at 20. Measured against the pinned 34,
/// `commit` refused it — and blamed the partition, which was fine.
#[test]
fn a_64_entry_table_round_trips_with_a_partition_the_canonical_shape_would_refuse() {
    let dev = MemDev::new(DISK_64M as usize);
    let geometry = GptGeometry {
        num_entries: 64,
        ..GptGeometry::canonical()
    };
    build_gpt_shaped(&dev, geometry, 20);

    let before = gpt_shape(&dev);
    assert_eq!(before.0, 64);
    assert_eq!(before.3, 18, "a 64-entry array ends at LBA 17");

    let set = PartitionSet::from_probe(&dev).unwrap();
    assert_eq!(set.partitions.len(), 1);
    assert_eq!(set.partitions[0].start, 20 * 512);
    set.commit(&dev).unwrap();

    assert_eq!(
        gpt_shape(&dev),
        before,
        "a commit that changed nothing reshaped the table"
    );
    let (_, parts) = probe(&dev).unwrap();
    assert_eq!(parts[0].start, 20 * 512, "the partition moved or vanished");
}

/// A disk that reserves more space than the metadata needs keeps its
/// reservation.
///
/// An alignment gap before the first partition is ordinary — plenty of
/// disks declare a first usable LBA of 2048 — and re-deriving the range
/// from the entry count would hand that reserved space to the next
/// partition added. This is the case that distinguishes "carry the
/// declared range" from "recompute it and hope they match".
#[test]
fn a_declared_usable_range_wider_than_the_metadata_needs_survives() {
    let dev = MemDev::new(DISK_64M as usize);
    let total_sectors = DISK_64M / 512;
    // 8192 rather than 2048: the planner aligns to 1 MiB, which is
    // 2048 sectors, so a reservation of exactly 2048 is one a planner
    // ignoring the declared range would land on anyway. A test whose
    // expected answer is also the wrong code's answer measures nothing.
    let geometry = GptGeometry {
        declared_usable: Some((8192, total_sectors - 8192)),
        ..GptGeometry::canonical()
    };
    build_gpt_shaped_declared(&dev, geometry, 40960);

    let before = gpt_shape(&dev);
    assert_eq!(before.3, 8192, "fixture first usable LBA");
    assert_eq!(before.4, total_sectors - 8192, "fixture last usable LBA");

    let mut set = PartitionSet::from_probe(&dev).unwrap();
    // And the reservation is respected by the planner, not merely
    // copied into the header: a partition added with no hint lands
    // inside the declared range.
    set.add(None, ONE_MIB, PartitionTypeId::LinuxFilesystem, None)
        .unwrap();
    set.commit(&dev).unwrap();

    assert_eq!(
        gpt_shape(&dev),
        before,
        "a commit narrowed the disk's declared usable range"
    );
    let (_, parts) = probe(&dev).unwrap();
    for p in &parts {
        assert!(
            p.start / 512 >= 8192,
            "a partition was placed inside the reserved gap at LBA {}",
            p.start / 512
        );
    }
}

/// As `build_gpt_shaped`, for a geometry whose usable range is declared
/// rather than derived: the first usable LBA is then the declared one.
fn build_gpt_shaped_declared(dev: &MemDev, geometry: GptGeometry, start_lba: u64) {
    let p = Partition {
        start: start_lba * 512,
        length: 4 * ONE_MIB,
        kind: PartitionKind::Gpt {
            type_guid: type_guids::LINUX_FILESYSTEM,
            attributes: 0,
        },
        label: Some("data".into()),
        uuid: Some([0x5Au8; 16]),
        slot: Some(0),
        issues: 0,
    };
    write_gpt_with_geometry(dev, &[p], [0x11u8; 16], geometry).unwrap();
    let (entries, _, _, first, last) = gpt_shape(dev);
    assert_eq!(entries, geometry.num_entries, "fixture entry count");
    let (want_first, want_last) = geometry.declared_usable.expect("a declared range");
    assert_eq!(first, want_first, "fixture first usable LBA");
    assert_eq!(last, want_last, "fixture last usable LBA");
}

// ---------------------------------------------------------------------------
// The smallest disk the writer can describe
// ---------------------------------------------------------------------------

/// `write_gpt` refuses a disk one sector too small, rather than writing
/// a header whose usable range runs backwards.
///
/// The old guard was `total_bytes < (34 + 32 + 1) * 512`, so a 67-sector
/// disk passed it — and then `last_usable_lba` came out as 33, one below
/// the first usable LBA. Both CRCs were correct, so the table was a
/// valid GPT describing an impossible disk, and `validate_partition`
/// would afterwards refuse every partition against that range with a
/// message blaming the partition.
///
/// Two sizes, because a bound is worth two tests: 67 is the last size
/// that must be refused and 68 the first that must be accepted. A guard
/// corrected in the wrong direction passes one and fails the other.
///
/// A 34 KiB disk is not a common thing to partition. What makes this
/// worth a test is that the failure was silent and the output
/// well-formed.
#[test]
fn the_writer_refuses_a_disk_one_sector_too_small_for_its_own_table() {
    let sector = 512usize;
    let dev = MemDev::new(67 * sector);
    match gpt_write::write_gpt(&dev, &[], [0x33u8; 16]) {
        Err(Error::DeviceTooSmall) => {}
        other => panic!("a 67-sector disk gave {other:?}"),
    }

    let dev = MemDev::new(68 * sector);
    gpt_write::write_gpt(&dev, &[], [0x33u8; 16])
        .expect("68 sectors is the smallest disk a canonical table fits on");

    let (_, _, _, first, last) = gpt_shape(&dev);
    assert_eq!(first, 34, "the first usable LBA moved");
    assert_eq!(last, 34, "a 68-sector disk has exactly one usable LBA");
    assert!(
        first <= last,
        "the table describes a usable range that runs backwards: {first}..{last}"
    );
}

// ---------------------------------------------------------------------------
// What "identical" has to mean for a backup
// ---------------------------------------------------------------------------

/// Rewrite the backup entry array through `edit`, then repair the
/// entry-array CRC and the backup header's own CRC so the table stays
/// structurally valid.
///
/// The repair is the point. A backup that fails its CRC is already
/// reported as a mismatch, so a test that skipped it would be measuring
/// the CRC check rather than the comparison.
fn edit_backup_entries(dev: &MemDev, edit: impl FnOnce(&mut [u8])) {
    let total = dev.size_bytes();
    let last_lba = total / 512 - 1;
    let header_off = last_lba * 512;

    let mut header = [0u8; 512];
    dev.read_at(header_off, &mut header).unwrap();
    let array_lba = u64::from_le_bytes(header[72..80].try_into().unwrap());
    let count = u32::from_le_bytes(header[80..84].try_into().unwrap()) as usize;
    let size = u32::from_le_bytes(header[84..88].try_into().unwrap()) as usize;
    let header_size = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;

    let mut array = vec![0u8; count * size];
    dev.read_at(array_lba * 512, &mut array).unwrap();
    edit(&mut array);
    dev.write_at(array_lba * 512, &array).unwrap();

    header[88..92].copy_from_slice(&crc32fast::hash(&array).to_le_bytes());
    header[16..20].fill(0);
    let crc = crc32fast::hash(&header[..header_size]);
    header[16..20].copy_from_slice(&crc.to_le_bytes());
    dev.write_at(header_off, &header).unwrap();
}

/// A backup that files the same partition in a different slot is not
/// identical to the primary.
///
/// `slot` is a partition's identity to everything above this crate —
/// the `3` in `/dev/sda3` — which is why both parsers take it from the
/// entry's array index rather than from its position in the list. A
/// backup that disagrees about it renumbers the disk the moment
/// firmware or a recovery tool falls back to it, and every fstab entry
/// and boot-loader config naming a partition by number is then wrong.
///
/// Everything else about the partition is untouched and both CRCs are
/// repaired, so the only thing this can be detecting is the slot.
#[test]
fn a_backup_that_moves_a_partition_to_another_slot_is_a_mismatch() {
    let dev = MemDev::new(DISK_64M as usize);
    let mut set = PartitionSet::empty_gpt(DISK_64M);
    set.add(
        None,
        4 * ONE_MIB,
        PartitionTypeId::LinuxFilesystem,
        Some("root".into()),
    )
    .unwrap();
    set.commit(&dev).unwrap();

    let (_, primary) = probe(&dev).unwrap();
    assert_eq!(primary[0].slot, Some(0), "the fixture's slot moved");
    assert_eq!(gpt::validate_backup(&dev, &primary), BackupStatus::Ok);

    edit_backup_entries(&dev, |array| {
        let (first, rest) = array.split_at_mut(128);
        let seventh = &mut rest[6 * 128..7 * 128];
        seventh.copy_from_slice(first);
        first.fill(0);
    });

    match gpt::validate_backup(&dev, &primary) {
        BackupStatus::Mismatch(m) => assert_eq!(
            m, "partition slot differs",
            "reported a mismatch, but not the one that is there"
        ),
        BackupStatus::Ok => {
            panic!("a backup that renumbers the disk was called identical to the primary")
        }
    }
}

/// A backup that names a partition something else is not identical
/// either.
#[test]
fn a_backup_that_renames_a_partition_is_a_mismatch() {
    let dev = MemDev::new(DISK_64M as usize);
    let mut set = PartitionSet::empty_gpt(DISK_64M);
    set.add(
        None,
        4 * ONE_MIB,
        PartitionTypeId::LinuxFilesystem,
        Some("root".into()),
    )
    .unwrap();
    set.commit(&dev).unwrap();

    let (_, primary) = probe(&dev).unwrap();
    assert_eq!(primary[0].label.as_deref(), Some("root"));

    edit_backup_entries(&dev, |array| {
        // The name field is 72 bytes of UTF-16LE at offset 56.
        let name = &mut array[56..128];
        name.fill(0);
        for (i, u) in "IMPOSTOR".encode_utf16().enumerate() {
            name[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
    });

    match gpt::validate_backup(&dev, &primary) {
        BackupStatus::Mismatch(m) => assert_eq!(
            m, "partition label differs",
            "reported a mismatch, but not the one that is there"
        ),
        BackupStatus::Ok => panic!("a backup that renames a partition was called identical"),
    }
}

/// A backup that agrees in all five fields is still `Ok`.
///
/// The acceptance control for the two above: comparing more fields is
/// only an improvement if a genuinely identical backup still passes,
/// and a comparison that reported a mismatch for everything would
/// satisfy both refusals while making the function useless.
#[test]
fn a_backup_that_agrees_in_every_field_is_still_ok() {
    let dev = MemDev::new(DISK_64M as usize);
    let mut set = PartitionSet::empty_gpt(DISK_64M);
    set.add(
        None,
        4 * ONE_MIB,
        PartitionTypeId::LinuxFilesystem,
        Some("root".into()),
    )
    .unwrap();
    set.add(
        None,
        2 * ONE_MIB,
        PartitionTypeId::LinuxSwap,
        Some("swap".into()),
    )
    .unwrap();
    set.commit(&dev).unwrap();

    let (_, primary) = probe(&dev).unwrap();
    assert_eq!(primary.len(), 2);
    // Rewriting the array with no change still repairs the CRCs, so
    // this also says the harness itself does not disturb the table.
    edit_backup_entries(&dev, |_| {});
    assert_eq!(gpt::validate_backup(&dev, &primary), BackupStatus::Ok);
}
