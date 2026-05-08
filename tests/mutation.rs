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
    if let PartitionKind::Gpt { type_guid } = parts[0].kind {
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
        assert_eq!(p.length % ONE_MIB, 0, "length not 1 MiB aligned: {}", p.length);
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
    assert_eq!(p.start, 2 * ONE_MIB, "expected snap to 2 MiB, got {}", p.start);
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
    set.add(None, 4 * ONE_MIB, PartitionTypeId::LinuxFilesystem, Some("a".into()))
        .unwrap();
    let idx = set
        .add(None, 4 * ONE_MIB, PartitionTypeId::LinuxFilesystem, Some("b".into()))
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
    set.add(None, 4 * ONE_MIB, PartitionTypeId::EfiSystem, Some("EFI".into()))
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
    set.add(None, 4 * ONE_MIB, PartitionTypeId::LinuxFilesystem, Some("a".into()))
        .unwrap();
    set.commit(&dev).unwrap();

    let mut reloaded = PartitionSet::from_probe(&dev).unwrap();
    assert_eq!(reloaded.partitions.len(), 1);
    reloaded
        .add(None, 4 * ONE_MIB, PartitionTypeId::LinuxFilesystem, Some("b".into()))
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
    assert!(matches!(parts[0].kind, PartitionKind::Mbr { type_byte: 0x83 }));
    assert!(matches!(parts[1].kind, PartitionKind::Mbr { type_byte: 0x82 }));
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
