//! Bootable-flag plumbing — confirms the MBR active bit and the GPT
//! attributes field round-trip through parse → write → re-parse, and that
//! `Partition::is_bootable()` answers correctly for the three cases that
//! matter to a downstream UI:
//!
//! 1. MBR with the active flag set on one entry → bootable on that entry only.
//! 2. GPT entry with the legacy-BIOS-bootable attribute (bit 2) set →
//!    bootable regardless of type GUID.
//! 3. GPT entry typed as the EFI System Partition GUID → bootable even when
//!    no attribute bits are set.

use fs_core::FileDevice;
use partitions::gpt::{attr, type_guids};
use partitions::{
    gpt_write, mbr, probe, BlockDevice, BlockRead, Partition, PartitionKind, TableKind,
};
use std::sync::Mutex;
use tempfile::tempdir;

/// In-memory BlockDevice mirror of the one in tests/mutation.rs — copied
/// rather than shared so the bootable test file stays self-contained.
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
    fn is_writable(&self) -> bool {
        true
    }
}

/// Build a 4 MiB raw image with a single MBR partition (type 0x83) and the
/// active flag toggled per the argument. Returns the path; the tempdir
/// keeps it alive for the caller.
fn write_mbr_image(active: bool, dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("mbr.img");
    let mut image = vec![0u8; 4 * 1024 * 1024];
    let entry = 0x1BE;
    image[entry] = if active { 0x80 } else { 0x00 };
    image[entry + 4] = 0x83;
    image[entry + 8..entry + 12].copy_from_slice(&2048u32.to_le_bytes());
    image[entry + 12..entry + 16].copy_from_slice(&4096u32.to_le_bytes());
    image[510] = 0x55;
    image[511] = 0xAA;
    std::fs::write(&path, &image).unwrap();
    path
}

#[test]
fn mbr_parse_picks_up_active_flag_when_set() {
    let dir = tempdir().unwrap();
    let path = write_mbr_image(true, dir.path());
    let dev = FileDevice::open(&path).unwrap();
    let (kind, parts) = probe::probe(&dev).unwrap();
    assert_eq!(kind, TableKind::Mbr);
    assert_eq!(parts.len(), 1);
    let p = &parts[0];
    assert!(p.is_bootable());
    match p.kind {
        PartitionKind::Mbr { type_byte, active } => {
            assert_eq!(type_byte, 0x83);
            assert!(active);
        }
        _ => panic!("expected MBR"),
    }
}

#[test]
fn mbr_parse_leaves_active_false_when_unset() {
    let dir = tempdir().unwrap();
    let path = write_mbr_image(false, dir.path());
    let dev = FileDevice::open(&path).unwrap();
    let (_, parts) = probe::probe(&dev).unwrap();
    let p = &parts[0];
    assert!(!p.is_bootable());
    match p.kind {
        PartitionKind::Mbr { active, .. } => assert!(!active),
        _ => panic!("expected MBR"),
    }
}

#[test]
fn mbr_write_round_trip_preserves_active_flag() {
    let dev = MemDev::new(4 * 1024 * 1024);
    let part = Partition {
        start: 2048 * 512,
        length: 4096 * 512,
        kind: PartitionKind::Mbr {
            type_byte: 0x83,
            active: true,
        },
        label: None,
        uuid: None,
    };
    mbr::write_mbr(&dev, &[part]).unwrap();
    let (_, parts) = probe::probe(&dev).unwrap();
    assert_eq!(parts.len(), 1);
    assert!(parts[0].is_bootable());
}

#[test]
fn gpt_efi_system_partition_is_bootable_without_attribute_bit() {
    let p = Partition {
        start: 1 << 20,
        length: 100 << 20,
        kind: PartitionKind::Gpt {
            type_guid: type_guids::EFI_SYSTEM,
            attributes: 0,
        },
        label: Some("EFI".into()),
        uuid: Some([0u8; 16]),
    };
    assert!(p.is_bootable());
}

#[test]
fn gpt_linux_filesystem_with_legacy_bios_bit_is_bootable() {
    let p = Partition {
        start: 1 << 20,
        length: 100 << 20,
        kind: PartitionKind::Gpt {
            type_guid: type_guids::LINUX_FILESYSTEM,
            attributes: attr::LEGACY_BIOS_BOOTABLE,
        },
        label: None,
        uuid: Some([0u8; 16]),
    };
    assert!(p.is_bootable());
}

#[test]
fn gpt_linux_filesystem_with_zero_attributes_is_not_bootable() {
    let p = Partition {
        start: 1 << 20,
        length: 100 << 20,
        kind: PartitionKind::Gpt {
            type_guid: type_guids::LINUX_FILESYSTEM,
            attributes: 0,
        },
        label: None,
        uuid: Some([0u8; 16]),
    };
    assert!(!p.is_bootable());
}

#[test]
fn gpt_write_round_trip_preserves_attributes() {
    // 64 MiB MemDev — enough for primary + backup GPT structures.
    let dev = MemDev::new(64 * 1024 * 1024);
    let disk_guid: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let part_uuid: [u8; 16] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00,
    ];
    let part = Partition {
        start: 34 * 512, // first usable LBA
        length: 8 * 1024 * 1024,
        kind: PartitionKind::Gpt {
            type_guid: type_guids::LINUX_FILESYSTEM,
            attributes: attr::LEGACY_BIOS_BOOTABLE,
        },
        label: Some("ROOT".into()),
        uuid: Some(part_uuid),
    };
    gpt_write::write_gpt(&dev, &[part], disk_guid).unwrap();
    let (kind, parts) = probe::probe(&dev).unwrap();
    assert_eq!(kind, TableKind::Gpt);
    assert_eq!(parts.len(), 1);
    match parts[0].kind {
        PartitionKind::Gpt { attributes, .. } => {
            assert_eq!(
                attributes & attr::LEGACY_BIOS_BOOTABLE,
                attr::LEGACY_BIOS_BOOTABLE,
                "legacy-BIOS-bootable bit must round-trip"
            );
        }
        _ => panic!("expected GPT"),
    }
    assert!(parts[0].is_bootable());
}
