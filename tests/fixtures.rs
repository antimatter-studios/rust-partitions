//! Integration tests with hand-built MBR / GPT / FS-magic fixtures.

use partitions::gpt::type_guids;
use partitions::sniff::{classify, ExtVersion, FsKind};
use partitions::{
    probe, sniff, BlockRead, Error, OwnedSlice, Partition, PartitionKind, SliceReader, TableKind,
};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// In-memory BlockRead for tests.
// ---------------------------------------------------------------------------

struct Bytes(Mutex<Vec<u8>>);

impl Bytes {
    fn new(size: usize) -> Self {
        Self(Mutex::new(vec![0u8; size]))
    }
    fn write(&self, off: usize, src: &[u8]) {
        let mut b = self.0.lock().unwrap();
        b[off..off + src.len()].copy_from_slice(src);
    }
    fn write_u32_le(&self, off: usize, v: u32) {
        self.write(off, &v.to_le_bytes());
    }
}

impl BlockRead for Bytes {
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

// ---------------------------------------------------------------------------
// MBR fixtures
// ---------------------------------------------------------------------------

fn write_mbr_entry(dev: &Bytes, slot: usize, type_byte: u8, start_lba: u32, sectors: u32) {
    let off = 446 + slot * 16;
    dev.write(off + 4, &[type_byte]);
    dev.write_u32_le(off + 8, start_lba);
    dev.write_u32_le(off + 12, sectors);
}

#[test]
fn mbr_two_primaries() {
    let dev = Bytes::new(4 * 1024 * 1024);
    // partition 0: Linux at LBA 2048, 1 MiB
    write_mbr_entry(&dev, 0, 0x83, 2048, 2048);
    // partition 1: Linux swap at LBA 4096, 1 MiB
    write_mbr_entry(&dev, 1, 0x82, 4096, 2048);
    // signature
    dev.write(510, &[0x55, 0xAA]);

    let (kind, parts) = probe(&dev).unwrap();
    assert_eq!(kind, TableKind::Mbr);
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].start, 2048 * 512);
    assert_eq!(parts[0].length, 2048 * 512);
    assert!(matches!(parts[0].kind, PartitionKind::Mbr { type_byte: 0x83 }));
    assert!(matches!(parts[1].kind, PartitionKind::Mbr { type_byte: 0x82 }));
}

#[test]
fn protective_mbr_without_gpt_is_corrupt() {
    let dev = Bytes::new(4 * 1024 * 1024);
    // only entry: 0xEE spanning the disk
    write_mbr_entry(&dev, 0, 0xEE, 1, (4 * 1024 * 1024 / 512) as u32 - 1);
    dev.write(510, &[0x55, 0xAA]);

    match probe(&dev) {
        Err(Error::GptCorrupt(_)) => {}
        other => panic!("expected GptCorrupt, got {other:?}"),
    }
}

#[test]
fn no_table_at_all() {
    let dev = Bytes::new(4 * 1024 * 1024);
    match probe(&dev) {
        Err(Error::NoPartitionTable) => {}
        other => panic!("expected NoPartitionTable, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// GPT fixtures
// ---------------------------------------------------------------------------

type GptFixtureEntry<'a> = (
    [u8; 16], // type_guid
    [u8; 16], // unique_guid
    u64,      // start_lba
    u64,      // end_lba (inclusive)
    &'a str,  // label
);

/// Lay down a valid GPT (header + entries) at the start of `dev`. Returns the
/// (start_byte, length_byte) of the entry array for callers that want to
/// corrupt it post-hoc.
fn build_gpt_with_entries(dev: &Bytes, entries: &[GptFixtureEntry]) -> (u64, u64) {
    let total_sectors = dev.size_bytes() / 512;

    // Protective MBR.
    dev.write(446 + 4, &[0xEE]);
    dev.write_u32_le(446 + 8, 1); // start_lba = 1
    dev.write_u32_le(446 + 12, (total_sectors - 1) as u32);
    dev.write(510, &[0x55, 0xAA]);

    let num_entries: u32 = 128;
    let entry_size: u32 = 128;
    let array_bytes = (num_entries as u64) * (entry_size as u64);
    let entry_lba = 2u64;
    let entry_offset = entry_lba * 512;

    // Build entry array.
    let mut array = vec![0u8; array_bytes as usize];
    for (i, (type_guid, unique_guid, start_lba, end_lba, label)) in entries.iter().enumerate() {
        let off = i * entry_size as usize;
        array[off..off + 16].copy_from_slice(type_guid);
        array[off + 16..off + 32].copy_from_slice(unique_guid);
        array[off + 32..off + 40].copy_from_slice(&start_lba.to_le_bytes());
        array[off + 40..off + 48].copy_from_slice(&end_lba.to_le_bytes());
        // attributes = 0
        // name UTF-16 LE.
        let name_off = off + 56;
        for (j, c) in label.encode_utf16().enumerate() {
            if j * 2 + 2 > 72 {
                break;
            }
            array[name_off + j * 2..name_off + j * 2 + 2].copy_from_slice(&c.to_le_bytes());
        }
    }
    dev.write(entry_offset as usize, &array);
    let entries_crc = crc32fast::hash(&array);

    // Build header (92 bytes).
    let mut header = [0u8; 512];
    header[0..8].copy_from_slice(b"EFI PART");
    header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // revision
    header[12..16].copy_from_slice(&92u32.to_le_bytes()); // header_size
    // CRC field at 16..20 left zero for now.
    header[20..24].copy_from_slice(&0u32.to_le_bytes()); // reserved
    header[24..32].copy_from_slice(&1u64.to_le_bytes()); // my_lba
    header[32..40].copy_from_slice(&(total_sectors - 1).to_le_bytes()); // alternate_lba
    header[40..48].copy_from_slice(&34u64.to_le_bytes()); // first_usable_lba
    header[48..56].copy_from_slice(&(total_sectors - 34).to_le_bytes()); // last_usable_lba
    header[56..72].copy_from_slice(&[0xCAu8; 16]); // disk_guid
    header[72..80].copy_from_slice(&entry_lba.to_le_bytes());
    header[80..84].copy_from_slice(&num_entries.to_le_bytes());
    header[84..88].copy_from_slice(&entry_size.to_le_bytes());
    header[88..92].copy_from_slice(&entries_crc.to_le_bytes());

    // Compute header CRC over the first 92 bytes (with CRC field zeroed).
    let header_crc = crc32fast::hash(&header[..92]);
    header[16..20].copy_from_slice(&header_crc.to_le_bytes());

    dev.write(512, &header);

    (entry_offset, array_bytes)
}

#[test]
fn gpt_with_two_partitions() {
    let dev = Bytes::new(8 * 1024 * 1024);
    build_gpt_with_entries(
        &dev,
        &[
            (
                type_guids::EFI_SYSTEM,
                [1u8; 16],
                34,
                2081,
                "EFI",
            ),
            (
                type_guids::LINUX_FILESYSTEM,
                [2u8; 16],
                2082,
                4129,
                "rootfs",
            ),
        ],
    );

    let (kind, parts) = probe(&dev).unwrap();
    assert_eq!(kind, TableKind::Gpt);
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].start, 34 * 512);
    assert_eq!(parts[0].length, (2081 - 34 + 1) * 512);
    assert_eq!(parts[0].label.as_deref(), Some("EFI"));
    assert_eq!(parts[1].label.as_deref(), Some("rootfs"));
    if let PartitionKind::Gpt { type_guid } = parts[1].kind {
        assert_eq!(type_guid, type_guids::LINUX_FILESYSTEM);
    } else {
        panic!("expected GPT partition kind");
    }
}

#[test]
fn gpt_header_crc_mismatch() {
    let dev = Bytes::new(8 * 1024 * 1024);
    build_gpt_with_entries(
        &dev,
        &[(type_guids::LINUX_FILESYSTEM, [3u8; 16], 34, 2081, "x")],
    );
    // Flip a byte in the header (not in the CRC field itself).
    dev.write(512 + 24, &[0xFF]); // my_lba LSB
    match probe(&dev) {
        Err(Error::GptHeaderCrc) => {}
        other => panic!("expected GptHeaderCrc, got {other:?}"),
    }
}

#[test]
fn gpt_entries_crc_mismatch() {
    let dev = Bytes::new(8 * 1024 * 1024);
    let (entry_off, _) = build_gpt_with_entries(
        &dev,
        &[(type_guids::LINUX_FILESYSTEM, [4u8; 16], 34, 2081, "x")],
    );
    // Corrupt the entry array.
    dev.write(entry_off as usize + 16, &[0x00, 0x00, 0x00, 0x00]);
    match probe(&dev) {
        Err(Error::GptEntriesCrc) => {}
        other => panic!("expected GptEntriesCrc, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// FS sniff
// ---------------------------------------------------------------------------

#[test]
fn sniff_ext4_with_extents() {
    // Build a 4 KiB buffer with ext4 superblock at 1024.
    let mut buf = vec![0u8; 4096];
    // magic at 1024+0x38 = 1080
    buf[1080] = 0x53;
    buf[1081] = 0xEF;
    // s_feature_incompat at 1024+0x60 = 1120 — set EXTENTS bit (0x40).
    buf[1120..1124].copy_from_slice(&0x40u32.to_le_bytes());
    let kind = classify(&buf);
    assert_eq!(kind, FsKind::Ext { version: ExtVersion::Ext4 });
}

#[test]
fn sniff_ext3_journal_only() {
    let mut buf = vec![0u8; 4096];
    buf[1080] = 0x53;
    buf[1081] = 0xEF;
    // s_feature_compat at 1024+0x5C = 1116 — set HAS_JOURNAL (0x4).
    buf[1116..1120].copy_from_slice(&0x4u32.to_le_bytes());
    let kind = classify(&buf);
    assert_eq!(kind, FsKind::Ext { version: ExtVersion::Ext3 });
}

#[test]
fn sniff_ntfs() {
    let mut buf = vec![0u8; 1024];
    buf[3..11].copy_from_slice(b"NTFS    ");
    buf[510] = 0x55;
    buf[511] = 0xAA;
    assert_eq!(classify(&buf), FsKind::Ntfs);
}

#[test]
fn sniff_exfat() {
    let mut buf = vec![0u8; 1024];
    buf[3..11].copy_from_slice(b"EXFAT   ");
    buf[510] = 0x55;
    buf[511] = 0xAA;
    assert_eq!(classify(&buf), FsKind::ExFat);
}

#[test]
fn sniff_fat32() {
    let mut buf = vec![0u8; 1024];
    buf[0x52..0x5A].copy_from_slice(b"FAT32   ");
    buf[510] = 0x55;
    buf[511] = 0xAA;
    assert_eq!(classify(&buf), FsKind::Fat32);
}

#[test]
fn sniff_fat16() {
    let mut buf = vec![0u8; 1024];
    buf[0x36..0x3E].copy_from_slice(b"FAT16   ");
    buf[510] = 0x55;
    buf[511] = 0xAA;
    assert_eq!(classify(&buf), FsKind::Fat16);
}

#[test]
fn sniff_hfs_plus() {
    let mut buf = vec![0u8; 2048];
    buf[1024..1026].copy_from_slice(b"H+");
    assert_eq!(classify(&buf), FsKind::HfsPlus);
}

#[test]
fn sniff_apfs() {
    let mut buf = vec![0u8; 64];
    buf[32..36].copy_from_slice(b"NXSB");
    assert_eq!(classify(&buf), FsKind::Apfs);
}

#[test]
fn sniff_linux_swap() {
    let mut buf = vec![0u8; 4096];
    buf[4086..4096].copy_from_slice(b"SWAPSPACE2");
    assert_eq!(classify(&buf), FsKind::LinuxSwap);
}

#[test]
fn sniff_squashfs() {
    let mut buf = vec![0u8; 64];
    buf[0..4].copy_from_slice(b"hsqs");
    assert_eq!(classify(&buf), FsKind::Squashfs);
}

#[test]
fn sniff_iso9660() {
    let mut buf = vec![0u8; 0x8800];
    buf[0x8001..0x8006].copy_from_slice(b"CD001");
    assert_eq!(classify(&buf), FsKind::Iso9660);
}

#[test]
fn sniff_unknown() {
    let buf = vec![0u8; 4096];
    assert_eq!(classify(&buf), FsKind::Unknown);
}

#[test]
fn sniff_through_partition_offset() {
    // Whole disk: 16 KiB. Pretend a partition starts at byte 4096 and we
    // wrote an NTFS boot sector there.
    let dev = Bytes::new(16 * 1024);
    dev.write(4096 + 3, b"NTFS    ");
    dev.write(4096 + 510, &[0x55, 0xAA]);

    let part = Partition {
        start: 4096,
        length: 8192,
        kind: PartitionKind::Mbr { type_byte: 0x07 },
        label: None,
        uuid: None,
    };
    let kind = sniff(&dev, &part).unwrap();
    assert_eq!(kind, FsKind::Ntfs);
}

// ---------------------------------------------------------------------------
// SliceReader
// ---------------------------------------------------------------------------

#[test]
fn slice_reader_rebases_offsets() {
    let dev = Bytes::new(8 * 1024);
    dev.write(2000, &[0xAB, 0xCD, 0xEF, 0x01]);

    let slice = SliceReader::new(&dev, 2000, 4);
    assert_eq!(slice.size_bytes(), 4);
    let mut buf = [0u8; 4];
    slice.read_at(0, &mut buf).unwrap();
    assert_eq!(buf, [0xAB, 0xCD, 0xEF, 0x01]);
}

#[test]
fn slice_reader_rejects_out_of_bounds() {
    let dev = Bytes::new(8 * 1024);
    let slice = SliceReader::new(&dev, 0, 16);
    let mut buf = [0u8; 8];
    match slice.read_at(12, &mut buf) {
        Err(fs_core::Error::ShortRead { .. }) => {}
        other => panic!("expected ShortRead, got {other:?}"),
    }
}

#[test]
fn owned_slice_works_through_arc() {
    let dev: Arc<dyn BlockRead> = Arc::new(Bytes::new(8 * 1024));
    {
        // Need to write through a Bytes ref since the Arc<dyn> erases it;
        // here we just test reading zeros.
    }
    let slice = OwnedSlice::new(dev.clone(), 0, 64);
    let mut buf = [1u8; 16];
    slice.read_at(8, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0));
}
