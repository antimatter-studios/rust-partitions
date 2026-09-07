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
            (type_guids::EFI_SYSTEM, [1u8; 16], 34, 2081, "EFI"),
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
    if let PartitionKind::Gpt { type_guid, .. } = parts[1].kind {
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
    assert_eq!(
        kind,
        FsKind::Ext {
            version: ExtVersion::Ext4
        }
    );
}

#[test]
fn sniff_ext3_journal_only() {
    let mut buf = vec![0u8; 4096];
    buf[1080] = 0x53;
    buf[1081] = 0xEF;
    // s_feature_compat at 1024+0x5C = 1116 — set HAS_JOURNAL (0x4).
    buf[1116..1120].copy_from_slice(&0x4u32.to_le_bytes());
    let kind = classify(&buf);
    assert_eq!(
        kind,
        FsKind::Ext {
            version: ExtVersion::Ext3
        }
    );
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
        kind: PartitionKind::Mbr {
            type_byte: 0x07,
            active: false,
        },
        label: None,
        uuid: None,
        slot: None,
        issues: 0,
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

/// Rewrite the GPT header's `partition_entry_lba` and restamp its CRC.
///
/// The header CRC is a checksum, not a signature: anyone who can change
/// a field can recompute it. So a hostile header is a well-formed
/// header with hostile numbers in it, and the CRC check catches none of
/// them.
fn set_partition_entry_lba(dev: &Bytes, lba: u64) {
    let mut header = [0u8; 512];
    dev.read_at(512, &mut header).unwrap();
    header[72..80].copy_from_slice(&lba.to_le_bytes());
    header[16..20].fill(0);
    let crc = crc32fast::hash(&header[..92]);
    header[16..20].copy_from_slice(&crc.to_le_bytes());
    dev.write(512, &header);
}

/// `partition_entry_lba` is multiplied by the sector size to find where
/// the entry array lives. Fifteen lines below, `starting_lba` is
/// multiplied by the same constant with `checked_mul`; this one was not.
#[test]
fn an_entry_array_lba_that_overflows_a_byte_offset_is_refused() {
    let dev = Bytes::new(8 * 1024 * 1024);
    build_gpt_with_entries(
        &dev,
        &[(type_guids::LINUX_FILESYSTEM, [3u8; 16], 34, 2081, "data")],
    );
    set_partition_entry_lba(&dev, u64::MAX);

    match probe(&dev) {
        Err(_) => {}
        Ok(what) => panic!("an entry array at LBA 2^64-1 was accepted: {what:?}"),
    }
}

/// A partition that does not fit inside the device it was found on.
///
/// `probe` still reports it -- what a table says is worth showing even
/// when it is wrong -- but a slice built on it would report an
/// impossible size to whatever filesystem driver is stacked on it.
#[test]
fn a_partition_reaching_past_the_device_is_still_reported() {
    let dev = Bytes::new(8 * 1024 * 1024);
    let past_the_end = (8 * 1024 * 1024 / 512) + 4096;
    build_gpt_with_entries(
        &dev,
        &[(
            type_guids::LINUX_FILESYSTEM,
            [4u8; 16],
            34,
            past_the_end,
            "toolong",
        )],
    );

    let (_, parts) = probe(&dev).expect("the table itself parses");
    assert_eq!(parts.len(), 1);
    assert!(
        parts[0].start + parts[0].length > dev.size_bytes(),
        "the fixture does not actually reach past the device"
    );
}

// ---------------------------------------------------------------------------
// MBR entries that are not volumes
// ---------------------------------------------------------------------------

/// An extended-partition container is not a volume. Its contents are a
/// linked list of EBRs — partition tables, not a filesystem — and this
/// crate does not walk that chain yet.
///
/// Reporting the container in the same list as the real partitions is
/// not "we do not report logical partitions yet", it is "we report the
/// container as if it were one of them": sniffing it reads an EBR and
/// calls it an unknown filesystem, and slicing it hands a driver the
/// chain.
#[test]
fn an_extended_container_is_not_reported_as_a_volume() {
    for container in [0x05u8, 0x0F] {
        let dev = Bytes::new(16 * 1024 * 1024);
        write_mbr_entry(&dev, 0, 0x83, 2048, 2048); // a real partition
        write_mbr_entry(&dev, 1, container, 8192, 16384); // the container
        dev.write(510, &[0x55, 0xAA]);

        let (kind, parts) = probe(&dev).unwrap();
        assert_eq!(kind, TableKind::Mbr);
        assert_eq!(
            parts.len(),
            1,
            "type {container:#04x}: the extended container was reported as a volume"
        );
        assert_eq!(parts[0].start, 2048 * 512);

        // The container is still visible to a caller that wants the raw
        // table rather than the volumes on it.
        let every = partitions::mbr::parse_all_entries(&mbr_sector(&dev)).unwrap();
        assert_eq!(every.len(), 2, "type {container:#04x}");
        assert!(matches!(
            every[1].kind,
            PartitionKind::Mbr { type_byte, .. } if type_byte == container
        ));
    }
}

/// A hybrid MBR — a `0xEE` entry alongside real entries mirroring some
/// of the GPT partitions — is what every bootable macOS/Windows dual-boot
/// USB and most Linux live images carry. `is_protective` requires exactly
/// one non-empty entry, so it says no, and the probe falls through to the
/// MBR parser.
///
/// The `0xEE` entry is a marker saying "the real table is the GPT", never
/// a volume. Handed back as a partition it spans the whole disk and
/// overlaps every real one.
#[test]
fn a_hybrid_mbrs_protective_entry_is_not_reported_as_a_volume() {
    let dev = Bytes::new(16 * 1024 * 1024);
    let total_sectors = (16 * 1024 * 1024 / 512) as u32;
    write_mbr_entry(&dev, 0, 0xEE, 1, total_sectors - 1);
    write_mbr_entry(&dev, 1, 0x83, 2048, 2048);
    write_mbr_entry(&dev, 2, 0xAF, 4096, 2048);
    dev.write(510, &[0x55, 0xAA]);

    let (kind, parts) = probe(&dev).unwrap();
    assert_eq!(kind, TableKind::Mbr);
    assert_eq!(
        parts.len(),
        2,
        "the whole-disk 0xEE marker was reported as a volume beside the real ones"
    );
    for p in &parts {
        assert!(
            !matches!(
                p.kind,
                PartitionKind::Mbr {
                    type_byte: 0xEE,
                    ..
                }
            ),
            "a 0xEE entry reached the volume list"
        );
    }
}

/// The first 512 bytes of a device, for the `mbr` module's own entry
/// points.
fn mbr_sector(dev: &Bytes) -> [u8; 512] {
    let mut sector = [0u8; 512];
    dev.read_at(0, &mut sector).unwrap();
    sector
}

// ---------------------------------------------------------------------------
// Sniffing a partition that runs off the end of its device
// ---------------------------------------------------------------------------

/// A partition running past the end of the device it was found on is
/// ordinary rather than hostile — a `dd` of the first part of a disk, or
/// a table left stale after the volume was shrunk, produces one. The C
/// ABI's `slice_on_device` says exactly that and clamps the length so a
/// caller reads what is there.
///
/// `sniff` did not clamp. It asked the parent device for a full window
/// at the partition's declared start, and `read_at` is all-or-nothing,
/// so the same partition that `partitions_open_slice` opens happily came
/// back from `partitions_sniff` as a short read. A consumer's UI then has
/// to explain why a partition it can open has no detectable filesystem.
///
/// The shape is not rare: a small ESP or BIOS-boot partition at the tail
/// of a `dd`-ed image is shorter than the 34 KiB window on its own.
#[test]
fn a_partition_running_off_the_end_is_still_sniffed() {
    const DEVICE: usize = 1024 * 1024;
    const START: u64 = DEVICE as u64 - 8 * 1024;
    let dev = Bytes::new(DEVICE);

    // A recognisable superblock at the partition's start.
    dev.write(START as usize + 3, b"NTFS    ");
    dev.write(START as usize + 510, &[0x55, 0xAA]);

    let part = Partition {
        start: START,
        // Four megabytes claimed, eight kilobytes present.
        length: 4 * 1024 * 1024,
        kind: PartitionKind::Mbr {
            type_byte: 0x07,
            active: false,
        },
        label: None,
        uuid: None,
        slot: Some(0),
        issues: 0,
    };

    assert_eq!(
        sniff::sniff(&dev, &part).expect("a truncated partition must still be classified"),
        FsKind::Ntfs
    );
}

/// A partition whose start is past the end of the device has nothing to
/// read, and stays an error. Clamping the window must not turn "there is
/// no such region" into "an unrecognised filesystem".
#[test]
fn a_partition_beginning_past_the_end_is_still_an_error() {
    let dev = Bytes::new(1024 * 1024);
    let part = Partition {
        start: 4 * 1024 * 1024,
        length: 1024 * 1024,
        kind: PartitionKind::Mbr {
            type_byte: 0x83,
            active: false,
        },
        label: None,
        uuid: None,
        slot: Some(0),
        issues: 0,
    };
    assert!(
        sniff::sniff(&dev, &part).is_err(),
        "a partition outside the device must not be classified"
    );
}

// ---------------------------------------------------------------------------
// GPT entries against the header's usable range, and against each other
// ---------------------------------------------------------------------------

impl fs_core::BlockDevice for Bytes {}

/// A table holding the three shapes the rules exist for: a healthy
/// entry, one overlapping it, and one sitting on top of the GPT itself.
fn gpt_with_broken_entries(dev: &Bytes) {
    build_gpt_with_entries(
        dev,
        &[
            (type_guids::LINUX_FILESYSTEM, [1u8; 16], 2048, 4095, "a"),
            (
                type_guids::LINUX_FILESYSTEM,
                [2u8; 16],
                3000,
                5000,
                "overlaps-a",
            ),
            (
                type_guids::LINUX_FILESYSTEM,
                [3u8; 16],
                1,
                33,
                "on-top-of-the-gpt",
            ),
        ],
    );
}

/// Every entry is returned, and each one says which rules it breaks.
///
/// Refusing the whole table would make a damaged disk unreadable as well
/// as uneditable, which is the opposite of what somebody looking at one
/// needs. So `probe` stays total and the policy moves up — but the
/// caller is told, which it was not before.
#[test]
fn a_gpt_entry_reports_the_rules_it_breaks() {
    use partitions::gpt::entry_issue;

    let dev = Bytes::new(8 * 1024 * 1024);
    gpt_with_broken_entries(&dev);

    let (kind, parts) = probe(&dev).unwrap();
    assert_eq!(kind, TableKind::Gpt);
    assert_eq!(parts.len(), 3, "every entry is still returned");

    assert_eq!(
        parts[0].issues,
        entry_issue::OVERLAPS_ANOTHER,
        "the first entry is legal except that the second sits on it"
    );
    assert_eq!(
        parts[1].issues,
        entry_issue::OVERLAPS_ANOTHER,
        "and so is the second, the other way round"
    );
    assert_eq!(
        parts[2].issues,
        entry_issue::BEFORE_FIRST_USABLE,
        "LBA 1..33 is the header and the entry array, not usable space"
    );

    assert!(entry_issue::describe(parts[2].issues).contains("first usable"));
}

/// A table whose entries all obey the rules reports nothing.
///
/// The positive control: without it, a bug that set every bit on every
/// entry would pass the test above.
#[test]
fn a_healthy_gpt_reports_no_issues() {
    let dev = Bytes::new(8 * 1024 * 1024);
    build_gpt_with_entries(
        &dev,
        &[
            (type_guids::EFI_SYSTEM, [1u8; 16], 34, 2081, "EFI"),
            (
                type_guids::LINUX_FILESYSTEM,
                [2u8; 16],
                2082,
                4129,
                "rootfs",
            ),
        ],
    );
    let (_, parts) = probe(&dev).unwrap();
    assert!(
        parts.iter().all(|p| p.issues == 0),
        "a healthy table must report nothing: {:?}",
        parts.iter().map(|p| p.issues).collect::<Vec<_>>()
    );
}

/// An entry that ends past the last usable LBA is reported as such.
#[test]
fn a_gpt_entry_running_into_the_backup_table_is_reported() {
    use partitions::gpt::entry_issue;

    let dev = Bytes::new(1024 * 1024);
    let total_sectors = 1024 * 1024 / 512;
    // last_usable_lba is total_sectors - 34; run one sector past it.
    build_gpt_with_entries(
        &dev,
        &[(
            type_guids::LINUX_FILESYSTEM,
            [1u8; 16],
            34,
            total_sectors - 33,
            "into-the-backup",
        )],
    );
    let (_, parts) = probe(&dev).unwrap();
    assert_eq!(parts[0].issues, entry_issue::PAST_LAST_USABLE);
}

/// The C ABI reports the same thing, and refuses to hand out a slice for
/// an entry that breaks a rule.
///
/// This is the call that turns a bad entry into damage. The slice for
/// the entry on LBA 1..33 is 16,896 bytes starting at 512 — the GPT
/// header and the whole entry array — and a consumer handed it and told
/// to format destroys the very table that described it.
#[test]
fn the_c_abi_reports_issues_and_refuses_a_slice_for_a_broken_entry() {
    use partitions::capi::*;
    use partitions::gpt::entry_issue;
    use std::ptr;
    use std::sync::Arc;

    let dev = Bytes::new(8 * 1024 * 1024);
    gpt_with_broken_entries(&dev);
    let handle = fs_core::ffi::FsCoreDevice::into_handle(Arc::new(dev));

    let mut list: *mut PartitionList = ptr::null_mut();
    let rc = unsafe { partitions_probe(handle, &mut list) };
    assert_eq!(rc, fs_core::ffi::FsCoreErrorCode::Ok);
    assert_eq!(unsafe { partitions_count(list) }, 3);

    let mut info = std::mem::MaybeUninit::<PartitionInfo>::uninit();
    let rc = unsafe { partitions_get(list, 2, info.as_mut_ptr()) };
    assert_eq!(rc, fs_core::ffi::FsCoreErrorCode::Ok);
    let info = unsafe { info.assume_init() };
    assert_eq!(info.issues, entry_issue::BEFORE_FIRST_USABLE);
    assert_eq!(info.start, 512, "the slice would start at the GPT header");

    // The healthy-but-overlapped entry is refused too, and the sound
    // arithmetic of its slice is not the point: acting on either half of
    // an overlapping pair writes over the other.
    for index in 0..3 {
        let slice = unsafe { partitions_open_slice(list, index) };
        assert!(
            slice.is_null(),
            "index {index} breaks a rule and must not be opened"
        );
    }

    unsafe { partitions_list_free(list) };
    unsafe { fs_core::ffi::fs_core_device_close(handle) };
}

/// A slice is still handed out for an entry that breaks nothing.
#[test]
fn the_c_abi_still_opens_a_slice_for_a_sound_entry() {
    use partitions::capi::*;
    use std::ptr;
    use std::sync::Arc;

    let dev = Bytes::new(8 * 1024 * 1024);
    build_gpt_with_entries(
        &dev,
        &[(type_guids::LINUX_FILESYSTEM, [1u8; 16], 2048, 4095, "sound")],
    );
    let handle = fs_core::ffi::FsCoreDevice::into_handle(Arc::new(dev));

    let mut list: *mut PartitionList = ptr::null_mut();
    assert_eq!(
        unsafe { partitions_probe(handle, &mut list) },
        fs_core::ffi::FsCoreErrorCode::Ok
    );
    let slice = unsafe { partitions_open_slice(list, 0) };
    assert!(!slice.is_null(), "a sound entry must still open");

    unsafe { fs_core::ffi::fs_core_device_close(slice) };
    unsafe { partitions_list_free(list) };
    unsafe { fs_core::ffi::fs_core_device_close(handle) };
}

/// A `Bytes` that accepts writes, for the commit half of a round trip.
struct WritableBytes(Bytes);

impl BlockRead for WritableBytes {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_core::Result<()> {
        self.0.read_at(offset, buf)
    }
    fn size_bytes(&self) -> u64 {
        self.0.size_bytes()
    }
}
impl fs_core::BlockDevice for WritableBytes {
    fn write_at(&self, offset: u64, buf: &[u8]) -> fs_core::Result<()> {
        self.0.write(offset as usize, buf);
        Ok(())
    }
    fn flush(&self) -> fs_core::Result<()> {
        Ok(())
    }
    fn is_writable(&self) -> bool {
        true
    }
}

/// Whatever `probe` returns for a damaged table, `commit` accepts back
/// once the caller has removed the entries the table itself says are
/// wrong.
///
/// This is the part a user actually runs into. The reader and the writer
/// disagreed about what a legal table is, so a disk in this state could
/// not be edited at all: measured before the change, removing either one
/// of the two illegal entries still failed to commit, and the error named
/// the other one —
///
/// ```text
/// remove the overlapping entry -> commit Err("partition starts before first usable LBA")
/// remove the on-top-of-GPT one -> commit Err("partitions overlap")
/// ```
///
/// — with nothing in what `probe` returned to say which entries those
/// were. Now the entries say so themselves, so "remove what the table
/// reports as broken" is a rule a caller can follow.
#[test]
fn removing_exactly_the_entries_that_report_issues_makes_the_table_committable() {
    use partitions::{PartitionRef, PartitionSet};

    let dev = WritableBytes(Bytes::new(8 * 1024 * 1024));
    gpt_with_broken_entries(&dev.0);

    let mut set = PartitionSet::from_probe(&dev).unwrap();
    assert_eq!(set.partitions.len(), 3);

    // Remove every entry the table reports as broken, highest index
    // first so the earlier indices stay valid.
    let broken: Vec<usize> = set
        .partitions
        .iter()
        .enumerate()
        .filter(|(_, p)| p.issues != 0)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(broken, vec![0, 1, 2], "all three are implicated");
    for &i in broken.iter().rev() {
        set.remove(PartitionRef::Index(i)).unwrap();
    }

    set.commit(&dev).expect("the remaining table must commit");

    // And the disk reads back as what was left.
    let (kind, parts) = probe(&dev).unwrap();
    assert_eq!(kind, TableKind::Gpt);
    assert!(parts.is_empty());
}

/// The narrower version of the same round trip: one sound entry among
/// the broken ones survives.
#[test]
fn a_sound_entry_survives_removing_the_broken_ones() {
    use partitions::{PartitionRef, PartitionSet};

    let dev = WritableBytes(Bytes::new(8 * 1024 * 1024));
    build_gpt_with_entries(
        &dev.0,
        &[
            (type_guids::LINUX_FILESYSTEM, [1u8; 16], 2048, 4095, "sound"),
            (
                type_guids::LINUX_FILESYSTEM,
                [2u8; 16],
                1,
                33,
                "on-top-of-the-gpt",
            ),
        ],
    );

    let mut set = PartitionSet::from_probe(&dev).unwrap();
    let broken: Vec<usize> = set
        .partitions
        .iter()
        .enumerate()
        .filter(|(_, p)| p.issues != 0)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(broken, vec![1], "only the second entry breaks a rule");
    set.remove(PartitionRef::Index(1)).unwrap();
    set.commit(&dev).expect("the sound entry must commit");

    let (_, parts) = probe(&dev).unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].label.as_deref(), Some("sound"));
    assert_eq!(parts[0].issues, 0);
}

// ---------------------------------------------------------------------------
// Each rule, pinned on its own
//
// The three-entry fixture above exercises the whole set at once, which
// is not the same as exercising each mechanism. These four reach the
// cases it cannot: a nested entry the sorted-neighbour pass alone would
// miss, the start-wraps-the-end hazard, and the last value each bound
// must accept.
// ---------------------------------------------------------------------------

/// An entry entirely inside another, not adjacent to it once sorted by
/// start, is still an overlap.
///
/// Sorted by start the entries are X(100..10000), Y(200..300),
/// Z(9000..9100). The neighbour pairs are (X, Y), which overlap, and
/// (Y, Z), which do not — 9000 is past 300. Z sits wholly inside X and
/// no neighbour pair says so, which is why `mark_overlaps` carries the
/// highest end seen so far as well as the previous one.
#[test]
fn an_entry_nested_inside_another_is_reported_as_overlapping() {
    use partitions::gpt::entry_issue;

    let dev = Bytes::new(16 * 1024 * 1024);
    build_gpt_with_entries(
        &dev,
        &[
            (type_guids::LINUX_FILESYSTEM, [1u8; 16], 100, 10_000, "long"),
            (type_guids::LINUX_FILESYSTEM, [2u8; 16], 200, 300, "early"),
            (
                type_guids::LINUX_FILESYSTEM,
                [3u8; 16],
                9_000,
                9_100,
                "swallowed",
            ),
        ],
    );
    let (_, parts) = probe(&dev).unwrap();
    assert!(
        parts[2].issues & entry_issue::OVERLAPS_ANOTHER != 0,
        "the entry nested inside the long one must be reported: issues={:#x}",
        parts[2].issues
    );
    assert!(
        parts[0].issues & entry_issue::OVERLAPS_ANOTHER != 0,
        "and so must the one it is nested in"
    );
}

/// Two entries sharing exactly one sector overlap.
///
/// The last value that is still an overlap, and the one a `<=` written
/// as `<` would let through — touching by a single sector is the shape
/// an off-by-one in a partition editor produces.
#[test]
fn two_entries_sharing_exactly_one_sector_overlap() {
    use partitions::gpt::entry_issue;

    let dev = Bytes::new(8 * 1024 * 1024);
    build_gpt_with_entries(
        &dev,
        &[
            (type_guids::LINUX_FILESYSTEM, [1u8; 16], 2048, 4095, "first"),
            (
                type_guids::LINUX_FILESYSTEM,
                [2u8; 16],
                4095,
                6000,
                "touching",
            ),
        ],
    );
    let (_, parts) = probe(&dev).unwrap();
    assert_eq!(parts[0].issues, entry_issue::OVERLAPS_ANOTHER);
    assert_eq!(parts[1].issues, entry_issue::OVERLAPS_ANOTHER);
}

/// Two entries that merely abut do not overlap.
///
/// The first value that is not an overlap, so the pair with the test
/// above bounds the rule from both sides: a `<=` written as `<` fails
/// the one, and a `<` written as `<=` fails this one, which would
/// report every back-to-back partition on a healthy disk.
#[test]
fn two_entries_that_merely_abut_do_not_overlap() {
    let dev = Bytes::new(8 * 1024 * 1024);
    build_gpt_with_entries(
        &dev,
        &[
            (type_guids::LINUX_FILESYSTEM, [1u8; 16], 2048, 4095, "first"),
            (type_guids::LINUX_FILESYSTEM, [2u8; 16], 4096, 6000, "next"),
        ],
    );
    let (_, parts) = probe(&dev).unwrap();
    assert!(
        parts.iter().all(|p| p.issues == 0),
        "back-to-back partitions are the normal shape of a disk: {:?}",
        parts.iter().map(|p| p.issues).collect::<Vec<_>>()
    );
}

/// An entry ending on exactly the last usable LBA is legal.
///
/// The last value the upper bound must accept. Without it, `end_lba >
/// last_usable` written as `>=` — one sector too strict — would reject
/// the last partition on every fully-allocated disk, with a green
/// suite.
#[test]
fn an_entry_ending_on_the_last_usable_lba_is_legal() {
    let dev = Bytes::new(1024 * 1024);
    let total_sectors = 1024 * 1024 / 512;
    let last_usable = total_sectors - 34;
    build_gpt_with_entries(
        &dev,
        &[(
            type_guids::LINUX_FILESYSTEM,
            [1u8; 16],
            34,
            last_usable,
            "right-up-to-the-edge",
        )],
    );
    let (_, parts) = probe(&dev).unwrap();
    assert_eq!(
        parts[0].issues, 0,
        "an entry ending on the last usable LBA breaks nothing"
    );
}

/// An entry that starts well past the disk is reported rather than
/// hidden.
///
/// The far-outside case, which is what a stale table left by a shrink
/// looks like. It is deliberately not the boundary case — that is
/// `an_entry_ending_on_the_last_usable_lba_is_legal` above, and the two
/// together bound the rule.
#[test]
fn an_entry_starting_past_the_disk_is_reported() {
    use partitions::gpt::entry_issue;

    let dev = Bytes::new(1024 * 1024);
    build_gpt_with_entries(
        &dev,
        &[(
            type_guids::LINUX_FILESYSTEM,
            [1u8; 16],
            1_000_000,
            1_000_001,
            "past-the-end",
        )],
    );
    let (_, parts) = probe(&dev).unwrap();
    assert_eq!(
        parts.len(),
        1,
        "the entry is still returned, so the caller can see it"
    );
    assert_eq!(parts[0].issues, entry_issue::PAST_LAST_USABLE);
}

// ---------------------------------------------------------------------------
// 4Kn disks
//
// A disk with 4096-byte *logical* sectors counts its GPT LBAs in
// 4096-byte units, so its header is at byte 4096 and byte 512 is still
// inside LBA 0 — the tail of the protective MBR, all zeros. The
// signature test therefore finds nothing, while LBA 0 still carries a
// protective MBR, because the MBR structure lives in the first 512
// bytes of the block whatever the block size.
// ---------------------------------------------------------------------------

/// Lay down a GPT in 4096-byte LBAs. `my_lba` and the header CRC are
/// parameters so the detection's individual conditions can be pinned.
fn build_gpt_4kn(dev: &Bytes, my_lba: u64, repair_crc: bool) {
    const BS: u64 = 4096;
    let total_lbas = dev.size_bytes() / BS;

    dev.write(446 + 4, &[0xEE]);
    dev.write_u32_le(446 + 8, 1);
    dev.write_u32_le(446 + 12, (total_lbas - 1) as u32);
    dev.write(510, &[0x55, 0xAA]);

    let num_entries: u32 = 128;
    let entry_size: u32 = 128;
    let entry_lba = 2u64;
    let mut array = vec![0u8; (num_entries as u64 * entry_size as u64) as usize];
    array[0..16].copy_from_slice(&type_guids::LINUX_FILESYSTEM);
    array[16..32].copy_from_slice(&[7u8; 16]);
    array[32..40].copy_from_slice(&256u64.to_le_bytes());
    array[40..48].copy_from_slice(&511u64.to_le_bytes());
    dev.write((entry_lba * BS) as usize, &array);

    let mut header = vec![0u8; BS as usize];
    header[0..8].copy_from_slice(b"EFI PART");
    header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    header[12..16].copy_from_slice(&92u32.to_le_bytes());
    header[24..32].copy_from_slice(&my_lba.to_le_bytes());
    header[32..40].copy_from_slice(&(total_lbas - 1).to_le_bytes());
    header[40..48].copy_from_slice(&34u64.to_le_bytes());
    header[48..56].copy_from_slice(&(total_lbas - 34).to_le_bytes());
    header[56..72].copy_from_slice(&[0xCAu8; 16]);
    header[72..80].copy_from_slice(&entry_lba.to_le_bytes());
    header[80..84].copy_from_slice(&num_entries.to_le_bytes());
    header[84..88].copy_from_slice(&entry_size.to_le_bytes());
    header[88..92].copy_from_slice(&crc32fast::hash(&array).to_le_bytes());
    if repair_crc {
        let hc = crc32fast::hash(&header[..92]);
        header[16..20].copy_from_slice(&hc.to_le_bytes());
    }
    dev.write(BS as usize, &header);
}

/// A healthy 4Kn GPT disk is refused by name, not reported as corrupt.
///
/// Before this it came back as
/// `GptCorrupt("protective MBR present but no GPT signature")` — a
/// perfectly sound disk described as a broken table, which sends a user
/// looking for damage that is not there.
#[test]
fn a_4kn_gpt_disk_is_refused_by_its_sector_size() {
    let dev = Bytes::new(64 * 1024 * 1024);
    build_gpt_4kn(&dev, 1, true);
    match probe(&dev) {
        Err(Error::UnsupportedSectorSize(msg)) => {
            assert!(
                msg.contains("4096"),
                "the refusal must name the size: {msg}"
            );
        }
        other => panic!("expected UnsupportedSectorSize, got {other:?}"),
    }
}

/// The detection needs a header whose CRC checks out.
///
/// Byte 4096 on a 512-byte-sector disk is inside the entry array, where
/// an entry's type GUID could in principle read as `EFI PART`. Random
/// bytes will not also carry a valid header CRC, so the CRC is what
/// makes a false positive impossible — and a false positive here would
/// refuse a healthy 512-byte disk, which is worse than the bug.
#[test]
fn a_bad_header_crc_at_byte_4096_is_not_taken_for_a_4kn_disk() {
    let dev = Bytes::new(64 * 1024 * 1024);
    build_gpt_4kn(&dev, 1, false); // CRC left wrong
    assert!(
        !matches!(probe(&dev), Err(Error::UnsupportedSectorSize(_))),
        "a header that fails its own CRC must not be read as a 4Kn disk"
    );
}

/// And a header that does not claim to be at LBA 1.
///
/// A header at byte 4096 says `my_lba == 1` only when LBA 1 *is* byte
/// 4096. Anything else is not a 4Kn primary header, whatever else is
/// true of it.
#[test]
fn a_header_at_byte_4096_claiming_another_lba_is_not_a_4kn_disk() {
    let dev = Bytes::new(64 * 1024 * 1024);
    build_gpt_4kn(&dev, 8, true);
    assert!(
        !matches!(probe(&dev), Err(Error::UnsupportedSectorSize(_))),
        "my_lba must be 1 for a header at byte 4096 to mean 4Kn"
    );
}

/// The positive control: an ordinary 512-byte-sector GPT disk is
/// untouched by the new check.
///
/// Its entry array covers byte 4096, so this is the case a careless
/// detection would break — and it is the commonest disk there is.
#[test]
fn an_ordinary_512_byte_gpt_disk_is_not_taken_for_a_4kn_disk() {
    let dev = Bytes::new(8 * 1024 * 1024);
    build_gpt_with_entries(
        &dev,
        &[(type_guids::LINUX_FILESYSTEM, [1u8; 16], 2048, 4095, "data")],
    );
    let (kind, parts) = probe(&dev).expect("a 512-byte GPT disk must still probe");
    assert_eq!(kind, TableKind::Gpt);
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].start, 2048 * 512);
}
