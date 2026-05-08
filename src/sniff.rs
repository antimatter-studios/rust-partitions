//! Filesystem-magic sniffer. Reads a small window from the start of a
//! partition and identifies the filesystem by its on-disk signature. This
//! does NOT validate the filesystem — it just answers "what is this likely
//! to be?" The driver itself does proper validation when mounting.

use crate::error::Result;
use crate::probe::Partition;
use crate::BlockRead;

/// Recognised filesystem signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKind {
    /// ext2 / ext3 / ext4 — superblock magic 0xEF53 at byte 1080. The
    /// `version` field carries the best guess from feature flags.
    Ext { version: ExtVersion },
    /// NTFS — "NTFS    " OEM name at boot-sector offset 3.
    Ntfs,
    /// exFAT — "EXFAT   " OEM name at boot-sector offset 3.
    ExFat,
    /// FAT32 — "FAT32   " in the extended BPB at offset 0x52.
    Fat32,
    /// FAT16 / FAT12 — "FAT16   " or "FAT12   " in the extended BPB at 0x36.
    Fat16,
    /// HFS+ — "H+" or "HX" at offset 1024.
    HfsPlus,
    /// APFS container — "NXSB" at offset 32.
    Apfs,
    /// Linux swap — "SWAPSPACE2" near the end of the first page.
    LinuxSwap,
    /// ISO 9660 — "CD001" at offset 0x8001.
    Iso9660,
    /// SquashFS — "hsqs" little-endian magic at offset 0.
    Squashfs,
    /// Detected nothing recognisable.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtVersion {
    /// Unable to distinguish ext2 vs ext3 vs ext4 — feature flags say no
    /// journal nor any ext4-only features.
    Ext2OrAny,
    /// HAS_JOURNAL set, no ext4-only incompat features → ext3.
    Ext3,
    /// At least one ext4 incompat feature set (extents, 64bit, flex_bg, etc).
    Ext4,
}

/// Sniff the filesystem at the start of `partition`. The partition's `length`
/// determines how much we're allowed to read.
pub fn sniff(dev: &dyn BlockRead, partition: &Partition) -> Result<FsKind> {
    // Largest window we need: 0x8001 + 5 bytes for ISO9660. Round up.
    let want = std::cmp::min(0x8800u64, partition.length) as usize;
    let mut buf = vec![0u8; want];
    dev.read_at(partition.start, &mut buf)?;
    Ok(classify(&buf))
}

/// Stand-alone classifier — exposed for tests and for callers who already
/// have the bytes in hand.
pub fn classify(buf: &[u8]) -> FsKind {
    // SquashFS first — magic at offset 0, cheap.
    if buf.len() >= 4 && &buf[0..4] == b"hsqs" {
        return FsKind::Squashfs;
    }

    // FAT / NTFS / exFAT all start with a BPB-like layout — boot sector at 0,
    // 0x55 0xAA at 510, OEM-ish strings at offset 3.
    if buf.len() >= 512 && buf[510] == 0x55 && buf[511] == 0xAA {
        let oem = &buf[3..11];
        if oem == b"NTFS    " {
            return FsKind::Ntfs;
        }
        if oem == b"EXFAT   " {
            return FsKind::ExFat;
        }
        // FAT32 stores "FAT32   " at offset 0x52 (extended BPB).
        if buf.len() >= 0x5A {
            let fat32_tag = &buf[0x52..0x5A];
            if fat32_tag == b"FAT32   " {
                return FsKind::Fat32;
            }
        }
        // FAT16 / FAT12 store the tag at offset 0x36.
        if buf.len() >= 0x3E {
            let fat16_tag = &buf[0x36..0x3E];
            if fat16_tag == b"FAT16   " || fat16_tag == b"FAT12   " {
                return FsKind::Fat16;
            }
        }
    }

    // ext: superblock at offset 1024, magic 0xEF53 at offset 1080.
    if buf.len() >= 1082 {
        let magic = u16::from_le_bytes([buf[1080], buf[1081]]);
        if magic == 0xEF53 {
            return FsKind::Ext {
                version: classify_ext(buf),
            };
        }
    }

    // HFS+: signature 'H+' (0x4842 BE) or 'HX' at offset 1024.
    if buf.len() >= 1026 {
        let sig = &buf[1024..1026];
        if sig == b"H+" || sig == b"HX" {
            return FsKind::HfsPlus;
        }
    }

    // APFS: container superblock magic 'NXSB' at offset 32.
    if buf.len() >= 36 && &buf[32..36] == b"NXSB" {
        return FsKind::Apfs;
    }

    // Linux swap: 'SWAPSPACE2' at (page_size - 10). Page can be 4096..65536.
    // Probe the common pages.
    for page in [4096usize, 8192, 16384, 32768, 65536] {
        if buf.len() >= page {
            let off = page - 10;
            if &buf[off..off + 10] == b"SWAPSPACE2" {
                return FsKind::LinuxSwap;
            }
        }
    }

    // ISO 9660: 'CD001' at offset 0x8001.
    if buf.len() >= 0x8006 && &buf[0x8001..0x8006] == b"CD001" {
        return FsKind::Iso9660;
    }

    FsKind::Unknown
}

/// Best-effort ext2/3/4 discrimination from the superblock feature flags.
///
/// Layout (offsets relative to start of partition):
///
/// ```text
///   0x400  +0x5C  s_feature_compat   (u32 little-endian)
///   0x400  +0x60  s_feature_incompat
///   0x400  +0x64  s_feature_ro_compat
/// ```
fn classify_ext(buf: &[u8]) -> ExtVersion {
    let sb = 1024usize;
    if buf.len() < sb + 0x68 {
        return ExtVersion::Ext2OrAny;
    }
    let feature_compat = u32::from_le_bytes(buf[sb + 0x5C..sb + 0x60].try_into().unwrap());
    let feature_incompat = u32::from_le_bytes(buf[sb + 0x60..sb + 0x64].try_into().unwrap());

    const EXT3_FEATURE_COMPAT_HAS_JOURNAL: u32 = 0x4;
    // Any of these incompat bits implies ext4.
    const EXT4_INCOMPAT_MASK: u32 = 0x040 // EXTENTS
        | 0x080 // 64BIT
        | 0x100 // MMP
        | 0x200 // FLEX_BG
        | 0x400 // EA_INODE
        | 0x1000 // DIRDATA
        | 0x2000 // BG_USE_META_CSUM
        | 0x4000 // LARGEDIR
        | 0x8000; // INLINE_DATA

    if feature_incompat & EXT4_INCOMPAT_MASK != 0 {
        return ExtVersion::Ext4;
    }
    if feature_compat & EXT3_FEATURE_COMPAT_HAS_JOURNAL != 0 {
        return ExtVersion::Ext3;
    }
    ExtVersion::Ext2OrAny
}
