//! C ABI for partition probing and FS sniffing.
//!
//! All functions take a generic
//! [`FsCoreDevice`][fs_core::ffi::FsCoreDevice] handle (from any sister
//! crate's constructor — `qcow2_open`, `fs_core_file_open`, etc.) so
//! callers don't need partition-specific opening logic.
//!
//! Surface:
//!
//! - [`partitions_probe`] → opaque [`PartitionList`] handle
//! - [`partitions_count`] / [`partitions_get`] → enumerate
//! - [`partitions_sniff`] → identify FS at a partition's start
//! - [`partitions_open_slice`] → create a child `FsCoreDevice` over one
//!   partition, ready to feed into a filesystem driver
//! - [`partitions_list_free`] → free the list
//!
//! Everything else (slicing, mounting) goes through the
//! [`FsCoreDevice`][fs_core::ffi::FsCoreDevice] handle, so consumers only
//! learn one device-handle type for the entire stack.

#![allow(clippy::missing_safety_doc)]

use crate::probe::{Partition, PartitionKind, TableKind};
use crate::sniff::{ExtVersion, FsKind};
use crate::{probe, sniff, OwnedSlice};
use fs_core::ffi::{ffi_guard, set_last_error, FsCoreDevice, FsCoreErrorCode};
use std::ffi::CString;
use std::panic::AssertUnwindSafe;
use std::ptr;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Stable numeric enum values for the C side. Do not renumber.
// ---------------------------------------------------------------------------

/// Filesystem kind code returned by [`partitions_sniff`] and stored in
/// [`PartitionInfo`].
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKindCode {
    Unknown = 0,
    Ext2 = 1,
    Ext3 = 2,
    Ext4 = 3,
    Ntfs = 4,
    ExFat = 5,
    Fat32 = 6,
    Fat16 = 7,
    HfsPlus = 8,
    Apfs = 9,
    LinuxSwap = 10,
    Iso9660 = 11,
    Squashfs = 12,
}

impl From<FsKind> for FsKindCode {
    fn from(k: FsKind) -> Self {
        match k {
            FsKind::Unknown => FsKindCode::Unknown,
            FsKind::Ext { version } => match version {
                ExtVersion::Ext2OrAny => FsKindCode::Ext2,
                ExtVersion::Ext3 => FsKindCode::Ext3,
                ExtVersion::Ext4 => FsKindCode::Ext4,
            },
            FsKind::Ntfs => FsKindCode::Ntfs,
            FsKind::ExFat => FsKindCode::ExFat,
            FsKind::Fat32 => FsKindCode::Fat32,
            FsKind::Fat16 => FsKindCode::Fat16,
            FsKind::HfsPlus => FsKindCode::HfsPlus,
            FsKind::Apfs => FsKindCode::Apfs,
            FsKind::LinuxSwap => FsKindCode::LinuxSwap,
            FsKind::Iso9660 => FsKindCode::Iso9660,
            FsKind::Squashfs => FsKindCode::Squashfs,
        }
    }
}

/// Partition table type code.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableKindCode {
    /// No table found.
    None = 0,
    Gpt = 1,
    Mbr = 2,
}

impl From<TableKind> for TableKindCode {
    fn from(t: TableKind) -> Self {
        match t {
            TableKind::Gpt => TableKindCode::Gpt,
            TableKind::Mbr => TableKindCode::Mbr,
        }
    }
}

// ---------------------------------------------------------------------------
// PartitionInfo — POD struct exposed across the FFI boundary.
// ---------------------------------------------------------------------------

/// One partition's worth of data, in a layout suitable for direct C
/// consumption. Lifetime of `label` and `type_guid` is tied to the parent
/// [`PartitionList`] — copy them out before freeing the list.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PartitionInfo {
    pub start: u64,
    pub length: u64,
    /// One of the [`FsKindCode`] discriminants. Filled in only after
    /// [`partitions_sniff`]; otherwise [`FsKindCode::Unknown`].
    pub fs_kind: i32,
    /// One of the [`TableKindCode`] discriminants — duplicated from the
    /// list-level table kind for caller convenience.
    pub table_kind: i32,
    /// GPT partition type GUID (16 bytes), or all zeros for MBR
    /// partitions.
    pub type_guid: [u8; 16],
    /// MBR type byte, or 0 for GPT partitions.
    pub type_byte: u8,
    /// 7 bytes of explicit padding so the struct has a deterministic
    /// layout on every target.
    pub _pad: [u8; 7],
    /// Pointer to a NUL-terminated UTF-8 label, or NULL when the
    /// partition has none. Owned by the [`PartitionList`].
    pub label: *const std::os::raw::c_char,
    /// Length of the label in bytes, excluding the NUL.
    pub label_len: usize,
}

// ---------------------------------------------------------------------------
// PartitionList — opaque to C; owns label CStrings + the parent device.
// ---------------------------------------------------------------------------

pub struct PartitionList {
    table: TableKindCode,
    parent: Arc<dyn fs_core::BlockDevice>,
    entries: Vec<PartitionEntry>,
}

struct PartitionEntry {
    info: PartitionInfo,
    /// Owned label bytes (NUL-terminated). Pointed to by `info.label`.
    /// Held here so the FFI pointer stays valid until the list is freed.
    _label_owner: Option<CString>,
    /// Original Partition for slice/sniff dispatch.
    raw: Partition,
}

// ---------------------------------------------------------------------------
// Entry points.
// ---------------------------------------------------------------------------

/// Probe `device` for a GPT or MBR partition table. On success, `*list_out`
/// holds an opaque list handle; on failure, it's set to NULL and the
/// thread-local last-error has detail.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn partitions_probe(
    device: *const FsCoreDevice,
    list_out: *mut *mut PartitionList,
) -> FsCoreErrorCode {
    if device.is_null() || list_out.is_null() {
        return FsCoreErrorCode::NullArg;
    }
    unsafe {
        *list_out = ptr::null_mut();
    }
    let parent_arc: Arc<dyn fs_core::BlockDevice> = unsafe { (*device).inner().clone() };

    ffi_guard(|| {
        let (table, parts) = probe::probe(&*parent_arc).map_err(|e| {
            // Lift partitions::Error to fs_core::Error::Custom for the
            // last-error message. The error code returned to the C
            // caller will be Custom.
            fs_core::Error::Custom(e.to_string())
        })?;
        let table_code: TableKindCode = table.into();

        let mut entries = Vec::with_capacity(parts.len());
        for raw in parts.into_iter() {
            let mut info = build_info(&raw, table_code);
            let (label_ptr, label_len, owner) = make_label_string(raw.label.as_deref());
            info.label = label_ptr;
            info.label_len = label_len;
            entries.push(PartitionEntry {
                info,
                _label_owner: owner,
                raw,
            });
        }

        let list = Box::new(PartitionList {
            table: table_code,
            parent: parent_arc,
            entries,
        });
        unsafe {
            *list_out = Box::into_raw(list);
        }
        Ok(())
    })
}

/// Number of partitions in the list. NULL list returns 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn partitions_count(list: *const PartitionList) -> usize {
    if list.is_null() {
        return 0;
    }
    unsafe { (*list).entries.len() }
}

/// Which on-disk partition table the list came from.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn partitions_table_kind(list: *const PartitionList) -> i32 {
    if list.is_null() {
        return TableKindCode::None as i32;
    }
    unsafe { (*list).table as i32 }
}

/// Copy the i-th entry into `*out`. Returns `OutOfBounds` for invalid
/// indices, `NullArg` for NULL pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn partitions_get(
    list: *const PartitionList,
    index: usize,
    out: *mut PartitionInfo,
) -> FsCoreErrorCode {
    if list.is_null() || out.is_null() {
        return FsCoreErrorCode::NullArg;
    }
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let l = unsafe { &*list };
        if index >= l.entries.len() {
            return FsCoreErrorCode::OutOfBounds;
        }
        unsafe {
            *out = l.entries[index].info.clone();
        }
        FsCoreErrorCode::Ok
    }));
    match result {
        Ok(rc) => rc,
        Err(_) => {
            set_last_error("panic in partitions_get");
            FsCoreErrorCode::Panic
        }
    }
}

/// Sniff the filesystem at the start of partition `index`. Returns one of
/// the [`FsKindCode`] discriminants as `i32`, or -1 on error (last-error
/// has detail).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn partitions_sniff(list: *const PartitionList, index: usize) -> i32 {
    if list.is_null() {
        set_last_error("partitions_sniff: list is null");
        return -1;
    }
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let l = unsafe { &*list };
        if index >= l.entries.len() {
            set_last_error("partitions_sniff: index out of bounds");
            return -1;
        }
        let raw = &l.entries[index].raw;
        match sniff::sniff(&*l.parent, raw) {
            Ok(kind) => FsKindCode::from(kind) as i32,
            Err(e) => {
                set_last_error(e.to_string());
                -1
            }
        }
    }));
    result.unwrap_or_else(|_| {
        set_last_error("panic in partitions_sniff");
        -1
    })
}

/// Build a child `FsCoreDevice` whose byte 0 maps to the start of
/// partition `index`. Useful for handing one partition to a filesystem
/// driver as if it were a whole disk. Returns NULL on error.
///
/// The returned handle holds an `Arc` to the parent device, so closing
/// the parent before the slice is fine — the slice keeps the parent
/// alive until both are closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn partitions_open_slice(
    list: *const PartitionList,
    index: usize,
) -> *mut FsCoreDevice {
    if list.is_null() {
        set_last_error("partitions_open_slice: list is null");
        return ptr::null_mut();
    }
    let res = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let l = unsafe { &*list };
        if index >= l.entries.len() {
            set_last_error("partitions_open_slice: index out of bounds");
            return ptr::null_mut();
        }
        let raw = &l.entries[index].raw;
        let slice = OwnedSlice::new(l.parent.clone(), raw.start, raw.length);
        FsCoreDevice::into_handle(Arc::new(slice))
    }));
    res.unwrap_or_else(|_| {
        set_last_error("panic in partitions_open_slice");
        ptr::null_mut()
    })
}

/// Free a partition list. Safe to call with NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn partitions_list_free(list: *mut PartitionList) {
    if list.is_null() {
        return;
    }
    let _ = std::panic::catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(list));
    }));
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_label_string(label: Option<&str>) -> (*const std::os::raw::c_char, usize, Option<CString>) {
    match label {
        Some(s) if !s.is_empty() => {
            let cs = CString::new(s.replace('\0', "?")).expect("no NUL after replace");
            let ptr = cs.as_ptr();
            let len = cs.as_bytes().len();
            (ptr, len, Some(cs))
        }
        _ => (ptr::null(), 0, None),
    }
}

fn build_info(p: &Partition, table: TableKindCode) -> PartitionInfo {
    let (type_guid, type_byte) = match p.kind {
        PartitionKind::Gpt { type_guid } => (type_guid, 0u8),
        PartitionKind::Mbr { type_byte } => ([0u8; 16], type_byte),
        PartitionKind::Whole => ([0u8; 16], 0u8),
    };
    PartitionInfo {
        start: p.start,
        length: p.length,
        fs_kind: FsKindCode::Unknown as i32,
        table_kind: table as i32,
        type_guid,
        type_byte,
        _pad: [0u8; 7],
        label: ptr::null(),
        label_len: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs_core::ffi::{fs_core_device_close, FsCoreErrorCode};
    use std::sync::Mutex;

    /// Tiny in-memory device that satisfies fs_core::BlockDevice so the
    /// FFI tests don't need a real qcow2 fixture.
    struct Bytes(Mutex<Vec<u8>>);
    impl fs_core::BlockRead for Bytes {
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
    impl fs_core::BlockDevice for Bytes {}

    fn make_mbr_device() -> *mut FsCoreDevice {
        let mut bytes = vec![0u8; 4 * 1024 * 1024];
        // MBR entry 0: Linux at LBA 2048 (1 MiB), 1 MiB long.
        let off = 446;
        bytes[off + 4] = 0x83;
        bytes[off + 8..off + 12].copy_from_slice(&2048u32.to_le_bytes());
        bytes[off + 12..off + 16].copy_from_slice(&2048u32.to_le_bytes());
        // Signature.
        bytes[510] = 0x55;
        bytes[511] = 0xAA;
        // Plant a faux NTFS BPB inside the partition so sniff returns NTFS.
        let part_start = 2048 * 512;
        bytes[part_start + 3..part_start + 11].copy_from_slice(b"NTFS    ");
        bytes[part_start + 510] = 0x55;
        bytes[part_start + 511] = 0xAA;

        let dev = Bytes(Mutex::new(bytes));
        FsCoreDevice::into_handle(Arc::new(dev))
    }

    #[test]
    fn probe_sniff_slice_round_trip() {
        let dev = make_mbr_device();

        let mut list_ptr: *mut PartitionList = ptr::null_mut();
        let rc = unsafe { partitions_probe(dev, &mut list_ptr) };
        assert_eq!(rc, FsCoreErrorCode::Ok);
        assert!(!list_ptr.is_null());

        unsafe {
            assert_eq!(partitions_count(list_ptr), 1);
            assert_eq!(partitions_table_kind(list_ptr), TableKindCode::Mbr as i32);

            let mut info = std::mem::zeroed::<PartitionInfo>();
            let rc = partitions_get(list_ptr, 0, &mut info);
            assert_eq!(rc, FsCoreErrorCode::Ok);
            assert_eq!(info.start, 2048 * 512);
            assert_eq!(info.length, 2048 * 512);
            assert_eq!(info.type_byte, 0x83);

            let kind = partitions_sniff(list_ptr, 0);
            assert_eq!(kind, FsKindCode::Ntfs as i32);

            // Open a slice device and verify size_bytes equals the
            // partition length.
            let slice = partitions_open_slice(list_ptr, 0);
            assert!(!slice.is_null());
            assert_eq!(fs_core::ffi::fs_core_device_size_bytes(slice), info.length);
            fs_core_device_close(slice);

            partitions_list_free(list_ptr);
            fs_core_device_close(dev);
        }
    }

    #[test]
    fn probe_with_no_table_returns_custom_error() {
        // Plain zero device — no MBR signature, no GPT.
        let dev = Bytes(Mutex::new(vec![0u8; 4096]));
        let h = FsCoreDevice::into_handle(Arc::new(dev));

        let mut list_ptr: *mut PartitionList = ptr::null_mut();
        let rc = unsafe { partitions_probe(h, &mut list_ptr) };
        assert_eq!(rc, FsCoreErrorCode::Custom);
        assert!(list_ptr.is_null());

        unsafe {
            fs_core_device_close(h);
        }
    }
}
