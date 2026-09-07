/*
 * am-partitions C ABI — GPT/MBR partition probe and FS-magic sniffer
 * over any FsCoreDevice handle.
 *
 * Workflow:
 *   1. Get an FsCoreDevice* from any sister crate (qcow2_open,
 *      fs_core_file_open, ...).
 *   2. partitions_probe(dev, &list)  -> opaque PartitionList*
 *   3. partitions_count(list), partitions_get(list, i, &info) -> enumerate
 *   4. partitions_sniff(list, i)     -> identify FS at partition start
 *   5. partitions_open_slice(list, i)-> child FsCoreDevice* over one
 *                                       partition (feed to a fs driver)
 *   6. fs_core_device_close(slice), partitions_list_free(list),
 *      fs_core_device_close(dev)
 *
 * Link with libam_partitions.a and include this header alongside fs_core.h.
 *
 * MIT license. (c) 2026 Antimatter Studios.
 */

#ifndef AM_PARTITIONS_H
#define AM_PARTITIONS_H

#include "fs_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Filesystem-kind codes returned by partitions_sniff and stored in
 * PartitionInfo.fs_kind. Stable: do not renumber.
 * ------------------------------------------------------------------------- */

typedef enum {
    PART_FS_UNKNOWN     = 0,
    PART_FS_EXT2        = 1,
    PART_FS_EXT3        = 2,
    PART_FS_EXT4        = 3,
    PART_FS_NTFS        = 4,
    PART_FS_EXFAT       = 5,
    PART_FS_FAT32       = 6,
    PART_FS_FAT16       = 7,
    PART_FS_HFS_PLUS    = 8,
    PART_FS_APFS        = 9,
    PART_FS_LINUX_SWAP  = 10,
    PART_FS_ISO9660     = 11,
    PART_FS_SQUASHFS    = 12,
} PartitionsFsKind;

typedef enum {
    PART_TABLE_NONE = 0,
    PART_TABLE_GPT  = 1,
    PART_TABLE_MBR  = 2,
} PartitionsTableKind;

/* -------------------------------------------------------------------------
 * PartitionInfo — POD struct copied out by partitions_get. The `label`
 * pointer (when non-NULL) and `type_guid` are owned by the parent
 * PartitionList; copy them out before `partitions_list_free`.
 *
 * This declaration mirrors, field for field, the #[repr(C)] struct of the
 * same name in src/capi.rs. partitions_get writes a whole struct through
 * the `out` pointer, so a mismatch here is a buffer overrun in the caller,
 * not a compile error. tests/c_abi.rs compiles this header and static-
 * asserts sizeof and every offsetof against the values Rust reports; keep
 * the two in step or that test fails.
 * ------------------------------------------------------------------------- */

typedef struct {
    uint64_t       start;           /* byte offset on the parent device */
    uint64_t       length;          /* bytes */
    int32_t        fs_kind;         /* one of PartitionsFsKind */
    int32_t        table_kind;      /* one of PartitionsTableKind */
    uint8_t        type_guid[16];   /* GPT type GUID, or zeros for MBR */
    uint8_t        type_byte;       /* MBR type byte, or 0 for GPT */
    uint8_t        _pad[7];         /* alignment */
    const char    *label;           /* NUL-terminated UTF-8, or NULL */
    size_t         label_len;       /* bytes excluding the NUL */
    uint8_t        bootable;        /* 1 = MBR active flag, GPT legacy-BIOS
                                     * bootable attribute, or GPT type ==
                                     * EFI System Partition; else 0 */
    uint8_t        _pad2[7];        /* alignment */
    uint64_t       attributes;      /* GPT attributes (entry offset +48);
                                     * 0 for MBR and whole-device entries */
    int32_t        slot;            /* the entry's slot in the on-disk table —
                                     * the partition's number to the rest of
                                     * the system — or -1 when it has none.
                                     * A table with a hole in it is routine,
                                     * so the index passed to partitions_get
                                     * is not the partition's number */
    uint32_t       issues;          /* which of the table's own rules this
                                     * entry breaks, as PartitionsEntryIssue
                                     * bits; 0 when it breaks none. Occupies
                                     * what used to be four bytes of padding,
                                     * so the struct's size and every other
                                     * field's offset are unchanged. A
                                     * non-zero value does not mean the
                                     * partition cannot be read; it means the
                                     * entry disagrees with the header that
                                     * describes it, and partitions_open_slice
                                     * will refuse it */
} PartitionInfo;

/* -------------------------------------------------------------------------
 * PartitionInfo.issues bits.
 *
 * A partition table is bytes off a disk, so an entry that breaks a rule is
 * an ordinary thing to be handed. They are reported per entry rather than
 * refusing the whole table, because refusing would make a damaged disk
 * unreadable as well as uneditable — which is the opposite of what somebody
 * looking at one needs.
 * ------------------------------------------------------------------------- */

#define PARTITIONS_ENTRY_OK                    0u
/* Starts before the header's first usable LBA — inside the protective MBR,
 * the GPT header itself, or the entry array. */
#define PARTITIONS_ENTRY_BEFORE_FIRST_USABLE   (1u << 0)
/* Ends past the header's last usable LBA — inside the backup entry array or
 * the backup header. */
#define PARTITIONS_ENTRY_PAST_LAST_USABLE      (1u << 1)
/* Shares at least one sector with another entry in the same table. */
#define PARTITIONS_ENTRY_OVERLAPS_ANOTHER      (1u << 2)

/* -------------------------------------------------------------------------
 * Opaque PartitionList. Allocated by partitions_probe, freed via
 * partitions_list_free.
 * ------------------------------------------------------------------------- */

typedef struct PartitionList PartitionList;

/* -------------------------------------------------------------------------
 * Entry points.
 * ------------------------------------------------------------------------- */

FsCoreErrorCode  partitions_probe(const FsCoreDevice *device,
                                   PartitionList **list_out);
size_t           partitions_count(const PartitionList *list);
int32_t          partitions_table_kind(const PartitionList *list);
FsCoreErrorCode  partitions_get(const PartitionList *list,
                                 size_t index,
                                 PartitionInfo *out);
/* Returns one of PartitionsFsKind, or -1 on error (last-error has detail). */
int32_t          partitions_sniff(const PartitionList *list, size_t index);
/* Sniff the whole device (no partition table). Returns one of PartitionsFsKind, or -1 on error. */
int32_t          partitions_sniff_device(const FsCoreDevice *device,
                                          uint64_t device_size_bytes);
/* Returns NULL on error (last-error has detail). */
FsCoreDevice   *partitions_open_slice(const PartitionList *list, size_t index);
void             partitions_list_free(PartitionList *list);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AM_PARTITIONS_H */
