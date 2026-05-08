# partitions

Pure-Rust partition-table probe and filesystem-magic sniffer over any
random-access block source.

## What it does

Given a `BlockRead` (a tiny trait: `read_at(offset, buf)` + `size_bytes()`),
this crate tells you:

1. Is there a GPT or MBR partition table?
2. What partitions exist? (start, length, type, label, UUID)
3. For each partition, what filesystem signature is at the start?

It does **not** mount anything, decode files, or write — it's a probe.

## Status

### Read side (probe + sniff)

- [x] GPT primary header (signature, CRC32 validation, entry array)
- [x] GPT backup header read + validate, with primary/backup mismatch reporting (`gpt::parse_backup`, `gpt::validate_backup` returning `BackupStatus::Ok` / `Mismatch`)
- [x] MBR with GPT-protective fallthrough
- [x] FS sniff: ext2/3/4, NTFS, exFAT, FAT16, FAT32, HFS+, APFS, Linux swap, ISO 9660, SquashFS
- [x] `SliceReader` adapter — rebases offsets on a sub-range of any `BlockRead`
- [x] C ABI for FFI (`partitions_probe`, `partitions_count`, `partitions_table_kind`, `partitions_get`, `partitions_sniff`, `partitions_open_slice`, `partitions_list_free`; header in `include/partitions.h`)
- [ ] LVM / LUKS / mdraid detection
- [ ] Logical-partition (extended MBR) chain walking

### Write side (table mutation)

- [x] GPT writer: protective MBR + primary header + entry array + backup mirror at end of disk, all CRCs computed correctly (`gpt_write::write_gpt`)
- [x] MBR writer (`mbr::write_mbr`, four primary entries)
- [x] Mutation API: `add` / `remove` / `resize` over an in-memory partition set, with 1 MiB alignment and a first-fit free-space finder (`PartitionSet`)
- [x] `commit(&dev)` semantics — writes happen on commit, not on mutation
- [x] Round-trip tests: probe → mutate → commit → re-probe matches intent (`tests/mutation.rs`)
- [ ] C ABI for the writer — the existing `partitions_*` handle stays read-only; a writable handle is a follow-up
- [ ] Optional `with_boot_code` variant of the MBR / protective-MBR writer for legacy BIOS boot

## Use

```rust
use partitions::{probe, sniff, BlockRead, FileBlock};

let dev = FileBlock::open("disk.img")?;
let parts = probe(&dev)?;
for p in &parts {
    let kind = sniff(&dev, p)?;
    println!("{} bytes @ {} -> {:?}", p.length, p.start, kind);
}
```

## Layout

```
src/
  lib.rs        public API + BlockRead/BlockDevice + FileBlock + SliceReader
  error.rs      Error / Result
  gpt.rs        GPT header + entry array parser, backup-header validator
  gpt_write.rs  GPT writer (protective MBR + primary + backup, CRCs)
  mbr.rs        MBR parser + writer
  mutation.rs   PartitionSet — in-memory add/remove/resize + commit
  sniff.rs      filesystem magic-byte sniffer
  probe.rs      top-level dispatch (try GPT, fall back to MBR)
tests/
  fixtures.rs   hand-built GPT/MBR + sniff fixtures
  mutation.rs   round-trip mutate/commit/re-probe tests
```

## License

MIT.
