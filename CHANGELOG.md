# Changelog

Notable changes to `am-partitions`, newest first. This is a `0.x` crate, so the
**minor** is the compatibility boundary: a minor bump may break API, a patch
never does.

## [Unreleased]

### Added

- **The parsers are fuzzed, on two tiers.** This crate is the first thing
  to touch an untrusted disk — it reads sector 0 before anything has
  established what the device even is, and whatever it decides sends the
  bytes to some other parser — and nothing here had a fuzz target.
  `fuzz/` holds four `cargo-fuzz` targets and runs nightly on a bounded
  budget; `tests/fuzz_decoders.rs` is the gate, replaying and mutating the
  same corpus deterministically on the stable toolchain in a fifth of a
  second.

  The corpus is five disks `sgdisk` and `sfdisk` wrote — an ordinary GPT,
  one with sixteen entries, one carrying a real filesystem, an MBR with
  four primaries, and an MBR with an extended container and a logical
  chain — at 256 KiB each, which is a whole disk as far as a partition
  table is concerned. Plus the window `classify` reads, cut from
  filesystems `mke2fs`, `mkfs.vfat`, `mkswap` and `mksquashfs` wrote.

  Two of the tests are oracles rather than fuel.
  `every_committed_disk_probes_to_the_table_the_tool_wrote` checks the
  table kind and partition count against what the tool actually wrote.
  `the_sniffer_agrees_with_the_tool_that_made_each_window` checks each
  classification against the tool that produced the filesystem — both on
  a machine with none of those tools installed (#125).

- **This crate's tables are checked against `sgdisk`, `sfdisk`, `blkid` and
  `partx`.** `tests/oracle_tools.rs` builds every table shape the crate can
  write and requires the reference tools to report it field by field -- table
  type, partition count, start and end LBA, size, type GUID and type byte,
  unique GUID, name, attributes, disk GUID, and that both GPT headers verify
  -- then has `sgdisk` and `sfdisk` write tables and requires this crate to
  read the same values back. 775 field comparisons over nine tests, each with
  a floor on the number it made, so a parsing change cannot reduce the oracle
  to nothing. A missing tool fails naming the package that carries it; it
  never skips. Behind the `oracle` feature, because the macOS and Windows CI
  legs have none of these tools (#119).

- **The backup GPT is consulted, and the caller is told.** `probe_with_status`
  returns the table kind, the partitions and a `TableSource`: the primary with
  the backup agreeing, the primary with a stale or damaged backup, or
  partitions recovered from the backup because the primary could not be read.
  A disk whose first sectors were overwritten read as unpartitioned, where
  gdisk, parted and Linux recover it, and a stale backup was never reported.
  `probe` is unchanged. The C ABI's `partitions_probe` now probes this way,
  and `partitions_table_source` returns the source as
  `PartitionsTableSource` (#30).

### Fixed

- **An MBR commit keeps the boot code and the disk identifier.**
  `write_mbr_preserving` built a fresh all-zero sector, so a probe-then-commit
  that edited nothing zeroed bytes 0..446 of LBA 0: the boot code a BIOS
  executes, and the 32-bit disk identifier at 440..444 that Linux turns into
  every `PARTUUID` on the disk. Measured against `sfdisk --dump` on an image
  it wrote, `label-id: 0xb05958d4` came back `0x00000000` and `blkid` stopped
  reporting a `PTUUID` at all. The sector now starts as the one on the device,
  with only the four entries rebuilt; a blank device still reads as zeros, so
  a table being created is written exactly as before (#101).
- **An MBR entry whose sectors did not change keeps its CHS bytes.** The
  writer zeroed the legacy first/last CHS fields of every entry it wrote, so
  the same unchanged commit rewrote `00 20 21 00 83 41 01 00` as
  `00 00 00 00 83 00 00 00`. An entry whose start and length are unchanged
  keeps the CHS pair it came with; a new or moved one still gets zeros, which
  is unchanged behaviour (#101).
- **The protective MBR's ending CHS is the disk's last block, not always
  `FF FF FF`.** The UEFI specification asks for the CHS address of the last
  logical block, and `FF FF FF` only when that cannot be represented; this
  crate wrote `FF FF FF` on every disk. Measured against `sgdisk` 1.0.10 on
  the same images, byte for byte: 8 MiB `05 04 01`, 64 MiB `28 20 08`,
  512 MiB `45 04 41`, and `FF FF FF` only from about 7.8 GiB up, where the
  cylinder passes the ten bits a CHS address has. `mbr::chs_for_lba` is the
  conversion, in the 255x63 geometry every tool assumes (#119).
- **A GPT commit keeps a hybrid disk's narrow `0xEE` marker.** #66 kept the
  mirrored entries and the boot code but still rebuilt the marker from the
  device's size, so a commit that changed nothing widened `sgdisk -h`'s
  marker over LBA 1..2047 into one over the whole disk -- swallowing the
  mirrored entry beside it, which is a malformed hybrid MBR rather than a
  hybrid one. A hybrid LBA 0 now keeps its marker byte for byte, like every
  other entry there. A bare protective MBR is still rebuilt from the device's
  size, so a resized image does not keep a stale marker and earn `sfdisk`'s
  `GPT PMBR size mismatch` (#119).
- **`probe` reads LBA 1 instead of guessing from the device size.** A
  device reporting a size below 1024 bytes -- `FileDevice` over a raw
  device node reports 0 -- had LBA 1 skipped, so an intact GPT was called
  "protective MBR present but no GPT signature", and the entry-array
  bound refused it too. LBA 1 is now read, and only a read past the end,
  or a device that stated its small size, means there is none; a size of
  0 no longer bounds the entry array (#37).
- **A 4Kn GPT header larger than 512 bytes is still recognised as 4Kn.**
  The 4Kn check read a 512-byte sector at byte 4096 and `parse_header`
  capped `header_size` at 512, while a header may fill its 4096-byte
  logical block. Such a disk was reported as a corrupt table instead of
  refused by its sector size. The check now reads the whole block and
  accepts a `header_size` up to it (#75).
- **A GPT commit keeps a hybrid disk's MBR.** A hybrid (a GPT with
  partitions mirrored into LBA 0, as Boot Camp and isohybrid images carry)
  was probed as GPT, and every commit -- including one that changed
  nothing -- replaced LBA 0 with a bare protective MBR, erasing the
  mirrored entries and the boot code. `from_probe` now records LBA 0's
  entries for a GPT set, and the writer keeps the boot code and each
  mirror whose partition is still written, and puts the `0xEE` marker back
  in the slot it came from. A set built from scratch still writes a bare
  protective MBR (#66, #82).
- **A new partition is not placed over an MBR extended container.** `add`,
  `find_free`, `resize` and the MBR writer's overlap pass walked only the
  volumes, and the container is a preserved entry, so `add` placed a
  partition over it and `commit` returned `Ok(())`. `ReservedEntry::span`
  gives each preserved entry's range -- none for a `0xEE` marker, by type,
  or an entry with no sectors -- and all four now respect it (#67).
- **Two GPT entries sharing a UUID no longer trade entry tails on commit.**
  `PartitionSet` keeps each wide entry's tail bytes keyed by UUID, so a
  cloned table with a duplicate UUID kept one tail for both, and a commit
  wrote it into both entries -- or, with one removed, gave the survivor
  the other's. `from_probe` now refuses such a table with `GptCorrupt`
  when the two tails differ; identical tails still round-trip, and
  `probe` still reads the table (#81).
- **A GPT image nested in an MBR disk no longer makes the disk "4Kn".**
  `probe` refused any disk whose byte 4096 parsed as a GPT header with
  `my_lba == 1`, which a disk image stored at LBA 7 of an ordinary MBR
  disk provides, so the outer disk's partitions were unreachable behind
  `UnsupportedSectorSize`. The 4Kn check now runs only when LBA 0
  carries a `0xEE` GPT marker, alone or in a hybrid, so a 4Kn hybrid is
  still refused by name (#68).
- **`slot` is documented as zero-based.** `Partition::slot`,
  `PartitionInfo.slot` and `include/partitions.h` said the slot *was* the
  `3` in `/dev/sda3`, while the value is the entry's zero-based position
  in the table, one lower. The value is unchanged; the docs now say the
  system's number is `slot + 1`, and a test pins slots 0 and 1 for the
  first two partitions written on both table types (#57).
- **`PartitionSet::commit_mut` records the slots a commit assigned.**
  `commit` takes `&self`, so a partition given the lowest free slot on
  disk still said `slot: None` in the set; after removing a partition in
  a lower slot, committing again moved it — slot 2 became slot 0 with
  nothing about it changed. `commit_mut` writes, flushes, and only then
  stores each partition's slot. `commit` is unchanged and documents the
  hazard (#69).
- **`Partition::issues` follows `remove` and `resize` on a GPT set.**
  The flags were computed once by `probe`, so removing one of an
  overlapping pair left the survivor reporting `OVERLAPS_ANOTHER`, and
  shrinking an entry back inside the usable range left
  `PAST_LAST_USABLE` set. The overlap bit is now re-derived from the set
  after either edit, and a successful resize clears `PAST_LAST_USABLE`
  on the entry it changed. MBR entries still carry no issues (#73).
- **`PartitionSet::add` and `resize` document the rounding they do.**
  Both round a length up to the next 1 MiB, not the next sector as their
  docs said (`add(None, 4096)` gives 1 MiB; `resize` to 512 bytes gives
  1 MiB), and `add` raises a start hint below the first usable LBA to it
  before aligning. The behaviour is unchanged and now pinned by tests;
  `add`'s "hinted start before first usable LBA" refusal, which tested
  the already-raised value and could not fire, is removed (#42, #26).
- **`probe` refuses GPT headers the specification forbids.** A primary
  header whose `my_lba` is not 1 — a backup header copied over LBA 1,
  whose entry-array pointer sent the parse to the far end of the disk —
  a major revision other than 1, and a `partition_entry_size` that is not
  128 times a power of two were all accepted with valid CRCs. Each is now
  `GptCorrupt` naming the field, matching what `sgdisk -v` reports; the
  writer refuses such an entry size too. Non-zero reserved bytes are
  still accepted, as `sgdisk` and Linux accept them (#29).
- **A Linux extended container (`0x85`) is no longer reported as a
  volume.** `mbr::entry_role` knew only `0x05` and `0x0F`, so `probe`
  returned a `0x85` container beside the real partitions: sniffing it
  read an EBR, and `partitions_open_slice` handed a driver the chain.
  It is now a container, preserved through `reserved_entries` with its
  original bytes like the other two, and `mbr::types::LINUX_EXTENDED`
  names it (#70).
- **`PartitionSet::add(None, ..)` finds space on a disk with a nested
  partition.** `find_free` walks partitions sorted by start and moved its
  cursor to each one's end, so a partition nested inside another dragged
  the cursor back inside the outer one; `add` then refused its own answer
  as an overlap, whatever the size asked for. Such a table is what
  `probe` keeps editable on purpose. The cursor now only moves forward
  (#27).
- **`sniff` refuses a partition starting at or past the end of the
  device before sizing its window.** It relied on the read to fail, and
  a zero-length read is `Ok` at any offset on a real `FileDevice`, so a
  region entirely off the device was sniffed as `Unknown` while
  `partitions_open_slice` refused the same entry. The test mock now
  behaves like `FileDevice` on an empty read (#53).
- **A 64 KiB-page Linux swap partition is recognised through `sniff`.**
  The window was 0x8800 bytes, sized for ISO9660, while `classify`
  probes swap pages up to 64 KiB. The window is now `sniff::WINDOW`,
  derived from the furthest probe (65536 bytes), which also means every
  sniff reads up to 65536 bytes instead of 34816 (#25).
- **`partitions_sniff_device` no longer answers `PART_FS_UNKNOWN` for a
  window its declared size cut short.** A declared size below both the
  device's real size and `sniff::WINDOW` that recognises nothing now
  returns -1 with a last-error naming both sizes; a recognised
  filesystem in a short window is still returned (#83).
- **`Partition::sector_span` refuses a zero-length partition wherever it
  starts, and counts a partly-occupied last sector.** The refusal was an
  underflow that only happened below byte 512, so `{start: 512, length:
  0}` returned the inverted span `(1, 0)`, and `{start: 0, length: 600}`
  returned `(0, 0)` for a partition that reaches into sector 1. The
  overlap checks in `PartitionSet::add`, `resize` and `find_free` read
  both as "no overlap" on a hand-built set. A set holding a zero-length
  entry now makes those calls return `Error::Invalid` (#71).
- **A GPT label is no longer dropped for the sake of its last
  character.** The name field holds 36 UTF-16 code units and a character
  outside the basic multilingual plane takes two of them, so cutting at
  36 units left a lone high surrogate on disk — not a shortened label but
  one that is not valid UTF-16 at all. The reader decoded strictly and
  answered `None`, so a 35-character name ending in an emoji came back as
  a partition with no name and nothing said why. The writer now truncates
  at a character boundary, and the reader shows what is readable of a
  name some other writer cut mid-pair rather than throwing all of it
  away.
- **Sniffing a partition clamps to the device the way slicing does.**
  `capi::slice_on_device` clamps a partition that runs past the end of
  the device it was found on, because a truncated image or a stale table
  produces one and refusing takes away the one thing the user wants.
  `sniff` sized its read window from the partition's declared length and
  `read_at` is all-or-nothing, so `partitions_sniff` returned a short
  read for exactly the image the clamp exists for, on the same index
  where `partitions_open_slice` returned a working device. A partition
  beginning *past* the end of the device still has nothing to read and
  stays an error.
- **A commit no longer renumbers the disk.** A partition's slot in the
  on-disk table is its identity to everything above this crate — the `3`
  in `/dev/sda3`, the `s3` in `disk4s3` — and it was dropped on the way
  in and re-derived from vector position on the way out. A GPT with a
  hole in it is routine, so probe → any edit → commit compacted a sparse
  table into slots 0..n: nothing about the surviving partitions changed
  except their numbers, and every fstab entry, boot-loader config and
  bookmark that named one by number then pointed at a different volume,
  with the operation reporting success. `PartitionSet::remove` made it
  worse by shifting every later partition down one.

### Added

- `Partition::slot` — the table slot an entry came from, `None` for a
  partition not yet placed in one. The writers honour it, give the lowest
  free slot to a partition that has none, and refuse two partitions
  claiming the same slot.

### Changed

- **C ABI break.** `PartitionInfo` grows a `slot` field (`-1` when the
  entry has none) and four bytes of padding, so it is 88 bytes rather
  than 80. `include/partitions.h` is updated in the same commit and
  `tests/c_abi.rs` compiles the header against the Rust struct, so the
  two cannot drift. A C caller that reads `PartitionInfo` needs a
  recompile.

### Fixed

- **An MBR entry that is not a volume is no longer reported as one.**
  `mbr::parse` emitted every non-empty entry, including the two kinds
  that describe no filesystem: the `0x05` / `0x0F` extended-partition
  containers, whose contents are a linked list of EBRs, and the `0xEE`
  GPT-protective marker, which in a hybrid MBR comes back as a whole-disk
  partition overlapping every real one. Sniffing a container read an EBR
  and called it an unknown filesystem; slicing one handed a driver the
  chain.
- **The GPT writer no longer commits a table it cannot read back.** The
  ending-LBA derivation `(start + length) / SECTOR_SIZE - 1` was written
  inline at five sites; `mutation` had been fixed for the overflow it can
  carry and the other four had not. In release, where these crates ship
  with `overflow-checks` off, `write_gpt` accepted a partition whose span
  leaves a `u64` and wrote an entry with `ending_lba` below
  `starting_lba` — both CRCs valid, backup written, success reported, and
  the table unparseable by this crate and by anything else that checks
  the pair. In debug the same input panicked. The derivation now lives in
  one checked place and the two profiles agree.
- `validate_partition` bounds a partition's *start* against the last
  usable LBA, not only its end. Without that the only thing keeping an
  absurd start out of the table was the end check, which a wrapped end
  passes trivially.

### Added

- `mbr::EntryRole` and `mbr::entry_role`, naming what an MBR entry
  describes, and `mbr::parse_all_entries` for a caller that wants the
  table as it is on disk — a repair or inspection tool — where leaving an
  entry out would be its own kind of wrong answer.
- `Partition::sector_span`, the one checked derivation of a partition's
  first and last sector.
- A `test (release)` CI job. A guard against a wrapping computation
  passes in a debug `cargo test` for the wrong reason — the panic — while
  the behaviour it guards against is still live in the built library.

## [0.4.1] — 2026-09-06

### Fixed

- A partition table's own numbers no longer drive unchecked arithmetic.
  A GPT entry states a first and a last LBA, and both come off the disk;
  multiplying them out to a byte range could wrap in the release
  profile, where overflow-checks is off.
- An oversized partition is clamped to the device rather than refused.
  A table that describes a partition running past the end of the device
  it is on is ordinary — an image truncated after the fact has one — and
  refusing the whole table made the disk unreadable when the partition
  before it was intact.

## [0.4.0] — 2026-09-04

### Changed

- **One description of the GPT and MBR layouts.** The two table formats were
  each described in more than one place, and the copies had begun to disagree
  about field offsets. There is now a single description of each that the
  parser and the writer both read.
- **One sector size, and one MBR LBA ceiling.** Both values appeared as bare
  literals at several sites. The LBA ceiling in particular is the boundary
  where MBR stops being able to address a disk at all, so a copy that drifted
  would silently accept a table that cannot be written back.

## [0.3.4] — 2026-08-29

### Fixed

- **`include/partitions.h` restored to the ABI actually shipped.** The header
  had drifted from the real `PartitionInfo` layout, so a C consumer compiling
  against it read the wrong fields.
- The release workflow's toolchain now agrees with `rust-toolchain.toml`. It
  had been building the published artifact with a different compiler than the
  one the repo pins.

### Added

- `chore` tasks own this crate's build, and the code-review report is recorded
  in the repo.
- Sibling clones in CI are pinned to a tag, `Cargo.lock` is committed, and the
  gate commands pass `--locked`. A release built from a floating dependency is
  not reproducible.

## [0.3.3] — 2026-06-21

### Changed

- Pinned toolchain moves from 1.94.1 to 1.95.0, in lockstep with the rest of
  the family.

## [0.3.2] — 2026-05-31

### Fixed

- A device reporting `device_size_bytes == 0` no longer divides by it.

### Added

- Tests for `partitions_sniff_device`.

## [0.3.1] — 2026-05-31

### Added

- **`partitions_sniff_device`**, for detecting a filesystem on a whole device
  that has no partition table at all — the superfloppy case.

## [0.3.0] — 2026-05-15

### Added

- The MBR active flag and GPT partition attributes are exposed, with
  `is_bootable()` over them.

## [0.2.0] — 2026-05-12

### Added

- CI (test, fmt, clippy) and a release-on-tag pipeline using trusted
  publishing.

### Changed

- `am-fs-core` dependency moves to 0.2.

## [0.1.0] — 2026-05-08

### Added

- Initial release: MBR and GPT partition-table probing.

[Unreleased]: https://github.com/antimatter-studios/rust-partitions/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/antimatter-studios/rust-partitions/compare/v0.3.4...v0.4.0
[0.3.4]: https://github.com/antimatter-studios/rust-partitions/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/antimatter-studios/rust-partitions/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/antimatter-studios/rust-partitions/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/antimatter-studios/rust-partitions/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/antimatter-studios/rust-partitions/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/antimatter-studios/rust-partitions/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/antimatter-studios/rust-partitions/releases/tag/v0.1.0
