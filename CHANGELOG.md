# Changelog

Notable changes to `am-partitions`, newest first. This is a `0.x` crate, so the
**minor** is the compatibility boundary: a minor bump may break API, a patch
never does.

## [Unreleased]

### Fixed

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
