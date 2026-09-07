# Changelog

Notable changes to `am-partitions`, newest first. This is a `0.x` crate, so the
**minor** is the compatibility boundary: a minor bump may break API, a patch
never does.

## [Unreleased]

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
