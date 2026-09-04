# Changelog

Notable changes to `am-partitions`, newest first. This is a `0.x` crate, so the
**minor** is the compatibility boundary: a minor bump may break API, a patch
never does.

## [Unreleased]

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
