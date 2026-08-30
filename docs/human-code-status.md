# Human-code findings — status

Tracks every **High** and **Medium** finding from
[`human-code-report-2026-08-28.md`](human-code-report-2026-08-28.md). The report
predates the work; this is the current position. Updated 2026-08-30.

**25 findings** — 5 High, 12 Medium, 8 Low. This covers the 17 High and Medium.

| | High | Medium |
|---|---|---|
| Fixed | 2 | 3 |
| Left for a human decision | 0 | 3 |
| Fixable, not yet done | 3 | 6 |

---

## High

### H1 — `include/partitions.h` declared a `PartitionInfo` 16 bytes short — **fixed earlier**

[#10](https://github.com/antimatter-studios/rust-partitions/pull/10). A C
consumer compiled against that header read every field after the short one from
the wrong offset.

### H2, H3, H4 — GPT and MBR layouts transcribed by hand — **fixed**

**H4 was the sharpest and the probe proved it.** `gpt_write` derived its
geometry (`FIRST_USABLE_LBA = 2 + ENTRY_ARRAY_SECTORS`) while `mutation` wrote
`34` and `33` as literals. They agreed only because somebody checked — and
setting `mutation`'s to 40 left **the whole suite green**, leaving a writer and a
planner that disagree about where a partition may start.

`gpt_layout` in `lib.rs` derives all of it from the pinned entry count, and both
modules import it.

**H2.** The GPT header was transcribed in `gpt::parse_header` and again in
`gpt_write::build_header` — two descriptions of one layout, agreeing because
both were written from the same table on the same afternoon. A wrong offset in
either produces a header the other half of this crate cannot read.
`gpt::header_offsets` names all thirteen.

**H3.** `446 + i * 16` at three sites and the per-entry field offsets at two
more. `mbr::layout` names them, with `entry_at(i)` for the arithmetic.

Three tests, and they check relationships rather than restating numbers: the
array is the entries laid out; first-usable is the protective MBR plus the header
plus the array; the four MBR entries end exactly where the boot signature begins;
and every named GPT field fits inside the 92 bytes the CRC covers.

| mutation | tests failing (was) |
|---|---|
| `FIRST_USABLE_LBA` typed as 40 | 2 (**0**) |
| `NUM_ENTRIES` halved | 2 |
| `TABLE_START` 446 → 440 | 3 |

### M8 — `div_ceil` hand-rolled beside real `div_ceil` calls — **fixed**

`byte / SECTOR_SIZE + if byte % SECTOR_SIZE != 0 { 1 } else { 0 }`, three lines
from a `div_ceil` call, in a file that uses the real one elsewhere.

### H5 — LBA-to-byte arithmetic on untrusted header values was unchecked — **fixed**

```rust
let start  = start_lba * SECTOR_SIZE;
let length = (end_lba - start_lba + 1) * SECTOR_SIZE;
```

Both LBAs come straight off the disk, and the only guard was their relative
ordering. Either multiplication can overflow a `u64` — a panic in debug, and in
release **a silent wrap, which is the worse half**: a wrapped `start` names a
byte offset the caller then reads from.

All three operations are checked now, each with its own message.

---

## Medium

### M6 — two error variants are unreachable, and one documented a feature that does not exist — **fixed**

`MbrCorrupt` is never constructed: a missing signature returns
`NoPartitionTable`, and extended chains are not implemented.

`GptBackupMismatch` is worse — its doc described an opt-in mode, *"the variant
only surfaces if a caller explicitly asks for backup validation"*, and **nothing
compares the primary and backup headers at all**. A reader would have gone
hunting for an argument that does not exist.

Both are `pub` and published, so both are documented as reserved rather than
removed; `GptBackupMismatch` is named as the variant to use if the feature is
ever added.

### M9 — `0xEE` had two names and one writer used neither — **fixed**

`TYPE_GPT_PROTECTIVE` is now defined *as* `types::GPT_PROTECTIVE` rather than a
second literal, and `gpt_write.rs` writes the constant instead of `0xEE` with a
`// type byte` comment. One byte, one value, three call sites that now agree by
construction.

### M10 — a doc comment described a different constant than the one it sat on — **fixed**

`GPT_FIRST_USABLE_LBA = 34` was documented as "spec-mandated GPT slot count",
which describes the 128 that is one *term* of the sum, not the sum. It now says
what 34 is: protective MBR + header + the 32-sector entry array.

### M1, M2 — `write_gpt` and `PartitionSet::add` are god functions — **needs your decision**

130 and 93 lines. Both are the paths that establish the table's invariants.

### M12 — `capi.rs` re-rolls the FFI panic guard five times while `ffi_guard` sits imported — **needs your decision**

Clear-cut on the face of it, but `ffi_guard` returns a code and these return
pointers — the same shape as `am-fs-core`'s M1. Fixing it properly means adding
a pointer-returning guard to `fs-core`, which is a change to another crate.

### M5 — `SECTOR_SIZE` defined three times and then ignored eight — **fixed**

`gpt`, `mbr` and `mutation` each declared `SECTOR_SIZE: u64 = 512`, and eight
more places wrote the literal anyway — because Rust will not take a `u64` const
as an array length, which is exactly the reason to add a second spelling rather
than repeat the number. `MBR_LBA_MAX` was declared twice, with a third bare
`0xFFFF_FFFF` in `gpt_write`'s protective-MBR sizing.

One definition each, in `lib.rs`, plus `SECTOR_SIZE_USIZE` for array lengths and
a `Sector` alias for signatures that want to name the type. The five
`[u8; 512]` signatures moved too, so nothing in the crate states the number
twice.

**Checked before as well as after.** Before, mutating any one of the three
`SECTOR_SIZE` declarations failed 3 tests, and `MBR_LBA_MAX` the same — so this
was a genuine tidy-up with no coverage hole behind it, which is worth
establishing, since several other duplications in this family turned out to be
hiding one.

After, the guard changes shape. With one definition the crate can no longer
disagree with *itself*, so a wrong value has to be caught by a test of the value
rather than of the consistency between copies:

| mutation | tests failing |
|---|---|
| `SECTOR_SIZE` 512 → 4096 | 2 — a probe round-trip, and the 2 TiB ceiling relation |
| `MBR_LBA_MAX` truncated to `0xFFFF` | 2 |
| `SECTOR_SIZE_USIZE` disagreeing with `SECTOR_SIZE` | 2 |

That last row is why the new tests exist: the second spelling is the one thing
nothing else in the crate could notice drifting.

### M3, M4, M7, M11 — duplication and unnamed values — **fixable, not yet done**

The overlap check four times; no LBA accessors so the conversion is open-coded
seven times; the test block device reimplemented four times; `sniff`'s magic
offsets half-named.

---

## Verification

54 tests pass, up from 51. `chore lint` clean. The only behavioural
change is H5: a GPT entry whose LBAs overflow a byte offset is now refused
rather than wrapping.
