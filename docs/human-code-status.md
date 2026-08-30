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

### H2, H3, H4 — GPT and MBR offsets transcribed by hand in three, five and two places — **fixable, not yet done**

All three are the same change: one description of each on-disk layout instead of
several agreeing by hand. H4 is the sharpest — GPT geometry derived two
different ways that agree only because someone checked.

Deferred as one change with the round-trip tests as the contract.

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

### M3, M4, M5, M7, M8, M11 — duplication and unnamed values — **fixable, not yet done**

The overlap check four times; no LBA accessors so the conversion is open-coded
seven times; `SECTOR_SIZE` defined three times then ignored eight; the test
block device reimplemented four times; `div_ceil` hand-rolled beside real
`div_ceil` calls; `sniff`'s magic offsets half-named.

One deduplication change, with M5 first — three definitions of a sector size
that eight sites then ignore is the one most likely to end in an actual
disagreement.

---

## Verification

49 tests pass, unchanged in number. `chore lint` clean. The only behavioural
change is H5: a GPT entry whose LBAs overflow a byte offset is now refused
rather than wrapping.
