# Human-code report — am-partitions

> **This is analysis only. No code was changed.**
> Phases 0 (Understand) and 1 (Scan and Triage) were run, then this document
> was written. The dev-loop implementation phase was deliberately skipped so
> the findings can be read and prioritised first. The working tree is
> unchanged apart from this file.

**Date:** 2026-08-28
**Scope:** full crate — `src/` (9 files, 2 165 lines), `tests/` (3 files,
1 063 lines), `include/partitions.h` (106 lines)
**Crate:** `am-partitions` v0.3.3, lib name `partitions`, edition 2021,
toolchain pinned to 1.95.0

| Count | |
|---|---|
| Items found | **25** |
| Items fixed | **0** (report-only run) |
| Items skipped | 0 — nothing was triaged out; see *Judged not a finding* for things deliberately left alone |

**Severity split:** 5 High · 12 Medium · 8 Low

**Baseline (unchanged by this run):** `cargo test --locked` → 48 passed, 0
failed, across 4 binaries (lib 5, `bootable.rs` 7, `fixtures.rs` 22,
`mutation.rs` 14). `cargo clippy --all-targets --locked -- -D warnings` →
clean. Doc-tests: 0.

---

## What to fix first

1. **H1** — the C header and the Rust `#[repr(C)]` struct disagree by 16
   bytes. This is a live memory-safety bug in every C consumer, and it is not
   a readability nicety. Fix before anything else; it is a four-line edit.
2. **H4** then **H2/H3** — pull the GPT geometry constants into one place, then
   the on-disk offsets. H4 is where two hand-maintained numbers currently
   agree only by luck; H2/H3 are the bulk of the offset noise and the reason
   H1 and H4 were able to happen at all.
3. **H5** — bound the LBA arithmetic. Cheap, and this crate's whole job is
   reading untrusted disk images.
4. Then the Mediums in listed order. M1/M2 (the two god functions) get much
   smaller for free once H2–H4 land, so do them after, not before.

---

## Findings

### High

---

#### H1 — `include/partitions.h` declares a `PartitionInfo` 16 bytes shorter than the Rust struct it mirrors

- **Files:** `src/capi.rs:104-138`, `include/partitions.h:63-73`
- **Category:** Duplicated code (an ABI contract transcribed by hand into two
  languages) / comment that lies
- **Severity:** High
- **Test coverage:** **None.** There is no C-side compile test, no
  `size_of::<PartitionInfo>()` assertion, and no `offsetof` check. The 5
  `capi.rs` unit tests all construct the struct from the Rust side, so they
  cannot see the drift.

Commit `00ce093` ("feat(api): expose MBR active flag + GPT attributes") added
three fields to the Rust struct. Its own commit message says so verbatim:

> Breaking changes (0.x minor bump): … C ABI: `PartitionInfo` gained
> `bootable: u8`, `_pad2: [u8;7]`, and `attributes: u64` at the end of the
> struct.

`include/partitions.h` was not in that commit's file list, and a later commit
that *did* touch the header (`5323841`) did not notice. The header has never
contained the word `bootable` or `attributes`.

Rust side (`src/capi.rs`), tail of the struct:

```rust
    pub label: *const std::os::raw::c_char,
    pub label_len: usize,
    pub bootable: u8,       // <-- absent from the header
    pub _pad2: [u8; 7],     // <-- absent from the header
    pub attributes: u64,    // <-- absent from the header
}
```

C side (`include/partitions.h`), same tail:

```c
    const char    *label;           /* NUL-terminated UTF-8, or NULL */
    size_t         label_len;       /* bytes excluding the NUL */
} PartitionInfo;
```

Measured on this machine (`cc`, aarch64): header struct = **64 bytes**, Rust
struct = **80 bytes**.

`partitions_get` does `*out = l.entries[index].info.clone();` — an 80-byte
store. A C caller that declares `PartitionInfo info;` on the stack per the
shipped header has reserved 64. **Every successful `partitions_get` call from
C overruns its output buffer by 16 bytes**, and any C code that indexes an
array of `PartitionInfo` is computing the wrong stride.

*Why the readability scan found it:* the struct is the same declaration
written twice in two languages with nothing tying them together. That is the
duplication smell, and this is the failure mode it predicts.

*Suggested fix:* add the three fields to the header, and add a
`const _: () = assert!(size_of::<PartitionInfo>() == 80);` (plus `offsetof`
checks in a small C compile test, if the CI can host one) so the next drift
fails the build instead of the caller.

---

#### H2 — GPT on-disk offsets are transcribed by hand in three independent places

- **Files:** `src/gpt.rs:148-196` (reader), `src/gpt.rs:198-242` (entry
  reader), `src/gpt_write.rs:90-118` + `src/gpt_write.rs:207-234` (writer),
  `tests/fixtures.rs:143-188` (fixture builder)
- **Category:** Magic numbers / duplicated code
- **Severity:** High
- **Test coverage:** Good on the happy path — `gpt_with_two_partitions`,
  `gpt_header_crc_mismatch`, `gpt_entries_crc_mismatch`,
  `gpt_round_trip_two_partitions`, `gpt_primary_and_backup_match_after_commit`.
  A refactor here is well guarded.

The GPT header field table (`0..8` signature, `12..16` header_size, `16..20`
CRC, `24..32` my_lba, `32..40` alternate_lba, `40..48` first_usable,
`48..56` last_usable, `56..72` disk_guid, `72..80` entry_lba, `80..84`
num_entries, `84..88` entry_size, `88..92` entries_crc) and the entry table
(`0..16` type GUID, `16..32` unique GUID, `32..40` start_lba, `40..48`
end_lba, `48..56` attributes, `56..128` UTF-16 name) each exist three times as
raw slice literals:

- `gpt.rs::parse_header` / `parse_entry_array` read them,
- `gpt_write.rs::build_header` / the entry loop write them,
- `tests/fixtures.rs::build_gpt_with_entries` writes them *again* to build the
  fixture the reader is tested against.

The third copy is the dangerous one: the test fixture and the parser were
transcribed from the same spec independently, so a shared misreading of the
spec produces a green test. The reader and writer are only checked against
each other, never against a byte-exact reference.

The doc comment at `gpt.rs:14-42` is an excellent ASCII table of exactly these
offsets — it should be executable, not prose. Named constants (or, better, a
small `Field` accessor set) in one module, consumed by reader, writer *and*
fixture builder, would make the three agree by construction.

Also unnamed in the same region: the validation bounds `92..=512`
(`gpt.rs:153`), `128..=4096` (`gpt.rs:176`) and `> 4096` (`gpt.rs:179`).

---

#### H3 — MBR entry offsets and the boot signature are literals in five files

- **Files:** `src/mbr.rs:69`, `src/mbr.rs:91`, `src/mbr.rs:164`,
  `src/mbr.rs:180-181`, `src/gpt_write.rs:122-144`, `src/probe.rs:94`,
  `src/sniff.rs:69`, `src/capi.rs:449-460`, `src/capi.rs:505-506`,
  `tests/fixtures.rs:54`, `tests/fixtures.rs:132-135`,
  `tests/bootable.rs:81-82`
- **Category:** Magic numbers / duplicated code
- **Severity:** High
- **Test coverage:** Good — `mbr_two_primaries`,
  `protective_mbr_without_gpt_is_corrupt`,
  `mbr_write_round_trip_preserves_active_flag`, `mbr_round_trip_two_partitions`,
  plus the `capi.rs` FFI round-trip.

`let off = 446 + i * 16;` appears three times inside `mbr.rs` alone (lines 69,
91, 164) and again in every test file and in `capi.rs`'s own fixtures. The
per-entry field offsets `+0` (status), `+4` (type), `+8` (start LBA), `+12`
(sector count) travel with it as bare arithmetic. `0x55` / `0xAA` at 510/511
appears in 8 distinct places across `src/` and `tests/`.

`mbr.rs`'s module doc (lines 3-20) already names every one of these offsets in
a table. Nothing stops a reader — or an editor — from getting `+8` and `+12`
the wrong way round in one of the five copies; only the round-trip tests would
catch it, and only for the two fields those tests assert.

The worst instance is `gpt_write.rs:121-144`, which open-codes an entire
protective MBR — `mbr[446]`, `mbr[447]`, `mbr[448]`, `mbr[449]`, `mbr[450]`,
`mbr[451..454]`, `mbr[454..458]`, `mbr[458..462]`, `mbr[510]`, `mbr[511]` —
without going through `mbr.rs` at all, so the MBR writer and the protective-MBR
writer share no code and no constants. See also M9: that block hardcodes
`0xEE` despite `mbr::TYPE_GPT_PROTECTIVE` existing.

---

#### H4 — GPT geometry is defined twice, derived two different ways, and agrees only by hand

- **Files:** `src/mutation.rs:19-20`, `src/gpt_write.rs:31-36`,
  `src/gpt_write.rs:59-64`, `src/mutation.rs:304-322`
- **Category:** Magic numbers / duplicated code
- **Severity:** High
- **Test coverage:** Partial. The round-trip tests
  (`gpt_round_trip_two_partitions`, `gpt_from_probe_then_mutate_then_commit`)
  would catch a divergence only if a partition landed exactly on the boundary
  the two definitions disagree about. No test places a partition at
  `first_usable_lba` or `last_usable_lba` exactly. `Error::DeviceTooSmall` is
  never asserted by any test, in any of its three construction sites.

`mutation.rs` hard-codes the geometry as absolute numbers:

```rust
const GPT_FIRST_USABLE_LBA: u64 = 34;
const GPT_BACKUP_RESERVE_SECTORS: u64 = 33; // entry array (32) + backup header (1)
```

`gpt_write.rs` derives the same two facts from first principles:

```rust
const ENTRY_ARRAY_SECTORS: u64 = ENTRY_ARRAY_BYTES / SECTOR_SIZE; // 32
const FIRST_USABLE_LBA: u64 = 2 + ENTRY_ARRAY_SECTORS;            // 34
…
let last_usable_lba = last_lba - ENTRY_ARRAY_SECTORS - 1;         // = last_lba - 33
```

They agree today. Nothing enforces it. `mutation.rs` computes the usable range
that `add`/`resize` validate against; `gpt_write.rs` computes the range it
stamps into the header and validates against on commit. If a future change to
`NUM_ENTRIES` moves one, the other stays put, and the failure surfaces as a
partition that `add()` accepted and `commit()` rejects — or worse, a header
whose `first_usable_lba` field disagrees with where partitions were actually
placed.

Two more copies of the same family:

- `mutation.rs:162-163` hardcodes `128` for the GPT slot limit while
  `gpt_write.rs:31` has `NUM_ENTRIES: u32 = 128` and `gpt_write.rs:66` checks
  against it.
- The MBR four-primary limit is a bare `4` in `mbr.rs:68`, `mbr.rs:90`,
  `mbr.rs:138` and `mutation.rs:159`.

These belong in one `constants` home shared by `gpt.rs`, `gpt_write.rs`,
`mbr.rs` and `mutation.rs`, with the derived values `const`-computed from the
primitives rather than restated.

---

#### H5 — LBA-to-byte arithmetic on untrusted header values is unchecked

- **Files:** `src/gpt.rs:218-225`
- **Category:** Dense expression hiding a bug
- **Severity:** High
- **Test coverage:** **None.** No fixture supplies out-of-range LBAs. Every
  GPT test builds a well-formed table.

```rust
let start_lba = u64::from_le_bytes(array[off + 32..off + 40].try_into().unwrap());
let end_lba   = u64::from_le_bytes(array[off + 40..off + 48].try_into().unwrap());
if end_lba < start_lba {
    return Err(Error::GptCorrupt("ending_lba < starting_lba"));
}
…
let start  = start_lba * SECTOR_SIZE;
let length = (end_lba - start_lba + 1) * SECTOR_SIZE;
```

`start_lba` and `end_lba` come straight off the disk. The only guard is the
relative ordering check. Both multiplications can overflow `u64` — panic in a
debug build, silent wrap in release — and neither LBA is bounded against
`dev.size_bytes()`. A crafted image with `end_lba = u64::MAX` reaches both
lines.

This is a probe crate whose entire purpose is reading disk images it did not
create. The two multiplications read as innocuous because they are buried in a
run of eight near-identical byte-slicing lines; naming the offsets (H2) makes
the missing bound obvious.

Related, lower-stakes: `gpt.rs:199-201` allocates
`num_partition_entries * partition_entry_size` — bounded at 4096 × 4096 = 16 MiB
by the checks at lines 176-181, but never checked against the device size
before the read. See L6.

---

### Medium

---

#### M1 — `write_gpt` is a 130-line god function

- **Files:** `src/gpt_write.rs:49-179`
- **Category:** God function
- **Severity:** Medium
- **Test coverage:** Good — 6 tests in `mutation.rs` and 2 in `bootable.rs`
  drive it.

Seven distinct jobs behind seven banner comments — the classic tell:

```
// --- Build the entry array (16 KiB, all zeros + populated slots). ---
// --- Protective MBR at LBA 0. ---
// --- Primary header at LBA 1. ---
// --- Primary entry array at LBA 2 ---
// --- Backup entry array at LBA (last_lba - 32) ---
// --- Backup header at last LBA. ---
```

plus writability/size validation and the sort-and-overlap pass before them.
Abstraction levels are mixed freely: `dev.is_writable()` sits fourteen lines
above `mbr[449] = 0x00;`. Natural extractions: `build_entry_array`,
`build_protective_mbr`, `check_no_overlaps`. Each banner comment is already
the name of the function it wants to be.

---

#### M2 — `PartitionSet::add` is a 93-line god function

- **Files:** `src/mutation.rs:149-241`
- **Category:** God function
- **Severity:** Medium
- **Test coverage:** Good — 8 tests exercise `add` directly.

Table-capacity validation, length rounding, alignment, usable-range lookup,
start-hint resolution, end-LBA overflow check, MBR range check, overlap scan,
partition-kind derivation, UUID minting, and the push. Roughly six locals that
each live in exactly one block.

---

#### M3 — The overlap check is written out four times

- **Files:** `src/gpt_write.rs:75-86`, `src/mbr.rs:149-160`,
  `src/mutation.rs:203-209`, `src/mutation.rs:273-282`
- **Category:** Duplicated code
- **Severity:** Medium
- **Test coverage:** Only two of the four are asserted —
  `gpt_overlap_rejected` (mutation `add`) and the `gpt_write` path via commit.
  `mbr::write_mbr`'s overlap branch and `resize`'s overlap branch have no test.

Four hand-rolled implementations of "do these byte ranges collide", each first
re-deriving start/end LBAs from bytes. Two use the sorted-scan form
(`start_lba <= prev`), two use the pairwise form
(`start <= p_end && end >= p_start`). Above the three-instance threshold, and
the two shapes make it hard to be sure they agree at the boundaries.

---

#### M4 — `Partition` has no LBA accessors, so the conversion is open-coded seven times

- **Files:** `src/mbr.rs:153`, `src/mutation.rs:205`, `src/mutation.rs:278`,
  `src/mutation.rs:348`, `src/gpt_write.rs:79`, `src/gpt_write.rs:101`,
  `src/gpt_write.rs:192`
- **Category:** Duplicated code / dense expression
- **Severity:** Medium
- **Test coverage:** Covered incidentally by every round-trip test.

`(p.start + p.length) / SECTOR_SIZE - 1` appears seven times, and
`p.start / SECTOR_SIZE` alongside it in most of them. The `- 1` (GPT's
`ending_lba` is inclusive) is the kind of off-by-one that wants to be written
once. `Partition::start_lba()` / `Partition::end_lba()` would remove all seven
and give H5's bounds check one obvious place to live.

---

#### M5 — `SECTOR_SIZE` is defined three times and then ignored eight times

- **Files:** `src/gpt.rs:54` (`pub`), `src/mbr.rs:30`, `src/mutation.rs:21`;
  literal `[0u8; 512]` at `src/mbr.rs:162`, `src/mutation.rs:109`,
  `src/gpt.rs:158`, `src/gpt.rs:279`, `src/probe.rs:87`, `src/probe.rs:88`,
  `src/gpt_write.rs:122`, `src/gpt_write.rs:216`
- **Category:** Magic numbers / duplicated code
- **Severity:** Medium
- **Test coverage:** Covered throughout; a consolidation is safe.

Three private/public definitions of `512` in three modules, and eight places
that write the literal anyway (array lengths can't take a `u64` const directly,
which is precisely why a `SECTOR_SIZE_USIZE` or a `type Sector = [u8; 512]`
alias is worth adding rather than repeating the number). `MBR_LBA_MAX =
0xFFFF_FFFF` is likewise defined twice — `src/mbr.rs:34` and
`src/mutation.rs:26`.

---

#### M6 — Two error variants are unreachable, and one of them has a doc comment describing behaviour that does not exist

- **Files:** `src/error.rs:19-26`
- **Category:** Speculative code / comment that lies
- **Severity:** Medium
- **Test coverage:** N/A — unreachable.

`Error::MbrCorrupt(&'static str)` is never constructed anywhere in `src/`. Its
doc says "MBR signature missing or extended-partition chain broken": a missing
signature returns `NoPartitionTable`, and extended chains are not implemented.

`Error::GptBackupMismatch(&'static str)` is never constructed either, and its
doc actively misleads:

```rust
/// GPT primary header and backup header disagree … The
/// probe path treats this as advisory by default — the variant only
/// surfaces if a caller explicitly asks for backup validation.
GptBackupMismatch(&'static str),
```

The caller-asks-for-it path is `gpt::validate_backup`, which returns
`BackupStatus::Mismatch` and never touches this variant. A reader following
the comment goes looking for a code path that isn't there.

Both are `pub` on a published crate, so removal is a breaking change — but the
docs should stop describing behaviour the code does not have, at minimum.

---

#### M7 — The in-memory test block device is reimplemented four times

- **Files:** `tests/fixtures.rs:14-46` (`Bytes`), `src/capi.rs:424-444`
  (`Bytes`), `tests/mutation.rs:14-62` (`MemDev`),
  `tests/bootable.rs:22-67` (`MemDev`)
- **Category:** Duplicated code
- **Severity:** Medium
- **Test coverage:** These *are* the tests.

Four near-identical `Mutex<Vec<u8>>`-backed `BlockRead`/`BlockDevice` impls,
with the same `ShortRead`/`OutOfBounds` bodies copy-pasted. `tests/bootable.rs`
even documents the copy:

```rust
/// In-memory BlockDevice mirror of the one in tests/mutation.rs — copied
/// rather than shared so the bootable test file stays self-contained.
```

Rust's `tests/common/mod.rs` convention exists for exactly this, and the
`fixtures.rs` copy has the extra `write` / `write_u32_le` helpers the others
had to do without. Consolidating also lets the `capi.rs` unit-test copy move
out of `src/`.

---

#### M8 — `div_ceil` hand-rolled in a file that already calls `div_ceil` twice

- **Files:** `src/mutation.rs:180`
- **Category:** Dense expression
- **Severity:** Medium
- **Test coverage:** Covered by `gpt_unaligned_hint_silently_aligned`.

```rust
let raw_sectors = byte / SECTOR_SIZE + if byte % SECTOR_SIZE != 0 { 1 } else { 0 };
```

is `byte.div_ceil(SECTOR_SIZE)`, which lines 167 and 258 of the same file
already use. Clippy's `manual_div_ceil` lint only matches the
`(a + b - 1) / b` shape, so this one slipped through a clean run.

---

#### M9 — `0xEE` has two names and one of the writers uses neither

- **Files:** `src/mbr.rs:37` (`TYPE_GPT_PROTECTIVE`), `src/mbr.rs:59`
  (`types::GPT_PROTECTIVE`), `src/gpt_write.rs:130`
- **Category:** Misleading names / magic numbers
- **Severity:** Medium
- **Test coverage:** `protective_mbr_without_gpt_is_corrupt` covers the reader;
  the writer's protective-MBR block is covered by the GPT round-trips.

`mbr.rs` exports the same byte under two names in the same file — one at
module scope, one inside `pub mod types`. `is_protective` uses the module-scope
one, and `gpt_write.rs:130` writes `mbr[450] = 0xEE;` with a `// type byte`
comment, using neither. Three places, three conventions, one byte.

---

#### M10 — A doc comment describes a different constant than the one it sits on

- **Files:** `src/mutation.rs:18-19`
- **Category:** Comment that lies
- **Severity:** Medium
- **Test coverage:** N/A.

```rust
/// Spec-mandated GPT slot count.
const GPT_FIRST_USABLE_LBA: u64 = 34;
```

34 is not a slot count; the slot count is 128. This reads like a leftover from
a deleted `GPT_SLOT_COUNT` constant. Sitting directly on top of H4's geometry
hazard, it is worse than no comment.

---

#### M11 — `sniff`'s magic offsets are half-named and half-literal

- **Files:** `src/sniff.rs:53`, `src/sniff.rs:69`, `src/sniff.rs:78-89`,
  `src/sniff.rs:94-96`, `src/sniff.rs:104-107`, `src/sniff.rs:112`,
  `src/sniff.rs:118-124`, `src/sniff.rs:128`
- **Category:** Magic numbers
- **Severity:** Medium
- **Test coverage:** Excellent — 11 per-filesystem `sniff_*` tests plus
  `sniff_through_partition_offset`. Safe to refactor.

Every signature offset is a bare literal in an `if`: `0x8800` (the read
window), `510`/`511`, `3..11`, `0x52..0x5A`, `0x36..0x3E`, `1080`/`1081`,
`0xEF53`, `1024..1026`, `32..36`, `page - 10`, `0x8001..0x8006`. The comment
above each one names it, which is the point — the names exist, they are just
in comments rather than in constants.

Inconsistent even with itself: `classify_ext` names
`EXT3_FEATURE_COMPAT_HAS_JOURNAL` and `EXT4_INCOMPAT_MASK` as real constants
twenty lines later, while the superblock offsets `0x5C`/`0x60`/`0x64` in the
same function stay raw.

---

#### M12 — `capi.rs` re-rolls the FFI panic guard five times while `ffi_guard` sits imported

- **Files:** `src/capi.rs:242`, `src/capi.rs:270`, `src/capi.rs:309`,
  `src/capi.rs:348`, `src/capi.rs:370` (vs `src/capi.rs:179`)
- **Category:** Duplicated code
- **Severity:** Medium
- **Test coverage:** Partial — `probe_with_no_table_returns_custom_error` and
  `sniff_device_null_returns_minus_one` cover two error shapes; no test drives
  an actual panic through any of the five guards.

`fs_core::ffi::ffi_guard` is imported and used exactly once, in
`partitions_probe`. The other five entry points each open-code
`std::panic::catch_unwind(AssertUnwindSafe(|| { … }))` with a bespoke
`unwrap_or_else` / `match` tail and a hand-written `set_last_error("panic in
…")` string. Five variations on one pattern, and the difference between them
is only the sentinel returned (`FsCoreErrorCode::Panic`, `-1`,
`ptr::null_mut()`, nothing). Two small generic helpers — one returning an
`i32` sentinel, one returning a pointer — would collapse all five.

---

### Low

---

#### L1 — `align_up` reimplements `u64::next_multiple_of`

- **Files:** `src/mutation.rs:366-375`
- **Category:** Speculative / redundant code
- **Severity:** Low
- **Test coverage:** Covered via `gpt_alignment_preserved` and
  `gpt_unaligned_hint_silently_aligned`.

`next_multiple_of` has been stable since 1.73; the toolchain pins 1.95, and
this file already uses the similarly-recent `div_ceil`. Semantics match
exactly, including the overflow behaviour. Five call sites (lines 171, 181,
258, 345, 356).

---

#### L2 — rustfmt has mangled trailing comments into column-21 orphans

- **Files:** `src/gpt_write.rs:124-135`, `tests/fixtures.rs:165`
- **Category:** Comments
- **Severity:** Low
- **Test coverage:** N/A.

```rust
    mbr[446] = 0x00; // boot indicator
                     // CHS first sector — write the canonical 0x00 0x02 0x00 trio meaning
                     // "head 0, sector 2, cylinder 0".
    mbr[447] = 0x00;
```

The continuation lines belong to the *next* statement but are indented as if
they belonged to the previous one's trailing comment. Moving each comment onto
its own line above the statement it describes fixes it and survives rustfmt.

---

#### L3 — `build_header` takes seven positional parameters

- **Files:** `src/gpt_write.rs:207-215`, call sites at
  `src/gpt_write.rs:148-156` and `src/gpt_write.rs:167-175`
- **Category:** Too many parameters
- **Severity:** Low
- **Test coverage:** Covered by the GPT round-trips.

Both call sites annotate every single argument to stay readable:

```rust
let primary = build_header(
    /* my_lba */ 1,
    /* alternate_lba */ last_lba,
    /* entry_lba */ 2,
    …
```

Five of the seven arguments are `u64`, so the compiler cannot catch a
transposition. The four values that are identical between the two calls
(`first_usable`, `last_usable`, `disk_guid`, `entry_array_crc`) are a struct
waiting to happen.

---

#### L4 — `probe` writes sector sizes as literals

- **Files:** `src/probe.rs:87-91`
- **Category:** Magic numbers
- **Severity:** Low
- **Test coverage:** Covered by every probe test.

`[0u8; 512]` twice, `dev.read_at(512, …)`, and `if dev.size_bytes() >= 1024`
— the last of which means "at least two sectors" and should say so. Rolls up
into M5.

---

#### L5 — `Error::Io` is unreachable in practice

- **Files:** `src/error.rs:11`, `src/error.rs:62-66`
- **Category:** Speculative code
- **Severity:** Low
- **Test coverage:** N/A.

Nothing in `src/` propagates a `std::io::Error` with `?`. The one place that
touches `std::io` (`fill_from_urandom`, `mutation.rs:407-413`) discards the
error with `.is_ok()`. The `From<io::Error>` impl therefore never fires. It is
public API on a published crate, so this is a note rather than a deletion
request — but the variant's "rare — retained for direct `std::io::Error`
sources" comment overstates the case.

---

#### L6 — The entry array is allocated from untrusted header fields without a device-size check

- **Files:** `src/gpt.rs:198-202`, bounds at `src/gpt.rs:176-181`
- **Category:** Speculative/defensive code with a gap
- **Severity:** Low (bounded to 16 MiB, so the blast radius is small)
- **Test coverage:** None for the out-of-range cases.

`num_partition_entries * partition_entry_size` is bounded to 4096 × 4096 by the
two range checks, so a hostile header buys a 16 MiB allocation and then a read
that fails — not a crash, but the allocation happens before anything confirms
the array even fits on the device. The bounds `4096` and `4096` are unnamed
(see H2).

---

#### L7 — The FAT/NTFS branch of `classify` nests three deep

- **Files:** `src/sniff.rs:69-91`
- **Category:** Deep nesting
- **Severity:** Low
- **Test coverage:** Excellent (5 tests over this branch).

`if signature` → `if buf.len() >= 0x5A` → `if fat32_tag == …`, twice. Early
returns from a `classify_bpb(buf) -> Option<FsKind>` helper would flatten it,
and would give the "these four filesystems all share a boot sector" idea a
name.

---

#### L8 — The two partition validators share four identical checks

- **Files:** `src/gpt_write.rs:181-205`, `src/mbr.rs:186-208`
- **Category:** Duplicated code — **below the three-instance threshold**
- **Severity:** Low
- **Test coverage:** Thin. Of the eight distinct rejection reasons across both
  functions, only "partitions overlap" is asserted by a test.

`validate_partition` and `validate_mbr_partition` both check kind, zero
length, and sector alignment with byte-identical bodies, then diverge into
table-specific bounds. Only two instances, so the skill's extraction rule says
leave it — noted here because the shared prefix is a natural place for the
`start_lba`/`end_lba` helpers from M4, at which point extraction becomes free.

---

## Judged not a finding

The brief asked specifically whether the partition-type tables are magic
numbers or legitimate tables. These were examined and deliberately left alone:

| Location | What it is | Verdict |
|---|---|---|
| `src/gpt.rs:87-127` — `mod type_guids` | Seven 16-byte GPT type GUIDs | **Legitimate table.** Every entry is a named `pub const` with the canonical dashed string in its doc comment, so a reader can grep either form. This is what H2's offsets should look like. |
| `src/gpt.rs:62-83` — `mod attr` | Seven named bits of the 64-bit attributes field | **Legitimate table.** Bit position, spec name, and *why you'd care* per entry. Exemplary. |
| `src/mbr.rs:40-61` — `mod types` | Twenty MBR type bytes | **Legitimate table.** Named, exported, grouped. (The one problem is M9 — `GPT_PROTECTIVE` also exists at module scope.) |
| `src/capi.rs:40-54`, `:81-86` | `FsKindCode` / `TableKindCode` discriminants | **Legitimate table.** Explicit values on a frozen ABI, with a "do not renumber" banner. Correct call. |
| `src/sniff.rs:152-162` | `EXT3_FEATURE_COMPAT_HAS_JOURNAL` + `EXT4_INCOMPAT_MASK` | **Acceptable as-is.** The nine bits folded into the mask each carry a trailing name comment, and only the aggregate is ever used — naming each one separately would add nine unused constants. Left alone. |
| `src/error.rs:4-33` | The `Error` enum | **Good.** Per-variant docs explaining when each fires. Only M6's two dead variants are a problem, and that is about reachability, not the table. |
| `src/gpt.rs:14-42`, `src/mbr.rs:3-24` | ASCII offset tables in module docs | **Good prose, wrong medium.** Accurate and genuinely helpful; the finding (H2/H3) is that they are the only place the offsets are named, not that they exist. Keep them *and* add the constants. |

---

## Test results

No code was changed, so before and after are the same run.

| | Before | After |
|---|---|---|
| Tests passing | 48 | 48 (unchanged — no edits) |
| Tests failing | 0 | 0 |
| Test binaries | 4 (lib 5, `bootable` 7, `fixtures` 22, `mutation` 14) | same |
| Doc-tests | 0 | 0 |
| `cargo clippy --all-targets --locked -- -D warnings` | clean | clean |
| `cargo fmt --check` | not run this session | — |

### Coverage gaps worth closing before Phase 2

A refactor is only as safe as the tests bracketing it. These are the places
where the current suite would *not* catch a regression:

1. **No C-side ABI test at all** (H1). A `size_of` assertion is one line.
2. **No malformed-GPT fixtures** (H5, L6) — every GPT test builds a valid
   table. Out-of-range `starting_lba`/`ending_lba`, oversized
   `num_partition_entries`, and an entry array that runs past the device end
   are all untested.
3. **`Error::DeviceTooSmall` is never asserted** despite three construction
   sites (`mbr.rs:143`, `mutation.rs:175`, `gpt_write.rs:60`) — relevant to H4,
   since that is the error a geometry divergence would surface as.
4. **Most validator rejection branches are untested** (L8) — of eight distinct
   `Error::Invalid` reasons across the two validators, only overlap is
   asserted.
5. **`mbr::write_mbr`'s overlap branch and `resize`'s overlap branch** have no
   test (M3).
6. **No test drives a panic through the five FFI guards** (M12).

Items 1-3 are worth adding regardless of whether the refactor happens.
