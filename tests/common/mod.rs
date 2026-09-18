//! The reference tools, and the plumbing that makes comparing against
//! them a comparison rather than a hope.
//!
//! Everything in this module exists to serve `tests/oracle_tools.rs`,
//! which is the first thing in this repository that checks a partition
//! table against a reader that is not this crate. The two halves it
//! needs are here: a way to run `sgdisk`, `sfdisk`, `blkid` and `partx`
//! over an image file and turn their output into values, and a counter
//! that makes "the comparison ran" as load-bearing as "the comparison
//! passed".
//!
//! # A missing tool is a failure, never a skip
//!
//! [`require_tool`] panics. It does not return a bool, there is no
//! `if tool_available()` early return anywhere in the oracle, and the
//! panic is unconditional rather than gated on `CI` being set.
//!
//! The softer shape -- return early with a printed line when the tool
//! is absent, fail only under `CI` -- is what `rust-fs-squashfs` uses,
//! and it is a reasonable trade there. It is the wrong trade here for
//! one reason: this crate's oracle is the only check in the repository
//! that is not this crate marking its own homework, so a laptop run
//! that skipped it would report the same green as one that ran it,
//! having compared a GPT header against nothing at all. The tools are
//! two apt packages. Saying so in the panic message costs less than a
//! suite that quietly means less on some machines than others.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where a tool comes from, named in the panic when it is not there.
///
/// The message is the whole point of this table: a test that fails with
/// "sgdisk: No such file or directory" sends the reader to a search
/// engine, and one that fails with the package name sends them to a
/// terminal. Both Debian/Ubuntu (what CI runs) and the no-root route
/// this repository's own host uses are named, because the second is not
/// guessable.
fn install_hint(tool: &str) -> String {
    let package = match tool {
        "sgdisk" => "gdisk",
        "sfdisk" | "blkid" | "partx" => "util-linux",
        other => other,
    };
    format!(
        "`{tool}` is not on PATH. It ships in the `{package}` package: \
         `sudo apt-get install -y {package}` on Debian/Ubuntu (which is what \
         the `oracle (external tools)` job in .github/workflows/ci.yml does), \
         or `~/.local/bin/deb-local-install {package}` for a no-root install \
         into ~/.local/debroot. This test does not skip when the tool is \
         missing: the oracle is the only check in this repository that \
         compares a partition table against a reader other than this crate, \
         so a run without it would be green having compared nothing."
    )
}

/// Assert `tool` is runnable, or fail naming the package that carries it.
pub fn require_tool(tool: &str) {
    let ran = Command::new(tool).arg("--version").output();
    match ran {
        // A tool that runs and says something is present. `sgdisk
        // --version` exits 0; `partx --version` exits 0; a build of
        // either that exits non-zero while printing its version is
        // still a usable tool, so the status alone is not the test.
        Ok(out) if out.status.success() || !out.stdout.is_empty() => {}
        Ok(out) => panic!(
            "{}\n(`{tool} --version` exited {:?} with empty stdout; stderr: {})",
            install_hint(tool),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim(),
        ),
        Err(e) => panic!("{}\n(spawning it failed: {e})", install_hint(tool)),
    }
}

/// Run `program` with `args`, requiring success, and return stdout.
///
/// Every oracle call goes through here so that a tool failing is a
/// failure with the tool's own stderr in it, rather than an empty
/// string that then parses to nothing and compares equal to nothing.
pub fn run(program: &str, args: &[&str]) -> String {
    let out = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn {program} {args:?}: {e}"));
    assert!(
        out.status.success(),
        "{program} {args:?} failed: code={:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Run `program` with `args`, returning `(success, stdout, stderr)`.
///
/// For the calls whose failure is the thing being asserted -- `sgdisk
/// -v` on a table that is supposed to be wrong, `sfdisk` on a geometry
/// it is supposed to refuse.
pub fn try_run(program: &str, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn {program} {args:?}: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Feed `script` to `sfdisk` on `img`'s standard input.
///
/// `sfdisk` takes its table from stdin, so it is the one tool here that
/// cannot be driven by arguments alone.
pub fn sfdisk_script(img: &Path, extra: &[&str], script: &str) -> String {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new("sfdisk")
        .args(extra)
        .arg(img)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sfdisk");
    child
        .stdin
        .as_mut()
        .expect("sfdisk stdin")
        .write_all(script.as_bytes())
        .expect("write sfdisk script");
    let out = child.wait_with_output().expect("wait for sfdisk");
    assert!(
        out.status.success(),
        "sfdisk {extra:?} {} failed on script:\n{script}\ncode={:?}\nstdout: {}\nstderr: {}",
        img.display(),
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

// ---------------------------------------------------------------------------
// Images
// ---------------------------------------------------------------------------

/// A sparse image file in a tempdir, alive as long as this value is.
///
/// The tools all read image files directly -- no loop device, no root --
/// which is what makes this oracle runnable in an unprivileged CI
/// container and on a laptop.
pub struct Image {
    /// Held only to keep the directory alive: dropping it deletes the
    /// image, and every tool here takes a path rather than a handle.
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl Image {
    /// A new all-zero sparse image of `size` bytes.
    pub fn new(name: &str, size: u64) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(format!("{name}.img"));
        let f = std::fs::File::create(&path).expect("create image");
        f.set_len(size).expect("size image");
        drop(f);
        Image { _dir: dir, path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn as_str(&self) -> &str {
        self.path.to_str().expect("image path is utf-8")
    }

    /// The image's bytes.
    pub fn bytes(&self) -> Vec<u8> {
        std::fs::read(&self.path).expect("read image")
    }

    /// `count` bytes at `offset`.
    pub fn read_at(&self, offset: usize, count: usize) -> Vec<u8> {
        let all = self.bytes();
        all[offset..offset + count].to_vec()
    }

    /// Overwrite `count` bytes at `offset` with zeros. Used to damage a
    /// table on purpose and ask both readers what they make of it.
    pub fn zero_range(&self, offset: u64, count: usize) {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&self.path)
            .expect("open image for writing");
        f.seek(SeekFrom::Start(offset)).expect("seek");
        f.write_all(&vec![0u8; count]).expect("zero range");
    }

    /// The device this crate writes through.
    pub fn device(&self) -> partitions::FileBlock {
        partitions::FileBlock::open_rw(&self.path).expect("open image read-write")
    }
}

// ---------------------------------------------------------------------------
// sgdisk
// ---------------------------------------------------------------------------

/// What `sgdisk -p` says about a disk, and about each partition in it.
#[derive(Debug, Default)]
pub struct SgdiskPrint {
    pub total_sectors: u64,
    pub logical_sector_size: u64,
    pub disk_guid: String,
    pub entry_count: u32,
    pub first_usable: u64,
    pub last_usable: u64,
    /// `(number, first_lba, last_lba, type_code, name)` per partition.
    pub partitions: Vec<SgdiskRow>,
}

#[derive(Debug)]
pub struct SgdiskRow {
    pub number: u32,
    pub first_lba: u64,
    pub last_lba: u64,
    pub name: String,
}

/// Parse `sgdisk -p <img>`.
///
/// The partition rows are read by **column position, not by splitting on
/// whitespace**, because the last column is a partition name and names
/// have spaces in them -- `first part` is one name, not two fields. The
/// header line fixes the columns: `Number`, `Start (sector)`,
/// `End (sector)`, `Size`, `Code`, `Name`, and the name begins where
/// `Name` begins.
pub fn sgdisk_print(img: &Path) -> SgdiskPrint {
    let text = run("sgdisk", &["-p", img.to_str().expect("utf-8 path")]);
    let mut out = SgdiskPrint::default();
    let mut name_col: Option<usize> = None;
    let mut code_col: Option<usize> = None;

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Disk ") {
            if let Some((_, tail)) = rest.split_once(": ") {
                if let Some(sectors) = tail.split_whitespace().next() {
                    if let Ok(n) = sectors.parse::<u64>() {
                        out.total_sectors = n;
                    }
                }
            }
        }
        if let Some(rest) = line.strip_prefix("Sector size (logical): ") {
            out.logical_sector_size = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
        if let Some(rest) = line.strip_prefix("Disk identifier (GUID): ") {
            out.disk_guid = rest.trim().to_string();
        }
        if let Some(rest) = line.strip_prefix("Partition table holds up to ") {
            out.entry_count = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
        if let Some(rest) = line.strip_prefix("First usable sector is ") {
            let mut parts = rest.split(", last usable sector is ");
            out.first_usable = parts
                .next()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            out.last_usable = parts
                .next()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
        }
        if line.trim_start().starts_with("Number") && line.contains("Name") {
            name_col = line.find("Name");
            code_col = line.find("Code");
            continue;
        }
        let (Some(nc), Some(cc)) = (name_col, code_col) else {
            continue;
        };
        let trimmed = line.trim_start();
        if trimmed.is_empty() || !trimmed.starts_with(|c: char| c.is_ascii_digit()) {
            continue;
        }
        // Columns before `Code` are whitespace-separated numbers; from
        // `Code` on, the two remaining fields are taken by offset.
        let head: Vec<&str> = line[..cc].split_whitespace().collect();
        assert!(
            head.len() >= 3,
            "sgdisk -p row does not have number/start/end before the Code column: {line:?}\n\
             full output:\n{text}"
        );
        let name = line.get(nc..).unwrap_or("").trim_end().to_string();
        out.partitions.push(SgdiskRow {
            number: head[0].parse().expect("partition number"),
            first_lba: head[1].parse().expect("first lba"),
            last_lba: head[2].parse().expect("last lba"),
            name,
        });
    }
    out
}

/// What `sgdisk -i N` says about one partition.
#[derive(Debug, Default)]
pub struct SgdiskInfo {
    pub type_guid: String,
    pub unique_guid: String,
    pub first_sector: u64,
    pub last_sector: u64,
    pub size_sectors: u64,
    pub attributes: u64,
    pub name: String,
}

/// Parse `sgdisk -i <n> <img>`.
///
/// `-i` is the only one of these tools that reports a GPT entry's
/// 64-bit attribute word, which is where the legacy-BIOS-bootable bit
/// this crate's `Partition::is_bootable` reads lives.
pub fn sgdisk_info(img: &Path, number: u32) -> SgdiskInfo {
    let n = number.to_string();
    let text = run("sgdisk", &["-i", &n, img.to_str().expect("utf-8 path")]);
    let mut out = SgdiskInfo::default();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Partition GUID code: ") {
            out.type_guid = rest
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string();
        } else if let Some(rest) = line.strip_prefix("Partition unique GUID: ") {
            out.unique_guid = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("First sector: ") {
            out.first_sector = leading_number(rest);
        } else if let Some(rest) = line.strip_prefix("Last sector: ") {
            out.last_sector = leading_number(rest);
        } else if let Some(rest) = line.strip_prefix("Partition size: ") {
            out.size_sectors = leading_number(rest);
        } else if let Some(rest) = line.strip_prefix("Attribute flags: ") {
            out.attributes = u64::from_str_radix(rest.trim(), 16).unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("Partition name: ") {
            out.name = rest.trim().trim_matches('\'').to_string();
        }
    }
    assert!(
        !out.type_guid.is_empty(),
        "sgdisk -i {number} {} reported no type GUID:\n{text}",
        img.display()
    );
    out
}

fn leading_number(s: &str) -> u64 {
    s.split_whitespace()
        .next()
        .and_then(|t| t.parse().ok())
        .unwrap_or_else(|| panic!("no leading number in {s:?}"))
}

/// `sgdisk -v <img>`: the header CRCs, the entry-array CRC and the
/// backup header, checked by the tool whose author wrote the GPT
/// implementation most of the world reads tables with.
///
/// Returns the tool's own summary line so a failure says what it found.
pub fn sgdisk_verify(img: &Path) -> (bool, String) {
    let (ok, stdout, stderr) = try_run("sgdisk", &["-v", img.to_str().expect("utf-8 path")]);
    let text = format!("{stdout}{stderr}");
    (ok && text.contains("No problems found"), text)
}

// ---------------------------------------------------------------------------
// sfdisk
// ---------------------------------------------------------------------------

/// `sfdisk --json <img>`, parsed into the `partitiontable` object.
pub fn sfdisk_json(img: &Path) -> serde_json::Value {
    let text = run("sfdisk", &["--json", img.to_str().expect("utf-8 path")]);
    let v: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("sfdisk --json is not JSON: {e}\n{text}"));
    v.get("partitiontable")
        .cloned()
        .unwrap_or_else(|| panic!("sfdisk --json has no partitiontable key:\n{text}"))
}

/// `sfdisk --dump <img>`, verbatim except for the `device:` line.
///
/// The dump is the tool's own round-trippable description of a table,
/// and comparing two of them is how a commit that was supposed to
/// change nothing is held to it. The device line is dropped because it
/// names the path, which differs between the two images being compared
/// and is not part of the table.
pub fn sfdisk_dump(img: &Path) -> String {
    run("sfdisk", &["--dump", img.to_str().expect("utf-8 path")])
        .lines()
        .filter(|l| !l.starts_with("device:"))
        .map(|l| format!("{l}\n"))
        .collect()
}

// ---------------------------------------------------------------------------
// blkid / partx
// ---------------------------------------------------------------------------

/// `blkid -p -o export <img>` as a key/value map.
///
/// `-p` is low-level probe mode, which is what makes blkid look at a
/// regular file at all rather than consulting the udev cache.
pub fn blkid_export(img: &Path) -> HashMap<String, String> {
    let (ok, stdout, stderr) = try_run(
        "blkid",
        &["-p", "-o", "export", img.to_str().expect("utf-8 path")],
    );
    assert!(
        ok,
        "blkid -p -o export {} failed\nstdout: {stdout}\nstderr: {stderr}",
        img.display()
    );
    stdout
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Undo the escaping `partx --pairs` puts on a value.
///
/// A GPT partition name is UTF-16 on disk and arbitrary text to a
/// human, and `partx` renders anything outside printable ASCII as
/// `\xNN` per byte so the line stays safe to `eval`. Comparing the
/// escaped form against the name this crate wrote would fail on every
/// non-ASCII name -- and, worse, would pass while comparing nothing if
/// the test quietly lowered its sights to ASCII-only names. So the
/// bytes are put back and decoded as UTF-8, which is what `partx`
/// encoded them from.
fn unescape_partx(raw: &str) -> String {
    let src: Vec<u8> = raw.as_bytes().to_vec();
    let mut out: Vec<u8> = Vec::with_capacity(src.len());
    let mut i = 0;
    while i < src.len() {
        if src[i] == b'\\' && i + 1 < src.len() {
            match src[i + 1] {
                b'x' if i + 3 < src.len() => {
                    let hex = std::str::from_utf8(&src[i + 2..i + 4]).unwrap_or("");
                    if let Ok(b) = u8::from_str_radix(hex, 16) {
                        out.push(b);
                        i += 4;
                        continue;
                    }
                }
                b'"' | b'\\' => {
                    out.push(src[i + 1]);
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        out.push(src[i]);
        i += 1;
    }
    String::from_utf8(out)
        .unwrap_or_else(|e| panic!("partx value {raw:?} does not unescape to UTF-8: {e}"))
}

/// One `partx --pairs` row.
pub type PartxRow = HashMap<String, String>;

/// `partx -o ... --pairs <img>`: util-linux's partition-table reader,
/// which is the same libblkid code path the kernel's userspace tools
/// use to enumerate partitions.
pub fn partx_pairs(img: &Path) -> Vec<PartxRow> {
    let (ok, stdout, stderr) = try_run(
        "partx",
        &[
            "-o",
            "NR,START,END,SECTORS,NAME,UUID,TYPE,FLAGS",
            "--pairs",
            img.to_str().expect("utf-8 path"),
        ],
    );
    assert!(
        ok,
        "partx --pairs {} failed\nstdout: {stdout}\nstderr: {stderr}",
        img.display()
    );
    stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let mut row = HashMap::new();
            // `KEY="value"` pairs, values quoted and possibly containing
            // spaces (NAME does).
            let bytes: Vec<char> = line.chars().collect();
            let mut i = 0;
            while i < bytes.len() {
                while i < bytes.len() && bytes[i].is_whitespace() {
                    i += 1;
                }
                let key_start = i;
                while i < bytes.len() && bytes[i] != '=' {
                    i += 1;
                }
                if i >= bytes.len() {
                    break;
                }
                let key: String = bytes[key_start..i].iter().collect();
                i += 1; // '='
                assert_eq!(
                    bytes.get(i),
                    Some(&'"'),
                    "partx pair is not quoted: {line:?}"
                );
                i += 1;
                let val_start = i;
                while i < bytes.len() && bytes[i] != '"' {
                    i += 1;
                }
                let raw: String = bytes[val_start..i].iter().collect();
                i += 1; // closing quote
                row.insert(key, unescape_partx(&raw));
            }
            row
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Counting the comparisons
// ---------------------------------------------------------------------------

/// A comparison counter that is also the comparison.
///
/// # Why the count is asserted at all
///
/// Every oracle here is a loop over partitions, over fields, or over
/// both, and every one of those loops can come out empty. A `sgdisk -p`
/// whose row format changed parses to zero rows; a `sfdisk --json` key
/// that got renamed yields `None` at every lookup; a fixture list built
/// from a `read_dir` that found nothing iterates zero times. In all
/// three the test passes, loudly and instantly, having compared this
/// crate against nothing -- which is the state the whole file exists to
/// end.
///
/// So each comparison goes through [`Comparisons::eq`], which asserts
/// *and* counts, and each test ends with [`Comparisons::floor`]. The
/// floor is the number of comparisons the test made when it was
/// written, rounded down; it moves up with the test and never down.
pub struct Comparisons {
    what: &'static str,
    count: usize,
}

impl Comparisons {
    pub fn new(what: &'static str) -> Self {
        Comparisons { what, count: 0 }
    }

    /// Assert `ours == theirs`, counting the comparison.
    ///
    /// `field` names what is being compared and `context` locates it --
    /// which image, which partition -- because a failure here is a
    /// disagreement between this crate and a reference implementation,
    /// and the first question asked of one is always "on what".
    pub fn eq<T: PartialEq + std::fmt::Debug>(
        &mut self,
        context: &str,
        field: &str,
        ours: T,
        theirs: T,
    ) {
        assert_eq!(
            ours, theirs,
            "{}: {context}: {field}: this crate says {ours:?}, the reference tool says {theirs:?}",
            self.what
        );
        self.count += 1;
    }

    /// Assert `cond`, counting it as a comparison.
    pub fn that(&mut self, context: &str, field: &str, cond: bool, detail: &str) {
        assert!(cond, "{}: {context}: {field}: {detail}", self.what);
        self.count += 1;
    }

    /// Fail unless at least `floor` comparisons ran.
    pub fn floor(&self, floor: usize) {
        assert!(
            self.count >= floor,
            "{}: only {} comparisons ran, floor is {floor}. A parsing change that \
             silently stopped finding fields would leave this test green having \
             compared this crate against nothing, which is exactly what the floor \
             is here to refuse.",
            self.what,
            self.count,
        );
        println!("{}: {} comparisons (floor {floor})", self.what, self.count);
    }
}

// ---------------------------------------------------------------------------
// GUID formatting
// ---------------------------------------------------------------------------

/// A 16-byte mixed-endian GPT GUID as the tools print it: the first
/// three fields little-endian, the last two big-endian, uppercase.
///
/// This is the single most valuable line in the file. A GUID written
/// with the wrong endianness round-trips through this crate perfectly
/// -- it reads back the bytes it wrote -- and is a different GUID to
/// every other reader on earth. Rendering ours the way `sgdisk` renders
/// its own and comparing the strings is what makes that failure visible.
pub fn guid_to_string(g: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9], g[10], g[11], g[12], g[13],
        g[14], g[15],
    )
}

/// The inverse of [`guid_to_string`], for driving the tools with a GUID
/// this crate chose.
pub fn guid_from_string(s: &str) -> [u8; 16] {
    let hex: Vec<u8> = s
        .chars()
        .filter(|c| *c != '-')
        .collect::<Vec<char>>()
        .chunks(2)
        .map(|pair| {
            let s: String = pair.iter().collect();
            u8::from_str_radix(&s, 16).unwrap_or_else(|_| panic!("bad hex in guid {s:?}"))
        })
        .collect();
    assert_eq!(hex.len(), 16, "a GUID is 16 bytes: {s:?}");
    [
        hex[3], hex[2], hex[1], hex[0], hex[5], hex[4], hex[7], hex[6], hex[8], hex[9], hex[10],
        hex[11], hex[12], hex[13], hex[14], hex[15],
    ]
}
