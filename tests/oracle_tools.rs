//! This crate against `sgdisk`, `sfdisk`, `blkid` and `partx`.
//!
//! Everything else in `tests/` is this crate checked against itself: a
//! table built by the writer, read by the reader, and the two required
//! to agree. That is worth having and it cannot see the failure this
//! crate is most exposed to, which is agreeing with itself and
//! disagreeing with the world. A GPT field written at the wrong offset
//! round-trips perfectly here and is rejected by every other reader; a
//! GUID assembled in the wrong byte order reads back as the GUID that
//! was written and names a different partition everywhere else.
//!
//! So this file runs the tools. Both directions, because they catch
//! different things:
//!
//! * **Our writer, their reader.** Build a table with this crate, then
//!   require `sgdisk -p`, `sgdisk -i`, `sgdisk -v`, `sfdisk --json`,
//!   `blkid -p` and `partx --pairs` to report the table this crate
//!   thinks it wrote -- table type, partition count, start and end LBA,
//!   size, type GUID, unique GUID, name, attributes, disk GUID, and for
//!   GPT that both the primary and the backup header check out.
//! * **Their writer, our reader.** Have `sgdisk` and `sfdisk` lay down
//!   tables and require this crate to read the same values back. This
//!   is the direction that catches an assumption about a field this
//!   crate's own writer never varies.
//!
//! # No loop device, no root
//!
//! Every tool here reads and writes a plain file. `sgdisk`, `sfdisk`,
//! `blkid -p` and `partx` all take a path, and none of them needs the
//! kernel to have scanned the table, so the whole suite runs
//! unprivileged in a container.
//!
//! # The tools are required, never probed for
//!
//! See `tests/common/mod.rs`: a missing tool is a panic naming the
//! package that carries it. This suite is the only thing in the
//! repository that is not this crate marking its own homework, and a
//! skip would make a run without the tools report exactly the same
//! green as a run with them.

mod common;

use common::*;
use partitions::gpt::{attr, type_guids};
use partitions::mbr::types as mbr_types;
use partitions::{
    gpt, gpt_write, mbr, probe, probe_with_status, Partition, PartitionKind, PartitionSet,
    TableKind, TableSource, SECTOR_SIZE,
};

/// Every tool this file drives, asserted present once per test that
/// uses it.
fn require_gpt_tools() {
    require_tool("sgdisk");
    require_tool("sfdisk");
    require_tool("blkid");
    require_tool("partx");
}

/// A GPT partition this crate is asked to write.
struct GptSpec {
    start_lba: u64,
    sectors: u64,
    type_guid: [u8; 16],
    uuid: [u8; 16],
    name: Option<&'static str>,
    attributes: u64,
}

impl GptSpec {
    fn to_partition(&self) -> Partition {
        Partition {
            start: self.start_lba * SECTOR_SIZE,
            length: self.sectors * SECTOR_SIZE,
            kind: PartitionKind::Gpt {
                type_guid: self.type_guid,
                attributes: self.attributes,
            },
            label: self.name.map(str::to_string),
            uuid: Some(self.uuid),
            slot: None,
            issues: 0,
        }
    }
}

/// A distinct, readable UUID per partition, so a value showing up under
/// the wrong partition is obvious in the failure message rather than
/// being one random GUID among several.
fn uuid_for(n: u8) -> [u8; 16] {
    let mut g = [n; 16];
    // A well-formed version-4 / variant-1 UUID, so the tools render it
    // as an ordinary GUID rather than flagging it. The version nibble
    // lives in the high nibble of byte 7 -- `time_hi_and_version` is
    // little-endian on disk -- and the variant bits in the top of byte
    // 8, which is big-endian.
    g[7] = (g[7] & 0x0F) | 0x40;
    g[8] = (g[8] & 0x3F) | 0x80;
    g
}

/// The layouts both directions are checked over.
///
/// The shapes are chosen for what they can break rather than for
/// variety: a partition at the very first usable LBA, one ending at the
/// very last, a one-sector partition, names at and past the 36-UTF-16
/// unit field limit, names with non-ASCII in them, every named type
/// GUID the crate knows, and the two attribute bits anything reads.
fn gpt_layouts() -> Vec<(&'static str, u64, Vec<GptSpec>)> {
    vec![
        (
            "two-ordinary-partitions",
            64 * 1024 * 1024,
            vec![
                GptSpec {
                    start_lba: 2048,
                    sectors: 16384,
                    type_guid: type_guids::LINUX_FILESYSTEM,
                    uuid: uuid_for(0x11),
                    name: Some("first part"),
                    attributes: 0,
                },
                GptSpec {
                    start_lba: 18432,
                    sectors: 16384,
                    type_guid: type_guids::EFI_SYSTEM,
                    uuid: uuid_for(0x22),
                    name: Some("esp"),
                    attributes: 0,
                },
            ],
        ),
        (
            "boundaries-first-usable-and-last-usable",
            16 * 1024 * 1024,
            vec![
                // LBA 34 is the first usable sector of a canonical
                // 128x128 table, and 1 sector is the smallest partition
                // that can exist. Both are off-by-one bait.
                GptSpec {
                    start_lba: 34,
                    sectors: 1,
                    type_guid: type_guids::LINUX_SWAP,
                    uuid: uuid_for(0x33),
                    name: Some("one sector at the floor"),
                    attributes: 0,
                },
                GptSpec {
                    start_lba: 2048,
                    sectors: 32768 - 33 - 2048,
                    type_guid: type_guids::MICROSOFT_BASIC_DATA,
                    uuid: uuid_for(0x44),
                    name: Some("up to the last usable sector"),
                    attributes: 0,
                },
            ],
        ),
        (
            "attributes-and-awkward-names",
            32 * 1024 * 1024,
            vec![
                GptSpec {
                    start_lba: 2048,
                    sectors: 2048,
                    type_guid: type_guids::APPLE_HFS_PLUS,
                    uuid: uuid_for(0x55),
                    // 36 UTF-16 units exactly: the last name that fits.
                    name: Some("123456789012345678901234567890123456"),
                    attributes: attr::REQUIRED_PARTITION | attr::LEGACY_BIOS_BOOTABLE,
                },
                GptSpec {
                    start_lba: 4096,
                    sectors: 2048,
                    type_guid: type_guids::APPLE_APFS,
                    uuid: uuid_for(0x66),
                    name: Some("café ünïcøde ✓"),
                    attributes: attr::MS_READ_ONLY | attr::MS_HIDDEN | attr::MS_NO_AUTOMOUNT,
                },
                GptSpec {
                    start_lba: 8192,
                    sectors: 2048,
                    type_guid: guid_from_string("DEADBEEF-1234-5678-9ABC-DEF012345678"),
                    uuid: uuid_for(0x77),
                    name: None,
                    attributes: 0,
                },
            ],
        ),
        (
            "a-full-house-of-eight",
            128 * 1024 * 1024,
            (0..8)
                .map(|i| GptSpec {
                    start_lba: 2048 + i * 4096,
                    sectors: 4096,
                    type_guid: type_guids::LINUX_FILESYSTEM,
                    uuid: uuid_for(0x80 + i as u8),
                    name: Some("packed"),
                    attributes: 0,
                })
                .collect(),
        ),
    ]
}

/// Write `specs` onto a fresh image with this crate's GPT writer.
fn write_gpt_image(name: &str, size: u64, disk_guid: [u8; 16], specs: &[GptSpec]) -> Image {
    let img = Image::new(name, size);
    let parts: Vec<Partition> = specs.iter().map(GptSpec::to_partition).collect();
    let dev = img.device();
    gpt_write::write_gpt(&dev, &parts, disk_guid).expect("this crate writes the GPT");
    partitions::BlockDevice::flush(&dev).expect("flush");
    drop(dev);
    img
}

// ===========================================================================
// Direction one: our writer, their reader
// ===========================================================================

/// Every field of every GPT this crate writes, as the four reference
/// readers see it.
#[test]
fn gpt_tables_this_crate_writes_are_read_back_field_by_field_by_sgdisk_sfdisk_partx_and_blkid() {
    require_gpt_tools();
    let mut c = Comparisons::new("our GPT writer vs sgdisk/sfdisk/partx/blkid");

    for (name, size, specs) in gpt_layouts() {
        let disk_guid = guid_from_string("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0");
        let img = write_gpt_image(name, size, disk_guid, &specs);
        let ctx = |extra: &str| format!("{name}{extra}");

        // --- the table itself -------------------------------------------
        let sf = sfdisk_json(img.path());
        let bk = blkid_export(img.path());
        let sg = sgdisk_print(img.path());
        let px = partx_pairs(img.path());

        c.eq(
            &ctx(""),
            "sfdisk label",
            "gpt",
            sf["label"].as_str().unwrap(),
        );
        c.eq(&ctx(""), "blkid PTTYPE", "gpt", bk["PTTYPE"].as_str());
        c.eq(
            &ctx(""),
            "sgdisk logical sector size",
            SECTOR_SIZE,
            sg.logical_sector_size,
        );
        c.eq(
            &ctx(""),
            "sgdisk total sectors",
            size / SECTOR_SIZE,
            sg.total_sectors,
        );
        c.eq(
            &ctx(""),
            "sgdisk entry count",
            gpt_write::GptGeometry::canonical().num_entries,
            sg.entry_count,
        );

        // The disk GUID, from three readers that render it three ways:
        // sfdisk and sgdisk uppercase, blkid lowercase.
        let want_guid = guid_to_string(&disk_guid);
        c.eq(
            &ctx(""),
            "sfdisk disk id",
            want_guid.as_str(),
            sf["id"].as_str().unwrap(),
        );
        c.eq(
            &ctx(""),
            "sgdisk disk identifier",
            want_guid.as_str(),
            sg.disk_guid.as_str(),
        );
        c.eq(
            &ctx(""),
            "blkid PTUUID",
            want_guid.to_ascii_lowercase().as_str(),
            bk["PTUUID"].as_str(),
        );

        // The usable range this crate declared, as both tools read it.
        let geom = gpt_write::GptGeometry::canonical();
        let (first_usable, last_usable) = geom
            .usable_range(size / SECTOR_SIZE)
            .expect("the canonical geometry fits this disk");
        c.eq(
            &ctx(""),
            "sfdisk firstlba",
            first_usable,
            sf["firstlba"].as_u64().unwrap(),
        );
        c.eq(
            &ctx(""),
            "sfdisk lastlba",
            last_usable,
            sf["lastlba"].as_u64().unwrap(),
        );
        c.eq(
            &ctx(""),
            "sgdisk first usable",
            first_usable,
            sg.first_usable,
        );
        c.eq(&ctx(""), "sgdisk last usable", last_usable, sg.last_usable);

        // --- partition counts, from all three enumerating readers -------
        let sf_parts = sf["partitions"]
            .as_array()
            .expect("sfdisk partitions array");
        c.eq(
            &ctx(""),
            "sfdisk partition count",
            specs.len(),
            sf_parts.len(),
        );
        c.eq(
            &ctx(""),
            "sgdisk partition count",
            specs.len(),
            sg.partitions.len(),
        );
        c.eq(&ctx(""), "partx partition count", specs.len(), px.len());

        // --- every field of every partition -----------------------------
        for (i, spec) in specs.iter().enumerate() {
            let ctx = ctx(&format!(" partition {}", i + 1));
            let last_lba = spec.start_lba + spec.sectors - 1;
            let sfp = &sf_parts[i];
            let sgr = &sg.partitions[i];
            let sgi = sgdisk_info(img.path(), (i + 1) as u32);
            let pxr = &px[i];

            c.eq(&ctx, "sgdisk -p number", (i + 1) as u32, sgr.number);
            c.eq(&ctx, "partx NR", (i + 1).to_string(), pxr["NR"].clone());

            c.eq(
                &ctx,
                "sfdisk start",
                spec.start_lba,
                sfp["start"].as_u64().unwrap(),
            );
            c.eq(
                &ctx,
                "sgdisk -p first sector",
                spec.start_lba,
                sgr.first_lba,
            );
            c.eq(
                &ctx,
                "sgdisk -i first sector",
                spec.start_lba,
                sgi.first_sector,
            );
            c.eq(
                &ctx,
                "partx START",
                spec.start_lba.to_string(),
                pxr["START"].clone(),
            );

            c.eq(&ctx, "sgdisk -p last sector", last_lba, sgr.last_lba);
            c.eq(&ctx, "sgdisk -i last sector", last_lba, sgi.last_sector);
            c.eq(&ctx, "partx END", last_lba.to_string(), pxr["END"].clone());

            c.eq(
                &ctx,
                "sfdisk size",
                spec.sectors,
                sfp["size"].as_u64().unwrap(),
            );
            c.eq(
                &ctx,
                "sgdisk -i partition size",
                spec.sectors,
                sgi.size_sectors,
            );
            c.eq(
                &ctx,
                "partx SECTORS",
                spec.sectors.to_string(),
                pxr["SECTORS"].clone(),
            );

            let type_guid = guid_to_string(&spec.type_guid);
            c.eq(
                &ctx,
                "sfdisk type",
                type_guid.as_str(),
                sfp["type"].as_str().unwrap(),
            );
            c.eq(
                &ctx,
                "sgdisk -i type GUID",
                type_guid.as_str(),
                sgi.type_guid.as_str(),
            );
            c.eq(
                &ctx,
                "partx TYPE",
                type_guid.to_ascii_lowercase(),
                pxr["TYPE"].clone(),
            );

            let uuid = guid_to_string(&spec.uuid);
            c.eq(
                &ctx,
                "sfdisk uuid",
                uuid.as_str(),
                sfp["uuid"].as_str().unwrap(),
            );
            c.eq(
                &ctx,
                "sgdisk -i unique GUID",
                uuid.as_str(),
                sgi.unique_guid.as_str(),
            );
            c.eq(
                &ctx,
                "partx UUID",
                uuid.to_ascii_lowercase(),
                pxr["UUID"].clone(),
            );

            let want_name = spec.name.unwrap_or("");
            // sfdisk omits the key entirely for an empty name; sgdisk
            // prints `''`; partx prints an empty value. All three mean
            // the same thing and all three are checked.
            c.eq(
                &ctx,
                "sfdisk name",
                want_name,
                sfp.get("name").and_then(|v| v.as_str()).unwrap_or(""),
            );
            // `sgdisk -p` elides a name that does not fit its Name
            // column, printing a prefix and `...`. That is a display
            // limit, not a disagreement, so the elided form is checked
            // as a prefix and the full name is checked against
            // `sgdisk -i`, which prints it whole.
            match sgr.name.strip_suffix("...") {
                Some(prefix) => c.that(
                    &ctx,
                    "sgdisk -p name (elided)",
                    want_name.starts_with(prefix),
                    &format!(
                        "sgdisk -p showed {:?}, which is not a prefix of the name this \
                         crate wrote, {want_name:?}",
                        sgr.name
                    ),
                ),
                None => c.eq(&ctx, "sgdisk -p name", want_name, sgr.name.as_str()),
            }
            c.eq(&ctx, "sgdisk -i name", want_name, sgi.name.as_str());
            c.eq(
                &ctx,
                "partx NAME",
                want_name.to_string(),
                pxr["NAME"].clone(),
            );

            c.eq(
                &ctx,
                "sgdisk -i attribute flags",
                spec.attributes,
                sgi.attributes,
            );
        }

        // --- and the tool's own verdict on the whole table ---------------
        let (ok, report) = sgdisk_verify(img.path());
        c.that(
            &ctx(""),
            "sgdisk -v",
            ok,
            &format!(
                "sgdisk found problems in a table this crate wrote. It checks the \
                 primary header CRC, the entry-array CRC and the backup header, so \
                 this is the check that says the bytes are a GPT and not merely \
                 something this crate can read back:\n{report}"
            ),
        );
    }

    // MEASURED 2026-09-18 against sgdisk 1.0.10 and util-linux 2.41.5:
    // 409 comparisons -- 4 layouts, 15 whole-table fields each, and 15
    // per-partition fields across 15 partitions. Floor 370, about 10%
    // below, so ordinary churn in the layout list does not trip it
    // while a reader that stopped parsing does. It moves up with the
    // test and never down.
    c.floor(370);
}

/// One MBR primary this crate is asked to write: start LBA, length in
/// sectors, the type byte, and whether the active (bootable) flag is
/// set. A named type rather than the tuple written inline, because the
/// layout list is a `Vec` of tuples of a `Vec` of these and clippy's
/// `type_complexity` is right that the spelled-out form is unreadable.
type MbrSpec = (u64, u64, u8, bool);

/// The MBR half, against the two tools that read one.
#[test]
fn mbr_tables_this_crate_writes_are_read_back_field_by_field_by_sfdisk_partx_and_blkid() {
    require_tool("sfdisk");
    require_tool("blkid");
    require_tool("partx");
    let mut c = Comparisons::new("our MBR writer vs sfdisk/partx/blkid");

    let layouts: Vec<(&str, u64, Vec<MbrSpec>)> = vec![
        (
            "two-primaries-one-active",
            64 * 1024 * 1024,
            vec![
                (2048, 16384, mbr_types::LINUX, true),
                (18432, 16384, mbr_types::LINUX_SWAP, false),
            ],
        ),
        (
            "four-primaries-of-four-types",
            64 * 1024 * 1024,
            vec![
                (2048, 2048, mbr_types::FAT32_LBA, false),
                (4096, 2048, mbr_types::NTFS_OR_EXFAT, true),
                (6144, 2048, mbr_types::LINUX, false),
                (8192, 2048, mbr_types::EFI_SYSTEM, false),
            ],
        ),
        (
            "one-partition-at-lba-1",
            8 * 1024 * 1024,
            // LBA 1 is legal in an MBR -- there is no reserved range
            // beyond the boot sector itself -- and is where a
            // superfloppy-style layout starts.
            vec![(1, 16382, mbr_types::FAT16, false)],
        ),
    ];

    for (name, size, parts) in layouts {
        let img = Image::new(name, size);
        let partitions: Vec<Partition> = parts
            .iter()
            .map(|&(start_lba, sectors, type_byte, active)| Partition {
                start: start_lba * SECTOR_SIZE,
                length: sectors * SECTOR_SIZE,
                kind: PartitionKind::Mbr { type_byte, active },
                label: None,
                uuid: None,
                slot: None,
                issues: 0,
            })
            .collect();
        let dev = img.device();
        mbr::write_mbr(&dev, &partitions).expect("this crate writes the MBR");
        partitions::BlockDevice::flush(&dev).expect("flush");
        drop(dev);

        let sf = sfdisk_json(img.path());
        let bk = blkid_export(img.path());
        let px = partx_pairs(img.path());

        c.eq(name, "sfdisk label", "dos", sf["label"].as_str().unwrap());
        c.eq(name, "blkid PTTYPE", "dos", bk["PTTYPE"].as_str());

        let sf_parts = sf["partitions"]
            .as_array()
            .expect("sfdisk partitions array");
        c.eq(name, "sfdisk partition count", parts.len(), sf_parts.len());
        c.eq(name, "partx partition count", parts.len(), px.len());

        for (i, &(start_lba, sectors, type_byte, active)) in parts.iter().enumerate() {
            let ctx = format!("{name} partition {}", i + 1);
            let sfp = &sf_parts[i];
            let pxr = &px[i];

            c.eq(
                &ctx,
                "sfdisk start",
                start_lba,
                sfp["start"].as_u64().unwrap(),
            );
            c.eq(&ctx, "sfdisk size", sectors, sfp["size"].as_u64().unwrap());
            c.eq(
                &ctx,
                "sfdisk type",
                format!("{type_byte:x}"),
                sfp["type"].as_str().unwrap().to_string(),
            );
            c.eq(
                &ctx,
                "sfdisk bootable",
                active,
                sfp.get("bootable")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            );
            c.eq(
                &ctx,
                "partx START",
                start_lba.to_string(),
                pxr["START"].clone(),
            );
            c.eq(
                &ctx,
                "partx END",
                (start_lba + sectors - 1).to_string(),
                pxr["END"].clone(),
            );
            c.eq(
                &ctx,
                "partx SECTORS",
                sectors.to_string(),
                pxr["SECTORS"].clone(),
            );
            c.eq(
                &ctx,
                "partx TYPE",
                format!("0x{type_byte:x}"),
                pxr["TYPE"].clone(),
            );
            c.eq(
                &ctx,
                "partx FLAGS",
                if active { "0x80" } else { "0x0" }.to_string(),
                pxr["FLAGS"].clone(),
            );
        }
    }

    // MEASURED 2026-09-18: 75 comparisons over 3 layouts and 8
    // partitions. Floor 70.
    c.floor(70);
}

/// The protective MBR, byte for byte against the one `sgdisk` writes.
///
/// `sfdisk --json` on a GPT disk reports the GPT and says nothing about
/// LBA 0, so the only way to check the protective entry against a
/// reference is to build the same disk both ways and compare the
/// sixteen bytes. This is the entry that decides whether a legacy tool
/// sees "one unknown partition covering the disk" -- correct -- or an
/// empty disk it is willing to repartition.
#[test]
fn the_protective_mbr_this_crate_writes_is_the_one_sgdisk_writes() {
    require_tool("sgdisk");
    require_tool("sfdisk");
    let mut c = Comparisons::new("our protective MBR vs sgdisk's");

    for size in [8 * 1024 * 1024u64, 64 * 1024 * 1024, 512 * 1024 * 1024] {
        let ctx = format!("{size}-byte disk");
        let disk_guid = guid_from_string("A1B2C3D4-E5F6-4708-8899-AABBCCDDEEFF");
        let ours = write_gpt_image(
            "ours",
            size,
            disk_guid,
            &[GptSpec {
                start_lba: 2048,
                sectors: 2048,
                type_guid: type_guids::LINUX_FILESYSTEM,
                uuid: uuid_for(0x99),
                name: Some("p1"),
                attributes: 0,
            }],
        );

        let theirs = Image::new("theirs", size);
        run(
            "sgdisk",
            &[
                "-o",
                "-n",
                "1:2048:+1M",
                "-t",
                "1:8300",
                "-c",
                "1:p1",
                theirs.as_str(),
            ],
        );

        // The first MBR entry: status, CHS first, type, CHS last,
        // starting LBA, sector count.
        let ours_entry = ours.read_at(446, 16);
        let theirs_entry = theirs.read_at(446, 16);
        c.eq(&ctx, "protective MBR entry", ours_entry, theirs_entry);

        // The three remaining entries are empty on both, and the boot
        // signature is there on both.
        c.eq(
            &ctx,
            "MBR entries 2-4",
            ours.read_at(462, 48),
            theirs.read_at(462, 48),
        );
        c.eq(
            &ctx,
            "MBR boot signature",
            ours.read_at(510, 2),
            vec![0x55, 0xAA],
        );

        // And both are described the same way by the tool that reads an
        // MBR without being told to look for a GPT.
        let ours_sf = sfdisk_json(ours.path());
        let theirs_sf = sfdisk_json(theirs.path());
        c.eq(
            &ctx,
            "sfdisk label",
            ours_sf["label"].clone(),
            theirs_sf["label"].clone(),
        );
    }

    // MEASURED 2026-09-18: 12 comparisons, 4 per disk size. Floor 12 --
    // this one is exact because the count is fixed by the size list
    // rather than by anything a tool prints.
    c.floor(12);
}

/// The backup header and array, which is half of what a GPT is.
///
/// Three questions, each asked of both readers: does `sgdisk -v` accept
/// the backup this crate wrote; does `sgdisk` still print the table
/// after the primary header is destroyed; and does this crate recover
/// the same partitions from the same damaged disk. The last two
/// together are what say the backup is a real second copy rather than
/// bytes that merely satisfy a CRC.
#[test]
fn the_backup_gpt_this_crate_writes_is_a_real_second_copy_to_sgdisk_and_to_this_crate() {
    require_tool("sgdisk");
    require_tool("sfdisk");
    let mut c = Comparisons::new("our backup GPT vs sgdisk");

    for (name, size, specs) in gpt_layouts() {
        let disk_guid = guid_from_string("BAC12345-6789-4ABC-8DEF-0123456789AB");
        let img = write_gpt_image(name, size, disk_guid, &specs);

        // Intact: both headers check out, and this crate agrees.
        let (ok, report) = sgdisk_verify(img.path());
        c.that(name, "sgdisk -v on an intact table", ok, &report);
        let dev = img.device();
        let (kind, _parts, source) = probe_with_status(&dev).expect("probe the intact table");
        c.eq(name, "table kind", TableKind::Gpt, kind);
        c.eq(name, "table source", TableSource::Primary, source);
        c.eq(
            name,
            "validate_backup",
            gpt::BackupStatus::Ok,
            gpt::validate_backup(&dev, &_parts),
        );
        drop(dev);

        // Destroy the primary header and ask both readers again. The
        // entry array is left alone: this is the "somebody wrote over
        // LBA 1" failure, which is the one the backup exists for.
        let before = sfdisk_json(img.path());
        img.zero_range(SECTOR_SIZE, SECTOR_SIZE as usize);

        let dev = img.device();
        // `probe` alone must still refuse: a damaged primary is an error
        // there by design, and it is `probe_with_status` that falls back.
        c.that(
            name,
            "probe refuses a destroyed primary",
            probe(&dev).is_err(),
            "probe must not silently read the backup",
        );
        let (kind, recovered, source) =
            probe_with_status(&dev).expect("probe_with_status recovers from the backup");
        c.eq(name, "recovered table kind", TableKind::Gpt, kind);
        c.eq(
            name,
            "recovered table source",
            TableSource::RecoveredFromBackup,
            source,
        );
        c.eq(
            name,
            "recovered partition count",
            specs.len(),
            recovered.len(),
        );
        drop(dev);

        // sgdisk reads the same disk from its backup too, and reports
        // the same partitions the table had before the damage.
        let (_ok, verify_report) = sgdisk_verify(img.path());
        c.that(
            name,
            "sgdisk -v notices the damaged primary",
            verify_report.contains("Caution")
                || verify_report.contains("problem")
                || verify_report.contains("corrupt")
                || verify_report.contains("invalid"),
            &format!("sgdisk -v said nothing about a zeroed primary header:\n{verify_report}"),
        );
        let sg = sgdisk_print(img.path());
        c.eq(
            name,
            "sgdisk partition count after recovery",
            specs.len(),
            sg.partitions.len(),
        );
        for (i, spec) in specs.iter().enumerate() {
            let ctx = format!("{name} recovered partition {}", i + 1);
            c.eq(
                &ctx,
                "sgdisk first sector",
                spec.start_lba,
                sg.partitions[i].first_lba,
            );
            c.eq(
                &ctx,
                "this crate's start (from the backup)",
                spec.start_lba * SECTOR_SIZE,
                recovered[i].start,
            );
            c.eq(
                &ctx,
                "this crate's length (from the backup)",
                spec.sectors * SECTOR_SIZE,
                recovered[i].length,
            );
            c.eq(
                &ctx,
                "this crate's uuid (from the backup)",
                Some(spec.uuid),
                recovered[i].uuid,
            );
        }

        // The pre-damage view is what both agree they recovered.
        let before_parts = before["partitions"].as_array().unwrap();
        c.eq(
            name,
            "sfdisk saw the same count before the damage",
            specs.len(),
            before_parts.len(),
        );
    }

    // MEASURED 2026-09-18: 104 comparisons over the 4 layouts and their
    // 15 partitions, intact and then with the primary header destroyed.
    // Floor 95.
    c.floor(95);
}

// ===========================================================================
// Direction two: their writer, our reader
// ===========================================================================

/// Tables `sgdisk` lays down, read by this crate.
#[test]
fn gpt_tables_sgdisk_writes_are_read_back_field_by_field_by_this_crate() {
    require_tool("sgdisk");
    require_tool("sfdisk");
    let mut c = Comparisons::new("sgdisk's GPT writer vs our reader");

    // `sgdisk` chooses the unique GUIDs, the disk GUID, the alignment
    // and the entry array's shape. That is the value of this direction:
    // every one of those is a field this crate's own writer never
    // varies, so a reader assumption about any of them is invisible to
    // the other half of this file.
    let cases: Vec<(&str, u64, Vec<&str>)> = vec![
        (
            "sgdisk-three-partitions",
            64 * 1024 * 1024,
            vec![
                "-n",
                "1:2048:+8M",
                "-t",
                "1:8300",
                "-c",
                "1:root",
                "-n",
                "2:0:+8M",
                "-t",
                "2:EF00",
                "-c",
                "2:EFI System",
                "-n",
                "3:0:+4M",
                "-t",
                "3:8200",
                "-c",
                "3:swap",
            ],
        ),
        (
            "sgdisk-attributes-set",
            32 * 1024 * 1024,
            vec![
                "-n",
                "1:2048:+4M",
                "-t",
                "1:8300",
                "-c",
                "1:legacy boot",
                "-A",
                "1:set:2",
                "-A",
                "1:set:60",
            ],
        ),
        (
            "sgdisk-sparse-slots",
            64 * 1024 * 1024,
            // Slots 1, 4 and 9 -- a table with holes, which is the
            // normal state of a disk something has been deleted from
            // and the case where "position in the array" and
            // "partition number" part company.
            vec![
                "-n",
                "1:2048:+2M",
                "-t",
                "1:8300",
                "-c",
                "1:one",
                "-n",
                "4:0:+2M",
                "-t",
                "4:0700",
                "-c",
                "4:four",
                "-n",
                "9:0:+2M",
                "-t",
                "9:8300",
                "-c",
                "9:nine",
            ],
        ),
        (
            "sgdisk-long-and-unicode-names",
            32 * 1024 * 1024,
            vec![
                "-n",
                "1:2048:+2M",
                "-t",
                "1:8300",
                "-c",
                "1:123456789012345678901234567890123456",
                "-n",
                "2:0:+2M",
                "-t",
                "2:8300",
                "-c",
                "2:café ünïcøde ✓",
            ],
        ),
    ];

    for (name, size, args) in cases {
        let img = Image::new(name, size);
        let mut argv: Vec<&str> = vec!["-o"];
        argv.extend(args.iter().copied());
        argv.push(img.as_str());
        run("sgdisk", &argv);

        // sfdisk's JSON is the machine-readable description of what
        // sgdisk just wrote, and is what this crate is held to.
        let sf = sfdisk_json(img.path());
        let sf_parts = sf["partitions"].as_array().expect("partitions array");

        let dev = img.device();
        let (kind, parts) = probe(&dev).expect("this crate reads a table sgdisk wrote");
        let set = PartitionSet::from_probe(&dev).expect("probe into a set");
        drop(dev);

        c.eq(name, "table kind", TableKind::Gpt, kind);
        c.eq(name, "partition count", sf_parts.len(), parts.len());
        c.eq(
            name,
            "disk GUID",
            sf["id"].as_str().unwrap().to_string(),
            guid_to_string(&set.disk_guid),
        );
        c.eq(
            name,
            "declared usable range",
            Some((
                sf["firstlba"].as_u64().unwrap(),
                sf["lastlba"].as_u64().unwrap(),
            )),
            set.gpt_geometry.declared_usable,
        );

        for (i, sfp) in sf_parts.iter().enumerate() {
            let number = sfp["node"]
                .as_str()
                .unwrap()
                .rsplit(|ch: char| !ch.is_ascii_digit())
                .next()
                .unwrap()
                .parse::<u32>()
                .expect("partition number from node name");
            let ctx = format!("{name} partition {number}");
            let sgi = sgdisk_info(img.path(), number);
            let ours = &parts[i];
            let (start_lba, end_lba) = ours.sector_span().expect("a span");

            c.eq(&ctx, "start LBA", sfp["start"].as_u64().unwrap(), start_lba);
            c.eq(
                &ctx,
                "end LBA",
                sfp["start"].as_u64().unwrap() + sfp["size"].as_u64().unwrap() - 1,
                end_lba,
            );
            c.eq(
                &ctx,
                "length in bytes",
                sfp["size"].as_u64().unwrap() * SECTOR_SIZE,
                ours.length,
            );
            c.eq(
                &ctx,
                "unique GUID",
                sfp["uuid"].as_str().unwrap().to_string(),
                guid_to_string(&ours.uuid.expect("a GPT partition has a UUID")),
            );
            c.eq(
                &ctx,
                "label",
                sfp.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                ours.label.clone().unwrap_or_default(),
            );
            // The slot is what the number means, zero-based.
            c.eq(&ctx, "slot", Some(number - 1), ours.slot);
            c.eq(&ctx, "issues", 0u32, ours.issues);

            match ours.kind {
                PartitionKind::Gpt {
                    type_guid,
                    attributes,
                } => {
                    c.eq(
                        &ctx,
                        "type GUID",
                        sfp["type"].as_str().unwrap().to_string(),
                        guid_to_string(&type_guid),
                    );
                    c.eq(&ctx, "attributes", sgi.attributes, attributes);
                }
                other => panic!("{ctx}: a GPT partition came back as {other:?}"),
            }
        }
    }

    // MEASURED 2026-09-18 against sgdisk 1.0.10: 97 comparisons over 4
    // sgdisk-built tables and their 9 partitions. Floor 88.
    c.floor(88);
}

/// Tables `sfdisk` lays down -- GPT and MBR both -- read by this crate.
#[test]
fn tables_sfdisk_writes_are_read_back_field_by_field_by_this_crate() {
    require_tool("sfdisk");
    require_tool("partx");
    let mut c = Comparisons::new("sfdisk's writer vs our reader");

    let gpt_script = "label: gpt\nlabel-id: 1E2D3C4B-5A69-4788-9796-A5B4C3D2E1F0\nunit: sectors\n\
        \n\
        start=2048, size=8192, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, \
        uuid=AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE, name=\"root\"\n\
        start=10240, size=8192, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, \
        uuid=BBBBBBBB-CCCC-4DDD-8EEE-FFFFFFFFFFFF, name=\"EFI System\"\n\
        start=18432, size=2048, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, \
        uuid=CCCCCCCC-DDDD-4EEE-8FFF-000000000001, name=\"swap\"\n";
    let mbr_script = "label: dos\nlabel-id: 0xdeadbeef\nunit: sectors\n\
        \n\
        start=2048, size=8192, type=83, bootable\n\
        start=10240, size=8192, type=7\n\
        start=18432, size=2048, type=82\n";

    for (name, script, want_kind) in [
        ("sfdisk-gpt", gpt_script, TableKind::Gpt),
        ("sfdisk-mbr", mbr_script, TableKind::Mbr),
    ] {
        let img = Image::new(name, 64 * 1024 * 1024);
        sfdisk_script(img.path(), &[], script);

        let sf = sfdisk_json(img.path());
        let sf_parts = sf["partitions"].as_array().expect("partitions array");
        let px = partx_pairs(img.path());

        let dev = img.device();
        let (kind, parts) = probe(&dev).expect("this crate reads a table sfdisk wrote");
        let set = PartitionSet::from_probe(&dev).expect("probe into a set");
        drop(dev);

        c.eq(name, "table kind", want_kind, kind);
        c.eq(name, "partition count", sf_parts.len(), parts.len());
        c.eq(name, "partx agrees on the count", px.len(), parts.len());

        if want_kind == TableKind::Gpt {
            c.eq(
                name,
                "disk GUID",
                sf["id"].as_str().unwrap().to_string(),
                guid_to_string(&set.disk_guid),
            );
        }

        for (i, sfp) in sf_parts.iter().enumerate() {
            let ctx = format!("{name} partition {}", i + 1);
            let ours = &parts[i];
            let (start_lba, end_lba) = ours.sector_span().expect("a span");
            c.eq(&ctx, "start LBA", sfp["start"].as_u64().unwrap(), start_lba);
            c.eq(
                &ctx,
                "end LBA",
                sfp["start"].as_u64().unwrap() + sfp["size"].as_u64().unwrap() - 1,
                end_lba,
            );
            c.eq(
                &ctx,
                "partx START",
                px[i]["START"].clone(),
                start_lba.to_string(),
            );
            c.eq(&ctx, "partx END", px[i]["END"].clone(), end_lba.to_string());
            c.eq(&ctx, "slot", Some(i as u32), ours.slot);

            match ours.kind {
                PartitionKind::Gpt { type_guid, .. } => {
                    c.eq(
                        &ctx,
                        "type GUID",
                        sfp["type"].as_str().unwrap().to_string(),
                        guid_to_string(&type_guid),
                    );
                    c.eq(
                        &ctx,
                        "label",
                        sfp.get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        ours.label.clone().unwrap_or_default(),
                    );
                    c.eq(
                        &ctx,
                        "unique GUID",
                        sfp["uuid"].as_str().unwrap().to_string(),
                        guid_to_string(&ours.uuid.expect("a GPT partition has a UUID")),
                    );
                }
                PartitionKind::Mbr { type_byte, active } => {
                    c.eq(
                        &ctx,
                        "type byte",
                        sfp["type"].as_str().unwrap().to_string(),
                        format!("{type_byte:x}"),
                    );
                    c.eq(
                        &ctx,
                        "active flag",
                        sfp.get("bootable")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                        active,
                    );
                    c.eq(
                        &ctx,
                        "is_bootable",
                        sfp.get("bootable")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                        ours.is_bootable(),
                    );
                }
                other => panic!("{ctx}: unexpected kind {other:?}"),
            }
        }
    }

    // MEASURED 2026-09-18 against util-linux 2.41.5: 55 comparisons
    // over one GPT and one MBR table, 3 partitions each. Floor 50.
    c.floor(50);
}

// ===========================================================================
// Round trips: a commit that changed nothing, as the tools see it
// ===========================================================================

/// A probe-then-commit that edited nothing must leave a table the tools
/// describe identically.
///
/// This is the shape of check the repository did not have and #101 was.
/// A self-round-trip cannot see it at all: this crate reads back what it
/// wrote, agrees with itself, and reports success while a field no
/// partition of its own carries has been zeroed. `sfdisk --dump` is the
/// reference tool's own round-trippable description of a table, so
/// comparing the dump before against the dump after asks the question
/// this crate cannot ask itself -- with the disk identifier, which
/// Linux turns into every `PARTUUID` on the disk, inside the answer.
#[test]
fn a_gpt_commit_that_changed_nothing_changes_nothing_sfdisk_or_sgdisk_can_see() {
    require_tool("sgdisk");
    require_tool("sfdisk");
    let mut c = Comparisons::new("our GPT round trip vs sfdisk --dump");

    for (name, args) in [
        (
            "plain",
            vec![
                "-n",
                "1:2048:+8M",
                "-t",
                "1:8300",
                "-c",
                "1:root",
                "-n",
                "2:0:+8M",
                "-t",
                "2:EF00",
                "-c",
                "2:EFI System",
            ],
        ),
        (
            "with-attributes-and-holes",
            vec![
                "-n",
                "1:2048:+4M",
                "-t",
                "1:8300",
                "-c",
                "1:one",
                "-A",
                "1:set:2",
                "-n",
                "5:0:+4M",
                "-t",
                "5:0700",
                "-c",
                "5:five",
            ],
        ),
    ] {
        let img = Image::new(name, 64 * 1024 * 1024);
        let mut argv: Vec<&str> = vec!["-o"];
        argv.extend(args);
        argv.push(img.as_str());
        run("sgdisk", &argv);

        let before_dump = sfdisk_dump(img.path());
        let before_json = sfdisk_json(img.path());
        let (before_ok, _) = sgdisk_verify(img.path());
        c.that(
            name,
            "sgdisk -v before",
            before_ok,
            "sgdisk's own table did not verify",
        );

        let dev = img.device();
        let set = PartitionSet::from_probe(&dev).expect("probe");
        set.commit(&dev).expect("commit an unchanged set");
        drop(dev);

        let after_dump = sfdisk_dump(img.path());
        let after_json = sfdisk_json(img.path());
        let (after_ok, report) = sgdisk_verify(img.path());

        c.eq(name, "sfdisk --dump", after_dump, before_dump);
        c.eq(name, "sfdisk --json", after_json, before_json);
        c.that(name, "sgdisk -v after", after_ok, &report);
    }

    // MEASURED 2026-09-18: 8 comparisons, 4 per table. Floor 8.
    c.floor(8);
}

/// The MBR half of the same question, and the one that had the answer
/// wrong.
///
/// The disk identifier at bytes 440..444 is what Linux turns into
/// `PARTUUID=<signature>-<NN>` -- the name a kernel command line or an
/// `fstab` entry uses for an MBR partition. Nothing in this crate reads
/// it, nothing in this crate's own tests could see it change, and
/// `sfdisk --dump` prints it on the `label-id:` line of every dump.
#[test]
fn an_mbr_commit_that_changed_nothing_keeps_the_disk_identifier_and_the_boot_code() {
    require_tool("sfdisk");
    require_tool("blkid");
    let mut c = Comparisons::new("our MBR round trip vs sfdisk --dump");

    let cases = [
        (
            "primaries-only",
            "label: dos\nlabel-id: 0xb05958d4\nunit: sectors\n\n\
             start=2048, size=16384, type=83, bootable\n\
             start=18432, size=16384, type=82\n",
        ),
        (
            "with-an-extended-container",
            "label: dos\nlabel-id: 0x1234abcd\nunit: sectors\n\n\
             start=2048, size=16384, type=83\n\
             start=18432, size=32768, type=5\n\
             start=20480, size=16384, type=83\n",
        ),
    ];

    for (name, script) in cases {
        let img = Image::new(name, 64 * 1024 * 1024);
        sfdisk_script(img.path(), &[], script);

        // Boot code, so the loss the doc comment used to understate is
        // a measured thing rather than a worry. `sfdisk` does not write
        // any, and a BIOS disk has 440 bytes of it.
        let boot_code: Vec<u8> = (0..440u32).map(|i| (i % 251) as u8 + 1).collect();
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(img.path())
                .expect("open for boot code");
            f.seek(SeekFrom::Start(0)).expect("seek");
            f.write_all(&boot_code).expect("write boot code");
        }

        let before_dump = sfdisk_dump(img.path());
        let before_json = sfdisk_json(img.path());
        let before_ptuuid = blkid_export(img.path())
            .get("PTUUID")
            .cloned()
            .expect("blkid reports a PTUUID for an MBR disk");

        let dev = img.device();
        let set = PartitionSet::from_probe(&dev).expect("probe");
        set.commit(&dev).expect("commit an unchanged set");
        drop(dev);

        let after_dump = sfdisk_dump(img.path());
        let after_json = sfdisk_json(img.path());
        let after_ptuuid = blkid_export(img.path())
            .get("PTUUID")
            .cloned()
            .expect("blkid reports a PTUUID after the commit");

        c.eq(name, "sfdisk --dump", after_dump, before_dump);
        c.eq(name, "sfdisk --json", after_json, before_json);
        c.eq(name, "blkid PTUUID", after_ptuuid, before_ptuuid);
        c.eq(name, "boot code at 0..440", img.read_at(0, 440), boot_code);
    }

    // MEASURED 2026-09-18: 8 comparisons, 4 per table. Floor 8.
    c.floor(8);
}

/// A hybrid MBR -- LBA 0 carrying mirrored entries beside the `0xEE`
/// marker -- survives a round trip, and both readers still see the GPT.
///
/// `sgdisk -h` is the tool that makes one, so the fixture is the real
/// thing rather than a hand-assembled sector, and the comparison is
/// against LBA 0 exactly as `sgdisk` left it.
#[test]
fn a_hybrid_mbr_sgdisk_wrote_survives_a_round_trip_through_this_crate() {
    require_tool("sgdisk");
    require_tool("sfdisk");
    let mut c = Comparisons::new("our hybrid round trip vs sgdisk");

    let img = Image::new("hybrid", 64 * 1024 * 1024);
    run(
        "sgdisk",
        &[
            "-o",
            "-n",
            "1:2048:+8M",
            "-t",
            "1:8300",
            "-c",
            "1:root",
            "-n",
            "2:0:+8M",
            "-t",
            "2:EF00",
            "-c",
            "2:esp",
            img.as_str(),
        ],
    );
    run("sgdisk", &["-h", "1:EE", img.as_str()]);

    let lba0_before = img.read_at(0, 512);
    let before_dump = sfdisk_dump(img.path());
    // The hybrid entry `sgdisk` mirrors is a real 0x83 entry, not a
    // protective one, so LBA 0 is no longer a bare protective MBR.
    c.that(
        "hybrid",
        "sgdisk wrote a mirrored entry",
        lba0_before[446 + 4] != 0xEE,
        "sgdisk -h did not put a mirrored entry in slot 0; the fixture is not hybrid",
    );

    let dev = img.device();
    let (kind, parts) = probe(&dev).expect("this crate reads the GPT behind a hybrid MBR");
    c.eq("hybrid", "table kind", TableKind::Gpt, kind);
    c.eq("hybrid", "partition count", 2usize, parts.len());
    let set = PartitionSet::from_probe(&dev).expect("probe into a set");
    c.that(
        "hybrid",
        "LBA 0's entries were kept",
        !set.reserved.is_empty(),
        "a hybrid LBA 0 has entries to preserve and the set carried none",
    );
    set.commit(&dev).expect("commit an unchanged hybrid set");
    drop(dev);

    c.eq("hybrid", "LBA 0 bytes", img.read_at(0, 512), lba0_before);
    c.eq(
        "hybrid",
        "sfdisk --dump",
        sfdisk_dump(img.path()),
        before_dump,
    );
    let (ok, report) = sgdisk_verify(img.path());
    c.that("hybrid", "sgdisk -v", ok, &report);

    // MEASURED 2026-09-18: 7 comparisons. Floor 7.
    c.floor(7);
}
// ===========================================================================
// 4Kn: not here, and why
// ===========================================================================
//
// A 4096-byte-sector GPT is the one shape this file cannot build with
// the tools on an ordinary runner. `sfdisk --sector-size 4096` writes
// one, and that option arrived in util-linux 2.40; ubuntu-latest ships
// 2.39.3, which rejects it outright. The dump format's `sector-size:`
// header is not a substitute -- measured on util-linux 2.41, a script
// carrying it is written at 512 bytes per sector regardless. `sgdisk`
// has no equivalent at all, and reading one back needs the same
// argument on the way in, so both halves of the comparison are gated
// on the same version.
//
// The honest ways to get one are a loop device opened with
// `losetup --sector-size 4096`, which needs root and would cost this
// suite the property that makes it runnable anywhere (no loop device,
// no root, every tool reading a plain file), or a runner with
// util-linux 2.40. Neither belongs in the commit that adds the oracle.
// Tracked in #123; this crate's refusal of a 4Kn table by name is
// covered meanwhile by tests/fixtures.rs and tests/mutation.rs, which
// is self-marked homework and is exactly why the issue is open.
