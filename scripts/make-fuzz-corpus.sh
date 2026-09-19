#!/usr/bin/env bash
# Rebuild fuzz/corpus from tables sgdisk and sfdisk wrote.
#
# This crate is the first thing to touch an untrusted disk -- it reads
# sector 0 before anything has established what the device even is --
# so the seeds are tables the reference tools produced, not bytes this
# crate wrote. A random sector is refused by the signature check on the
# first line and never reaches the entry arithmetic underneath.
#
# Images are deliberately small. A GPT needs 33 sectors at each end and
# nothing in between has to be real, so 256 KiB is a whole disk as far
# as a partition table is concerned, and the committed corpus stays
# around a megabyte.
#
# Usage: scripts/make-fuzz-corpus.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/partitions-fuzz-corpus.XXXXXX")"
trap 'rm -rf "$work"' EXIT

for tool in sgdisk sfdisk mke2fs mkfs.vfat mkswap mksquashfs; do
    command -v "$tool" >/dev/null || {
        echo "$tool not found; it seeds part of the corpus" >&2
        exit 1
    }
done

rm -rf "$here/fuzz/corpus"
mkdir -p "$here/fuzz/corpus"/{device,mbr,gpt_header,sniff}

disk="$here/fuzz/corpus/device"

# --- GPT, an ordinary one -------------------------------------------
truncate -s 256K "$disk/gpt.img"
sgdisk -o \
    -n 1:34:100  -t 1:8300 -c 1:root \
    -n 2:101:200 -t 2:8200 -c 2:swap \
    -n 3:201:400 -t 3:ef00 -c 3:esp \
    "$disk/gpt.img" >/dev/null 2>&1

# --- GPT with the entry array full ----------------------------------
# The header declares how many entries there are and how long each one
# is, and their product sizes a read. A table with entries spread to
# the end of the array exercises more of that walk than three at the
# front.
truncate -s 256K "$disk/gpt-many.img"
sgdisk -o "$disk/gpt-many.img" >/dev/null 2>&1
for i in $(seq 1 16); do
    start=$((34 + (i - 1) * 25))
    sgdisk -n "$i:$start:$((start + 20))" -t "$i:8300" -c "$i:p$i" \
        "$disk/gpt-many.img" >/dev/null 2>&1
done

# --- GPT carrying a real filesystem ---------------------------------
# So that `probe` has something for `sniff` to classify afterwards,
# which is how the two are reached together in a real caller.
mkdir -p "$work/empty"
mksquashfs "$work/empty" "$work/tiny.sqfs" -noappend -no-progress \
    -all-time 0 -mkfs-time 0 >/dev/null 2>&1
truncate -s 256K "$disk/gpt-with-fs.img"
sgdisk -o -n 1:34:100 -t 1:8300 -c 1:sqfs "$disk/gpt-with-fs.img" >/dev/null 2>&1
dd if="$work/tiny.sqfs" of="$disk/gpt-with-fs.img" bs=512 seek=34 conv=notrunc status=none

# --- MBR, four primaries --------------------------------------------
truncate -s 256K "$disk/mbr.img"
sfdisk --no-reread --no-tell-kernel "$disk/mbr.img" >/dev/null 2>&1 <<'EOF'
label: dos
start=64, size=64, type=83
start=128, size=64, type=82
start=192, size=64, type=c
start=256, size=64, type=7
EOF

# --- MBR with an extended partition and a logical chain -------------
# The chain is the sharp part: each logical partition's entry points at
# the next extended boot record, and a chain that points back at itself
# is the cheapest way to turn a probe into a hang.
truncate -s 256K "$disk/mbr-extended.img"
sfdisk --no-reread --no-tell-kernel "$disk/mbr-extended.img" >/dev/null 2>&1 <<'EOF'
label: dos
start=64, size=32, type=83
start=128, size=320, type=5
start=160, size=32, type=83
start=224, size=32, type=83
start=288, size=32, type=83
EOF

# --- Sector cuts for the targets that take one sector ---------------
python3 - "$here/fuzz/corpus" <<'PY'
import os, struct, sys

root = sys.argv[1]
SECTOR = 512

for img_name in sorted(os.listdir(os.path.join(root, 'device'))):
    stem = img_name[:-len('.img')]
    img = open(os.path.join(root, 'device', img_name), 'rb').read()

    lba0 = img[:SECTOR]
    assert lba0[510:512] == b'\x55\xaa', f"{img_name}: no MBR signature in sector 0"
    with open(os.path.join(root, 'mbr', f'{stem}.bin'), 'wb') as f:
        f.write(lba0)

    lba1 = img[SECTOR:2 * SECTOR]
    if lba1[:8] == b'EFI PART':
        with open(os.path.join(root, 'gpt_header', f'{stem}.bin'), 'wb') as f:
            f.write(lba1)
PY

# --- Filesystem windows for the sniffer -----------------------------
# `classify` reads a window from the start of a partition, and the
# furthest thing it looks at is the ISO9660 descriptor at 0x8001 -- so
# 48 KiB is the whole of what it can see. Committing the window rather
# than the filesystem keeps these to a few tens of kilobytes each.
window() {
    dd if="$1" of="$here/fuzz/corpus/sniff/$2.bin" bs=1 count=49152 status=none
}

truncate -s 1M "$work/ext2.img"
mke2fs -q -t ext2 -b 1024 "$work/ext2.img" >/dev/null 2>&1
window "$work/ext2.img" ext2

# -s 1 (one sector per cluster) because FAT16 needs more than 4085
# clusters to be FAT16 at all, and the default cluster size on a small
# image gives fewer -- mkfs.vfat then refuses rather than silently
# producing FAT12.
truncate -s 8M "$work/fat16.img"
mkfs.vfat -F 16 -s 1 "$work/fat16.img" >/dev/null 2>&1
window "$work/fat16.img" fat16

truncate -s 64M "$work/fat32.img"
mkfs.vfat -F 32 -s 1 "$work/fat32.img" >/dev/null 2>&1
window "$work/fat32.img" fat32

truncate -s 1M "$work/swap.img"
mkswap "$work/swap.img" >/dev/null 2>&1
window "$work/swap.img" swap

# SquashFS is smaller than the window, which is itself worth a seed:
# `classify` has to answer from four bytes without reading past the end.
cp "$work/tiny.sqfs" "$here/fuzz/corpus/sniff/squashfs.bin"

echo "corpus rebuilt under fuzz/corpus:"
find "$here/fuzz/corpus" -type f | sort | sed "s#$here/##"
echo "total: $(find "$here/fuzz/corpus" -type f | wc -l) seeds, $(du -sh "$here/fuzz/corpus" | cut -f1)"
