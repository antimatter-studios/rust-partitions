// Shared by both tiers, included textually rather than depended on.
//
// `tests/fuzz_decoders.rs` and `fuzz/src/lib.rs` both `include!` this
// file. A crate dependency would have been tidier, but the fuzz crate
// depends on `libfuzzer-sys`, which builds libFuzzer's C++ runtime, and
// making the gate depend on the fuzz crate would drag that into every
// pull request build on the stable toolchain.
//
// What matters is that the two tiers read a device identically, so a
// reproducer from one reproduces in the other.

// Fully qualified below rather than imported: this file is `include!`d
// into modules that already import these names, and a duplicate `use`
// is a hard error.
use fs_core::{BlockRead, Result as BlockResult};

/// A disk held in memory, presented as a device.
pub struct Bytes(pub Vec<u8>);

impl BlockRead for Bytes {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> BlockResult<()> {
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        let end = start.saturating_add(buf.len());
        if end > self.0.len() {
            // What a real device answers for a read past its end, so a
            // crafted table cannot be told apart from a short device by
            // which error it provokes.
            return Err(fs_core::Error::ShortRead {
                offset,
                want: buf.len(),
                got: self.0.len().saturating_sub(start),
            });
        }
        buf.copy_from_slice(&self.0[start..end]);
        Ok(())
    }

    fn size_bytes(&self) -> u64 {
        self.0.len() as u64
    }
}

/// How many partitions one walk will sniff.
///
/// A crafted table can claim any number, and following all of them
/// would make a case slow rather than failing it -- which reads as a
/// hang without being one.
pub const PARTITION_BUDGET: usize = 64;

/// Probe a device and sniff what it found, which is the sequence a real
/// caller performs: decide what the table is, then decide what is in
/// each partition.
///
/// Every result is discarded. A crafted table is *supposed* to be
/// refused; what it may not do is panic, hang, or read somebody else's
/// memory. An extended-partition chain that points back at itself is
/// the cheapest way to try, which is why this is budgeted.
pub fn walk(image: &[u8]) {
    let dev = Bytes(image.to_vec());

    let _ = partitions::probe(&dev);
    let Ok((_kind, partitions, _source)) = partitions::probe_with_status(&dev) else {
        return;
    };

    for partition in partitions.iter().take(PARTITION_BUDGET) {
        let _ = partitions::sniff(&dev, partition);
    }
}
