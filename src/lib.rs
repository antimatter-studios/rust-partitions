//! Partition-table probe (GPT/MBR) and filesystem-magic sniffer over any
//! random-access block source.
//!
//! See the crate-level [`README`](https://github.com/antimatter-studios/rust-partitions)
//! for design and scope.
//!
//! Block-device abstractions come from
//! [`fs_core`](https://github.com/antimatter-studios/rust-fs-core); this
//! crate re-exports the bits most consumers will use so callers can `use
//! partitions::BlockRead;` without an extra dependency line.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod capi;
pub mod error;
pub mod gpt;
pub mod gpt_write;
pub mod mbr;
pub mod mutation;
pub mod probe;
pub mod sniff;

pub use error::{Error, Result};
pub use mutation::{PartitionRef, PartitionSet, PartitionTypeId};
pub use probe::{probe, Partition, PartitionKind, TableKind};
pub use sniff::{sniff, FsKind};

// Re-export the core block-device pieces so consumers don't have to depend
// on fs-core directly for the common cases. SliceReader / OwnedSlice
// originally lived here but moved to fs-core in v0.2 — they're generic
// block-layer types, not partition-specific. Re-exported to keep
// existing `partitions::SliceReader` callers working.
pub use fs_core::{BlockDevice, BlockRead, FileDevice as FileBlock, OwnedSlice, SliceReader};
