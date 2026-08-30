use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    /// Block-layer error (read failure, short read, etc.). Lifted from
    /// `fs_core::Error` so any `BlockRead` failure flows up unchanged.
    Block(fs_core::Error),
    /// Underlying I/O failure that didn't go through fs-core (rare —
    /// retained for direct `std::io::Error` sources).
    Io(io::Error),
    /// No GPT signature and no MBR signature found.
    NoPartitionTable,
    /// GPT header was located but failed CRC validation.
    GptHeaderCrc,
    /// GPT partition-entry array failed CRC validation.
    GptEntriesCrc,
    /// GPT header field combination is internally inconsistent.
    GptCorrupt(&'static str),
    /// Reserved. Never constructed.
    ///
    /// The doc used to read "MBR signature missing or extended-partition
    /// chain broken", and neither happens here: a missing signature
    /// returns [`Error::NoPartitionTable`], and extended chains are not
    /// implemented. Kept because it is `pub` and published, so removing
    /// it would break a consumer matching on it.
    MbrCorrupt(&'static str),
    /// Reserved. Never constructed.
    ///
    /// The doc used to describe an opt-in backup-validation mode — "the
    /// variant only surfaces if a caller explicitly asks" — and there is
    /// no such option: nothing compares the primary and backup headers.
    /// A reader looking for that feature would have gone hunting for an
    /// argument that does not exist.
    ///
    /// Kept because it is `pub` and published. It is the variant to use
    /// if backup validation is added.
    GptBackupMismatch(&'static str),
    /// Mutation API rejected an input: overlap, out-of-bounds, alignment
    /// impossible, etc. Carries a short reason string.
    Invalid(&'static str),
    /// Mutation API tried to write a partition table that does not fit the
    /// device, or the device is too small for the chosen table type.
    DeviceTooSmall,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Block(e) => write!(f, "{e}"),
            Error::Io(e) => write!(f, "io: {e}"),
            Error::NoPartitionTable => write!(f, "no GPT or MBR signature found"),
            Error::GptHeaderCrc => write!(f, "GPT header CRC32 mismatch"),
            Error::GptEntriesCrc => write!(f, "GPT partition-entry array CRC32 mismatch"),
            Error::GptCorrupt(s) => write!(f, "GPT corrupt: {s}"),
            Error::MbrCorrupt(s) => write!(f, "MBR corrupt: {s}"),
            Error::GptBackupMismatch(s) => write!(f, "GPT backup mismatch: {s}"),
            Error::Invalid(s) => write!(f, "invalid argument: {s}"),
            Error::DeviceTooSmall => write!(f, "device too small for the requested table"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Block(e) => Some(e),
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<fs_core::Error> for Error {
    fn from(e: fs_core::Error) -> Self {
        Error::Block(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
