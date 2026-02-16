use serde::{Deserialize, Serialize};
use std::fmt;

/// Errors that can occur when parsing sFlow datagrams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SflowError {
    /// The input buffer is too short to read the expected field.
    Incomplete {
        /// Number of bytes available.
        available: usize,
        /// Description of the field being parsed.
        context: String,
    },
    /// The datagram version is not sFlow v5.
    UnsupportedVersion {
        /// The version number found in the datagram header.
        version: u32,
    },
    /// A structural parse error at a known offset.
    ParseError {
        /// Byte offset from the start of the datagram.
        offset: usize,
        /// Description of what was being parsed.
        context: String,
        /// Description of the error.
        kind: String,
    },
    /// The datagram contains more samples than the configured limit.
    TooManySamples {
        /// Number of samples declared in the datagram header.
        count: u32,
        /// Configured maximum.
        max: u32,
    },
}

impl fmt::Display for SflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SflowError::Incomplete { available, context } => {
                write!(
                    f,
                    "Incomplete data: only {available} bytes available ({context})"
                )
            }
            SflowError::UnsupportedVersion { version } => {
                write!(f, "Unsupported sFlow version: {version} (expected 5)")
            }
            SflowError::ParseError {
                offset,
                context,
                kind,
            } => {
                write!(f, "Parse error at offset {offset}: {kind} ({context})")
            }
            SflowError::TooManySamples { count, max } => {
                write!(f, "Too many samples: {count} exceeds maximum of {max}")
            }
        }
    }
}

impl std::error::Error for SflowError {}
