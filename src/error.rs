use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SflowError {
    Incomplete {
        available: usize,
        context: String,
    },
    UnsupportedVersion {
        version: u32,
    },
    ParseError {
        offset: usize,
        context: String,
        kind: String,
    },
    TooManySamples {
        count: u32,
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
