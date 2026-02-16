pub mod counter_records;
pub mod datagram;
pub mod error;
pub mod flow_records;
pub mod samples;

#[cfg(test)]
mod tests;

pub use counter_records::CounterRecord;
pub use datagram::{AddressType, SflowDatagram};
pub use error::SflowError;
pub use flow_records::FlowRecord;
pub use samples::SflowSample;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParseResult {
    pub datagrams: Vec<SflowDatagram>,
    pub error: Option<SflowError>,
}

#[derive(Debug, Clone, Default)]
pub struct SflowParser {
    max_samples: Option<u32>,
}

impl SflowParser {
    pub fn builder() -> SflowParserBuilder {
        SflowParserBuilder { max_samples: None }
    }

    pub fn parse_bytes(&self, packet: &[u8]) -> ParseResult {
        let mut datagrams = Vec::new();
        let mut remaining = packet;

        loop {
            if remaining.is_empty() {
                break;
            }

            // Need at least 4 bytes for version
            if remaining.len() < 4 {
                return ParseResult {
                    datagrams,
                    error: Some(SflowError::Incomplete {
                        available: remaining.len(),
                        context: "datagram header".to_string(),
                    }),
                };
            }

            match datagram::parse_datagram(remaining) {
                Ok((rest, dg)) => {
                    if let Some(max) = self.max_samples
                        && dg.samples.len() as u32 > max
                    {
                        return ParseResult {
                            datagrams,
                            error: Some(SflowError::TooManySamples {
                                count: dg.samples.len() as u32,
                                max,
                            }),
                        };
                    }
                    datagrams.push(dg);
                    remaining = rest;
                }
                Err(e) => {
                    return ParseResult {
                        datagrams,
                        error: Some(e),
                    };
                }
            }
        }

        ParseResult {
            datagrams,
            error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SflowParserBuilder {
    max_samples: Option<u32>,
}

impl SflowParserBuilder {
    pub fn with_max_samples(mut self, max: u32) -> Self {
        self.max_samples = Some(max);
        self
    }

    pub fn build(self) -> SflowParser {
        SflowParser {
            max_samples: self.max_samples,
        }
    }
}
