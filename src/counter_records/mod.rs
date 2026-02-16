pub mod ethernet_interface;
pub mod generic_interface;
pub mod processor;
pub mod token_ring;
pub mod vlan;

use nom::IResult;
use nom::number::complete::be_u32;
use serde::{Deserialize, Serialize};

pub use ethernet_interface::EthernetInterface;
pub use generic_interface::GenericInterface;
pub use processor::Processor;
pub use token_ring::TokenRing;
pub use vlan::Vlan;

/// A counter record within a counter sample.
///
/// Counter records contain periodic interface and system statistics
/// reported by the sFlow agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CounterRecord {
    /// Generic interface counters (enterprise=0, format=1).
    GenericInterface(GenericInterface),
    /// Ethernet-specific interface counters (enterprise=0, format=2).
    EthernetInterface(EthernetInterface),
    /// Token Ring interface counters (enterprise=0, format=3).
    TokenRing(TokenRing),
    /// VLAN counters (enterprise=0, format=5).
    Vlan(Vlan),
    /// Processor/CPU counters (enterprise=0, format=1001).
    Processor(Processor),
    /// Unrecognized counter record type, preserved as raw bytes.
    Unknown {
        /// Enterprise code from the record header.
        enterprise: u32,
        /// Format code from the record header.
        format: u32,
        /// Raw record data.
        data: Vec<u8>,
    },
}

pub(crate) fn parse_counter_records(
    mut input: &[u8],
    num_records: u32,
) -> IResult<&[u8], Vec<CounterRecord>> {
    // Cap capacity to prevent DoS: each record needs at least 8 bytes (format + length)
    let cap = (num_records as usize).min(input.len() / 8);
    let mut records = Vec::with_capacity(cap);

    for _ in 0..num_records {
        let (rest, data_format) = be_u32(input)?;
        let enterprise = data_format >> 12;
        let format = data_format & 0xFFF;

        let (rest, record_length) = be_u32(rest)?;
        let record_length = record_length as usize;

        if rest.len() < record_length {
            return Err(nom::Err::Error(nom::error::Error::new(
                rest,
                nom::error::ErrorKind::Eof,
            )));
        }

        let record_data = &rest[..record_length];
        let after_record = &rest[record_length..];

        let record = if enterprise == 0 {
            match format {
                1 => {
                    let (_, r) = generic_interface::parse_generic_interface(record_data)?;
                    CounterRecord::GenericInterface(r)
                }
                2 => {
                    let (_, r) = ethernet_interface::parse_ethernet_interface(record_data)?;
                    CounterRecord::EthernetInterface(r)
                }
                3 => {
                    let (_, r) = token_ring::parse_token_ring(record_data)?;
                    CounterRecord::TokenRing(r)
                }
                5 => {
                    let (_, r) = vlan::parse_vlan(record_data)?;
                    CounterRecord::Vlan(r)
                }
                1001 => {
                    let (_, r) = processor::parse_processor(record_data)?;
                    CounterRecord::Processor(r)
                }
                _ => CounterRecord::Unknown {
                    enterprise,
                    format,
                    data: record_data.to_vec(),
                },
            }
        } else {
            CounterRecord::Unknown {
                enterprise,
                format,
                data: record_data.to_vec(),
            }
        };

        records.push(record);
        input = after_record;
    }

    Ok((input, records))
}
