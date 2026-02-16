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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CounterRecord {
    GenericInterface(GenericInterface),
    EthernetInterface(EthernetInterface),
    TokenRing(TokenRing),
    Vlan(Vlan),
    Processor(Processor),
    Unknown {
        enterprise: u32,
        format: u32,
        data: Vec<u8>,
    },
}

pub fn parse_counter_records(
    mut input: &[u8],
    num_records: u32,
) -> IResult<&[u8], Vec<CounterRecord>> {
    let mut records = Vec::with_capacity(num_records as usize);

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
