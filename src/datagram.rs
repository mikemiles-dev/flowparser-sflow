use nom::IResult;
use nom::number::complete::{be_u32, be_u64};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::SflowError;
use crate::samples::{SflowSample, parse_samples};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AddressType {
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SflowDatagram {
    pub version: u32,
    pub agent_address: AddressType,
    pub sub_agent_id: u32,
    pub sequence_number: u32,
    pub uptime: u32,
    pub samples: Vec<SflowSample>,
}

pub fn parse_address(input: &[u8]) -> IResult<&[u8], AddressType> {
    let (input, addr_type) = be_u32(input)?;
    match addr_type {
        1 => {
            let (input, a) = be_u32(input)?;
            Ok((input, AddressType::IPv4(Ipv4Addr::from(a))))
        }
        2 => {
            let (input, hi) = be_u64(input)?;
            let (input, lo) = be_u64(input)?;
            let mut octets = [0u8; 16];
            octets[..8].copy_from_slice(&hi.to_be_bytes());
            octets[8..].copy_from_slice(&lo.to_be_bytes());
            Ok((input, AddressType::IPv6(Ipv6Addr::from(octets))))
        }
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Switch,
        ))),
    }
}

pub fn parse_datagram(input: &[u8]) -> Result<(&[u8], SflowDatagram), SflowError> {
    let original = input;

    let (input, version) = be_u32(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
        SflowError::Incomplete {
            available: original.len(),
            context: "datagram header version".to_string(),
        }
    })?;

    if version != 5 {
        return Err(SflowError::UnsupportedVersion { version });
    }

    let (input, agent_address) =
        parse_address(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            SflowError::ParseError {
                offset: original.len() - input.len(),
                context: "agent address".to_string(),
                kind: "invalid address type".to_string(),
            }
        })?;

    let (input, sub_agent_id) =
        be_u32(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            SflowError::Incomplete {
                available: input.len(),
                context: "sub_agent_id".to_string(),
            }
        })?;

    let (input, sequence_number) =
        be_u32(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            SflowError::Incomplete {
                available: input.len(),
                context: "sequence_number".to_string(),
            }
        })?;

    let (input, uptime) = be_u32(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
        SflowError::Incomplete {
            available: input.len(),
            context: "uptime".to_string(),
        }
    })?;

    let (input, num_samples) =
        be_u32(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            SflowError::Incomplete {
                available: input.len(),
                context: "num_samples".to_string(),
            }
        })?;

    let (input, samples) = parse_samples(input, num_samples)?;

    Ok((
        input,
        SflowDatagram {
            version,
            agent_address,
            sub_agent_id,
            sequence_number,
            uptime,
            samples,
        },
    ))
}
