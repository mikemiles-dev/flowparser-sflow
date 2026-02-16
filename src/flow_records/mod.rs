pub mod extended_gateway;
pub mod extended_router;
pub mod extended_switch;
pub mod extended_url;
pub mod extended_user;
pub mod raw_packet_header;
pub mod sampled_ethernet;
pub mod sampled_ipv4;
pub mod sampled_ipv6;

use nom::IResult;
use nom::bytes::complete::take;
use nom::number::complete::be_u32;
use serde::{Deserialize, Serialize};

pub use extended_gateway::ExtendedGateway;
pub use extended_router::ExtendedRouter;
pub use extended_switch::ExtendedSwitch;
pub use extended_url::ExtendedUrl;
pub use extended_user::ExtendedUser;
pub use raw_packet_header::RawPacketHeader;
pub use sampled_ethernet::SampledEthernet;
pub use sampled_ipv4::SampledIpv4;
pub use sampled_ipv6::SampledIpv6;

/// A flow record within a flow sample.
///
/// Flow records describe properties of a sampled packet, ranging from
/// raw header bytes to decoded L2/L3/L4 fields and extended routing data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowRecord {
    /// Raw packet header bytes (enterprise=0, format=1).
    RawPacketHeader(RawPacketHeader),
    /// Sampled Ethernet frame header (enterprise=0, format=2).
    SampledEthernet(SampledEthernet),
    /// Sampled IPv4 packet header (enterprise=0, format=3).
    SampledIpv4(SampledIpv4),
    /// Sampled IPv6 packet header (enterprise=0, format=4).
    SampledIpv6(SampledIpv6),
    /// Extended switch data — VLAN and priority (enterprise=0, format=1001).
    ExtendedSwitch(ExtendedSwitch),
    /// Extended router data — next hop and masks (enterprise=0, format=1002).
    ExtendedRouter(ExtendedRouter),
    /// Extended gateway data — BGP AS path and communities (enterprise=0, format=1003).
    ExtendedGateway(ExtendedGateway),
    /// Extended user data — source and destination user identifiers (enterprise=0, format=1004).
    ExtendedUser(ExtendedUser),
    /// Extended URL data — URL and host strings (enterprise=0, format=1005).
    ExtendedUrl(ExtendedUrl),
    /// Unrecognized flow record type, preserved as raw bytes.
    Unknown {
        /// Enterprise code from the record header.
        enterprise: u32,
        /// Format code from the record header.
        format: u32,
        /// Raw record data.
        data: Vec<u8>,
    },
}

/// Parse an XDR-encoded sFlow string (length-prefixed, padded to 4-byte boundary).
///
/// Note: Invalid UTF-8 bytes are replaced with U+FFFD (replacement character).
pub(crate) fn parse_sflow_string(input: &[u8]) -> IResult<&[u8], String> {
    let (input, length) = be_u32(input)?;
    let (input, bytes) = take(length as usize)(input)?;
    // Pad to 4-byte boundary
    let padding = (4 - (length as usize % 4)) % 4;
    let (input, _) = take(padding)(input)?;
    let s = String::from_utf8_lossy(bytes).into_owned();
    Ok((input, s))
}

pub(crate) fn parse_flow_records(
    mut input: &[u8],
    num_records: u32,
) -> IResult<&[u8], Vec<FlowRecord>> {
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
                    let (_, r) = raw_packet_header::parse_raw_packet_header(record_data)?;
                    FlowRecord::RawPacketHeader(r)
                }
                2 => {
                    let (_, r) = sampled_ethernet::parse_sampled_ethernet(record_data)?;
                    FlowRecord::SampledEthernet(r)
                }
                3 => {
                    let (_, r) = sampled_ipv4::parse_sampled_ipv4(record_data)?;
                    FlowRecord::SampledIpv4(r)
                }
                4 => {
                    let (_, r) = sampled_ipv6::parse_sampled_ipv6(record_data)?;
                    FlowRecord::SampledIpv6(r)
                }
                1001 => {
                    let (_, r) = extended_switch::parse_extended_switch(record_data)?;
                    FlowRecord::ExtendedSwitch(r)
                }
                1002 => {
                    let (_, r) = extended_router::parse_extended_router(record_data)?;
                    FlowRecord::ExtendedRouter(r)
                }
                1003 => {
                    let (_, r) = extended_gateway::parse_extended_gateway(record_data)?;
                    FlowRecord::ExtendedGateway(r)
                }
                1004 => {
                    let (_, r) = extended_user::parse_extended_user(record_data)?;
                    FlowRecord::ExtendedUser(r)
                }
                1005 => {
                    let (_, r) = extended_url::parse_extended_url(record_data)?;
                    FlowRecord::ExtendedUrl(r)
                }
                _ => FlowRecord::Unknown {
                    enterprise,
                    format,
                    data: record_data.to_vec(),
                },
            }
        } else {
            FlowRecord::Unknown {
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
