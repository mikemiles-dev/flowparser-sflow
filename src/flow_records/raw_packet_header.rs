use nom::IResult;
use nom::bytes::complete::take;
use nom::number::complete::be_u32;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawPacketHeader {
    pub header_protocol: u32,
    pub frame_length: u32,
    pub stripped: u32,
    pub header_length: u32,
    pub header: Vec<u8>,
}

pub fn parse_raw_packet_header(input: &[u8]) -> IResult<&[u8], RawPacketHeader> {
    let (input, header_protocol) = be_u32(input)?;
    let (input, frame_length) = be_u32(input)?;
    let (input, stripped) = be_u32(input)?;
    let (input, header_length) = be_u32(input)?;
    let (input, header) = take(header_length as usize)(input)?;

    Ok((
        input,
        RawPacketHeader {
            header_protocol,
            frame_length,
            stripped,
            header_length,
            header: header.to_vec(),
        },
    ))
}
