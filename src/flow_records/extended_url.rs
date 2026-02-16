use nom::IResult;
use nom::bytes::complete::take;
use nom::number::complete::be_u32;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtendedUrl {
    pub direction: u32,
    pub url: String,
    pub host: String,
}

fn parse_sflow_string(input: &[u8]) -> IResult<&[u8], String> {
    let (input, length) = be_u32(input)?;
    let (input, bytes) = take(length as usize)(input)?;
    let padding = (4 - (length as usize % 4)) % 4;
    let (input, _) = take(padding)(input)?;
    let s = String::from_utf8_lossy(bytes).into_owned();
    Ok((input, s))
}

pub fn parse_extended_url(input: &[u8]) -> IResult<&[u8], ExtendedUrl> {
    let (input, direction) = be_u32(input)?;
    let (input, url) = parse_sflow_string(input)?;
    let (input, host) = parse_sflow_string(input)?;

    Ok((
        input,
        ExtendedUrl {
            direction,
            url,
            host,
        },
    ))
}
