use nom::IResult;
use nom::bytes::complete::take;
use nom::number::complete::be_u32;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtendedUser {
    pub src_charset: u32,
    pub src_user: String,
    pub dst_charset: u32,
    pub dst_user: String,
}

fn parse_sflow_string(input: &[u8]) -> IResult<&[u8], String> {
    let (input, length) = be_u32(input)?;
    let (input, bytes) = take(length as usize)(input)?;
    // Pad to 4-byte boundary
    let padding = (4 - (length as usize % 4)) % 4;
    let (input, _) = take(padding)(input)?;
    let s = String::from_utf8_lossy(bytes).into_owned();
    Ok((input, s))
}

pub fn parse_extended_user(input: &[u8]) -> IResult<&[u8], ExtendedUser> {
    let (input, src_charset) = be_u32(input)?;
    let (input, src_user) = parse_sflow_string(input)?;
    let (input, dst_charset) = be_u32(input)?;
    let (input, dst_user) = parse_sflow_string(input)?;

    Ok((
        input,
        ExtendedUser {
            src_charset,
            src_user,
            dst_charset,
            dst_user,
        },
    ))
}
