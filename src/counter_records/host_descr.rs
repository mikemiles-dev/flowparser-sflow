use nom::IResult;
use nom::bytes::complete::take;
use nom::number::complete::be_u32;
use serde::{Deserialize, Serialize};

use crate::flow_records::parse_sflow_string;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostDescr {
    pub hostname: String,
    pub uuid: [u8; 16],
    pub machine_type: u32,
    pub os_name: u32,
    pub os_release: String,
}

pub(crate) fn parse_host_descr(input: &[u8]) -> IResult<&[u8], HostDescr> {
    let (input, hostname) = parse_sflow_string(input)?;
    let (input, uuid_bytes) = take(16u8)(input)?;
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(uuid_bytes);
    let (input, machine_type) = be_u32(input)?;
    let (input, os_name) = be_u32(input)?;
    let (input, os_release) = parse_sflow_string(input)?;

    Ok((
        input,
        HostDescr {
            hostname,
            uuid,
            machine_type,
            os_name,
            os_release,
        },
    ))
}
