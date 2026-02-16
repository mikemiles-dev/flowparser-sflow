use sflow_parser::*;
use std::net::Ipv4Addr;

fn make_datagram() -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&5u32.to_be_bytes());
    data.extend_from_slice(&1u32.to_be_bytes());
    data.extend_from_slice(&u32::from(Ipv4Addr::new(10, 0, 0, 1)).to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&1u32.to_be_bytes());
    data.extend_from_slice(&1000u32.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());
    data
}

#[test]
fn test_json_round_trip() {
    let parser = SflowParser::default();
    let result = parser.parse_bytes(&make_datagram());

    let json = serde_json::to_string_pretty(&result).unwrap();
    let deserialized: ParseResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, deserialized);
}

#[test]
fn test_json_contains_readable_ip() {
    let parser = SflowParser::default();
    let result = parser.parse_bytes(&make_datagram());
    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("10.0.0.1"));
}

#[test]
fn test_error_serialization() {
    let err = SflowError::UnsupportedVersion { version: 4 };
    let json = serde_json::to_string(&err).unwrap();
    let deserialized: SflowError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, deserialized);
}

#[test]
fn test_datagram_debug_display() {
    let parser = SflowParser::default();
    let result = parser.parse_bytes(&make_datagram());
    let debug = format!("{:?}", result.datagrams[0]);
    assert!(debug.contains("SflowDatagram"));
    assert!(debug.contains("version: 5"));
}
