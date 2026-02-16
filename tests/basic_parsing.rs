use sflow_parser::*;
use std::net::Ipv4Addr;

fn build_datagram_with_flow_and_counter() -> Vec<u8> {
    let mut data = Vec::new();
    // Header
    data.extend_from_slice(&5u32.to_be_bytes());
    data.extend_from_slice(&1u32.to_be_bytes()); // IPv4
    data.extend_from_slice(&u32::from(Ipv4Addr::new(10, 0, 0, 1)).to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes()); // sub_agent_id
    data.extend_from_slice(&42u32.to_be_bytes()); // sequence_number
    data.extend_from_slice(&5000u32.to_be_bytes()); // uptime
    data.extend_from_slice(&2u32.to_be_bytes()); // 2 samples

    // Flow sample (enterprise=0, format=1) with 1 extended switch record
    let mut flow_body = Vec::new();
    flow_body.extend_from_slice(&1u32.to_be_bytes()); // seq
    flow_body.extend_from_slice(&3u32.to_be_bytes()); // source_id
    flow_body.extend_from_slice(&256u32.to_be_bytes()); // rate
    flow_body.extend_from_slice(&1000u32.to_be_bytes()); // pool
    flow_body.extend_from_slice(&0u32.to_be_bytes()); // drops
    flow_body.extend_from_slice(&1u32.to_be_bytes()); // input
    flow_body.extend_from_slice(&2u32.to_be_bytes()); // output
    flow_body.extend_from_slice(&1u32.to_be_bytes()); // num_records=1
    // Extended switch record
    let df = (0u32 << 12) | 1001;
    flow_body.extend_from_slice(&df.to_be_bytes());
    flow_body.extend_from_slice(&16u32.to_be_bytes()); // len
    flow_body.extend_from_slice(&100u32.to_be_bytes());
    flow_body.extend_from_slice(&0u32.to_be_bytes());
    flow_body.extend_from_slice(&200u32.to_be_bytes());
    flow_body.extend_from_slice(&0u32.to_be_bytes());

    let flow_df = (0u32 << 12) | 1;
    data.extend_from_slice(&flow_df.to_be_bytes());
    data.extend_from_slice(&(flow_body.len() as u32).to_be_bytes());
    data.extend_from_slice(&flow_body);

    // Counter sample (enterprise=0, format=2) with 1 VLAN record
    let mut counter_body = Vec::new();
    counter_body.extend_from_slice(&1u32.to_be_bytes()); // seq
    counter_body.extend_from_slice(&1u32.to_be_bytes()); // source_id
    counter_body.extend_from_slice(&1u32.to_be_bytes()); // num_records=1
    // VLAN record
    let vdf = (0u32 << 12) | 5;
    counter_body.extend_from_slice(&vdf.to_be_bytes());
    counter_body.extend_from_slice(&28u32.to_be_bytes()); // len
    counter_body.extend_from_slice(&100u32.to_be_bytes()); // vlan_id
    counter_body.extend_from_slice(&4096u64.to_be_bytes()); // octets
    counter_body.extend_from_slice(&50u32.to_be_bytes());
    counter_body.extend_from_slice(&5u32.to_be_bytes());
    counter_body.extend_from_slice(&2u32.to_be_bytes());
    counter_body.extend_from_slice(&0u32.to_be_bytes());

    let counter_df = (0u32 << 12) | 2;
    data.extend_from_slice(&counter_df.to_be_bytes());
    data.extend_from_slice(&(counter_body.len() as u32).to_be_bytes());
    data.extend_from_slice(&counter_body);

    data
}

#[test]
fn test_parse_complete_datagram_with_multiple_sample_types() {
    let data = build_datagram_with_flow_and_counter();
    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);

    assert!(result.error.is_none());
    assert_eq!(result.datagrams.len(), 1);

    let dg = &result.datagrams[0];
    assert_eq!(dg.version, 5);
    assert_eq!(dg.sequence_number, 42);
    assert_eq!(dg.samples.len(), 2);

    // First sample is flow
    assert!(matches!(&dg.samples[0], SflowSample::Flow(_)));
    // Second sample is counter
    assert!(matches!(&dg.samples[1], SflowSample::Counter(_)));
}

#[test]
fn test_parse_zero_sample_datagram() {
    let mut data = Vec::new();
    data.extend_from_slice(&5u32.to_be_bytes());
    data.extend_from_slice(&1u32.to_be_bytes());
    data.extend_from_slice(&u32::from(Ipv4Addr::new(192, 168, 1, 1)).to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&1u32.to_be_bytes());
    data.extend_from_slice(&100u32.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes()); // 0 samples

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());
    assert_eq!(result.datagrams[0].samples.len(), 0);
}

#[test]
fn test_default_parser_equals_builder() {
    let data = build_datagram_with_flow_and_counter();

    let default_result = SflowParser::default().parse_bytes(&data);
    let builder_result = SflowParser::builder().build().parse_bytes(&data);

    assert_eq!(default_result, builder_result);
}
