use sflow_parser::*;
use std::net::Ipv4Addr;

#[test]
fn test_datagram_with_mixed_samples() {
    let mut data = Vec::new();
    // Header
    data.extend_from_slice(&5u32.to_be_bytes());
    data.extend_from_slice(&1u32.to_be_bytes());
    data.extend_from_slice(&u32::from(Ipv4Addr::new(10, 0, 0, 1)).to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&1u32.to_be_bytes());
    data.extend_from_slice(&1000u32.to_be_bytes());
    data.extend_from_slice(&3u32.to_be_bytes()); // 3 samples

    // Flow sample with 0 records
    let mut flow_body = Vec::new();
    flow_body.extend_from_slice(&1u32.to_be_bytes());
    flow_body.extend_from_slice(&0u32.to_be_bytes());
    flow_body.extend_from_slice(&256u32.to_be_bytes());
    flow_body.extend_from_slice(&100u32.to_be_bytes());
    flow_body.extend_from_slice(&0u32.to_be_bytes());
    flow_body.extend_from_slice(&1u32.to_be_bytes());
    flow_body.extend_from_slice(&2u32.to_be_bytes());
    flow_body.extend_from_slice(&0u32.to_be_bytes()); // 0 records
    data.extend_from_slice(&((0u32 << 12) | 1).to_be_bytes());
    data.extend_from_slice(&(flow_body.len() as u32).to_be_bytes());
    data.extend_from_slice(&flow_body);

    // Counter sample with 0 records
    let mut counter_body = Vec::new();
    counter_body.extend_from_slice(&1u32.to_be_bytes());
    counter_body.extend_from_slice(&1u32.to_be_bytes());
    counter_body.extend_from_slice(&0u32.to_be_bytes()); // 0 records
    data.extend_from_slice(&((0u32 << 12) | 2).to_be_bytes());
    data.extend_from_slice(&(counter_body.len() as u32).to_be_bytes());
    data.extend_from_slice(&counter_body);

    // Expanded flow sample with 0 records
    let mut exp_flow_body = Vec::new();
    exp_flow_body.extend_from_slice(&1u32.to_be_bytes()); // seq
    exp_flow_body.extend_from_slice(&0u32.to_be_bytes()); // type
    exp_flow_body.extend_from_slice(&1u32.to_be_bytes()); // index
    exp_flow_body.extend_from_slice(&512u32.to_be_bytes()); // rate
    exp_flow_body.extend_from_slice(&200u32.to_be_bytes()); // pool
    exp_flow_body.extend_from_slice(&0u32.to_be_bytes()); // drops
    exp_flow_body.extend_from_slice(&0u32.to_be_bytes()); // input_format
    exp_flow_body.extend_from_slice(&1u32.to_be_bytes()); // input_value
    exp_flow_body.extend_from_slice(&0u32.to_be_bytes()); // output_format
    exp_flow_body.extend_from_slice(&2u32.to_be_bytes()); // output_value
    exp_flow_body.extend_from_slice(&0u32.to_be_bytes()); // 0 records
    data.extend_from_slice(&((0u32 << 12) | 3).to_be_bytes());
    data.extend_from_slice(&(exp_flow_body.len() as u32).to_be_bytes());
    data.extend_from_slice(&exp_flow_body);

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());
    assert_eq!(result.datagrams.len(), 1);

    let samples = &result.datagrams[0].samples;
    assert_eq!(samples.len(), 3);
    assert!(matches!(samples[0], SflowSample::Flow(_)));
    assert!(matches!(samples[1], SflowSample::Counter(_)));
    assert!(matches!(samples[2], SflowSample::ExpandedFlow(_)));
}
