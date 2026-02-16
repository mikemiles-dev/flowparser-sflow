use std::net::{Ipv4Addr, Ipv6Addr};

use crate::counter_records::*;
use crate::datagram::*;
use crate::flow_records::*;
use crate::samples::*;
use crate::*;

// Helper to build a minimal v5 datagram header with IPv4 agent and 0 samples
fn minimal_datagram_ipv4(agent_ip: [u8; 4], num_samples: u32) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&5u32.to_be_bytes()); // version
    data.extend_from_slice(&1u32.to_be_bytes()); // address type IPv4
    data.extend_from_slice(&agent_ip); // agent address
    data.extend_from_slice(&0u32.to_be_bytes()); // sub_agent_id
    data.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
    data.extend_from_slice(&1000u32.to_be_bytes()); // uptime
    data.extend_from_slice(&num_samples.to_be_bytes());
    data
}

fn minimal_datagram_ipv6(num_samples: u32) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&5u32.to_be_bytes()); // version
    data.extend_from_slice(&2u32.to_be_bytes()); // address type IPv6
    data.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // agent address
    data.extend_from_slice(&0u32.to_be_bytes()); // sub_agent_id
    data.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
    data.extend_from_slice(&1000u32.to_be_bytes()); // uptime
    data.extend_from_slice(&num_samples.to_be_bytes());
    data
}

// Append a sample header (enterprise/format + length) + sample data
fn append_sample(buf: &mut Vec<u8>, enterprise: u32, format: u32, sample_data: &[u8]) {
    let data_format = (enterprise << 12) | (format & 0xFFF);
    buf.extend_from_slice(&data_format.to_be_bytes());
    buf.extend_from_slice(&(sample_data.len() as u32).to_be_bytes());
    buf.extend_from_slice(sample_data);
}

// Append a record header (enterprise/format + length) + record data
fn append_record(buf: &mut Vec<u8>, enterprise: u32, format: u32, record_data: &[u8]) {
    let data_format = (enterprise << 12) | (format & 0xFFF);
    buf.extend_from_slice(&data_format.to_be_bytes());
    buf.extend_from_slice(&(record_data.len() as u32).to_be_bytes());
    buf.extend_from_slice(record_data);
}

// Build flow sample body (header + records)
fn build_flow_sample_body(records_data: &[u8], num_records: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
    body.extend_from_slice(&3u32.to_be_bytes()); // source_id (type=0, index=3)
    body.extend_from_slice(&256u32.to_be_bytes()); // sampling_rate
    body.extend_from_slice(&1000u32.to_be_bytes()); // sample_pool
    body.extend_from_slice(&0u32.to_be_bytes()); // drops
    body.extend_from_slice(&1u32.to_be_bytes()); // input
    body.extend_from_slice(&2u32.to_be_bytes()); // output
    body.extend_from_slice(&num_records.to_be_bytes());
    body.extend_from_slice(records_data);
    body
}

// Build counter sample body (header + records)
fn build_counter_sample_body(records_data: &[u8], num_records: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
    body.extend_from_slice(&1u32.to_be_bytes()); // source_id (type=0, index=1)
    body.extend_from_slice(&num_records.to_be_bytes());
    body.extend_from_slice(records_data);
    body
}

// === Datagram Header Tests ===

#[test]
fn test_parse_datagram_ipv4_agent() {
    let data = minimal_datagram_ipv4([10, 0, 0, 1], 0);
    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());
    assert_eq!(result.datagrams.len(), 1);
    let dg = &result.datagrams[0];
    assert_eq!(dg.version, 5);
    assert_eq!(
        dg.agent_address,
        AddressType::IPv4(Ipv4Addr::new(10, 0, 0, 1))
    );
    assert_eq!(dg.sub_agent_id, 0);
    assert_eq!(dg.sequence_number, 1);
    assert_eq!(dg.uptime, 1000);
    assert_eq!(dg.samples.len(), 0);
}

#[test]
fn test_parse_datagram_ipv6_agent() {
    let data = minimal_datagram_ipv6(0);
    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());
    assert_eq!(result.datagrams.len(), 1);
    let dg = &result.datagrams[0];
    assert_eq!(dg.version, 5);
    match &dg.agent_address {
        AddressType::IPv6(addr) => {
            assert_eq!(*addr, "fe80::1".parse::<Ipv6Addr>().unwrap());
        }
        _ => panic!("Expected IPv6 address"),
    }
}

#[test]
fn test_parse_datagram_bad_version() {
    let mut data = minimal_datagram_ipv4([10, 0, 0, 1], 0);
    // Change version to 4
    data[3] = 4;
    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_some());
    match result.error.unwrap() {
        SflowError::UnsupportedVersion { version } => {
            assert_eq!(version, 4)
        }
        other => panic!("Expected UnsupportedVersion, got {:?}", other),
    }
}

#[test]
fn test_parse_truncated_input() {
    let data = vec![0, 0, 0]; // Too short
    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_some());
    match result.error.unwrap() {
        SflowError::Incomplete { .. } => {}
        other => panic!("Expected Incomplete, got {:?}", other),
    }
}

// === Flow Sample Tests ===

#[test]
fn test_parse_flow_sample_with_extended_switch() {
    let mut records = Vec::new();
    let switch_data: Vec<u8> = [
        100u32.to_be_bytes(), // src_vlan
        0u32.to_be_bytes(),   // src_priority
        200u32.to_be_bytes(), // dst_vlan
        0u32.to_be_bytes(),   // dst_priority
    ]
    .concat();
    append_record(&mut records, 0, 1001, &switch_data);

    let sample_body = build_flow_sample_body(&records, 1);
    let mut data = minimal_datagram_ipv4([10, 0, 0, 1], 1);
    append_sample(&mut data, 0, 1, &sample_body);

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());
    let dg = &result.datagrams[0];
    assert_eq!(dg.samples.len(), 1);

    match &dg.samples[0] {
        SflowSample::Flow(fs) => {
            assert_eq!(fs.sequence_number, 1);
            assert_eq!(fs.source_id_type, 0);
            assert_eq!(fs.source_id_index, 3);
            assert_eq!(fs.sampling_rate, 256);
            assert_eq!(fs.records.len(), 1);
            match &fs.records[0] {
                FlowRecord::ExtendedSwitch(es) => {
                    assert_eq!(es.src_vlan, 100);
                    assert_eq!(es.dst_vlan, 200);
                }
                other => {
                    panic!("Expected ExtendedSwitch, got {:?}", other)
                }
            }
        }
        other => panic!("Expected Flow sample, got {:?}", other),
    }
}

#[test]
fn test_parse_expanded_flow_sample() {
    // Build expanded flow sample with 0 records
    let mut sample_body = Vec::new();
    sample_body.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
    sample_body.extend_from_slice(&0u32.to_be_bytes()); // source_id_type
    sample_body.extend_from_slice(&5u32.to_be_bytes()); // source_id_index
    sample_body.extend_from_slice(&512u32.to_be_bytes()); // sampling_rate
    sample_body.extend_from_slice(&2000u32.to_be_bytes()); // sample_pool
    sample_body.extend_from_slice(&0u32.to_be_bytes()); // drops
    sample_body.extend_from_slice(&0u32.to_be_bytes()); // input_format
    sample_body.extend_from_slice(&1u32.to_be_bytes()); // input_value
    sample_body.extend_from_slice(&0u32.to_be_bytes()); // output_format
    sample_body.extend_from_slice(&2u32.to_be_bytes()); // output_value
    sample_body.extend_from_slice(&0u32.to_be_bytes()); // num_records

    let mut data = minimal_datagram_ipv4([10, 0, 0, 1], 1);
    append_sample(&mut data, 0, 3, &sample_body);

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());

    match &result.datagrams[0].samples[0] {
        SflowSample::ExpandedFlow(efs) => {
            assert_eq!(efs.source_id_type, 0);
            assert_eq!(efs.source_id_index, 5);
            assert_eq!(efs.sampling_rate, 512);
            assert_eq!(efs.input_value, 1);
            assert_eq!(efs.output_value, 2);
        }
        other => panic!("Expected ExpandedFlow, got {:?}", other),
    }
}

// === Counter Sample Tests ===

#[test]
fn test_parse_counter_sample_with_vlan() {
    let mut records = Vec::new();
    let vlan_data: Vec<u8> = [
        100u32.to_be_bytes().as_slice(), // vlan_id
        &4096u64.to_be_bytes(),          // octets
        &50u32.to_be_bytes(),            // ucast_pkts
        &5u32.to_be_bytes(),             // multicast_pkts
        &2u32.to_be_bytes(),             // broadcast_pkts
        &0u32.to_be_bytes(),             // discards
    ]
    .concat();
    append_record(&mut records, 0, 5, &vlan_data);

    let sample_body = build_counter_sample_body(&records, 1);
    let mut data = minimal_datagram_ipv4([10, 0, 0, 1], 1);
    append_sample(&mut data, 0, 2, &sample_body);

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());

    match &result.datagrams[0].samples[0] {
        SflowSample::Counter(cs) => {
            assert_eq!(cs.sequence_number, 1);
            assert_eq!(cs.source_id_type, 0);
            assert_eq!(cs.source_id_index, 1);
            assert_eq!(cs.records.len(), 1);
            match &cs.records[0] {
                CounterRecord::Vlan(v) => {
                    assert_eq!(v.vlan_id, 100);
                    assert_eq!(v.octets, 4096);
                    assert_eq!(v.ucast_pkts, 50);
                }
                other => panic!("Expected Vlan, got {:?}", other),
            }
        }
        other => panic!("Expected Counter sample, got {:?}", other),
    }
}

#[test]
fn test_parse_expanded_counter_sample() {
    // Build expanded counter sample: source_id_type + source_id_index separate
    let mut expanded_body = Vec::new();
    expanded_body.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
    expanded_body.extend_from_slice(&0u32.to_be_bytes()); // source_id_type
    expanded_body.extend_from_slice(&7u32.to_be_bytes()); // source_id_index
    expanded_body.extend_from_slice(&0u32.to_be_bytes()); // num_records

    let mut data = minimal_datagram_ipv4([10, 0, 0, 1], 1);
    append_sample(&mut data, 0, 4, &expanded_body);

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());

    match &result.datagrams[0].samples[0] {
        SflowSample::ExpandedCounter(ecs) => {
            assert_eq!(ecs.source_id_type, 0);
            assert_eq!(ecs.source_id_index, 7);
        }
        other => panic!("Expected ExpandedCounter, got {:?}", other),
    }
}

// === Flow Record Type Tests ===

#[test]
fn test_parse_raw_packet_header() {
    let header_bytes = vec![0xAA, 0xBB, 0xCC, 0xDD];
    let mut record_data = Vec::new();
    record_data.extend_from_slice(&1u32.to_be_bytes()); // header_protocol (Ethernet)
    record_data.extend_from_slice(&100u32.to_be_bytes()); // frame_length
    record_data.extend_from_slice(&0u32.to_be_bytes()); // stripped
    record_data.extend_from_slice(&4u32.to_be_bytes()); // header_length
    record_data.extend_from_slice(&header_bytes); // header

    let mut records = Vec::new();
    append_record(&mut records, 0, 1, &record_data);
    let sample_body = build_flow_sample_body(&records, 1);
    let mut data = minimal_datagram_ipv4([10, 0, 0, 1], 1);
    append_sample(&mut data, 0, 1, &sample_body);

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());

    let fs = match &result.datagrams[0].samples[0] {
        SflowSample::Flow(fs) => fs,
        other => panic!("Expected Flow, got {:?}", other),
    };
    match &fs.records[0] {
        FlowRecord::RawPacketHeader(rph) => {
            assert_eq!(rph.header_protocol, 1);
            assert_eq!(rph.frame_length, 100);
            assert_eq!(rph.header_length, 4);
            assert_eq!(rph.header, header_bytes);
        }
        other => panic!("Expected RawPacketHeader, got {:?}", other),
    }
}

#[test]
fn test_parse_sampled_ipv4() {
    let mut record_data = Vec::new();
    record_data.extend_from_slice(&100u32.to_be_bytes()); // length
    record_data.extend_from_slice(&6u32.to_be_bytes()); // protocol (TCP)
    record_data.extend_from_slice(&[192, 168, 1, 1]); // src_ip
    record_data.extend_from_slice(&u32::from(Ipv4Addr::new(192, 168, 1, 1)).to_be_bytes());
    // Redo properly
    let mut record_data = Vec::new();
    record_data.extend_from_slice(&100u32.to_be_bytes()); // length
    record_data.extend_from_slice(&6u32.to_be_bytes()); // protocol (TCP)
    record_data.extend_from_slice(&u32::from(Ipv4Addr::new(192, 168, 1, 1)).to_be_bytes()); // src_ip
    record_data.extend_from_slice(&u32::from(Ipv4Addr::new(10, 0, 0, 1)).to_be_bytes()); // dst_ip
    record_data.extend_from_slice(&80u32.to_be_bytes()); // src_port
    record_data.extend_from_slice(&443u32.to_be_bytes()); // dst_port
    record_data.extend_from_slice(&2u32.to_be_bytes()); // tcp_flags
    record_data.extend_from_slice(&0u32.to_be_bytes()); // tos

    let mut records = Vec::new();
    append_record(&mut records, 0, 3, &record_data);
    let sample_body = build_flow_sample_body(&records, 1);
    let mut data = minimal_datagram_ipv4([10, 0, 0, 1], 1);
    append_sample(&mut data, 0, 1, &sample_body);

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());

    let fs = match &result.datagrams[0].samples[0] {
        SflowSample::Flow(fs) => fs,
        other => panic!("Expected Flow, got {:?}", other),
    };
    match &fs.records[0] {
        FlowRecord::SampledIpv4(s) => {
            assert_eq!(s.protocol, 6);
            assert_eq!(s.src_ip, Ipv4Addr::new(192, 168, 1, 1));
            assert_eq!(s.dst_ip, Ipv4Addr::new(10, 0, 0, 1));
            assert_eq!(s.src_port, 80);
            assert_eq!(s.dst_port, 443);
        }
        other => panic!("Expected SampledIpv4, got {:?}", other),
    }
}

#[test]
fn test_parse_sampled_ipv6() {
    let src_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

    let mut record_data = Vec::new();
    record_data.extend_from_slice(&200u32.to_be_bytes()); // length
    record_data.extend_from_slice(&17u32.to_be_bytes()); // protocol (UDP)
    record_data.extend_from_slice(&src_ip.octets()); // src_ip
    record_data.extend_from_slice(&dst_ip.octets()); // dst_ip
    record_data.extend_from_slice(&1234u32.to_be_bytes()); // src_port
    record_data.extend_from_slice(&5678u32.to_be_bytes()); // dst_port
    record_data.extend_from_slice(&0u32.to_be_bytes()); // tcp_flags
    record_data.extend_from_slice(&0u32.to_be_bytes()); // priority

    let mut records = Vec::new();
    append_record(&mut records, 0, 4, &record_data);
    let sample_body = build_flow_sample_body(&records, 1);
    let mut data = minimal_datagram_ipv4([10, 0, 0, 1], 1);
    append_sample(&mut data, 0, 1, &sample_body);

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());

    let fs = match &result.datagrams[0].samples[0] {
        SflowSample::Flow(fs) => fs,
        other => panic!("Expected Flow, got {:?}", other),
    };
    match &fs.records[0] {
        FlowRecord::SampledIpv6(s) => {
            assert_eq!(s.protocol, 17);
            assert_eq!(s.src_ip, src_ip);
            assert_eq!(s.dst_ip, dst_ip);
            assert_eq!(s.src_port, 1234);
            assert_eq!(s.dst_port, 5678);
        }
        other => panic!("Expected SampledIpv6, got {:?}", other),
    }
}

#[test]
fn test_parse_extended_router() {
    let mut record_data = Vec::new();
    record_data.extend_from_slice(&1u32.to_be_bytes()); // address type IPv4
    record_data.extend_from_slice(&u32::from(Ipv4Addr::new(10, 0, 0, 254)).to_be_bytes()); // next_hop
    record_data.extend_from_slice(&24u32.to_be_bytes()); // src_mask_len
    record_data.extend_from_slice(&16u32.to_be_bytes()); // dst_mask_len

    let mut records = Vec::new();
    append_record(&mut records, 0, 1002, &record_data);
    let sample_body = build_flow_sample_body(&records, 1);
    let mut data = minimal_datagram_ipv4([10, 0, 0, 1], 1);
    append_sample(&mut data, 0, 1, &sample_body);

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());

    let fs = match &result.datagrams[0].samples[0] {
        SflowSample::Flow(fs) => fs,
        other => panic!("Expected Flow, got {:?}", other),
    };
    match &fs.records[0] {
        FlowRecord::ExtendedRouter(er) => {
            assert_eq!(er.next_hop, AddressType::IPv4(Ipv4Addr::new(10, 0, 0, 254)));
            assert_eq!(er.src_mask_len, 24);
            assert_eq!(er.dst_mask_len, 16);
        }
        other => panic!("Expected ExtendedRouter, got {:?}", other),
    }
}

#[test]
fn test_parse_extended_gateway() {
    let mut record_data = Vec::new();
    record_data.extend_from_slice(&1u32.to_be_bytes()); // address type IPv4
    record_data.extend_from_slice(&u32::from(Ipv4Addr::new(10, 0, 0, 1)).to_be_bytes()); // next_hop
    record_data.extend_from_slice(&65000u32.to_be_bytes()); // as_number
    record_data.extend_from_slice(&65000u32.to_be_bytes()); // src_as
    record_data.extend_from_slice(&65001u32.to_be_bytes()); // src_peer_as
    record_data.extend_from_slice(&1u32.to_be_bytes()); // as_path_count
    // AS path segment
    record_data.extend_from_slice(&2u32.to_be_bytes()); // segment_type (AS_SEQUENCE)
    record_data.extend_from_slice(&2u32.to_be_bytes()); // count
    record_data.extend_from_slice(&65001u32.to_be_bytes()); // AS value
    record_data.extend_from_slice(&65002u32.to_be_bytes()); // AS value
    // Communities
    record_data.extend_from_slice(&1u32.to_be_bytes()); // communities_count
    record_data.extend_from_slice(&0xFFFF0001u32.to_be_bytes()); // community

    let mut records = Vec::new();
    append_record(&mut records, 0, 1003, &record_data);
    let sample_body = build_flow_sample_body(&records, 1);
    let mut data = minimal_datagram_ipv4([10, 0, 0, 1], 1);
    append_sample(&mut data, 0, 1, &sample_body);

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());

    let fs = match &result.datagrams[0].samples[0] {
        SflowSample::Flow(fs) => fs,
        other => panic!("Expected Flow, got {:?}", other),
    };
    match &fs.records[0] {
        FlowRecord::ExtendedGateway(eg) => {
            assert_eq!(eg.as_number, 65000);
            assert_eq!(eg.src_peer_as, 65001);
            assert_eq!(eg.as_path_segments.len(), 1);
            assert_eq!(eg.as_path_segments[0].segment_type, 2);
            assert_eq!(eg.as_path_segments[0].values, vec![65001, 65002]);
            assert_eq!(eg.communities, vec![0xFFFF0001]);
        }
        other => panic!("Expected ExtendedGateway, got {:?}", other),
    }
}

#[test]
fn test_parse_extended_user() {
    let mut record_data = Vec::new();
    record_data.extend_from_slice(&0u32.to_be_bytes()); // src_charset
    record_data.extend_from_slice(&5u32.to_be_bytes()); // src_user length
    record_data.extend_from_slice(b"admin"); // src_user
    record_data.extend_from_slice(&[0, 0, 0]); // padding to 4-byte boundary
    record_data.extend_from_slice(&0u32.to_be_bytes()); // dst_charset
    record_data.extend_from_slice(&4u32.to_be_bytes()); // dst_user length
    record_data.extend_from_slice(b"root"); // dst_user (already 4-byte aligned)

    let mut records = Vec::new();
    append_record(&mut records, 0, 1004, &record_data);
    let sample_body = build_flow_sample_body(&records, 1);
    let mut data = minimal_datagram_ipv4([10, 0, 0, 1], 1);
    append_sample(&mut data, 0, 1, &sample_body);

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());

    let fs = match &result.datagrams[0].samples[0] {
        SflowSample::Flow(fs) => fs,
        other => panic!("Expected Flow, got {:?}", other),
    };
    match &fs.records[0] {
        FlowRecord::ExtendedUser(eu) => {
            assert_eq!(eu.src_user, "admin");
            assert_eq!(eu.dst_user, "root");
        }
        other => panic!("Expected ExtendedUser, got {:?}", other),
    }
}

#[test]
fn test_parse_extended_url() {
    let mut record_data = Vec::new();
    record_data.extend_from_slice(&1u32.to_be_bytes()); // direction
    record_data.extend_from_slice(&11u32.to_be_bytes()); // url length
    record_data.extend_from_slice(b"/index.html"); // url
    record_data.push(0); // padding to 4-byte boundary
    record_data.extend_from_slice(&11u32.to_be_bytes()); // host length
    record_data.extend_from_slice(b"example.com"); // host
    record_data.push(0); // padding

    let mut records = Vec::new();
    append_record(&mut records, 0, 1005, &record_data);
    let sample_body = build_flow_sample_body(&records, 1);
    let mut data = minimal_datagram_ipv4([10, 0, 0, 1], 1);
    append_sample(&mut data, 0, 1, &sample_body);

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());

    let fs = match &result.datagrams[0].samples[0] {
        SflowSample::Flow(fs) => fs,
        other => panic!("Expected Flow, got {:?}", other),
    };
    match &fs.records[0] {
        FlowRecord::ExtendedUrl(eu) => {
            assert_eq!(eu.direction, 1);
            assert_eq!(eu.url, "/index.html");
            assert_eq!(eu.host, "example.com");
        }
        other => panic!("Expected ExtendedUrl, got {:?}", other),
    }
}

// === Counter Record Type Tests ===

#[test]
fn test_parse_generic_interface() {
    let mut record_data = Vec::new();
    record_data.extend_from_slice(&1u32.to_be_bytes()); // if_index
    record_data.extend_from_slice(&6u32.to_be_bytes()); // if_type (ethernet)
    record_data.extend_from_slice(&1_000_000_000u64.to_be_bytes()); // if_speed
    record_data.extend_from_slice(&1u32.to_be_bytes()); // if_direction
    record_data.extend_from_slice(&3u32.to_be_bytes()); // if_status
    record_data.extend_from_slice(&1000000u64.to_be_bytes()); // if_in_octets
    record_data.extend_from_slice(&500u32.to_be_bytes()); // if_in_ucast_pkts
    record_data.extend_from_slice(&10u32.to_be_bytes()); // if_in_multicast_pkts
    record_data.extend_from_slice(&5u32.to_be_bytes()); // if_in_broadcast_pkts
    record_data.extend_from_slice(&0u32.to_be_bytes()); // if_in_discards
    record_data.extend_from_slice(&0u32.to_be_bytes()); // if_in_errors
    record_data.extend_from_slice(&0u32.to_be_bytes()); // if_in_unknown_protos
    record_data.extend_from_slice(&2000000u64.to_be_bytes()); // if_out_octets
    record_data.extend_from_slice(&600u32.to_be_bytes()); // if_out_ucast_pkts
    record_data.extend_from_slice(&20u32.to_be_bytes()); // if_out_multicast_pkts
    record_data.extend_from_slice(&8u32.to_be_bytes()); // if_out_broadcast_pkts
    record_data.extend_from_slice(&1u32.to_be_bytes()); // if_out_discards
    record_data.extend_from_slice(&0u32.to_be_bytes()); // if_out_errors
    record_data.extend_from_slice(&0u32.to_be_bytes()); // if_promiscuous_mode

    let mut records = Vec::new();
    append_record(&mut records, 0, 1, &record_data);
    let sample_body = build_counter_sample_body(&records, 1);
    let mut data = minimal_datagram_ipv4([10, 0, 0, 1], 1);
    append_sample(&mut data, 0, 2, &sample_body);

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());

    let cs = match &result.datagrams[0].samples[0] {
        SflowSample::Counter(cs) => cs,
        other => panic!("Expected Counter, got {:?}", other),
    };
    match &cs.records[0] {
        CounterRecord::GenericInterface(gi) => {
            assert_eq!(gi.if_index, 1);
            assert_eq!(gi.if_type, 6);
            assert_eq!(gi.if_speed, 1_000_000_000);
            assert_eq!(gi.if_in_octets, 1_000_000);
            assert_eq!(gi.if_out_octets, 2_000_000);
            assert_eq!(gi.if_in_ucast_pkts, 500);
        }
        other => {
            panic!("Expected GenericInterface, got {:?}", other)
        }
    }
}

#[test]
fn test_parse_ethernet_interface() {
    let mut record_data = Vec::new();
    for i in 0u32..13 {
        record_data.extend_from_slice(&i.to_be_bytes());
    }

    let mut records = Vec::new();
    append_record(&mut records, 0, 2, &record_data);
    let sample_body = build_counter_sample_body(&records, 1);
    let mut data = minimal_datagram_ipv4([10, 0, 0, 1], 1);
    append_sample(&mut data, 0, 2, &sample_body);

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());

    let cs = match &result.datagrams[0].samples[0] {
        SflowSample::Counter(cs) => cs,
        other => panic!("Expected Counter, got {:?}", other),
    };
    match &cs.records[0] {
        CounterRecord::EthernetInterface(ei) => {
            assert_eq!(ei.dot3_stats_alignment_errors, 0);
            assert_eq!(ei.dot3_stats_fcs_errors, 1);
            assert_eq!(ei.dot3_stats_symbol_errors, 12);
        }
        other => {
            panic!("Expected EthernetInterface, got {:?}", other)
        }
    }
}

#[test]
fn test_parse_processor() {
    let mut record_data = Vec::new();
    record_data.extend_from_slice(&10u32.to_be_bytes()); // cpu_5s
    record_data.extend_from_slice(&15u32.to_be_bytes()); // cpu_1m
    record_data.extend_from_slice(&12u32.to_be_bytes()); // cpu_5m
    record_data.extend_from_slice(&8_000_000_000u64.to_be_bytes()); // total_memory
    record_data.extend_from_slice(&4_000_000_000u64.to_be_bytes()); // free_memory

    let mut records = Vec::new();
    append_record(&mut records, 0, 1001, &record_data);
    let sample_body = build_counter_sample_body(&records, 1);
    let mut data = minimal_datagram_ipv4([10, 0, 0, 1], 1);
    append_sample(&mut data, 0, 2, &sample_body);

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());

    let cs = match &result.datagrams[0].samples[0] {
        SflowSample::Counter(cs) => cs,
        other => panic!("Expected Counter, got {:?}", other),
    };
    match &cs.records[0] {
        CounterRecord::Processor(p) => {
            assert_eq!(p.cpu_5s, 10);
            assert_eq!(p.cpu_1m, 15);
            assert_eq!(p.cpu_5m, 12);
            assert_eq!(p.total_memory, 8_000_000_000);
            assert_eq!(p.free_memory, 4_000_000_000);
        }
        other => panic!("Expected Processor, got {:?}", other),
    }
}

// === Unknown Record Handling ===

#[test]
fn test_unknown_sample_type() {
    let unknown_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let mut data = minimal_datagram_ipv4([10, 0, 0, 1], 1);
    append_sample(&mut data, 99, 1, &unknown_data);

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());

    match &result.datagrams[0].samples[0] {
        SflowSample::Unknown {
            enterprise,
            format,
            data,
        } => {
            assert_eq!(*enterprise, 99);
            assert_eq!(*format, 1);
            assert_eq!(data, &[0xDE, 0xAD, 0xBE, 0xEF]);
        }
        other => panic!("Expected Unknown sample, got {:?}", other),
    }
}

#[test]
fn test_unknown_flow_record() {
    let mut records = Vec::new();
    let unknown_data = vec![0x01, 0x02, 0x03, 0x04];
    append_record(&mut records, 0, 999, &unknown_data);

    let sample_body = build_flow_sample_body(&records, 1);
    let mut data = minimal_datagram_ipv4([10, 0, 0, 1], 1);
    append_sample(&mut data, 0, 1, &sample_body);

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());

    let fs = match &result.datagrams[0].samples[0] {
        SflowSample::Flow(fs) => fs,
        other => panic!("Expected Flow, got {:?}", other),
    };
    match &fs.records[0] {
        FlowRecord::Unknown {
            enterprise,
            format,
            data,
        } => {
            assert_eq!(*enterprise, 0);
            assert_eq!(*format, 999);
            assert_eq!(data, &[0x01, 0x02, 0x03, 0x04]);
        }
        other => panic!("Expected Unknown record, got {:?}", other),
    }
}

#[test]
fn test_unknown_counter_record() {
    let mut records = Vec::new();
    let unknown_data = vec![0x01, 0x02, 0x03, 0x04];
    append_record(&mut records, 5, 42, &unknown_data);

    let sample_body = build_counter_sample_body(&records, 1);
    let mut data = minimal_datagram_ipv4([10, 0, 0, 1], 1);
    append_sample(&mut data, 0, 2, &sample_body);

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_none());

    let cs = match &result.datagrams[0].samples[0] {
        SflowSample::Counter(cs) => cs,
        other => panic!("Expected Counter, got {:?}", other),
    };
    match &cs.records[0] {
        CounterRecord::Unknown {
            enterprise,
            format,
            data,
        } => {
            assert_eq!(*enterprise, 5);
            assert_eq!(*format, 42);
            assert_eq!(data, &[0x01, 0x02, 0x03, 0x04]);
        }
        other => panic!("Expected Unknown record, got {:?}", other),
    }
}

// === Builder / API Tests ===

#[test]
fn test_max_samples_limit() {
    // Create datagram with 2 samples but limit to 1
    let sample_body = build_flow_sample_body(&[], 0);
    let mut data = minimal_datagram_ipv4([10, 0, 0, 1], 2);
    append_sample(&mut data, 0, 1, &sample_body);
    append_sample(&mut data, 0, 1, &sample_body);

    let parser = SflowParser::builder().with_max_samples(1).build();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_some());
    match result.error.unwrap() {
        SflowError::TooManySamples { count, max } => {
            assert_eq!(count, 2);
            assert_eq!(max, 1);
        }
        other => panic!("Expected TooManySamples, got {:?}", other),
    }
}

#[test]
fn test_empty_input() {
    let parser = SflowParser::default();
    let result = parser.parse_bytes(&[]);
    assert!(result.error.is_none());
    assert_eq!(result.datagrams.len(), 0);
}

#[test]
fn test_parse_result_serialization() {
    let data = minimal_datagram_ipv4([10, 0, 0, 1], 0);
    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);

    let json = serde_json::to_string(&result).unwrap();
    let deserialized: ParseResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, deserialized);
}
