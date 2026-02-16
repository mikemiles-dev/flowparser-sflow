use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use sflow_parser::SflowParser;
use std::fs::File;
use std::io::BufReader;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <pcap-file>", args[0]);
        std::process::exit(1);
    }

    let file = File::open(&args[1]).expect("Failed to open pcap file");
    let reader = BufReader::new(file);
    let mut pcap_reader =
        PcapNGReader::new(65535, reader).expect("Failed to create pcap reader");

    let parser = SflowParser::default();
    let mut packet_count = 0;

    loop {
        match pcap_reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                        // Try to extract UDP payload (skip ethernet + IP + UDP headers)
                        if let Some(payload) = extract_udp_payload(epb.data) {
                            let result = parser.parse_bytes(payload);
                            for datagram in &result.datagrams {
                                packet_count += 1;
                                println!(
                                    "Packet {}: seq={} samples={}",
                                    packet_count,
                                    datagram.sequence_number,
                                    datagram.samples.len()
                                );
                            }
                        }
                    }
                    PcapBlockOwned::NG(Block::SectionHeader(_))
                    | PcapBlockOwned::NG(Block::InterfaceDescription(_)) => {}
                    _ => {}
                }
                pcap_reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                pcap_reader.refill().expect("Failed to refill");
            }
            Err(e) => {
                eprintln!("Error reading pcap: {:?}", e);
                break;
            }
        }
    }

    println!("Parsed {} sFlow datagrams", packet_count);
}

fn extract_udp_payload(data: &[u8]) -> Option<&[u8]> {
    use etherparse::SlicedPacket;
    let packet = SlicedPacket::from_ethernet(data).ok()?;
    // etherparse 0.19: payload is accessed via the net/transport slices
    // After stripping headers, remaining data is the UDP payload
    match packet.transport {
        Some(etherparse::TransportSlice::Udp(udp)) => Some(udp.payload()),
        _ => None,
    }
}
