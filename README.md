# flowparser-sflow

[![Crates.io](https://img.shields.io/crates/v/flowparser-sflow.svg)](https://crates.io/crates/flowparser-sflow)
[![Rust](https://github.com/mikemiles-dev/sflow_parser/actions/workflows/rust.yml/badge.svg)](https://github.com/mikemiles-dev/sflow_parser/actions/workflows/rust.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

An sFlow v5 parser library written in Rust. Parses sFlow v5 datagrams ([sFlow v5 specification](https://sflow.org/sflow_version_5.txt)) including flow samples, counter samples, and all standard record types.

## Features

- **sFlow v5** datagram parsing with IPv4 and IPv6 agent addresses
- **All four sample types**: Flow Sample, Counter Sample, Expanded Flow Sample, Expanded Counter Sample
- **38 flow record types**: Raw Packet Header, Sampled Ethernet, Sampled IPv4/IPv6, Extended Switch/Router/Gateway/User/URL, Extended MPLS (tunnel, VC, FTN, LDP FEC), Extended NAT, Extended VLAN Tunnel, Extended 802.11 (payload, Rx, Tx), Extended L2/IPv4/IPv6 Tunnel (egress/ingress), Extended Decapsulate/VNI (egress/ingress), Extended Egress Queue/ACL/Function/Transit/Queue, Extended Socket IPv4/IPv6, Extended Proxy Socket IPv4/IPv6, JVM Runtime, Memcache Operation, App Operation, HTTP Request, Extended Proxy Request
- **43 counter record types**: Generic/Ethernet/Token Ring/VG/VLAN/802.11/LAG/SFP interface counters, Slow Path Counts, InfiniBand, Processor, Queue Length, Radio Utilization, OpenFlow Port, Port Name, Host Description/Adapters/Parent/CPU/Memory/Disk IO/Net IO, Virtual Node/CPU/Memory/Disk IO/Net IO, MIB-II IP/ICMP/TCP/UDP, JMX Runtime, JVM Statistics, HTTP Counters, App Operations/Resources/Workers, Memcache Counters, OVS Datapath Stats, Energy/Temperature/Humidity/Fans, XenServer VIF (enterprise 4300)
- **Unknown record handling**: Unrecognized records captured as raw bytes for forward compatibility
- **Serde support**: All types serialize/deserialize to JSON and other formats
- **Builder pattern**: Optional configuration (e.g., max samples limit for DoS protection)

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
flowparser-sflow = "0.2.0"
```

### Basic Parsing

```rust,ignore
use flowparser_sflow::{SflowParser, SflowSample};

let parser = SflowParser::default();

// Parse sFlow datagram bytes (e.g., received from UDP socket)
let result = parser.parse_bytes(&datagram_bytes);

for datagram in &result.datagrams {
    println!(
        "Agent: {:?}, Seq: {}, Samples: {}",
        datagram.agent_address,
        datagram.sequence_number,
        datagram.samples.len()
    );

    for sample in &datagram.samples {
        match sample {
            SflowSample::Flow(fs) => {
                println!("  Flow sample: {} records", fs.records.len());
            }
            SflowSample::Counter(cs) => {
                println!("  Counter sample: {} records", cs.records.len());
            }
            _ => {}
        }
    }
}

if let Some(err) = &result.error {
    eprintln!("Parse error: {}", err);
}
```

### JSON Serialization

```rust,ignore
use flowparser_sflow::SflowParser;

let parser = SflowParser::default();
let result = parser.parse_bytes(&datagram_bytes);

// Serialize to JSON
let json = serde_json::to_string_pretty(&result.datagrams).unwrap();
println!("{}", json);
```

### Builder Configuration

```rust
use flowparser_sflow::SflowParser;

// Limit max samples per datagram (DoS protection)
let parser = SflowParser::builder()
    .with_max_samples(100)
    .build();
```

### UDP Listener Example

```rust,no_run
use flowparser_sflow::SflowParser;
use std::net::UdpSocket;

let socket = UdpSocket::bind("0.0.0.0:6343").unwrap();
let parser = SflowParser::default();
let mut buf = [0u8; 65535];

loop {
    let (size, src) = socket.recv_from(&mut buf).unwrap();
    let result = parser.parse_bytes(&buf[..size]);
    for datagram in &result.datagrams {
        println!("From {}: {} samples", src, datagram.samples.len());
    }
}
```

## sFlow v5 Protocol Structure

```text
Datagram
├── Header (version, agent address, sub-agent ID, sequence, uptime)
└── Samples[]
    ├── Flow Sample (enterprise=0, format=1)
    │   └── Flow Records[]
    │       ├── Raw Packet Header (0:1)
    │       ├── Sampled Ethernet (0:2)
    │       ├── Sampled IPv4 (0:3)
    │       ├── Sampled IPv6 (0:4)
    │       ├── Extended Switch (0:1001)
    │       ├── Extended Router (0:1002)
    │       ├── Extended Gateway (0:1003)
    │       ├── Extended User (0:1004)
    │       ├── Extended URL (0:1005)
    │       ├── Extended MPLS (0:1006)
    │       ├── Extended NAT (0:1007)
    │       ├── Extended MPLS Tunnel/VC/FTN/LDP FEC (0:1008–1011)
    │       ├── Extended VLAN Tunnel (0:1012)
    │       ├── Extended 802.11 Payload/Rx/Tx (0:1013–1015)
    │       ├── Extended L2/IPv4/IPv6 Tunnel Egress/Ingress (0:1021–1026)
    │       ├── Extended Decapsulate/VNI Egress/Ingress (0:1027–1030)
    │       ├── Extended Egress Queue/ACL/Function/Transit/Queue (0:1036–1040)
    │       ├── Extended Socket IPv4/IPv6 (0:2100–2101)
    │       ├── Extended Proxy Socket IPv4/IPv6 (0:2102–2103)
    │       ├── JVM Runtime (0:2105)
    │       ├── Memcache Operation (0:2200)
    │       ├── App Operation (0:2202)
    │       ├── HTTP Request (0:2206)
    │       └── Extended Proxy Request (0:2207)
    ├── Counter Sample (enterprise=0, format=2)
    │   └── Counter Records[]
    │       ├── Generic Interface (0:1)
    │       ├── Ethernet Interface (0:2)
    │       ├── Token Ring (0:3)
    │       ├── VG Counters (0:4)
    │       ├── VLAN (0:5)
    │       ├── IEEE 802.11 Counters (0:6)
    │       ├── LAG Port Stats (0:7)
    │       ├── Slow Path Counts (0:8)
    │       ├── InfiniBand Counters (0:9)
    │       ├── SFP/Optical (0:10)
    │       ├── Processor (0:1001)
    │       ├── Radio Utilization (0:1002)
    │       ├── Queue Length (0:1003)
    │       ├── OpenFlow Port (0:1004)
    │       ├── Port Name (0:1005)
    │       ├── Host Descr/Adapters/Parent/CPU/Memory/Disk IO/Net IO (0:2000–2006)
    │       ├── Virtual Node/CPU/Memory/Disk IO/Net IO (0:2100–2104)
    │       ├── MIB-II IP/ICMP/TCP/UDP (0:2007–2010)
    │       ├── JMX Runtime (0:2105)
    │       ├── JVM Statistics (0:2106)
    │       ├── HTTP Counters (0:2201)
    │       ├── App Operations/Resources/Workers (0:2202–2206)
    │       ├── Memcache Counters (0:2204)
    │       ├── OVS Datapath Stats (0:2207)
    │       ├── Energy/Temperature/Humidity/Fans (0:3000–3003)
    │       └── XenServer VIF (4300:2)
    ├── Expanded Flow Sample (enterprise=0, format=3)
    └── Expanded Counter Sample (enterprise=0, format=4)
```

## Types

| Type | Description |
|------|-------------|
| `SflowParser` | Main parser with optional configuration |
| `SflowDatagram` | Parsed datagram with header fields and samples |
| `SflowSample` | Enum: Flow, Counter, ExpandedFlow, ExpandedCounter, Unknown |
| `FlowRecord` | Enum of all flow record types |
| `CounterRecord` | Enum of all counter record types |
| `AddressType` | IPv4 or IPv6 agent address |
| `ParseResult` | Contains parsed datagrams and optional error |
| `SflowError` | Error variants: Incomplete, UnsupportedVersion, ParseError, TooManySamples |
| `ParseContext` | Enum identifying the parsing phase where an error occurred |
| `ParseErrorKind` | Enum categorizing parse errors (InvalidAddressType, NomError) |

## Examples

Run the included examples:

```bash
# Single-threaded UDP listener
cargo run --example sflow_udp_listener_single_threaded

# Multi-threaded UDP listener
cargo run --example sflow_udp_listener_multi_threaded

# Async (tokio) UDP listener
cargo run --example sflow_udp_listener_tokio

# Parse from pcap file
cargo run --example sflow_pcap -- <file.pcap>
```

## Benchmarks

```bash
cargo bench
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
