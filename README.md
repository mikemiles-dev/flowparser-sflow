# sflow_parser

[![Rust](https://github.com/mikemiles-dev/sflow_parser/actions/workflows/rust.yml/badge.svg)](https://github.com/mikemiles-dev/sflow_parser/actions/workflows/rust.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

An sFlow v5 parser library written in Rust. Parses sFlow datagrams (RFC 3176) including flow samples, counter samples, and all standard record types.

## Features

- **sFlow v5** datagram parsing with IPv4 and IPv6 agent addresses
- **All four sample types**: Flow Sample, Counter Sample, Expanded Flow Sample, Expanded Counter Sample
- **Flow record types**: Raw Packet Header, Sampled Ethernet, Sampled IPv4/IPv6, Extended Switch, Extended Router, Extended Gateway, Extended User, Extended URL
- **Counter record types**: Generic Interface, Ethernet Interface, Token Ring, VLAN, Processor
- **Unknown record handling**: Unrecognized records captured as raw bytes for forward compatibility
- **Serde support**: All types serialize/deserialize to JSON and other formats
- **Builder pattern**: Optional configuration (e.g., max samples limit for DoS protection)

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
sflow_parser = "0.1.0"
```

### Basic Parsing

```rust,ignore
use sflow_parser::{SflowParser, SflowSample};

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
use sflow_parser::SflowParser;

let parser = SflowParser::default();
let result = parser.parse_bytes(&datagram_bytes);

// Serialize to JSON
let json = serde_json::to_string_pretty(&result.datagrams).unwrap();
println!("{}", json);
```

### Builder Configuration

```rust
use sflow_parser::SflowParser;

// Limit max samples per datagram (DoS protection)
let parser = SflowParser::builder()
    .with_max_samples(100)
    .build();
```

### UDP Listener Example

```rust,no_run
use sflow_parser::SflowParser;
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
    │       └── Extended URL (0:1005)
    ├── Counter Sample (enterprise=0, format=2)
    │   └── Counter Records[]
    │       ├── Generic Interface (0:1)
    │       ├── Ethernet Interface (0:2)
    │       ├── Token Ring (0:3)
    │       ├── VLAN (0:5)
    │       └── Processor (0:1001)
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
