# Releases

## 0.2.0

### Breaking Changes

- **`SflowError::Incomplete`**: `context` field changed from `String` to `ParseContext` enum; added `expected: Option<usize>` field
- **`SflowError::ParseError`**: `context` field changed from `String` to `ParseContext` enum; `kind` field changed from `String` to `ParseErrorKind` enum

### Added

- `ParseContext` enum with 14 variants covering all parsing phases (e.g., `DatagramHeader`, `AgentAddress`, `FlowSample`)
- `ParseErrorKind` enum with `InvalidAddressType` and `NomError(nom::error::ErrorKind)` variants
- `expected: Option<usize>` field on `SflowError::Incomplete` for cases where the required byte count is known

### Improved

- Error paths no longer allocate on the heap (enums are `Copy` instead of `String`)
- Consumers can exhaustively match on error contexts and kinds
- Display output remains compatible with previous format

## 0.1.1

- Added crates.io badge to README

## 0.1.0 (Initial Release)

- sFlow v5 datagram parsing with IPv4 and IPv6 agent addresses
- All four sample types: Flow Sample, Counter Sample, Expanded Flow Sample, Expanded Counter Sample
- Flow record types: Raw Packet Header, Sampled Ethernet, Sampled IPv4/IPv6, Extended Switch, Extended Router, Extended Gateway, Extended User, Extended URL
- Counter record types: Generic Interface, Ethernet Interface, Token Ring, VLAN, Processor
- Unknown/unrecognized records preserved as raw bytes for forward compatibility
- Serde support for all types (JSON serialization/deserialization)
- Builder pattern with configurable max samples limit (DoS protection)
- Structured error types: `Incomplete`, `UnsupportedVersion`, `ParseError`, `TooManySamples`
- Examples: single-threaded, multi-threaded, and async (tokio) UDP listeners; pcap file parser
- Benchmarks for datagram, flow sample, and counter sample parsing
