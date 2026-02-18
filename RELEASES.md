# Releases

## 0.2.0

### Breaking Changes

- **`SflowError::Incomplete`**: `context` field changed from `String` to `ParseContext` enum; added `expected: Option<usize>` field
- **`SflowError::ParseError`**: `context` field changed from `String` to `ParseContext` enum; `kind` field changed from `String` to `ParseErrorKind` enum
- **`HostDescr::uuid`**: field type changed from `[u8; 16]` to `uuid::Uuid`
- **`HostDescr::machine_type`**: field type changed from `u32` to `MachineType` enum
- **`HostDescr::os_name`**: field type changed from `u32` to `OsName` enum
- **`HostCpu`**: `load_one`, `load_five`, `load_fifteen` changed from `u32` to `f32`
- **`VirtCpu::state`**: field type changed from `u32` to `VirtDomainState` enum
- **`Eq` removed** from `HostCpu`, `CounterRecord`, `CounterSample`, `ExpandedCounterSample`, `SflowSample`, `SflowDatagram`, `ParseResult` (due to `f32` fields; `PartialEq` is preserved)

### Added

- **34 new flow record types** (enterprise=0):
  - MPLS & NAT (formats 1006–1012): `ExtendedMpls`, `ExtendedNat`, `ExtendedMplsTunnel`, `ExtendedMplsVc`, `ExtendedMplsFtn`, `ExtendedMplsLdpFec`, `ExtendedVlanTunnel`
  - 802.11 wireless (formats 1013–1015): `Extended80211Payload`, `Extended80211Rx`, `Extended80211Tx`
  - Tunnel (formats 1021–1030): `ExtendedL2TunnelEgress`, `ExtendedL2TunnelIngress`, `ExtendedIpv4TunnelEgress`, `ExtendedIpv4TunnelIngress`, `ExtendedIpv6TunnelEgress`, `ExtendedIpv6TunnelIngress`, `ExtendedDecapsulateEgress`, `ExtendedDecapsulateIngress`, `ExtendedVniEgress`, `ExtendedVniIngress`
  - Queue, ACL, function, transit (formats 1036–1040): `ExtendedEgressQueue`, `ExtendedAcl`, `ExtendedFunction`, `ExtendedTransit`, `ExtendedQueue`
  - Socket (formats 2100–2103): `ExtendedSocketIpv4`, `ExtendedSocketIpv6`, `ExtendedProxySocketIpv4`, `ExtendedProxySocketIpv6`
  - Application & JVM (formats 2105, 2200, 2202, 2206, 2207): `JvmRuntime`, `MemcacheOperation`, `AppOperation`, `HttpRequest`, `ExtendedProxyRequest`
- **40 new counter record types**:
  - Core (formats 4, 6, 7, 10): `VgCounters`, `Ieee80211Counters`, `LagPortStats`, `Sfp`
  - Slow path & InfiniBand (formats 8, 9): `SlowPathCounts`, `IbCounters`
  - OpenFlow & radio (formats 1002, 1004, 1005): `RadioUtilization`, `OfPort`, `PortName`
  - Queue length (format 1003): `QueueLength`
  - Host monitoring (formats 2000–2006): `HostDescr`, `HostAdapters`, `HostParent`, `HostCpu`, `HostMemory`, `HostDiskIo`, `HostNetIo`
  - Virtual machine / hypervisor (formats 2100–2104): `VirtNode`, `VirtCpu`, `VirtMemory`, `VirtDiskIo`, `VirtNetIo`
  - MIB-II (formats 2007–2010): `Mib2IpGroup`, `Mib2IcmpGroup`, `Mib2TcpGroup`, `Mib2UdpGroup`
  - JVM (formats 2105–2106): `JmxRuntime`, `JvmStatistics`
  - Application & HTTP (formats 2201–2206): `HttpCounters`, `AppOperations`, `AppResources`, `MemcacheCounters`, `AppWorkers`
  - Open vSwitch (format 2207): `OvsDpStats`
  - Environmental (formats 3000–3003): `Energy`, `Temperature`, `Humidity`, `Fans`
  - XenServer VIF (enterprise=4300, format=2): `XenVif`
- `ParseContext` enum with 14 variants covering all parsing phases (e.g., `DatagramHeader`, `AgentAddress`, `FlowSample`)
- `ParseErrorKind` enum with `InvalidAddressType` and `NomError(nom::error::ErrorKind)` variants
- `expected: Option<usize>` field on `SflowError::Incomplete` for cases where the required byte count is known
- `uuid` crate dependency for proper UUID representation in `HostDescr`

### Improved

- Error paths no longer allocate on the heap (enums are `Copy` instead of `String`)
- Consumers can exhaustively match on error contexts and kinds
- Display output remains compatible with previous format
- Records previously parsed as `Unknown` (e.g., formats 2100, 2200, 1029, 1030) are now fully decoded
- `HostDescr.uuid` field changed from `[u8; 16]` to `uuid::Uuid` for proper formatting and serialization

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
