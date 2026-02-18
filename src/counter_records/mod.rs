pub mod app_operations;
pub mod app_resources;
pub mod app_workers;
pub mod ethernet_interface;
pub mod generic_interface;
pub mod host_adapters;
pub mod host_cpu;
pub mod host_descr;
pub mod host_disk_io;
pub mod host_memory;
pub mod host_net_io;
pub mod host_parent;
pub mod http_counters;
pub mod ieee80211_counters;
pub mod jvm_statistics;
pub mod lag_port_stats;
pub mod memcache_counters;
pub mod mib2_icmp_group;
pub mod mib2_ip_group;
pub mod mib2_tcp_group;
pub mod mib2_udp_group;
pub mod of_port;
pub mod port_name;
pub mod processor;
pub mod radio_utilization;
pub mod sfp;
pub mod token_ring;
pub mod vg_counters;
pub mod vlan;

use nom::IResult;
use nom::number::complete::be_u32;
use serde::{Deserialize, Serialize};

pub use app_operations::AppOperations;
pub use app_resources::AppResources;
pub use app_workers::AppWorkers;
pub use ethernet_interface::EthernetInterface;
pub use generic_interface::GenericInterface;
pub use host_adapters::HostAdapters;
pub use host_cpu::HostCpu;
pub use host_descr::HostDescr;
pub use host_disk_io::HostDiskIo;
pub use host_memory::HostMemory;
pub use host_net_io::HostNetIo;
pub use host_parent::HostParent;
pub use http_counters::HttpCounters;
pub use ieee80211_counters::Ieee80211Counters;
pub use jvm_statistics::JvmStatistics;
pub use lag_port_stats::LagPortStats;
pub use memcache_counters::MemcacheCounters;
pub use mib2_icmp_group::Mib2IcmpGroup;
pub use mib2_ip_group::Mib2IpGroup;
pub use mib2_tcp_group::Mib2TcpGroup;
pub use mib2_udp_group::Mib2UdpGroup;
pub use of_port::OfPort;
pub use port_name::PortName;
pub use processor::Processor;
pub use radio_utilization::RadioUtilization;
pub use sfp::Sfp;
pub use token_ring::TokenRing;
pub use vg_counters::VgCounters;
pub use vlan::Vlan;

/// A counter record within a counter sample.
///
/// Counter records contain periodic interface and system statistics
/// reported by the sFlow agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CounterRecord {
    /// Generic interface counters (enterprise=0, format=1).
    GenericInterface(GenericInterface),
    /// Ethernet-specific interface counters (enterprise=0, format=2).
    EthernetInterface(EthernetInterface),
    /// Token Ring interface counters (enterprise=0, format=3).
    TokenRing(TokenRing),
    /// 100VG-AnyLAN counters (enterprise=0, format=4).
    VgCounters(VgCounters),
    /// VLAN counters (enterprise=0, format=5).
    Vlan(Vlan),
    /// IEEE 802.11 counters (enterprise=0, format=6).
    Ieee80211Counters(Ieee80211Counters),
    /// LAG port statistics (enterprise=0, format=7).
    LagPortStats(LagPortStats),
    /// SFP/optical transceiver counters (enterprise=0, format=10).
    Sfp(Sfp),
    /// Processor/CPU counters (enterprise=0, format=1001).
    Processor(Processor),
    /// Radio utilization counters (enterprise=0, format=1002).
    RadioUtilization(RadioUtilization),
    /// OpenFlow port mapping (enterprise=0, format=1004).
    OfPort(OfPort),
    /// Port name (enterprise=0, format=1005).
    PortName(PortName),
    /// Host description (enterprise=0, format=2000).
    HostDescr(HostDescr),
    /// Host network adapters (enterprise=0, format=2001).
    HostAdapters(HostAdapters),
    /// Host parent (virtualization) (enterprise=0, format=2002).
    HostParent(HostParent),
    /// Host CPU counters (enterprise=0, format=2003).
    HostCpu(HostCpu),
    /// Host memory counters (enterprise=0, format=2004).
    HostMemory(HostMemory),
    /// Host disk I/O counters (enterprise=0, format=2005).
    HostDiskIo(HostDiskIo),
    /// Host network I/O counters (enterprise=0, format=2006).
    HostNetIo(HostNetIo),
    /// MIB-II IP group counters (enterprise=0, format=2007).
    Mib2IpGroup(Mib2IpGroup),
    /// MIB-II ICMP group counters (enterprise=0, format=2008).
    Mib2IcmpGroup(Mib2IcmpGroup),
    /// MIB-II TCP group counters (enterprise=0, format=2009).
    Mib2TcpGroup(Mib2TcpGroup),
    /// MIB-II UDP group counters (enterprise=0, format=2010).
    Mib2UdpGroup(Mib2UdpGroup),
    /// JVM statistics counters (enterprise=0, format=2106).
    JvmStatistics(JvmStatistics),
    /// HTTP method and status counters (enterprise=0, format=2201).
    HttpCounters(HttpCounters),
    /// Application operations counters (enterprise=0, format=2202).
    AppOperations(AppOperations),
    /// Application resource counters (enterprise=0, format=2203).
    AppResources(AppResources),
    /// Memcache counters (enterprise=0, format=2204).
    MemcacheCounters(MemcacheCounters),
    /// Application worker counters (enterprise=0, format=2206).
    AppWorkers(AppWorkers),
    /// Unrecognized counter record type, preserved as raw bytes.
    Unknown {
        /// Enterprise code from the record header.
        enterprise: u32,
        /// Format code from the record header.
        format: u32,
        /// Raw record data.
        data: Vec<u8>,
    },
}

pub(crate) fn parse_counter_records(
    mut input: &[u8],
    num_records: u32,
) -> IResult<&[u8], Vec<CounterRecord>> {
    // Cap capacity to prevent DoS: each record needs at least 8 bytes (format + length)
    let cap = (num_records as usize).min(input.len() / 8);
    let mut records = Vec::with_capacity(cap);

    for _ in 0..num_records {
        let (rest, data_format) = be_u32(input)?;
        let enterprise = data_format >> 12;
        let format = data_format & 0xFFF;

        let (rest, record_length) = be_u32(rest)?;
        let record_length = record_length as usize;

        if rest.len() < record_length {
            return Err(nom::Err::Error(nom::error::Error::new(
                rest,
                nom::error::ErrorKind::Eof,
            )));
        }

        let record_data = &rest[..record_length];
        let after_record = &rest[record_length..];

        let record = if enterprise == 0 {
            match format {
                1 => {
                    let (_, r) = generic_interface::parse_generic_interface(record_data)?;
                    CounterRecord::GenericInterface(r)
                }
                2 => {
                    let (_, r) = ethernet_interface::parse_ethernet_interface(record_data)?;
                    CounterRecord::EthernetInterface(r)
                }
                3 => {
                    let (_, r) = token_ring::parse_token_ring(record_data)?;
                    CounterRecord::TokenRing(r)
                }
                4 => {
                    let (_, r) = vg_counters::parse_vg_counters(record_data)?;
                    CounterRecord::VgCounters(r)
                }
                5 => {
                    let (_, r) = vlan::parse_vlan(record_data)?;
                    CounterRecord::Vlan(r)
                }
                6 => {
                    let (_, r) = ieee80211_counters::parse_ieee80211_counters(record_data)?;
                    CounterRecord::Ieee80211Counters(r)
                }
                7 => {
                    let (_, r) = lag_port_stats::parse_lag_port_stats(record_data)?;
                    CounterRecord::LagPortStats(r)
                }
                10 => {
                    let (_, r) = sfp::parse_sfp(record_data)?;
                    CounterRecord::Sfp(r)
                }
                1001 => {
                    let (_, r) = processor::parse_processor(record_data)?;
                    CounterRecord::Processor(r)
                }
                1002 => {
                    let (_, r) = radio_utilization::parse_radio_utilization(record_data)?;
                    CounterRecord::RadioUtilization(r)
                }
                1004 => {
                    let (_, r) = of_port::parse_of_port(record_data)?;
                    CounterRecord::OfPort(r)
                }
                1005 => {
                    let (_, r) = port_name::parse_port_name(record_data)?;
                    CounterRecord::PortName(r)
                }
                2000 => {
                    let (_, r) = host_descr::parse_host_descr(record_data)?;
                    CounterRecord::HostDescr(r)
                }
                2001 => {
                    let (_, r) = host_adapters::parse_host_adapters(record_data)?;
                    CounterRecord::HostAdapters(r)
                }
                2002 => {
                    let (_, r) = host_parent::parse_host_parent(record_data)?;
                    CounterRecord::HostParent(r)
                }
                2003 => {
                    let (_, r) = host_cpu::parse_host_cpu(record_data)?;
                    CounterRecord::HostCpu(r)
                }
                2004 => {
                    let (_, r) = host_memory::parse_host_memory(record_data)?;
                    CounterRecord::HostMemory(r)
                }
                2005 => {
                    let (_, r) = host_disk_io::parse_host_disk_io(record_data)?;
                    CounterRecord::HostDiskIo(r)
                }
                2006 => {
                    let (_, r) = host_net_io::parse_host_net_io(record_data)?;
                    CounterRecord::HostNetIo(r)
                }
                2007 => {
                    let (_, r) = mib2_ip_group::parse_mib2_ip_group(record_data)?;
                    CounterRecord::Mib2IpGroup(r)
                }
                2008 => {
                    let (_, r) = mib2_icmp_group::parse_mib2_icmp_group(record_data)?;
                    CounterRecord::Mib2IcmpGroup(r)
                }
                2009 => {
                    let (_, r) = mib2_tcp_group::parse_mib2_tcp_group(record_data)?;
                    CounterRecord::Mib2TcpGroup(r)
                }
                2010 => {
                    let (_, r) = mib2_udp_group::parse_mib2_udp_group(record_data)?;
                    CounterRecord::Mib2UdpGroup(r)
                }
                2106 => {
                    let (_, r) = jvm_statistics::parse_jvm_statistics(record_data)?;
                    CounterRecord::JvmStatistics(r)
                }
                2201 => {
                    let (_, r) = http_counters::parse_http_counters(record_data)?;
                    CounterRecord::HttpCounters(r)
                }
                2202 => {
                    let (_, r) = app_operations::parse_app_operations(record_data)?;
                    CounterRecord::AppOperations(r)
                }
                2203 => {
                    let (_, r) = app_resources::parse_app_resources(record_data)?;
                    CounterRecord::AppResources(r)
                }
                2204 => {
                    let (_, r) = memcache_counters::parse_memcache_counters(record_data)?;
                    CounterRecord::MemcacheCounters(r)
                }
                2206 => {
                    let (_, r) = app_workers::parse_app_workers(record_data)?;
                    CounterRecord::AppWorkers(r)
                }
                _ => CounterRecord::Unknown {
                    enterprise,
                    format,
                    data: record_data.to_vec(),
                },
            }
        } else {
            CounterRecord::Unknown {
                enterprise,
                format,
                data: record_data.to_vec(),
            }
        };

        records.push(record);
        input = after_record;
    }

    Ok((input, records))
}
