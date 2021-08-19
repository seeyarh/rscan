use crossbeam_channel::unbounded;
use etherparse::{
    InternetSlice, PacketBuilder, PacketBuilderStep, SlicedPacket, TransportSlice, UdpHeader,
};
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

struct Target {
    ip: IpAddr,
    port: u16,
}

struct ScanConfig {
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ipv4: Option<Ipv4Addr>,
    src_ipv6: Option<Ipv6Addr>,
    src_port: u16,
}

#[derive(Debug)]
enum PacketGenError {
    MissingIpv4,
    MissingIpv6,
}

impl fmt::Display for PacketGenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PacketGenError::MissingIpv4 => write!(f, "Missing source Ipv4 address"),
            PacketGenError::MissingIpv6 => write!(f, "Missing source Ipv6 address"),
        }
    }
}

impl Error for PacketGenError {
    fn description(&self) -> &str {
        match *self {
            PacketGenError::MissingIpv4 => "Missing source Ipv4 address",
            PacketGenError::MissingIpv6 => "Missing source Ipv6 address",
        }
    }
}

impl Target {
    fn to_pkt(
        &self,
        mut pkt: &mut [u8],
        scan_config: &ScanConfig,
    ) -> Result<usize, PacketGenError> {
        let pkt_builder = PacketBuilder::ethernet2([0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0]);

        let pkt_builder = match self.ip {
            IpAddr::V4(ipv4) => {
                let src_ipv4 = scan_config.src_ipv4.ok_or(PacketGenError::MissingIpv4)?;
                pkt_builder.ipv4(src_ipv4.octets(), ipv4.octets(), 20)
            }
            IpAddr::V6(ipv6) => {
                let src_ipv6 = scan_config.src_ipv6.ok_or(PacketGenError::MissingIpv6)?;
                pkt_builder.ipv6(src_ipv6.octets(), ipv6.octets(), 20)
            }
        };

        let pkt_builder = pkt_builder.tcp(scan_config.src_port, self.port, 0, 1).syn();

        let len = pkt_builder.size(0);
        pkt_builder.write(&mut pkt, &[]).unwrap();
        Ok(len)
    }
}
struct Scanner {}

struct Sender {}

struct Receiver {}
