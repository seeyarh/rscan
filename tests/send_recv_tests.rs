mod setup;

use std::error::Error;
use std::io::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use byteorder::{ByteOrder, LittleEndian};
use etherparse::{
    InternetSlice, PacketBuilder, PacketBuilderStep, SlicedPacket, TransportSlice, UdpHeader,
};

use afpacket::sync::RawPacketStream;
use rscan::{ScanConfig, Scanner, Target};

fn generate_pkt(
    mut pkt: &mut [u8],
    payload: &mut [u8],
    pkt_builder: PacketBuilderStep<UdpHeader>,
) -> usize {
    let len = pkt_builder.size(payload.len());
    pkt_builder
        .write(&mut pkt, payload)
        .expect("failed to build packet");
    len
}

const SRC_IP: [u8; 4] = [192, 168, 69, 1];
const DST_IP: [u8; 4] = [192, 168, 69, 2];

const SRC_PORT: u16 = 1234;
const DST_PORT: u16 = 4321;

const MAX_PACKET_SIZE: usize = 1500;

#[derive(Debug, Clone)]
struct Filter {
    src_ip: [u8; 4],
    dest_ip: [u8; 4],
}

fn filter_pkt(parsed_pkt: &SlicedPacket, filter: &Filter) -> bool {
    let mut ip_match = false;
    let mut transport_match = false;
    if let Some(ref ip) = parsed_pkt.ip {
        if let InternetSlice::Ipv4(ipv4) = ip {
            ip_match = (ipv4.source() == filter.src_ip) && (ipv4.destination() == filter.dest_ip);
        }
    }

    ip_match
}

fn synacker(mut ps: RawPacketStream, filter: Filter) {
    let mut rx_pkt = [0; MAX_PACKET_SIZE];
    let mut tx_pkt = [0; MAX_PACKET_SIZE];
    loop {
        let len = ps.read(&mut rx_pkt).expect("failed to read pkt");
        match SlicedPacket::from_ethernet(&rx_pkt[..len]) {
            Ok(sliced) => {
                if filter_pkt(&sliced, &filter) {
                    if let Some(len) = generate_synack(&sliced, &mut tx_pkt) {
                        ps.write_all(&tx_pkt[..len]).expect("failed to write pkt");
                    }
                }
            }
            Err(e) => println!("Err {:?}", e),
        }
    }
}

fn generate_synack(rx_sliced: &SlicedPacket, mut tx_pkt: &mut [u8]) -> Option<usize> {
    let pkt_builder = PacketBuilder::ethernet2([0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0]);
    let rx_ip = rx_sliced.ip.as_ref()?;

    let pkt_builder = match rx_ip {
        InternetSlice::Ipv4(ipv4) => {
            let dst = ipv4.destination_addr().octets();
            let src = ipv4.source_addr().octets();
            pkt_builder.ipv4(dst, src, 20)
        }
        InternetSlice::Ipv6(ipv6, _) => {
            let dst = ipv6.destination_addr().octets();
            let src = ipv6.source_addr().octets();
            pkt_builder.ipv6(dst, src, 20)
        }
    };

    let rx_transport = rx_sliced.transport.as_ref()?;
    let pkt_builder = match rx_transport {
        TransportSlice::Udp(_) => return None,
        TransportSlice::Tcp(tcp) => pkt_builder
            .tcp(
                tcp.destination_port(),
                tcp.source_port(),
                tcp.sequence_number() + 1,
                tcp.window_size(),
            )
            .syn()
            .ack(tcp.sequence_number()),
    };

    let len = pkt_builder.size(0);
    pkt_builder
        .write(&mut tx_pkt, &[])
        .expect("failed to write pkt");
    Some(len)
}

#[test]
fn send_recv_test() {
    fn test_fn(mut dev1_ps: RawPacketStream, mut dev2_ps: RawPacketStream) {
        let scan_config = ScanConfig {
            src_mac: [0, 0, 0, 0, 0, 0],
            dst_mac: [0, 0, 0, 0, 0, 0],
            src_ipv4: Some(Ipv4Addr::from(SRC_IP)),
            src_ipv6: None,
            src_port: 10000,
        };

        let scanner = Scanner::new(dev1_ps, scan_config);

        let filter = Filter {
            src_ip: SRC_IP,
            dest_ip: DST_IP,
        };

        let synacker_handle = thread::spawn(move || {
            synacker(dev2_ps, filter);
        });

        //let max_port = 65_536;
        let max_port = 2;
        let targets: Vec<Target> = (1..max_port)
            .into_iter()
            .map(|port| Target {
                ip: IpAddr::V4(Ipv4Addr::from(DST_IP)),
                port,
            })
            .collect();

        for target in targets {
            scanner
                .target_sender
                .send(target)
                .expect("failed to send target");
        }

        thread::sleep(Duration::from_secs(30));
    }

    setup::run_test(test_fn);
}
