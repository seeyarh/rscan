mod setup;

use std::io::prelude::*;
use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use std::time::{Duration, Instant};

use etherparse::{InternetSlice, PacketBuilder, SlicedPacket, TransportSlice};

use afpacket::sync::RawPacketStream;
use rscan::{ScanConfig, Scanner, Target};

const SRC_IP: [u8; 4] = [192, 168, 69, 1];
const DST_IP: [u8; 4] = [192, 168, 69, 2];

const MAX_PACKET_SIZE: usize = 1500;

fn synacker(mut ps: RawPacketStream) {
    let mut rx_pkt = [0; MAX_PACKET_SIZE];
    let mut tx_pkt = [0; MAX_PACKET_SIZE];
    loop {
        let len = ps.read(&mut rx_pkt).expect("failed to read pkt");
        match SlicedPacket::from_ethernet(&rx_pkt[..len]) {
            Ok(sliced) => {
                if let Some(len) = generate_synack(&sliced, &mut tx_pkt) {
                    log::info!("sending synack",);
                    ps.write_all(&tx_pkt[..len]).expect("failed to write pkt");
                }
            }
            Err(e) => log::error!("Err {:?}", e),
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
    fn test_fn(dev1_ps: RawPacketStream, dev2_ps: RawPacketStream) {
        let scan_config = ScanConfig {
            src_mac: [0, 0, 0, 0, 0, 0],
            dst_mac: [0, 0, 0, 0, 0, 0],
            src_ipv4: Some(Ipv4Addr::from(SRC_IP)),
            src_ipv6: None,
            src_port: 10000,
        };

        let _synacker_handle = thread::spawn(move || {
            synacker(dev2_ps);
        });

        thread::sleep(Duration::from_secs(1));

        let scanner = Scanner::new(dev1_ps, scan_config);

        let max_port = 100;
        //let max_port = 2;
        let targets: Vec<Target> = (1..max_port)
            .into_iter()
            .map(|port| Target {
                ip: IpAddr::V4(Ipv4Addr::from(DST_IP)),
                port,
            })
            .collect();

        for target in targets.iter() {
            scanner
                .target_sender
                .send(target.clone())
                .expect("failed to send target");
        }

        let mut responders = vec![];

        let rx_timeout = Duration::from_secs(5);
        let start = Instant::now();
        while responders.len() < targets.len() && start.elapsed() < rx_timeout {
            match scanner.result_receiver.try_recv() {
                Ok(responder) => responders.push(responder),
                Err(_e) => {
                    //log::error!("Err {:?}", e);
                }
            }
        }

        log::info!("num targets    = {}", targets.len());
        log::info!("num responders = {}", responders.len());
        assert_eq!(targets.len(), responders.len());
    }

    setup::run_test(test_fn);
}
