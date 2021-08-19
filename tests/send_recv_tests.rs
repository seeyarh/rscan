mod setup;

use std::error::Error;
use std::io::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use byteorder::{ByteOrder, LittleEndian};
use etherparse::{
    InternetSlice, PacketBuilder, PacketBuilderStep, SlicedPacket, TransportSlice, UdpHeader,
};

use afpacket::sync::RawPacketStream;

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
    src_port: u16,
    dest_ip: [u8; 4],
    dest_port: u16,
}

impl Filter {
    fn new(
        src_ip: [u8; 4],
        src_port: u16,
        dest_ip: [u8; 4],
        dest_port: u16,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            src_ip,
            src_port,
            dest_ip,
            dest_port,
        })
    }
}

fn filter_pkt(parsed_pkt: &SlicedPacket, filter: &Filter) -> bool {
    let mut ip_match = false;
    let mut transport_match = false;
    if let Some(ref ip) = parsed_pkt.ip {
        if let InternetSlice::Ipv4(ipv4) = ip {
            ip_match = (ipv4.source() == filter.src_ip) && (ipv4.destination() == filter.dest_ip);
        }
    }

    if let Some(ref transport) = parsed_pkt.transport {
        if let TransportSlice::Udp(udp) = transport {
            transport_match = (udp.source_port() == filter.src_port)
                && (udp.destination_port() == filter.dest_port);
        }
    }

    ip_match && transport_match
}

#[test]
fn send_recv_test() {
    fn test_fn(mut dev1: RawPacketStream, mut dev2: RawPacketStream) {
        let pkts_to_send = 10_000 as u64;

        let filter = Filter::new(SRC_IP, SRC_PORT, DST_IP, DST_PORT).unwrap();

        let send_done = Arc::new(AtomicBool::new(false));
        let send_done_rx = send_done.clone();

        let rx_timeout = Duration::from_secs(5);

        eprintln!("starting receiver");
        let recv_handle = thread::spawn(move || {
            let mut pkt: [u8; MAX_PACKET_SIZE] = [0; MAX_PACKET_SIZE];
            let mut matched_recvd_pkts = 0;
            let mut recvd_nums = vec![false; pkts_to_send as usize];
            let mut send_done_time: Option<Instant> = None;
            let start = Instant::now();

            let mut i = 0;
            while matched_recvd_pkts != pkts_to_send {
                i += 1;
                if i % 65_536 == 0 {
                    if send_done_rx.load(Ordering::Relaxed) {
                        if let Some(send_done_time) = send_done_time {
                            if send_done_time.elapsed() > rx_timeout {
                                eprintln!("recv ending after timeout");
                                break;
                            }
                        } else {
                            send_done_time = Some(Instant::now());
                        }
                    }
                }

                let len_recvd = dev1.read(&mut pkt[..]).expect("failed to read packet");
                if len_recvd > 0 {
                    match SlicedPacket::from_ethernet(&pkt[..len_recvd]) {
                        Ok(pkt) => {
                            if filter_pkt(&pkt, &filter) {
                                let n = LittleEndian::read_u64(&pkt.payload[..8]);
                                recvd_nums[n as usize] = true;
                                matched_recvd_pkts += 1;
                            }
                        }
                        Err(e) => log::warn!("failed to parse packet {:?}", e),
                    }
                }
            }

            let duration = start.elapsed();
            eprintln!("receive time is: {:?}", duration);
            recvd_nums
        });

        // give the receiver a chance to get going
        thread::sleep(Duration::from_millis(50));

        eprintln!("starting sender");
        let send_handle = thread::spawn(move || {
            let mut pkt: [u8; MAX_PACKET_SIZE] = [0; MAX_PACKET_SIZE];
            let mut payload: [u8; 8] = [0; 8];

            let start = Instant::now();
            for i in 0..pkts_to_send {
                //thread::sleep(Duration::from_millis(1));
                let pkt_builder = PacketBuilder::ethernet2([0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0])
                    .ipv4(SRC_IP, DST_IP, 20)
                    .udp(SRC_PORT, DST_PORT);

                LittleEndian::write_u64(&mut payload, i);
                let len_pkt = generate_pkt(&mut pkt[..], &mut payload[..], pkt_builder);

                dev2.write(&pkt[..len_pkt]).expect("failed to send pkt");
            }

            send_done.store(true, Ordering::Relaxed);
            let duration = start.elapsed();
            eprintln!("send time is: {:?}", duration);
        });

        send_handle.join().expect("failed to join tx handle");
        eprintln!("send done");

        let recvd_nums = recv_handle.join().expect("failed to join recv handle");
        eprintln!("recv done");

        let mut n_missing = 0;
        for (_i, recvd) in recvd_nums.iter().enumerate() {
            if !recvd {
                //log::debug!("missing {}", i);
                n_missing += 1;
            }
        }
        assert_eq!(n_missing, 0);
    }

    setup::run_test(test_fn);
}
