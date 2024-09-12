mod setup;

use std::fs;
use std::io::prelude::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use etherparse::{ip_number, SlicedPacket};

use afpacket::sync::RawPacketStream;
use rscan::packet::build_tcp_response;
use rscan::{ScanConfig, ScanResult, Scanner, Target, TcpFlags};

const SRC_IP: [u8; 4] = [192, 168, 69, 1];
const DST_IP: [u8; 4] = [192, 168, 69, 2];

const MAX_PACKET_SIZE: usize = 1500;

fn read_http_response_bytes() -> Vec<u8> {
    fs::read("test_data/google-http-302.bin").expect("failed to read bytes file")
}

fn http_responder(mut ps: RawPacketStream, shutdown: Arc<AtomicBool>) {
    let http_bin = read_http_response_bytes();
    let mut rx_pkt = [0; MAX_PACKET_SIZE];
    let mut tx_pkt = [0; MAX_PACKET_SIZE];
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let len = ps.read(&mut rx_pkt).expect("failed to read pkt");
        match SlicedPacket::from_ethernet(&rx_pkt[..len]) {
            Ok(sliced) => {
                if let Some(len) = build_tcp_response(&sliced, &http_bin, &mut tx_pkt) {
                    ps.write_all(&tx_pkt[..len]).expect("failed to write pkt");
                }
            }
            Err(e) => log::error!("Err {:?}", e),
        }
    }
}

#[test]
fn http_test() {
    fn test_fn(dev1_ps: RawPacketStream, dev2_ps: RawPacketStream) {
        let scan_config = ScanConfig {
            src_mac: [0, 0, 0, 0, 0, 0],
            dst_mac: [0, 0, 0, 0, 0, 0],
            src_ipv4: Some(Ipv4Addr::from(SRC_IP)),
            src_ipv6: None,
            src_port: 10000,
            handshakes_file: "handshakes.yaml".into(),
        };

        let scanner = Scanner::new(dev1_ps, scan_config);
        let shutdown = Arc::new(AtomicBool::new(false));
        let test_receiver_shutdown = shutdown.clone();
        let test_receiver_handle = thread::Builder::new()
            .name("http test".into())
            .spawn(move || {
                http_responder(dev2_ps, test_receiver_shutdown);
            })
            .expect("failed to start synacker thread");

        thread::sleep(Duration::from_secs(1));

        let max_port = 5;
        let targets: Vec<Target> = (1..max_port)
            .into_iter()
            .map(|port| Target {
                ip: IpAddr::V4(Ipv4Addr::from(DST_IP)),
                port,
                ip_number: u8::from(ip_number::TCP),
                data: None,
            })
            .collect();

        for target in targets.iter() {
            thread::sleep(Duration::from_micros(1));
            scanner.scan_target(&target);
        }

        let mut syn_results: Vec<ScanResult> = vec![];
        let mut handshake_results: Vec<ScanResult> = vec![];

        let rx_timeout = Duration::from_secs(5);
        let start = Instant::now();
        while ((syn_results.len() < targets.len()) || (handshake_results.len() < targets.len()))
            && (start.elapsed() < rx_timeout)
        {
            match scanner.result_receiver.try_recv() {
                Ok(scan_result) => {
                    if scan_result.ip == IpAddr::V4(Ipv4Addr::from(DST_IP)) {
                        log::info!("{:?}", scan_result);
                        if scan_result.tcp_flags == Some(TcpFlags::Synack) {
                            syn_results.push(scan_result);
                        } else if scan_result.tcp_flags == Some(TcpFlags::Ack) {
                            if scan_result.service == Some("http".into()) {
                                handshake_results.push(scan_result);
                            }
                        }
                    }
                }
                Err(_e) => {
                    //log::error!("Err {:?}", e);
                }
            }
        }

        scanner.shutdown();

        shutdown.swap(true, Ordering::Relaxed);

        let _ = test_receiver_handle
            .join()
            .expect("failed to wait for receive thread");

        log::info!("num targets   = {}", targets.len());
        log::info!("num syn       = {}", syn_results.len());
        log::info!("num handshake = {}", handshake_results.len());
        assert_eq!(targets.len(), syn_results.len());
        assert_eq!(targets.len(), handshake_results.len());
    }

    setup::run_test(test_fn);
}
