use super::handshake::Handshake;
use super::packet;
use crate::{ScanConfig, ScanResult, TcpFlags, MAX_PACKET_SIZE};
use afpacket::sync::RawPacketStream;
use crossbeam_channel::Sender;
use etherparse::{ip_number, InternetSlice, SlicedPacket, TransportSlice};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::prelude::*;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize, Hash)]
struct Host {
    ip: IpAddr,
    port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash)]
struct State {}

pub fn start_rx(
    mut rx: RawPacketStream,
    _conf: ScanConfig,
    _handshakes: Vec<Handshake>,
    response_sender: Sender<Vec<u8>>,
    results_sender: Sender<ScanResult>,
    shutdown: Arc<AtomicBool>,
) {
    let mut pkt = [0; MAX_PACKET_SIZE];
    let mut _host_state: HashMap<Host, State> = HashMap::new();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let len = rx.read(&mut pkt).expect("failed to read pkt");
        if let Some((result, response_pkt)) = handle_packet(&pkt[..len]) {
            results_sender.send(result).expect("failed to send result");
            if let Some(response_pkt) = response_pkt {
                response_sender
                    .send(response_pkt)
                    .expect("failed to send response packet");
            }
        }
    }
}

fn handle_packet(pkt: &[u8]) -> Option<(ScanResult, Option<Vec<u8>>)> {
    match SlicedPacket::from_ethernet(&pkt) {
        Err(e) => {
            log::error!("Error parsing packet {:?}", e);
            None
        }
        Ok(value) => {
            packet::log_response(&value);
            let ip = match &value.ip? {
                InternetSlice::Ipv4(slice) => IpAddr::V4(slice.header().source_addr()),
                InternetSlice::Ipv6(slice) => IpAddr::V6(slice.header().source_addr()),
            };
            let transport = value.transport?;
            match transport {
                TransportSlice::Icmpv4(_)
                | TransportSlice::Icmpv6(_)
                | TransportSlice::Unknown(_)
                | TransportSlice::Udp(_) => None,
                TransportSlice::Tcp(tcp) => {
                    if tcp.syn() && tcp.ack() {
                        let scan_result = ScanResult {
                            ip,
                            port: tcp.source_port(),
                            transport_protocol: u8::from(ip_number::TCP),
                            service: None,
                            tcp_flags: Some(TcpFlags::Synack),
                            data: None,
                        };
                        Some((scan_result, None))
                    } else {
                        None
                    }
                }
            }
        }
    }
}
