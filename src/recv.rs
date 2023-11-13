use super::handshake::Handshake;
use super::packet;
use crate::packet::build_tcp_response;
use crate::{ScanConfig, ScanResult, TcpFlags, MAX_PACKET_SIZE};
use afpacket::sync::RawPacketStream;
use crossbeam_channel::Sender;
use etherparse::{ip_number, InternetSlice, SlicedPacket, TransportSlice};
use memchr::memmem;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::prelude::*;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize, Hash, Eq, PartialEq)]
struct Host {
    ip: IpAddr,
    port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash)]
struct State {
    handshakes_attempted: usize,
    tcp_flags: TcpFlags,
}

pub fn start_rx(
    mut rx: RawPacketStream,
    conf: ScanConfig,
    handshakes: Vec<Handshake>,
    response_sender: Sender<Vec<u8>>,
    results_sender: Sender<ScanResult>,
    shutdown: Arc<AtomicBool>,
) {
    let mut recv_pkt = [0; MAX_PACKET_SIZE];
    let mut resp_pkt = [0; MAX_PACKET_SIZE];
    let mut host_state: HashMap<Host, State> = HashMap::new();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let len = rx.read(&mut recv_pkt).expect("failed to read pkt");
        if let Some((result, resp_len)) = handle_packet(
            &conf,
            &recv_pkt[..len],
            &mut resp_pkt,
            &handshakes,
            &mut host_state,
        ) {
            results_sender.send(result).expect("failed to send result");
            if resp_len > 0 {
                response_sender
                    .send(resp_pkt[..resp_len].into())
                    .expect("failed to send response packet");
            }
        }
    }
}

fn handle_packet(
    conf: &ScanConfig,
    recvd_pkt: &[u8],
    resp_pkt: &mut [u8],
    handshakes: &[Handshake],
    host_state: &mut HashMap<Host, State>,
) -> Option<(ScanResult, usize)> {
    match SlicedPacket::from_ethernet(&recvd_pkt) {
        Err(e) => {
            //log::error!("Error parsing packet error: {:?}", e);
            //log::error!("Error parsing packet recvd_pkt {:?}", recvd_pkt);
            None
        }
        Ok(value) => {
            let ip = match &value.ip.as_ref()? {
                InternetSlice::Ipv4(slice) => IpAddr::V4(slice.header().source_addr()),
                InternetSlice::Ipv6(slice) => IpAddr::V6(slice.header().source_addr()),
            };
            let transport = value.transport.as_ref()?;
            match transport {
                TransportSlice::Icmpv4(_)
                | TransportSlice::Icmpv6(_)
                | TransportSlice::Unknown(_)
                | TransportSlice::Udp(_) => None,
                TransportSlice::Tcp(tcp) => {
                    if tcp.destination_port() != conf.src_port {
                        return None;
                    }
                    packet::log_response(&value);
                    let host = Host {
                        ip,
                        port: tcp.source_port(),
                    };
                    let mut resp_len = 0;
                    if tcp.syn() && tcp.ack() {
                        let scan_result = ScanResult {
                            ip,
                            port: tcp.source_port(),
                            transport_protocol: u8::from(ip_number::TCP),
                            service: None,
                            tcp_flags: Some(TcpFlags::Synack),
                            data: vec![],
                        };

                        // have we tried to scan this host previously?
                        match host_state.get_mut(&host) {
                            // if so, try next handshake,
                            Some(state) => {
                                // this shouldn't be oob, check if we're out of hs in the ack section
                                let _next_handshake = &handshakes[state.handshakes_attempted];
                                state.handshakes_attempted += 1;
                                state.tcp_flags = TcpFlags::Synack;
                            }
                            // if not, try first handshake
                            None => {
                                let next_handshake = &handshakes[0];
                                let state = State {
                                    handshakes_attempted: 1,
                                    tcp_flags: TcpFlags::Synack,
                                };
                                host_state.insert(host, state);
                                resp_len =
                                    build_tcp_response(&value, &next_handshake.request, resp_pkt)
                                        .expect("failed to build tcp response");
                            }
                        }
                        Some((scan_result, resp_len))
                    } else if tcp.ack() {
                        log::info!("recv ack");

                        let mut scan_result = ScanResult {
                            ip,
                            port: tcp.source_port(),
                            transport_protocol: u8::from(ip_number::TCP),
                            service: None,
                            tcp_flags: Some(TcpFlags::Ack),
                            data: value.payload.into(),
                        };
                        // check handshake responses to see if any match
                        let payload = value.payload;
                        for h in handshakes {
                            log::info!("checking service {}", &h.service);
                            log::info!("checking {:x?} is in {:x?}", &h.response, payload);
                            if memmem::find(payload, &h.response).is_some() {
                                log::info!("match for service {}", &h.service);
                                scan_result.service = Some(h.service.clone());
                                break;
                            }
                        }

                        Some((scan_result, resp_len))
                    } else if tcp.rst() {
                        let scan_result = ScanResult {
                            ip,
                            port: tcp.source_port(),
                            transport_protocol: u8::from(ip_number::TCP),
                            service: None,
                            tcp_flags: Some(TcpFlags::Rst),
                            data: vec![],
                        };
                        // have we tried to scan this host previously, and received a synack at some point?
                        match host_state.get_mut(&host) {
                            // if so, re-enqueue for syn scan and try next handshake,
                            Some(_state) => {
                                //
                            }
                            // if not, don't try to scan
                            None => {}
                        }
                        Some((scan_result, resp_len))
                    } else {
                        None
                    }
                }
            }
        }
    }
}
