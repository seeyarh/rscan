use afpacket::sync::RawPacketStream;
use crossbeam_channel::{select, unbounded, Receiver, Sender};
use etherparse::{InternetSlice, PacketBuilder, SlicedPacket, TransportSlice};
use std::error::Error;
use std::fmt;
use std::io::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::thread::{spawn, JoinHandle};

#[derive(Clone, Debug)]
pub struct Target {
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Clone, Debug)]
pub struct ScanConfig {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ipv4: Option<Ipv4Addr>,
    pub src_ipv6: Option<Ipv6Addr>,
    pub src_port: u16,
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

#[derive(Debug)]
pub struct Scanner {
    pub target_sender: Sender<Target>,
    pub result_receiver: Receiver<Target>,
    pub shutdown_sender: Sender<()>,
    pub tx_handle: JoinHandle<()>,
    pub rx_handle: JoinHandle<()>,
}

impl Scanner {
    pub fn new(packet_stream: RawPacketStream, conf: ScanConfig) -> Self {
        let tx = packet_stream;
        let rx = tx.clone();

        let (target_sender, target_receiver) = unbounded();
        let (result_sender, result_receiver) = unbounded();
        let (shutdown_sender, shutdown_receiver) = unbounded();

        let tx_shutdown_receiver = shutdown_receiver.clone();
        let tx_conf = conf.clone();
        let tx_handle = spawn(move || {
            start_tx(tx, tx_conf, target_receiver, tx_shutdown_receiver);
        });

        let rx_shutdown_receiver = shutdown_receiver;
        let rx_conf = conf;
        let rx_handle = spawn(move || {
            start_rx(rx, rx_conf, result_sender, rx_shutdown_receiver);
        });

        Scanner {
            target_sender,
            result_receiver,
            shutdown_sender,
            tx_handle,
            rx_handle,
        }
    }
}

const MAX_PACKET_SIZE: usize = 1500;

fn start_tx(
    mut tx: RawPacketStream,
    conf: ScanConfig,
    targets: Receiver<Target>,
    shutdown: Receiver<()>,
) {
    let mut pkt = [0; MAX_PACKET_SIZE];

    loop {
        select! {
            recv(targets) -> target => {
                log::info!("scanning {:?}", target);
                let target = target.expect("failed to recv target");
                let len = target.to_pkt(&mut pkt, &conf).expect("failed to create packet");
                tx.write_all(&pkt[..len]).expect("failed to write packet");

            }
            recv(shutdown) -> _ => break,
        }
    }
}

fn start_rx(
    mut rx: RawPacketStream,
    _conf: ScanConfig,
    results: Sender<Target>,
    shutdown: Receiver<()>,
) {
    let mut pkt = [0; MAX_PACKET_SIZE];

    loop {
        let len = rx.read(&mut pkt).expect("failed to read pkt");
        if let Some(responder) = parse(&pkt[..len]) {
            results.send(responder).expect("failed to send");
        }

        if let Ok(_) = shutdown.try_recv() {
            break;
        }
    }
}

fn parse(pkt: &[u8]) -> Option<Target> {
    match SlicedPacket::from_ethernet(&pkt) {
        Err(e) => {
            log::error!("Error parsing packet {:?}", e);
            None
        }
        Ok(value) => {
            let ip = value.ip?;
            let transport = value.transport?;
            match transport {
                TransportSlice::Udp(_) => None,
                TransportSlice::Tcp(tcp) => {
                    if tcp.syn() && tcp.ack() {
                        let ip = match ip {
                            InternetSlice::Ipv4(ipv4) => IpAddr::V4(ipv4.source_addr()),
                            InternetSlice::Ipv6(ipv6, _) => IpAddr::V6(ipv6.source_addr()),
                        };

                        let port = tcp.source_port();
                        let responder = Target { ip, port };
                        log::info!("responder: {:?}", responder);
                        Some(responder)
                    } else {
                        None
                    }
                }
            }
        }
    }
}
