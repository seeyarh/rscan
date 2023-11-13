use afpacket::sync::RawPacketStream;
use crossbeam_channel::{unbounded, Receiver, Sender};
use etherparse::PacketBuilder;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

pub mod handshake;
pub mod packet;
pub mod recv;
pub mod send;

pub const MAX_PACKET_SIZE: usize = 1500;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Target {
    pub ip: IpAddr,
    pub port: u16,
    pub ip_number: u8,
    pub data: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum TcpFlags {
    Syn,
    Synack,
    Ack,
    Rst,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub ip: IpAddr,
    pub port: u16,
    pub transport_protocol: u8,
    pub service: Option<String>,
    pub tcp_flags: Option<TcpFlags>,
    #[serde_as(as = "Base64")]
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanConfig {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ipv4: Option<Ipv4Addr>,
    pub src_ipv6: Option<Ipv6Addr>,
    pub src_port: u16,
    pub handshakes_file: String,
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
        let pkt_builder = PacketBuilder::ethernet2(scan_config.src_mac, scan_config.dst_mac);

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

        let pkt_builder = pkt_builder
            .tcp(scan_config.src_port, self.port, random(), 65535)
            .syn();

        let len = pkt_builder.size(0);
        pkt_builder.write(&mut pkt, &[]).unwrap();
        Ok(len)
    }
}

#[derive(Debug)]
pub struct Scanner {
    pub conf: ScanConfig,
    pub target_sender: Sender<Vec<u8>>,
    pub result_receiver: Receiver<ScanResult>,
    tx_handle: JoinHandle<()>,
    rx_handle: JoinHandle<()>,
    shutdown: Arc<AtomicBool>,
}

impl Scanner {
    pub fn new(packet_stream: RawPacketStream, conf: ScanConfig) -> Self {
        let tx = packet_stream;
        let rx = tx.clone();

        let (target_sender, target_receiver) = unbounded();
        let (result_sender, result_receiver) = unbounded();
        let shutdown = Arc::new(AtomicBool::new(false));

        let tx_shutdown = shutdown.clone();
        let tx_handle = thread::Builder::new()
            .name("tx".into())
            .spawn(move || {
                send::start_tx(tx, target_receiver, tx_shutdown);
            })
            .expect("failed to start tx thread");

        let handshakes = handshake::get_service_handshakes(&conf.handshakes_file)
            .expect("failed to get handshakes from file");

        let rx_target_sender = target_sender.clone();
        let rx_shutdown = shutdown.clone();
        let rx_conf = conf.clone();
        let rx_handle = thread::Builder::new()
            .name("rx".into())
            .spawn(move || {
                recv::start_rx(
                    rx,
                    rx_conf,
                    handshakes,
                    rx_target_sender,
                    result_sender,
                    rx_shutdown,
                );
            })
            .expect("failed to start rx thread");

        Scanner {
            conf,
            target_sender,
            result_receiver,
            tx_handle,
            rx_handle,
            shutdown,
        }
    }

    pub fn scan_target(&self, target: &Target) {
        let mut pkt = vec![0; MAX_PACKET_SIZE];
        let len = target
            .to_pkt(&mut pkt, &self.conf)
            .expect("failed to convert target to packet");
        self.target_sender
            .send(pkt[..len].to_vec())
            .expect("failed to send target");
    }
    pub fn shutdown(self) {
        self.shutdown.swap(true, Ordering::Relaxed);
        self.tx_handle
            .join()
            .expect("failed to wait for tx thread to stop");
        self.rx_handle
            .join()
            .expect("failed to wait for rx thread to stop");
    }
}
