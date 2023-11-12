use afpacket::sync::RawPacketStream;
use clap::Parser;
use crossbeam_channel::Receiver;
use rscan::{ScanConfig, ScanResult, Scanner, Target};
use std::error::Error;
use std::io::{self, BufRead, BufReader};
use std::net::IpAddr;
use std::thread;
use std::time::Duration;

/// Rscan
#[derive(Debug, Clone, Parser)]
#[command(version = "1.0", author = "Collins Huff")]
struct Opts {
    /// input file, if omitted defaults to stdin
    #[arg(short, long)]
    input: Option<String>,

    /// output file, if omitted defaults to stdout
    #[arg(short, long)]
    output: Option<String>,

    /// log file, if omitted defaults to stderr
    #[arg(short, long)]
    log: Option<String>,

    /// service handshakes file
    #[arg(short, long)]
    handshakes_file: String,

    /// interface name
    #[arg(short, long)]
    dev: String,

    /// source MAC address
    #[arg(long)]
    src_mac: String,

    /// destination MAC address
    #[arg(long)]
    dest_mac: String,

    /// source IPv4 address
    #[arg(long)]
    src_ipv4: Option<String>,

    /// source IPv6 address
    #[arg(long)]
    src_ipv6: Option<String>,

    /// source port
    #[arg(long)]
    src_port: u16,

    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn parse_mac(mac: &str) -> Result<[u8; 6], Box<dyn Error>> {
    let mut mac_bytes: [u8; 6] = [0; 6];
    let parts: Vec<&str> = mac.split(':').into_iter().collect();
    if parts.len() != 6 {
        Err("wrong len".into())
    } else {
        for (i, part) in parts.iter().enumerate() {
            let mac_byte = u8::from_str_radix(part, 16)?;
            mac_bytes[i] = mac_byte;
        }
        Ok(mac_bytes)
    }
}

fn main() {
    env_logger::init();
    let opts = Opts::parse();
    let mut ps = RawPacketStream::new().unwrap();
    ps.bind(&opts.dev)
        .expect("failed to bind to specified interface");

    let src_ipv4 =
        opts.src_ipv4.map(
            |ip| match ip.parse().expect("failed to parse source ip address") {
                IpAddr::V4(ip) => ip,
                _ => panic!("provided source ipv4 address is not valid"),
            },
        );

    let src_ipv6 =
        opts.src_ipv6.map(
            |ip| match ip.parse().expect("failed to parse source ip address") {
                IpAddr::V6(ip) => ip,
                _ => panic!("provided source ipv6 address is not valid"),
            },
        );

    let scan_config = ScanConfig {
        src_mac: parse_mac(&opts.src_mac).expect("failed to parse src mac"),
        dst_mac: parse_mac(&opts.dest_mac).expect("failed to parse src mac"),
        src_ipv4,
        src_ipv6,
        src_port: opts.src_port,
        handshakes_file: opts.handshakes_file,
    };

    let scanner = Scanner::new(ps, scan_config);

    let results = scanner.result_receiver.clone();
    std::thread::spawn(|| {
        print_hits(results);
    });

    let reader = BufReader::new(io::stdin());
    for line in reader.lines() {
        let line = line.expect("failed to read line");
        let target: Target = serde_json::from_str(&line).expect("failed to parse target");
        thread::sleep(Duration::from_micros(1));
        log::trace!("sending target to scanner: {:?}", target);
        scanner.scan_target(&target);
    }

    thread::sleep(Duration::from_secs(10));

    scanner.shutdown();
}

fn print_hits(results: Receiver<ScanResult>) {
    for result in results {
        let result = serde_json::to_string(&result).expect("failed to serialize result");
        println!("{}", result);
    }
}
