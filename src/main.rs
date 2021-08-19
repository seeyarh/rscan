use afpacket::sync::RawPacketStream;
use nom::HexDisplay;
use std::io::prelude::*;

fn main() {
    let mut ps = RawPacketStream::new().unwrap();
    ps.bind("wlan0").unwrap();
    for _ in 0..10 {
        let mut buf = [0u8; 1500];
        ps.read(&mut buf).unwrap();
        println!("{}", buf.to_hex(24));

        ps.write(&buf).unwrap();
    }
}
