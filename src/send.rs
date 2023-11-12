use afpacket::sync::RawPacketStream;
use crossbeam_channel::{Receiver, TryRecvError};
use std::io::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub fn start_tx(mut tx: RawPacketStream, pkts: Receiver<Vec<u8>>, shutdown: Arc<AtomicBool>) {
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        match pkts.try_recv() {
            Err(TryRecvError::Empty) => (),
            Err(_) => log::error!("failed to read from target channel"),
            Ok(pkt) => {
                tx.write_all(&pkt).expect("failed to write packet");
            }
        }
    }
}
