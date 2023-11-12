use etherparse::{InternetSlice, PacketBuilder, SlicedPacket, TransportSlice};

pub fn generate_synack(rx_sliced: &SlicedPacket, mut tx_pkt: &mut [u8]) -> Option<usize> {
    let pkt_builder = PacketBuilder::ethernet2([0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0]);
    let rx_ip = rx_sliced.ip.as_ref()?;

    let pkt_builder = match rx_ip {
        InternetSlice::Ipv4(ipv4) => {
            let dst = ipv4.header().destination_addr().octets();
            let src = ipv4.header().source_addr().octets();
            pkt_builder.ipv4(dst, src, 20)
        }
        InternetSlice::Ipv6(ipv6) => {
            let dst = ipv6.header().destination_addr().octets();
            let src = ipv6.header().source_addr().octets();
            pkt_builder.ipv6(dst, src, 20)
        }
    };

    let rx_transport = rx_sliced.transport.as_ref()?;
    let pkt_builder = match rx_transport {
        &TransportSlice::Udp(_)
        | &TransportSlice::Icmpv4(_)
        | &TransportSlice::Icmpv6(_)
        | &TransportSlice::Unknown(_) => return None,
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

pub fn log_response(sliced_pkt: &SlicedPacket) {
    let ip_str = match &sliced_pkt.ip {
        None => String::new(),
        Some(internet_slice) => match &internet_slice {
            InternetSlice::Ipv4(slice) => serde_json::to_string(&slice.header().to_header())
                .expect("failed to convert header to string"),
            InternetSlice::Ipv6(ipv6_header_slice) => {
                serde_json::to_string(&ipv6_header_slice.header().to_header())
                    .expect("failed to convert header to string")
            }
        },
    };
    let transport_str =
        match &sliced_pkt.transport {
            None => String::new(),
            Some(transport_slice) => match transport_slice {
                TransportSlice::Icmpv4(slice) => serde_json::to_string(&slice.header())
                    .expect("failed to convert header to string"),
                TransportSlice::Icmpv6(slice) => serde_json::to_string(&slice.header())
                    .expect("failed to convert header to string"),
                TransportSlice::Tcp(slice) => serde_json::to_string(&slice.to_header())
                    .expect("failed to convert_header to string"),
                TransportSlice::Udp(slice) => serde_json::to_string(&slice.to_header())
                    .expect("failed to convert header to string"),
                TransportSlice::Unknown(_) => String::new(),
            },
        };

    let payload = format!("{:x?}", sliced_pkt.payload);
    log::info!(
        "Received packet: ip {}, transport, {}, payload {}",
        ip_str,
        transport_str,
        payload
    );
}
