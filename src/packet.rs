use etherparse::{
    Ethernet2Header, InternetSlice, IpHeader, LinkSlice, PacketBuilder, PacketBuilderStep,
    SlicedPacket, TcpHeader, TransportSlice,
};
use std::str;

// Build ip header response to received packet by swapping source and dest ips
pub fn build_response_ip_header(
    rx_sliced: &SlicedPacket,
    builder: PacketBuilderStep<Ethernet2Header>,
) -> Option<PacketBuilderStep<IpHeader>> {
    let rx_ip = rx_sliced.ip.as_ref()?;

    let builder = match rx_ip {
        InternetSlice::Ipv4(ipv4) => {
            let dst = ipv4.header().destination_addr().octets();
            let src = ipv4.header().source_addr().octets();
            builder.ipv4(dst, src, 20)
        }
        InternetSlice::Ipv6(ipv6) => {
            let dst = ipv6.header().destination_addr().octets();
            let src = ipv6.header().source_addr().octets();
            builder.ipv6(dst, src, 20)
        }
    };

    Some(builder)
}

// Build tcp header response to received packet by looking at the received tcp flags.
// Returns PacketBuilderStep<TcpHeader> with the response tcp header and a bool indicating whether the
// response may contain a payload (whether the response header is an ack)
pub fn build_response_tcp_header(
    rx_sliced: &SlicedPacket,
    builder: PacketBuilderStep<IpHeader>,
) -> Option<(PacketBuilderStep<TcpHeader>, bool)> {
    let rx_transport = rx_sliced.transport.as_ref()?;
    match rx_transport {
        &TransportSlice::Udp(_)
        | &TransportSlice::Icmpv4(_)
        | &TransportSlice::Icmpv6(_)
        | &TransportSlice::Unknown(_) => return None,
        TransportSlice::Tcp(tcp) => {
            let builder = builder.tcp(
                tcp.destination_port(),
                tcp.source_port(),
                tcp.sequence_number() + 1,
                tcp.window_size(),
            );

            if tcp.syn() && tcp.ack() {
                return Some((builder.ack(tcp.sequence_number()), true));
            } else if tcp.syn() {
                return Some((builder.syn().ack(tcp.sequence_number()), false));
            } else if tcp.ack() {
                return Some((builder.ack(tcp.sequence_number()), true));
            } else if tcp.fin() {
                return Some((builder.fin().ack(tcp.sequence_number()), false));
            } else if tcp.rst() {
                return Some((builder.rst().ack(tcp.sequence_number()), false));
            } else {
                return None;
            }
        }
    }
}

// Build a tcp response to the received packet. If the received packet is not a tcp packet, return None
// If applicable, write the argument payload
pub fn build_tcp_response(
    rx_sliced: &SlicedPacket,
    payload: &[u8],
    mut tx_pkt: &mut [u8],
) -> Option<usize> {
    let link = rx_sliced.link.as_ref()?;
    let LinkSlice::Ethernet2(link) = link;
    let src_mac = link.destination();
    let dest_mac = link.source();
    let pkt_builder = PacketBuilder::ethernet2(src_mac, dest_mac);

    let pkt_builder = match build_response_ip_header(rx_sliced, pkt_builder) {
        None => {
            log::info!("failed to make ip header");
            return None;
        }
        Some(b) => b,
    };
    let (pkt_builder, can_include_payload) = match build_response_tcp_header(rx_sliced, pkt_builder)
    {
        None => {
            log::info!("failed to make tcp header");
            return None;
        }
        Some(b) => b,
    };

    let mut len = pkt_builder.size(0);
    if can_include_payload {
        len += payload.len();
        pkt_builder
            .write(&mut tx_pkt, payload)
            .expect("failed to write pkt");
    } else {
        pkt_builder
            .write(&mut tx_pkt, &[])
            .expect("failed to write pkt");
    }
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

    //let payload = format!("{:x?}", sliced_pkt.payload);
    log::info!(
        "Received packet: ip {}, transport, {}, payload {}",
        ip_str,
        transport_str,
        str::from_utf8(sliced_pkt.payload).expect("failed to convert payload to str")
    );
}
