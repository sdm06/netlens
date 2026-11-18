use netlens::parse::{ethernet, ip, tcp};

#[test]
fn parses_ipv4_tcp() {
    let mut frame = vec![0u8; 14 + 20 + 20];
    frame[12] = 0x08;
    frame[13] = 0x00;

    let header = &mut frame[14..34];
    header[0] = 0x45;
    header[2] = 0;
    header[3] = 40;
    header[9] = 6;
    header[12..16].copy_from_slice(&[10, 0, 0, 1]);
    header[16..20].copy_from_slice(&[10, 0, 0, 2]);

    let segment = &mut frame[34..54];
    segment[0..2].copy_from_slice(&1234u16.to_be_bytes());
    segment[2..4].copy_from_slice(&80u16.to_be_bytes());
    segment[12] = 0x50;
    segment[13] = tcp::SYN;

    let eth = ethernet::parse(&frame).expect("ethernet frame");
    assert_eq!(eth.ethertype, ethernet::ETHERTYPE_IPV4);

    let packet = ip::parse_v4(eth.payload).expect("ipv4 packet");
    assert_eq!(packet.src.to_string(), "10.0.0.1");
    assert_eq!(packet.dst.to_string(), "10.0.0.2");
    assert_eq!(packet.protocol, 6);

    let parsed = tcp::parse(packet.payload).expect("tcp segment");
    assert_eq!(parsed.src_port, 1234);
    assert_eq!(parsed.dst_port, 80);
    assert_eq!(parsed.flags & tcp::SYN, tcp::SYN);
}

#[test]
fn parses_dns_name() {
    let mut payload = vec![0u8; 12];
    payload[4] = 0;
    payload[5] = 1;
    payload.extend_from_slice(&[
        3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    assert_eq!(
        netlens::parse::dns::query_name(&payload).as_deref(),
        Some("www.example.com")
    );
}
