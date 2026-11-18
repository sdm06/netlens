use netlens::capture;

fn ethernet_ip_tcp() -> Vec<u8> {
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
    segment[13] = 0x02;
    frame
}

fn pcap() -> Vec<u8> {
    let packet = ethernet_ip_tcp();
    let mut data = Vec::new();
    data.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    data.extend_from_slice(&2u16.to_le_bytes());
    data.extend_from_slice(&4u16.to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&65535u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    data.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    data.extend_from_slice(&packet);
    data
}

fn pcapng_block(kind: u32, body: &[u8]) -> Vec<u8> {
    let length = (8 + body.len() + 4) as u32;
    let mut block = Vec::new();
    block.extend_from_slice(&kind.to_le_bytes());
    block.extend_from_slice(&length.to_le_bytes());
    block.extend_from_slice(body);
    block.extend_from_slice(&length.to_le_bytes());
    block
}

fn pcapng() -> Vec<u8> {
    let mut shb = Vec::new();
    shb.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
    shb.extend_from_slice(&1u16.to_le_bytes());
    shb.extend_from_slice(&0u16.to_le_bytes());
    shb.extend_from_slice(&(-1i64).to_le_bytes());

    let mut idb = Vec::new();
    idb.extend_from_slice(&1u16.to_le_bytes());
    idb.extend_from_slice(&0u16.to_le_bytes());
    idb.extend_from_slice(&65535u32.to_le_bytes());
    idb.extend_from_slice(&9u16.to_le_bytes());
    idb.extend_from_slice(&1u16.to_le_bytes());
    idb.push(6);
    idb.extend_from_slice(&[0, 0, 0]);
    idb.extend_from_slice(&0u16.to_le_bytes());
    idb.extend_from_slice(&0u16.to_le_bytes());

    let packet = ethernet_ip_tcp();
    let mut epb = Vec::new();
    epb.extend_from_slice(&0u32.to_le_bytes());
    epb.extend_from_slice(&0u32.to_le_bytes());
    epb.extend_from_slice(&1_000_000u32.to_le_bytes());
    epb.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    epb.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    epb.extend_from_slice(&packet);
    while epb.len() % 4 != 0 {
        epb.push(0);
    }

    let mut data = pcapng_block(0x0a0d_0d0a, &shb);
    data.extend_from_slice(&pcapng_block(1, &idb));
    data.extend_from_slice(&pcapng_block(6, &epb));
    data
}

#[test]
fn analyzes_classic_pcap() {
    let summary = capture::analyze_bytes("test.pcap", &pcap()).unwrap();
    assert_eq!(summary.packets, 1);
    assert_eq!(summary.flows, 1);
    assert_eq!(summary.protocols.get(&6), Some(&1));
    assert_eq!(summary.top_talkers[0].dst_port, 80);
    assert_eq!(summary.source, "test.pcap");
}

#[test]
fn analyzes_pcapng() {
    let summary = capture::analyze_bytes("test.pcapng", &pcapng()).unwrap();
    assert_eq!(summary.packets, 1);
    assert_eq!(summary.flows, 1);
    assert_eq!(summary.start_ts, Some(1.0));
    assert_eq!(capture::format(&pcapng()), "pcapng");
}

#[test]
fn detects_format() {
    assert_eq!(capture::format(&pcap()), "pcap");
    assert_eq!(capture::format(&pcapng()), "pcapng");
}
