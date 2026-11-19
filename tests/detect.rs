use std::net::IpAddr;

use netlens::detect::rules::{Event, Rule};
use netlens::detect::{dns, scanner, synflood, util};

fn event<'a>(
    src: &str,
    dst: &str,
    dport: u16,
    flags: Option<u8>,
    name: Option<&'a str>,
) -> Event<'a> {
    Event {
        src: src.parse::<IpAddr>().unwrap(),
        dst: dst.parse::<IpAddr>().unwrap(),
        src_port: 40000,
        dst_port: dport,
        protocol: if flags.is_some() { 6 } else { 17 },
        tcp_flags: flags,
        dns_name: name,
        bytes: 100,
        ts: 1.0,
    }
}

#[test]
fn detects_port_scan() {
    let mut detector = scanner::PortScanDetector::new(10.0, 5);
    let mut alert = None;
    for port in 1000..1010 {
        let current = event("10.0.0.9", "10.0.0.1", port, Some(0x02), None);
        alert = detector.observe(&current);
        if alert.is_some() {
            break;
        }
    }
    assert!(alert.is_some());
}

#[test]
fn detects_syn_flood() {
    let mut detector = synflood::SynFloodDetector::new(5.0, 4);
    let mut alert = None;
    for index in 0..10 {
        let src = format!("10.0.1.{index}");
        let current = event(&src, "10.0.0.1", 80, Some(0x02), None);
        alert = detector.observe(&current);
        if alert.is_some() {
            break;
        }
    }
    assert!(alert.is_some());
}

#[test]
fn detects_dns_tunnel() {
    let name = format!("{}.example.com", "a".repeat(70));
    let mut detector = dns::DnsTunnelDetector::new(60, 3.6, 8);
    let mut alert = None;
    for _ in 0..3 {
        let current = event("10.0.0.7", "10.0.0.2", 53, None, Some(&name));
        alert = detector.observe(&current);
    }
    assert!(alert.is_some());
}

#[test]
fn entropy_distinguishes_random_and_repeated() {
    assert!(util::shannon_entropy(&"a".repeat(64)) < 0.01);
    assert!(util::shannon_entropy("abcdefghijklmnop") > 3.9);
}
