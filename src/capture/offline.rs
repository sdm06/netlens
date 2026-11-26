use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::analysis::{AnalysisSummary, Bucket};
use crate::capture;
use crate::detect::rules::{Alert, Severity};
use crate::flows::aggregator::{FlowKey, FlowTable};
use crate::graph::topology::Topology;

pub use crate::capture::analyze_file as analyze;

pub fn demo_summary() -> AnalysisSummary {
    let mut table = FlowTable::default();
    let pairs = [
        ("10.0.0.5", "10.0.0.1", 51515u16, 443u16, 6u8, 42_000u64),
        ("10.0.0.6", "10.0.0.1", 51516, 443, 6, 31_000),
        ("10.0.0.7", "10.0.0.2", 40100, 53, 17, 8_400),
        ("10.0.0.5", "10.0.0.9", 50000, 22, 6, 4_200),
        ("10.0.0.8", "10.0.0.2", 40101, 80, 6, 2_100),
    ];
    for (src, dst, sport, dport, proto, size) in pairs {
        let key = FlowKey {
            src: src.parse::<IpAddr>().expect("valid demo source"),
            dst: dst.parse::<IpAddr>().expect("valid demo destination"),
            src_port: sport,
            dst_port: dport,
            protocol: proto,
        };
        table.record(key, size, 0.0);
    }

    let all_flows = table.all();
    let mut top_talkers = all_flows.clone();
    top_talkers.sort_by_key(|flow| std::cmp::Reverse(flow.bytes));
    top_talkers.truncate(10);

    let timeseries = vec![
        Bucket {
            start: 0.0,
            packets: 84,
            bytes: 62_400,
        },
        Bucket {
            start: 1.0,
            packets: 132,
            bytes: 148_200,
        },
        Bucket {
            start: 2.0,
            packets: 96,
            bytes: 71_800,
        },
        Bucket {
            start: 3.0,
            packets: 214,
            bytes: 342_900,
        },
        Bucket {
            start: 4.0,
            packets: 118,
            bytes: 91_600,
        },
        Bucket {
            start: 5.0,
            packets: 560,
            bytes: 175_440,
        },
    ];
    let protocols = BTreeMap::from([(6u8, 4u64), (17u8, 1u64)]);
    let alerts = vec![
        Alert {
            severity: Severity::High,
            rule: "port-scan".to_string(),
            src: "10.0.0.9".to_string(),
            detail: "24 distinct host:port targets in 10s".to_string(),
            ts: 5.0,
        },
        Alert {
            severity: Severity::Medium,
            rule: "volume-anomaly".to_string(),
            src: "network".to_string(),
            detail: "bucket 342900 B is 3.4 sigma above mean 120000 B".to_string(),
            ts: 3.0,
        },
    ];

    AnalysisSummary {
        source: "demo".to_string(),
        packets: timeseries.iter().map(|bucket| bucket.packets).sum(),
        bytes: timeseries.iter().map(|bucket| bucket.bytes).sum(),
        flows: table.len(),
        start_ts: Some(0.0),
        end_ts: Some(6.0),
        bucket_seconds: 1.0,
        alerts,
        top_talkers,
        all_flows,
        timeseries,
        protocols,
        topology: Topology::from_flows(&table.all()),
    }
}

pub fn format(path: &str) -> &'static str {
    match std::fs::read(path) {
        Ok(data) => capture::format(&data),
        Err(_) => "unknown",
    }
}
