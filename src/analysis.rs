use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::detect::DetectorSet;
use crate::detect::rules::Alert;
use crate::flows::aggregator::{FlowKey, FlowStats, FlowTable};
use crate::graph::topology::Topology;
use crate::parse;

// One time slice of traffic. Keeping these around means the UI can filter
// without ever touching the capture file again.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Bucket {
    pub start: f64,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub source: String,
    pub packets: u64,
    pub bytes: u64,
    pub flows: usize,
    pub start_ts: Option<f64>,
    pub end_ts: Option<f64>,
    pub bucket_seconds: f64,
    pub alerts: Vec<Alert>,
    pub top_talkers: Vec<FlowStats>,
    pub all_flows: Vec<FlowStats>,
    pub timeseries: Vec<Bucket>,
    pub protocols: BTreeMap<u8, u64>,
    pub topology: Topology,
}

#[derive(Debug, Clone, Default)]
pub struct Filters {
    pub query: String,
    pub protocol: Option<u8>,
    pub min_bytes: u64,
    pub start: Option<f64>,
    pub end: Option<f64>,
}

impl AnalysisSummary {
    // Filtering rebuilds the small derived views instead of re-reading packets.
    // That keeps the UI responsive even when the capture itself is large.
    pub fn filtered(&self, filters: &Filters) -> Self {
        let query = filters.query.trim().to_ascii_lowercase();
        let flows: Vec<FlowStats> = self
            .all_flows
            .iter()
            .filter(|flow| filters.protocol.is_none_or(|p| p == flow.protocol))
            .filter(|flow| flow.bytes >= filters.min_bytes)
            .filter(|flow| {
                filters.start.is_none_or(|start| flow.last_ts >= start)
                    && filters.end.is_none_or(|end| flow.first_ts <= end)
            })
            .filter(|flow| {
                query.is_empty()
                    || flow.src.to_ascii_lowercase().contains(&query)
                    || flow.dst.to_ascii_lowercase().contains(&query)
            })
            .cloned()
            .collect();

        let timeseries: Vec<Bucket> = self
            .timeseries
            .iter()
            .copied()
            .filter(|bucket| {
                filters.start.is_none_or(|start| bucket.start >= start)
                    && filters.end.is_none_or(|end| bucket.start <= end)
            })
            .collect();

        let alerts = self
            .alerts
            .iter()
            .filter(|alert| {
                filters.start.is_none_or(|start| alert.ts >= start)
                    && filters.end.is_none_or(|end| alert.ts <= end)
            })
            .cloned()
            .collect();

        let packets = timeseries.iter().map(|bucket| bucket.packets).sum();
        let bytes = timeseries.iter().map(|bucket| bucket.bytes).sum();
        let protocols = flows.iter().fold(BTreeMap::new(), |mut map, flow| {
            *map.entry(flow.protocol).or_insert(0) += 1;
            map
        });
        let mut top_talkers = flows.clone();
        top_talkers.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        top_talkers.truncate(10);

        Self {
            source: self.source.clone(),
            packets,
            bytes,
            flows: flows.len(),
            start_ts: timeseries.first().map(|bucket| bucket.start),
            end_ts: timeseries
                .last()
                .map(|bucket| bucket.start + self.bucket_seconds),
            bucket_seconds: self.bucket_seconds,
            alerts,
            top_talkers,
            all_flows: flows.clone(),
            timeseries,
            protocols,
            topology: Topology::from_flows(&flows),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AnalyzerConfig {
    pub bucket_seconds: f64,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            bucket_seconds: 1.0,
        }
    }
}

#[derive(Debug)]
pub struct Analyzer {
    config: AnalyzerConfig,
    source: String,
    packets: u64,
    bytes: u64,
    table: FlowTable,
    alerts: Vec<Alert>,
    buckets: BTreeMap<u64, Bucket>,
    protocols: BTreeMap<u8, u64>,
    detectors: DetectorSet,
    first_ts: Option<f64>,
    last_ts: Option<f64>,
    current_bucket: Option<u64>,
}

impl Analyzer {
    pub fn new(source: impl Into<String>) -> Self {
        Self::with_config(source, AnalyzerConfig::default())
    }

    pub fn with_config(source: impl Into<String>, config: AnalyzerConfig) -> Self {
        Self {
            config,
            source: source.into(),
            packets: 0,
            bytes: 0,
            table: FlowTable::default(),
            alerts: Vec::new(),
            buckets: BTreeMap::new(),
            protocols: BTreeMap::new(),
            detectors: DetectorSet::new(),
            first_ts: None,
            last_ts: None,
            current_bucket: None,
        }
    }

    pub fn observe(&mut self, ts: f64, linktype: u32, frame: &[u8]) {
        // Every frame counts, even if we cannot decode it. The counters should
        // agree with what tcpdump says, not with what the parsers understand.
        self.packets += 1;
        self.bytes += frame.len() as u64;
        self.first_ts = Some(self.first_ts.map_or(ts, |first| first.min(ts)));
        self.last_ts = Some(self.last_ts.map_or(ts, |last| last.max(ts)));

        let bucket_index = (ts / self.config.bucket_seconds).max(0.0) as u64;
        if self.current_bucket != Some(bucket_index) {
            if let Some(previous) = self.current_bucket {
                let total = self.buckets.get(&previous).map_or(0, |bucket| bucket.bytes);
                if let Some(alert) = self
                    .detectors
                    .observe_volume(total, previous as f64 * self.config.bucket_seconds)
                {
                    self.alerts.push(alert);
                }
            }
            self.current_bucket = Some(bucket_index);
            self.buckets.entry(bucket_index).or_insert(Bucket {
                start: bucket_index as f64 * self.config.bucket_seconds,
                packets: 0,
                bytes: 0,
            });
        }
        if let Some(bucket) = self.buckets.get_mut(&bucket_index) {
            bucket.packets += 1;
            bucket.bytes += frame.len() as u64;
        }

        if linktype != 1 {
            return;
        }
        let Ok(ethernet) = parse::ethernet::parse(frame) else {
            return;
        };
        let ip = match ethernet.ethertype {
            parse::ethernet::ETHERTYPE_IPV4 => parse::ip::parse_v4(ethernet.payload).ok(),
            parse::ethernet::ETHERTYPE_IPV6 => parse::ip::parse_v6(ethernet.payload).ok(),
            _ => None,
        };
        let Some(ip) = ip else {
            return;
        };
        // Non-first fragments do not carry a transport header, so there is
        // nothing useful to attach to a flow.
        if ip.fragment_offset > 0 {
            return;
        }
        let Ok(Some(transport)) = parse::transport(ip.protocol, ip.payload) else {
            return;
        };

        let dns_name =
            if ip.protocol == 17 && (transport.src_port == 53 || transport.dst_port == 53) {
                parse::dns::query_name(transport.payload)
            } else {
                None
            };

        let event = crate::detect::rules::Event {
            src: ip.src,
            dst: ip.dst,
            src_port: transport.src_port,
            dst_port: transport.dst_port,
            protocol: ip.protocol,
            tcp_flags: if ip.protocol == 6 {
                parse::tcp::parse(ip.payload)
                    .ok()
                    .map(|segment| segment.flags)
            } else {
                None
            },
            dns_name: dns_name.as_deref(),
            bytes: frame.len() as u64,
            ts,
        };
        if let Some(alert) = self.detectors.observe(&event) {
            self.alerts.push(alert);
        }

        let key = FlowKey {
            src: ip.src,
            dst: ip.dst,
            src_port: transport.src_port,
            dst_port: transport.dst_port,
            protocol: ip.protocol,
        };
        self.table.record(key, frame.len() as u64, ts);
        *self.protocols.entry(ip.protocol).or_insert(0) += 1;
    }

    pub fn finish(mut self) -> AnalysisSummary {
        if let Some(current) = self.current_bucket {
            let total = self.buckets.get(&current).map_or(0, |bucket| bucket.bytes);
            if let Some(alert) = self
                .detectors
                .observe_volume(total, current as f64 * self.config.bucket_seconds)
            {
                self.alerts.push(alert);
            }
        }

        let all_flows = self.table.all();
        let mut top_talkers = all_flows.clone();
        top_talkers.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        top_talkers.truncate(10);
        let timeseries = self.buckets.into_values().collect();

        AnalysisSummary {
            source: self.source,
            packets: self.packets,
            bytes: self.bytes,
            flows: self.table.len(),
            start_ts: self.first_ts,
            end_ts: self.last_ts,
            bucket_seconds: self.config.bucket_seconds,
            alerts: self.alerts,
            top_talkers,
            all_flows,
            timeseries,
            protocols: self.protocols,
            topology: Topology::from_flows(&self.table.all()),
        }
    }

    pub fn alerts(&self) -> &[Alert] {
        &self.alerts
    }
}
