use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStats {
    pub src: String,
    pub dst: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub packets: u64,
    pub bytes: u64,
    pub first_ts: f64,
    pub last_ts: f64,
}

#[derive(Debug, Default)]
pub struct FlowTable {
    flows: HashMap<FlowKey, FlowStats>,
}

impl FlowTable {
    pub fn record(&mut self, key: FlowKey, bytes: u64, ts: f64) {
        let entry = self.flows.entry(key).or_insert_with(|| FlowStats {
            src: key.src.to_string(),
            dst: key.dst.to_string(),
            src_port: key.src_port,
            dst_port: key.dst_port,
            protocol: key.protocol,
            packets: 0,
            bytes: 0,
            first_ts: ts,
            last_ts: ts,
        });
        entry.packets += 1;
        entry.bytes += bytes;
        entry.first_ts = entry.first_ts.min(ts);
        entry.last_ts = entry.last_ts.max(ts);
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn flows(&self) -> impl Iterator<Item = &FlowStats> {
        self.flows.values()
    }

    pub fn all(&self) -> Vec<FlowStats> {
        self.flows.values().cloned().collect()
    }

    pub fn top_talkers(&self, limit: usize) -> Vec<FlowStats> {
        let mut flows = self.all();
        flows.sort_by_key(|flow| std::cmp::Reverse(flow.bytes));
        flows.truncate(limit);
        flows
    }
}
