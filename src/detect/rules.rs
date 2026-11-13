use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub severity: Severity,
    pub rule: String,
    pub src: String,
    pub detail: String,
    pub ts: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct Event<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub tcp_flags: Option<u8>,
    pub dns_name: Option<&'a str>,
    pub bytes: u64,
    pub ts: f64,
}

pub trait Rule {
    fn name(&self) -> &str;
    fn observe(&mut self, event: &Event<'_>) -> Option<Alert>;
}
