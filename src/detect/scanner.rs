use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

use super::rules::{Alert, Event, Rule, Severity};

#[derive(Debug)]
pub struct PortScanDetector {
    window_secs: f64,
    threshold: usize,
    events: HashMap<IpAddr, VecDeque<(f64, IpAddr, u16)>>,
}

impl PortScanDetector {
    pub fn new(window_secs: f64, threshold: usize) -> Self {
        Self {
            window_secs,
            threshold,
            events: HashMap::new(),
        }
    }

    pub fn is_syn(event: &Event<'_>) -> bool {
        event.protocol == 6 && event.tcp_flags.is_some_and(super::util::is_syn)
    }
}

impl Rule for PortScanDetector {
    fn name(&self) -> &str {
        "port-scan"
    }

    fn observe(&mut self, event: &Event<'_>) -> Option<Alert> {
        if !Self::is_syn(event) {
            return None;
        }
        let events = self.events.entry(event.src).or_default();
        events.push_back((event.ts, event.dst, event.dst_port));
        while let Some(&(seen_at, _, _)) = events.front() {
            if event.ts - seen_at > self.window_secs {
                events.pop_front();
            } else {
                break;
            }
        }
        // Count host:port pairs rather than packets. Hitting one port many
        // times is not a scan.
        let targets: HashSet<(IpAddr, u16)> =
            events.iter().map(|&(_, dst, port)| (dst, port)).collect();
        if targets.len() >= self.threshold {
            let count = targets.len();
            events.clear();
            Some(Alert {
                severity: Severity::High,
                rule: self.name().to_string(),
                src: event.src.to_string(),
                detail: format!(
                    "{count} distinct host:port targets in {:.0}s",
                    self.window_secs
                ),
                ts: event.ts,
            })
        } else {
            None
        }
    }
}
