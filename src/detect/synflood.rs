use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use super::rules::{Alert, Event, Rule, Severity};
use super::util::is_syn;

#[derive(Debug)]
pub struct SynFloodDetector {
    window_secs: f64,
    threshold: usize,
    syns: HashMap<IpAddr, VecDeque<(f64, IpAddr)>>,
}

impl SynFloodDetector {
    pub fn new(window_secs: f64, threshold: usize) -> Self {
        Self {
            window_secs,
            threshold,
            syns: HashMap::new(),
        }
    }
}

impl Rule for SynFloodDetector {
    fn name(&self) -> &str {
        "syn-flood"
    }

    fn observe(&mut self, event: &Event<'_>) -> Option<Alert> {
        if event.protocol != 6 || !event.tcp_flags.is_some_and(is_syn) {
            return None;
        }
        let entries = self.syns.entry(event.dst).or_default();
        entries.push_back((event.ts, event.src));
        while let Some(&(seen_at, _)) = entries.front() {
            if event.ts - seen_at > self.window_secs {
                entries.pop_front();
            } else {
                break;
            }
        }
        if entries.len() >= self.threshold {
            let count = entries.len();
            let sources: std::collections::HashSet<IpAddr> =
                entries.iter().map(|(_, src)| *src).collect();
            entries.clear();
            Some(Alert {
                severity: Severity::High,
                rule: self.name().to_string(),
                // The alert is about the victim here, so put the destination
                // in the src field the UI shows.
                src: event.dst.to_string(),
                detail: format!(
                    "{count} SYNs from {} sources in {:.0}s",
                    sources.len(),
                    self.window_secs
                ),
                ts: event.ts,
            })
        } else {
            None
        }
    }
}
