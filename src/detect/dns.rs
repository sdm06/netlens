use std::collections::HashMap;

use super::rules::{Alert, Event, Rule, Severity};
use super::util::{label_count, shannon_entropy};

#[derive(Debug)]
pub struct DnsTunnelDetector {
    min_name_len: usize,
    min_entropy: f64,
    max_labels: usize,
    offenders: HashMap<std::net::IpAddr, usize>,
}

impl DnsTunnelDetector {
    pub fn new(min_name_len: usize, min_entropy: f64, max_labels: usize) -> Self {
        Self {
            min_name_len,
            min_entropy,
            max_labels,
            offenders: HashMap::new(),
        }
    }
}

impl Rule for DnsTunnelDetector {
    fn name(&self) -> &str {
        "dns-tunnel"
    }

    fn observe(&mut self, event: &Event<'_>) -> Option<Alert> {
        let name = event.dns_name?;
        let score = shannon_entropy(name);
        let labels = label_count(name);
        let suspicious = name.len() >= self.min_name_len
            || score >= self.min_entropy
            || labels >= self.max_labels;
        if !suspicious {
            return None;
        }
        let count = self.offenders.entry(event.src).or_insert(0);
        *count += 1;
        if *count < 3 {
            return None;
        }
        let short: String = name.chars().take(48).collect();
        Some(Alert {
            severity: Severity::Medium,
            rule: self.name().to_string(),
            src: event.src.to_string(),
            detail: format!(
                "repeated suspicious query '{short}' (len {}, entropy {score:.2}, {labels} labels)",
                name.len()
            ),
            ts: event.ts,
        })
    }
}
