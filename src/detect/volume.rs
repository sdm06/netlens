use crate::detect::rules::{Alert, Severity};
use crate::flows::stats::Ewma;

#[derive(Debug, Clone)]
pub struct VolumeAnomaly {
    ewma: Ewma,
    threshold: f64,
    warmup: usize,
    seen: usize,
}

impl VolumeAnomaly {
    pub fn new(alpha: f64, threshold: f64, warmup: usize) -> Self {
        Self {
            ewma: Ewma::new(alpha),
            threshold,
            warmup,
            seen: 0,
        }
    }

    pub fn observe(&mut self, bytes: u64, ts: f64) -> Option<Alert> {
        self.seen += 1;
        let z = self.ewma.update(bytes as f64);
        // Give the EWMA a few buckets to settle before trusting its mean.
        if self.seen <= self.warmup || z < self.threshold {
            return None;
        }
        Some(Alert {
            severity: Severity::Medium,
            rule: "volume-anomaly".to_string(),
            src: "network".to_string(),
            detail: format!(
                "bucket {bytes} B is {z:.1} sigma above mean {:.0} B",
                self.ewma.mean()
            ),
            ts,
        })
    }
}
