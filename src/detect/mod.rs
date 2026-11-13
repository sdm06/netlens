pub mod anomaly;
pub mod dns;
pub mod rules;
pub mod scanner;
pub mod synflood;
pub mod util;
pub mod volume;

use self::dns::DnsTunnelDetector;
use self::rules::{Alert, Event, Rule};
use self::scanner::PortScanDetector;
use self::synflood::SynFloodDetector;
use self::volume::VolumeAnomaly;

#[derive(Debug)]
pub struct DetectorSet {
    pub port_scan: PortScanDetector,
    pub syn_flood: SynFloodDetector,
    pub dns_tunnel: DnsTunnelDetector,
    pub volume: VolumeAnomaly,
}

impl DetectorSet {
    pub fn new() -> Self {
        Self {
            port_scan: PortScanDetector::new(10.0, 20),
            syn_flood: SynFloodDetector::new(5.0, 50),
            dns_tunnel: DnsTunnelDetector::new(60, 3.6, 8),
            volume: VolumeAnomaly::new(0.25, 3.0, 4),
        }
    }

    pub fn observe(&mut self, event: &Event<'_>) -> Option<Alert> {
        self.port_scan
            .observe(event)
            .or_else(|| self.syn_flood.observe(event))
            .or_else(|| self.dns_tunnel.observe(event))
    }

    pub fn observe_volume(&mut self, bytes: u64, ts: f64) -> Option<Alert> {
        self.volume.observe(bytes, ts)
    }
}

impl Default for DetectorSet {
    fn default() -> Self {
        Self::new()
    }
}
