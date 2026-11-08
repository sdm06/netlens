pub mod live;
pub mod offline;
pub mod pcap;
pub mod pcapng;

use std::fs;

use anyhow::{Context, Result, bail};

use crate::analysis::{AnalysisSummary, Analyzer};

pub trait Visitor {
    fn visit(&mut self, ts: f64, linktype: u32, packet: &[u8]);
}

impl<F> Visitor for F
where
    F: FnMut(f64, u32, &[u8]),
{
    fn visit(&mut self, ts: f64, linktype: u32, packet: &[u8]) {
        self(ts, linktype, packet)
    }
}

pub fn format(data: &[u8]) -> &'static str {
    if data.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        "pcapng"
    } else {
        "pcap"
    }
}

pub fn read_file(path: &str, visitor: &mut impl Visitor) -> Result<()> {
    let data = fs::read(path).with_context(|| format!("reading {path}"))?;
    match format(&data) {
        "pcapng" => pcapng::read(&data, visitor),
        _ => pcap::read(&data, visitor),
    }
}

pub fn read_bytes(data: &[u8], visitor: &mut impl Visitor) -> Result<()> {
    match format(data) {
        "pcapng" => pcapng::read(data, visitor),
        _ => pcap::read(data, visitor),
    }
}

struct AnalyzerVisitor<'a> {
    analyzer: &'a mut Analyzer,
}

impl Visitor for AnalyzerVisitor<'_> {
    fn visit(&mut self, ts: f64, linktype: u32, packet: &[u8]) {
        self.analyzer.observe(ts, linktype, packet);
    }
}

pub fn analyze_file(path: &str) -> Result<AnalysisSummary> {
    let mut analyzer = Analyzer::new(path);
    read_file(
        path,
        &mut AnalyzerVisitor {
            analyzer: &mut analyzer,
        },
    )?;
    Ok(analyzer.finish())
}

pub fn analyze_bytes(source: &str, data: &[u8]) -> Result<AnalysisSummary> {
    let mut analyzer = Analyzer::new(source);
    read_bytes(
        data,
        &mut AnalyzerVisitor {
            analyzer: &mut analyzer,
        },
    )?;
    Ok(analyzer.finish())
}

pub fn load_summary(path: &str) -> Result<AnalysisSummary> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    let summary: AnalysisSummary = serde_json::from_str(&text).context("invalid NetLens report")?;
    if summary.timeseries.is_empty() && summary.all_flows.is_empty() {
        bail!("report contains no flows or timeseries");
    }
    Ok(summary)
}
