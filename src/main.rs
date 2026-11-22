use anyhow::Result;
use clap::{Parser, Subcommand};
use netlens::analysis::{Analyzer, Filters};
use netlens::capture::{self, offline};
use netlens::ui::app::NetLensApp;

#[derive(Parser)]
#[command(
    name = "netlens",
    version,
    about = "Live packet lens: topology map and anomaly detection"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Analyze {
        path: String,
        #[arg(long)]
        json: Option<String>,
        #[arg(long)]
        start: Option<f64>,
        #[arg(long)]
        end: Option<f64>,
        #[arg(long)]
        protocol: Option<u8>,
        #[arg(long)]
        query: Option<String>,
    },
    Interfaces,
    Live {
        interface: String,
        #[arg(long, default_value_t = 10.0)]
        duration: f64,
        #[arg(long)]
        json: Option<String>,
    },
    Demo {
        #[arg(long)]
        json: Option<String>,
    },
    Ui {
        path: Option<String>,
    },
}

// Glue between the capture readers and the analyzer. Keeping it as a struct
// avoids fighting HRTB bounds on a closure with a borrowed packet slice.
struct AnalyzerVisitor<'a> {
    analyzer: &'a mut Analyzer,
}

impl capture::Visitor for AnalyzerVisitor<'_> {
    fn visit(&mut self, ts: f64, linktype: u32, packet: &[u8]) {
        self.analyzer.observe(ts, linktype, packet);
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Analyze {
            path,
            json,
            start,
            end,
            protocol,
            query,
        } => {
            let summary = offline::analyze(&path)?;
            let filters = Filters {
                query: query.unwrap_or_default(),
                protocol,
                min_bytes: 0,
                start,
                end,
            };
            output(&summary.filtered(&filters), json)?;
        }
        Command::Interfaces => {
            let interfaces = capture::live::list_interfaces();
            if interfaces.is_empty() {
                println!("No network interfaces found");
            }
            for interface in interfaces {
                println!("{interface}");
            }
        }
        Command::Live {
            interface,
            duration,
            json,
        } => {
            let mut analyzer = Analyzer::new(format!("live:{interface}"));
            capture::live::capture(
                &interface,
                Some(duration),
                &mut AnalyzerVisitor {
                    analyzer: &mut analyzer,
                },
            )?;
            output(&analyzer.finish(), json)?;
        }
        Command::Demo { json } => output(&offline::demo_summary(), json)?,
        Command::Ui { path } => run_ui(path)?,
    }
    Ok(())
}

fn output(summary: &netlens::analysis::AnalysisSummary, json: Option<String>) -> Result<()> {
    let rendered = serde_json::to_string_pretty(summary)?;
    match json {
        Some(path) => std::fs::write(path, rendered)?,
        None => println!("{rendered}"),
    }
    Ok(())
}

fn run_ui(path: Option<String>) -> Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "NetLens",
        options,
        Box::new(move |cc| Ok(Box::new(NetLensApp::new(cc, path)))),
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(())
}
