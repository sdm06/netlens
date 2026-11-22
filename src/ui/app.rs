use crate::analysis::{AnalysisSummary, Filters};
use crate::capture::{self, offline};
use eframe::egui;

use super::{charts, topology_view};

#[derive(PartialEq, Eq)]
enum Tab {
    Dashboard,
    Topology,
}

pub struct NetLensApp {
    summary: AnalysisSummary,
    filters: Filters,
    tab: Tab,
    path: String,
    save_path: String,
    status: String,
}

impl NetLensApp {
    pub fn new(_cc: &eframe::CreationContext<'_>, path: Option<String>) -> Self {
        let (summary, status) = match path {
            Some(path) => match capture::analyze_file(&path) {
                Ok(summary) => (summary, format!("Loaded {path}")),
                Err(error) => (
                    offline::demo_summary(),
                    format!("Could not load {path}: {error}"),
                ),
            },
            None => (
                offline::demo_summary(),
                "Demo data: drop a .pcap, .pcapng or report .json file".to_string(),
            ),
        };
        Self {
            summary,
            filters: Filters::default(),
            tab: Tab::Dashboard,
            path: String::new(),
            save_path: "netlens-report.json".to_string(),
            status,
        }
    }

    fn load_path(&mut self, path: String) {
        let result = if path.ends_with(".json") {
            capture::load_summary(&path)
        } else {
            capture::analyze_file(&path)
        };
        match result {
            Ok(summary) => {
                self.status = format!("Loaded {path}");
                self.summary = summary;
                self.filters = Filters::default();
            }
            Err(error) => self.status = format!("Could not load {path}: {error}"),
        }
    }

    fn save_report(&mut self) {
        match serde_json::to_string_pretty(&self.summary) {
            Ok(json) => match std::fs::write(&self.save_path, json) {
                Ok(()) => self.status = format!("Saved {}", self.save_path),
                Err(error) => self.status = format!("Save failed: {error}"),
            },
            Err(error) => self.status = format!("Serialize failed: {error}"),
        }
    }
}

impl eframe::App for NetLensApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Dropping a capture is the fastest way to get from a file to a view.
        let dropped = ctx.input(|input| input.raw.dropped_files.clone());
        if let Some(path) = dropped.first().and_then(|file| file.path.clone()) {
            self.load_path(path.to_string_lossy().into_owned());
        }

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Dashboard, "Dashboard");
                ui.selectable_value(&mut self.tab, Tab::Topology, "Topology");
                ui.separator();
                ui.label("File:");
                ui.add(egui::TextEdit::singleline(&mut self.path).desired_width(240.0));
                if ui.button("Load").clicked() {
                    self.load_path(self.path.clone());
                }
                if ui.button("Demo").clicked() {
                    self.summary = offline::demo_summary();
                    self.filters = Filters::default();
                    self.status = "Demo data".to_string();
                }
                ui.separator();
                ui.label("Report:");
                ui.add(egui::TextEdit::singleline(&mut self.save_path).desired_width(160.0));
                if ui.button("Save JSON").clicked() {
                    self.save_report();
                }
            });
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.label(&self.status);
        });

        let filtered = self.summary.filtered(&self.filters);
        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Dashboard => charts::dashboard(ui, &self.summary, &filtered, &mut self.filters),
            Tab::Topology => topology_view::show(ui, &filtered),
        });
    }
}
