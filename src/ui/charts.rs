use crate::analysis::{AnalysisSummary, Filters};
use eframe::egui::{self, Color32};
use egui_plot::{Bar, BarChart, Line, Plot, PlotPoints};

pub fn dashboard(
    ui: &mut egui::Ui,
    full: &AnalysisSummary,
    summary: &AnalysisSummary,
    filters: &mut Filters,
) {
    ui.heading("Overview");
    ui.horizontal_wrapped(|ui| {
        ui.label(format!("{} packets", summary.packets));
        ui.separator();
        ui.label(format!("{} bytes", summary.bytes));
        ui.separator();
        ui.label(format!("{} flows", summary.flows));
        ui.separator();
        ui.label(format!("{} alerts", summary.alerts.len()));
        if let (Some(start), Some(end)) = (summary.start_ts, summary.end_ts) {
            ui.separator();
            ui.label(format!("{:.1}s span", end - start));
        }
    });

    ui.separator();
    ui.heading("Filters");
    ui.horizontal_wrapped(|ui| {
        ui.label("Search:");
        ui.add(
            egui::TextEdit::singleline(&mut filters.query)
                .hint_text("IP address")
                .desired_width(180.0),
        );

        let selected = match filters.protocol {
            Some(protocol) => protocol.to_string(),
            None => "All".to_string(),
        };
        let mut protocols: Vec<u8> = full.protocols.keys().copied().collect();
        protocols.sort_unstable();
        egui::ComboBox::from_label("Protocol")
            .selected_text(selected)
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut filters.protocol, None, "All");
                for protocol in protocols {
                    ui.selectable_value(
                        &mut filters.protocol,
                        Some(protocol),
                        protocol.to_string(),
                    );
                }
            });

        let max_bytes = full
            .all_flows
            .iter()
            .map(|flow| flow.bytes)
            .max()
            .unwrap_or(1);
        ui.add(egui::Slider::new(&mut filters.min_bytes, 0..=max_bytes).text("min bytes"));
    });

    let start = full.start_ts.unwrap_or(0.0);
    let end = full.end_ts.unwrap_or(start + 1.0).max(start + 0.001);
    let range = start..=end;
    ui.horizontal_wrapped(|ui| {
        ui.label("Time window:");
        let mut from = filters.start.unwrap_or(start);
        if ui
            .add(egui::Slider::new(&mut from, range.clone()).text("from"))
            .changed()
        {
            filters.start = Some(from);
        }
        if ui.button("clear start").clicked() {
            filters.start = None;
        }
        let mut to = filters.end.unwrap_or(end);
        if ui
            .add(egui::Slider::new(&mut to, range).text("to"))
            .changed()
        {
            filters.end = Some(to);
        }
        if ui.button("clear end").clicked() {
            filters.end = None;
        }
    });

    ui.separator();
    ui.heading("Traffic over time");
    let points: Vec<[f64; 2]> = summary
        .timeseries
        .iter()
        .map(|bucket| [bucket.start, bucket.bytes as f64])
        .collect();
    Plot::new("traffic")
        .height(190.0)
        .x_axis_label("seconds")
        .y_axis_label("bytes")
        .show(ui, |plot| {
            plot.line(Line::new(PlotPoints::new(points)).name("bytes"));
        });

    ui.separator();
    ui.heading("Protocols");
    let bars: Vec<Bar> = summary
        .protocols
        .iter()
        .enumerate()
        .map(|(index, (_, count))| Bar::new(index as f64, *count as f64))
        .collect();
    Plot::new("protocols").height(120.0).show(ui, |plot| {
        plot.bar_chart(BarChart::new(bars).name("flows"));
    });

    ui.separator();
    ui.heading("Top talkers");
    egui::Grid::new("top-talkers")
        .num_columns(6)
        .striped(true)
        .show(ui, |ui| {
            ui.strong("Source");
            ui.strong("Destination");
            ui.strong("Proto");
            ui.strong("Packets");
            ui.strong("Bytes");
            ui.strong("Window");
            ui.end_row();
            for flow in &summary.top_talkers {
                ui.label(&flow.src);
                ui.label(&flow.dst);
                ui.label(flow.protocol.to_string());
                ui.label(flow.packets.to_string());
                ui.label(flow.bytes.to_string());
                ui.label(format!("{:.1}-{:.1}", flow.first_ts, flow.last_ts));
                ui.end_row();
            }
        });

    ui.separator();
    ui.heading("Alerts");
    if summary.alerts.is_empty() {
        ui.label("No alerts in this view.");
    }
    for alert in &summary.alerts {
        let color = match alert.severity {
            crate::detect::rules::Severity::Low => Color32::from_gray(180),
            crate::detect::rules::Severity::Medium => Color32::from_rgb(255, 196, 96),
            crate::detect::rules::Severity::High => Color32::from_rgb(255, 128, 112),
        };
        ui.horizontal(|ui| {
            ui.colored_label(color, format!("{:?}", alert.severity));
            ui.label(format!("{} · {} · {}", alert.rule, alert.src, alert.detail));
        });
    }
}
