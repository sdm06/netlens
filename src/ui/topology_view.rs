use std::collections::HashMap;

use crate::analysis::AnalysisSummary;
use crate::graph::community::label_propagation;
use crate::graph::layout::force_directed;
use eframe::egui::{Align2, Color32, FontId, Pos2, Sense, Stroke, Vec2};

const PALETTE: [Color32; 6] = [
    Color32::from_rgb(80, 160, 255),
    Color32::from_rgb(120, 220, 150),
    Color32::from_rgb(255, 180, 90),
    Color32::from_rgb(210, 130, 255),
    Color32::from_rgb(90, 220, 220),
    Color32::from_rgb(255, 120, 160),
];

pub fn show(ui: &mut egui::Ui, summary: &AnalysisSummary) {
    let topology = &summary.topology;
    let mut ids: Vec<&String> = topology.nodes.keys().collect();
    ids.sort();
    let indices: HashMap<&String, usize> = ids
        .iter()
        .enumerate()
        .map(|(index, id)| (*id, index))
        .collect();

    let mut edge_totals: HashMap<(usize, usize), (u64, u64)> = HashMap::new();
    for edge in &topology.edges {
        let Some(&a) = indices.get(&edge.src) else {
            continue;
        };
        let Some(&b) = indices.get(&edge.dst) else {
            continue;
        };
        if a == b {
            continue;
        }
        let key = (a.min(b), a.max(b));
        let totals = edge_totals.entry(key).or_insert((0, 0));
        totals.0 += edge.packets;
        totals.1 += edge.bytes;
    }
    let layout_edges: Vec<(usize, usize)> = edge_totals.keys().copied().collect();
    let communities = label_propagation(ids.len(), &layout_edges, 30);

    let max_bytes = topology
        .nodes
        .values()
        .map(|node| node.bytes)
        .max()
        .unwrap_or(1)
        .max(1);
    let padding = 26.0_f64;
    let (rect, _) = ui.allocate_exact_size(ui.available_size(), Sense::hover());
    let iterations = if ids.len() > 100 { 40 } else { 140 };
    let positions = force_directed(
        ids.len(),
        &layout_edges,
        iterations,
        rect.width() as f64,
        rect.height() as f64,
        padding,
    );
    let painter = ui.painter_at(rect);

    painter.text(
        rect.left_top() + Vec2::new(10.0, 8.0),
        Align2::LEFT_TOP,
        format!(
            "{} nodes · {} links · {} communities",
            ids.len(),
            edge_totals.len(),
            communities
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
                .len()
        ),
        FontId::proportional(14.0),
        Color32::WHITE,
    );

    let max_edge_bytes = edge_totals
        .values()
        .map(|(_, bytes)| *bytes)
        .max()
        .unwrap_or(1)
        .max(1);
    for (&(a, b), &(_, bytes)) in &edge_totals {
        let from = Pos2::new(
            rect.left() + positions[a].x as f32,
            rect.top() + positions[a].y as f32,
        );
        let to = Pos2::new(
            rect.left() + positions[b].x as f32,
            rect.top() + positions[b].y as f32,
        );
        let width = 1.0 + 2.0 * (bytes as f64 / max_edge_bytes as f64).sqrt() as f32;
        painter.line_segment([from, to], Stroke::new(width, Color32::from_gray(90)));
    }

    let show_labels = ids.len() <= 60;
    for (index, id) in ids.iter().enumerate() {
        let point = Pos2::new(
            rect.left() + positions[index].x as f32,
            rect.top() + positions[index].y as f32,
        );
        let node = &topology.nodes[*id];
        let scale = (node.bytes as f64 / max_bytes as f64).sqrt() as f32;
        let radius = 6.0 + 12.0 * scale;
        let color = PALETTE[communities[index] % PALETTE.len()];
        painter.circle_filled(point, radius, color);
        painter.circle_stroke(point, radius, Stroke::new(1.0_f32, Color32::WHITE));
        if show_labels || node.bytes as f64 * 10.0 >= max_bytes as f64 {
            painter.text(
                point + Vec2::new(radius + 4.0, 0.0),
                Align2::LEFT_CENTER,
                format!("{id} · {} B", node.bytes),
                FontId::monospace(11.0),
                Color32::WHITE,
            );
        }
    }
}
