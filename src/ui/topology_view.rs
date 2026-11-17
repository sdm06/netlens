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
    let edges: Vec<(usize, usize)> = topology
        .edges
        .iter()
        .filter_map(|edge| Some((*indices.get(&edge.src)?, *indices.get(&edge.dst)?)))
        .collect();
    let communities = label_propagation(ids.len(), &edges, 30);

    let (rect, _) = ui.allocate_exact_size(ui.available_size(), Sense::hover());
    let iterations = if ids.len() > 100 { 40 } else { 140 };
    let positions = force_directed(
        ids.len(),
        &edges,
        iterations,
        rect.width() as f64,
        rect.height() as f64,
    );
    let painter = ui.painter_at(rect);
    let max_bytes = topology
        .nodes
        .values()
        .map(|node| node.bytes)
        .max()
        .unwrap_or(1)
        .max(1);

    painter.text(
        rect.left_top() + Vec2::new(10.0, 8.0),
        Align2::LEFT_TOP,
        format!(
            "{} nodes · {} edges · {} communities",
            ids.len(),
            topology.edges.len(),
            communities
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
                .len()
        ),
        FontId::proportional(14.0),
        Color32::WHITE,
    );

    for (a, b) in edges {
        let from = Pos2::new(
            rect.left() + positions[a].x as f32,
            rect.top() + positions[a].y as f32,
        );
        let to = Pos2::new(
            rect.left() + positions[b].x as f32,
            rect.top() + positions[b].y as f32,
        );
        painter.line_segment([from, to], Stroke::new(1.0, Color32::from_gray(80)));
    }

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
        painter.circle_stroke(point, radius, Stroke::new(1.0, Color32::WHITE));
        painter.text(
            point + Vec2::new(radius + 4.0, 0.0),
            Align2::LEFT_CENTER,
            format!("{id} · {} B", node.bytes),
            FontId::monospace(11.0),
            Color32::WHITE,
        );
    }
}
