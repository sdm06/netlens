#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

pub fn force_directed(
    node_count: usize,
    edges: &[(usize, usize)],
    iterations: usize,
    width: f64,
    height: f64,
    padding: f64,
) -> Vec<Point> {
    if node_count == 0 {
        return Vec::new();
    }

    let width = width.max(1.0);
    let height = height.max(1.0);
    let center = Point {
        x: width / 2.0,
        y: height / 2.0,
    };
    if node_count == 1 {
        return vec![center];
    }

    let padding = padding.clamp(0.0, (width.min(height) / 2.0 - 1.0).max(0.0));
    let radius = (width.min(height) / 3.0).max(1.0);
    let mut positions: Vec<Point> = (0..node_count)
        .map(|index| {
            let angle = index as f64 * 2.399_963_229_728_653;
            let spread = ((index as f64 + 1.0) / node_count as f64).sqrt();
            Point {
                x: center.x + radius * spread * angle.cos(),
                y: center.y + radius * spread * angle.sin(),
            }
        })
        .collect();

    let area = width * height;
    let k = (area / node_count as f64).sqrt().max(1.0);
    let mut temperature = (width.min(height) / 8.0).max(1.0);

    // Repulsion and edge attraction run in free space. Clamping here would
    // pile nodes onto the border, so the result is fitted to the view later.
    for _ in 0..iterations {
        let mut displacement = vec![Point::default(); node_count];

        for i in 0..node_count {
            for j in (i + 1)..node_count {
                let dx = positions[i].x - positions[j].x;
                let dy = positions[i].y - positions[j].y;
                let distance = (dx * dx + dy * dy).sqrt().max(0.01);
                let force = k * k / distance;
                let fx = dx / distance * force;
                let fy = dy / distance * force;
                displacement[i].x += fx;
                displacement[i].y += fy;
                displacement[j].x -= fx;
                displacement[j].y -= fy;
            }
        }

        for &(a, b) in edges {
            if a >= node_count || b >= node_count || a == b {
                continue;
            }
            let dx = positions[a].x - positions[b].x;
            let dy = positions[a].y - positions[b].y;
            let distance = (dx * dx + dy * dy).sqrt().max(0.01);
            let force = distance * distance / k;
            let fx = dx / distance * force;
            let fy = dy / distance * force;
            displacement[a].x -= fx;
            displacement[a].y -= fy;
            displacement[b].x += fx;
            displacement[b].y += fy;
        }

        for i in 0..node_count {
            displacement[i].x += (center.x - positions[i].x) * 0.02;
            displacement[i].y += (center.y - positions[i].y) * 0.02;

            let dx = displacement[i].x;
            let dy = displacement[i].y;
            let distance = (dx * dx + dy * dy).sqrt().max(0.01);
            let step = temperature.min(distance);
            positions[i].x += dx / distance * step;
            positions[i].y += dy / distance * step;
        }

        temperature *= 0.95;
    }

    let min_x = positions
        .iter()
        .fold(f64::INFINITY, |min, point| min.min(point.x));
    let max_x = positions
        .iter()
        .fold(f64::NEG_INFINITY, |max, point| max.max(point.x));
    let min_y = positions
        .iter()
        .fold(f64::INFINITY, |min, point| min.min(point.y));
    let max_y = positions
        .iter()
        .fold(f64::NEG_INFINITY, |max, point| max.max(point.y));
    let span_x = (max_x - min_x).max(1.0);
    let span_y = (max_y - min_y).max(1.0);
    let available_width = (width - 2.0 * padding).max(1.0);
    let available_height = (height - 2.0 * padding).max(1.0);

    for point in &mut positions {
        point.x = padding + (point.x - min_x) / span_x * available_width;
        point.y = padding + (point.y - min_y) / span_y * available_height;
    }

    positions
}
