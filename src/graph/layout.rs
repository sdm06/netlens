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
) -> Vec<Point> {
    if node_count == 0 {
        return Vec::new();
    }
    let mut positions: Vec<Point> = (0..node_count)
        .map(|index| {
            let angle = index as f64 * 2.399_963_229_728_653;
            let radius = (index as f64).sqrt() * 20.0 + 10.0;
            Point {
                x: width / 2.0 + radius * angle.cos(),
                y: height / 2.0 + radius * angle.sin(),
            }
        })
        .collect();

    let area = width * height;
    let k = (area / node_count as f64).sqrt();
    let mut temperature = width / 10.0;

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
            if a >= node_count || b >= node_count {
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
            let dx = displacement[i].x;
            let dy = displacement[i].y;
            let distance = (dx * dx + dy * dy).sqrt().max(0.01);
            let step = temperature.min(distance);
            positions[i].x = (positions[i].x + dx / distance * step).clamp(10.0, width - 10.0);
            positions[i].y = (positions[i].y + dy / distance * step).clamp(10.0, height - 10.0);
        }

        temperature *= 0.95;
    }

    positions
}
