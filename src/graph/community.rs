use std::cmp::Reverse;
use std::collections::HashMap;

pub fn label_propagation(
    node_count: usize,
    edges: &[(usize, usize)],
    iterations: usize,
) -> Vec<usize> {
    let mut labels: Vec<usize> = (0..node_count).collect();
    let mut adjacency = vec![Vec::new(); node_count];
    for &(a, b) in edges {
        if a < node_count && b < node_count {
            adjacency[a].push(b);
            adjacency[b].push(a);
        }
    }

    for _ in 0..iterations {
        let mut changed = false;
        for node in 0..node_count {
            if adjacency[node].is_empty() {
                continue;
            }
            let mut counts: HashMap<usize, usize> = HashMap::new();
            for &neighbor in &adjacency[node] {
                *counts.entry(labels[neighbor]).or_insert(0) += 1;
            }
            let best = counts
                .into_iter()
                .max_by_key(|(label, count)| (*count, Reverse(*label)))
                .map(|(label, _)| label)
                .expect("counts is non-empty");
            if best != labels[node] {
                labels[node] = best;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    labels
}
