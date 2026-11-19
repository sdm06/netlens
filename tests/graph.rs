use netlens::graph::community::label_propagation;
use netlens::graph::layout::force_directed;

#[test]
fn layout_stays_in_bounds() {
    let edges = [(0, 1), (1, 2), (2, 3), (3, 4)];
    let points = force_directed(5, &edges, 50, 800.0, 600.0);
    assert_eq!(points.len(), 5);
    for point in points {
        assert!(point.x >= 10.0 && point.x <= 790.0);
        assert!(point.y >= 10.0 && point.y <= 590.0);
    }
}

#[test]
fn communities_group_connected_nodes() {
    let edges = [(0, 1), (1, 2), (3, 4)];
    let labels = label_propagation(5, &edges, 20);
    assert_eq!(labels[0], labels[1]);
    assert_eq!(labels[1], labels[2]);
    assert_eq!(labels[3], labels[4]);
}
