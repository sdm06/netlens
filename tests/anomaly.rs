use netlens::detect::anomaly::AnomalyDetector;
use netlens::flows::stats::Ewma;

#[test]
fn ewma_scores_spike() {
    let mut ewma = Ewma::new(0.2);
    for _ in 0..20 {
        ewma.update(10.0);
    }
    let z = ewma.update(100.0);
    assert!(z > 2.0, "z was {z}");
}

#[test]
fn detector_reports_large_deviation() {
    let mut detector = AnomalyDetector::new(0.2, 2.0);
    for _ in 0..20 {
        assert!(detector.observe(10.0).is_none());
    }
    assert!(detector.observe(100.0).is_some());
}
