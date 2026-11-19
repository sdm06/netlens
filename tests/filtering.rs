use netlens::analysis::Filters;
use netlens::capture::offline;

#[test]
fn filters_by_query_and_protocol() {
    let summary = offline::demo_summary();
    let by_ip = summary.filtered(&Filters {
        query: "10.0.0.5".to_string(),
        ..Filters::default()
    });
    assert_eq!(by_ip.flows, 2);
    assert!(
        by_ip
            .all_flows
            .iter()
            .all(|flow| flow.src == "10.0.0.5" || flow.dst == "10.0.0.5")
    );

    let udp = summary.filtered(&Filters {
        protocol: Some(17),
        ..Filters::default()
    });
    assert_eq!(udp.flows, 1);
    assert_eq!(udp.top_talkers[0].dst_port, 53);

    let filtered = summary.filtered(&Filters {
        min_bytes: 30_000,
        ..Filters::default()
    });
    assert_eq!(filtered.flows, 2);
}

#[test]
fn report_roundtrip() {
    let summary = offline::demo_summary();
    let json = serde_json::to_string(&summary).unwrap();
    let restored: netlens::analysis::AnalysisSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.packets, summary.packets);
    assert_eq!(restored.flows, summary.flows);
    assert_eq!(restored.alerts.len(), summary.alerts.len());
}
