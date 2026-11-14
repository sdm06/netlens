use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::flows::aggregator::FlowStats;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub src: String,
    pub dst: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Topology {
    pub nodes: HashMap<String, Node>,
    pub edges: Vec<Edge>,
}

impl Topology {
    pub fn from_flows(flows: &[FlowStats]) -> Self {
        let mut topology = Topology::default();
        for flow in flows {
            let source = topology
                .nodes
                .entry(flow.src.clone())
                .or_insert_with(|| Node {
                    id: flow.src.clone(),
                    packets: 0,
                    bytes: 0,
                });
            source.packets += flow.packets;
            source.bytes += flow.bytes;

            let destination = topology
                .nodes
                .entry(flow.dst.clone())
                .or_insert_with(|| Node {
                    id: flow.dst.clone(),
                    packets: 0,
                    bytes: 0,
                });
            destination.packets += flow.packets;
            destination.bytes += flow.bytes;

            topology.edges.push(Edge {
                src: flow.src.clone(),
                dst: flow.dst.clone(),
                packets: flow.packets,
                bytes: flow.bytes,
            });
        }
        topology
    }
}
