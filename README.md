# netlens

A packet lens for when a capture file is too big to stare at in Wireshark.

I built `netlens` to scratch an itch: I wanted one small Rust binary that could read a capture, tell me who is talking to whom, and point at the weird bits without making me configure a dashboard stack first. It reads PCAP and PCAPNG, can capture live traffic, aggregates flows, runs a few detection rules, and draws the network as a graph.

## What it does

- Reads classic PCAP (both endians, microsecond and nanosecond timestamps) and PCAPNG.
- Sniffs a live interface with `pnet_datalink` when you have the right privileges.
- Decodes Ethernet (including VLAN tags), IPv4, IPv6 with extension headers, TCP, UDP, and DNS names.
- Groups packets into flows and keeps per-second byte buckets.
- Flags port scans, SYN floods, suspicious DNS queries, and volume spikes.
- Lays out the topology with force-directed placement and colours nodes by community.
- Lets you filter the view by IP, protocol, minimum bytes, and time window.
- Saves reports as JSON so you can reopen them later.

## Running it

```bash
cargo run -- demo
cargo run -- analyze capture.pcap
cargo run -- analyze capture.pcap --json report.json
cargo run -- analyze capture.pcap --query 10.0.0.5 --protocol 6 --start 1 --end 5
cargo run -- ui
cargo run -- ui report.json
```

Live capture needs elevated rights on most systems:

```bash
cargo run -- interfaces
sudo cargo run -- live en0 --duration 20 --json live-report.json
```

In the UI you can type a path and hit **Load**, or just drop a `.pcap`, `.pcapng`, or saved `.json` report onto the window. **Save JSON** writes the current view out.

## Detection rules

| Rule | What sets it off |
| ---- | ---------------- |
| `port-scan` | 20+ distinct host:port targets from one source in 10 seconds |
| `syn-flood` | 50+ SYNs aimed at one destination in 5 seconds |
| `dns-tunnel` | 3+ long or high-entropy DNS queries from the same source |
| `volume-anomaly` | A one-second byte bucket 3 sigma above the EWMA mean |

These are deliberately simple. They are meant to be useful signs, not a full IDS.

## Layout

```
analysis.rs    analyzer, summary, filters, time buckets
capture/       pcap, pcapng, live capture, report loading
parse/         wire-format decoders
flows/         flow table and EWMA statistics
detect/        rules and the detector set
graph/         topology, layout, communities
ui/            egui dashboard
```

## Things I might add next

- TCP stream reassembly and HTTP parsing.
- ASN or geo enrichment for the topology nodes.
- Saved filter presets and alert suppression.
- GraphML export.

## Checks

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Licensed under MIT.
