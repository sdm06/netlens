use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use pnet_datalink::{Channel, Config, interfaces};

use super::Visitor;

pub fn list_interfaces() -> Vec<String> {
    interfaces()
        .into_iter()
        .map(|interface| {
            let description = interface.description;
            if description.is_empty() {
                interface.name
            } else {
                format!("{} ({description})", interface.name)
            }
        })
        .collect()
}

fn timestamp() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |duration| duration.as_secs_f64())
}

// Raw sockets are noisy about permissions, so surface a useful message here
// rather than letting the error bubble up as a bare io error.
pub fn capture(
    interface: &str,
    duration_secs: Option<f64>,
    visitor: &mut impl Visitor,
) -> Result<()> {
    let target = interfaces()
        .into_iter()
        .find(|candidate| candidate.name == interface || candidate.description == interface);
    let Some(target) = target else {
        bail!(
            "interface '{interface}' not found; run `netlens interfaces` to list available devices"
        );
    };

    let channel = pnet_datalink::channel(&target, Config::default())
        .map_err(|error| anyhow::anyhow!("cannot open {interface}: {error}"))?;
    let Channel::Ethernet(_sender, mut receiver) = channel else {
        bail!("interface {interface} does not provide ethernet frames");
    };

    let started = Instant::now();
    loop {
        if duration_secs.is_some_and(|limit| started.elapsed().as_secs_f64() >= limit) {
            break;
        }
        match receiver.next() {
            Ok(packet) => visitor.visit(timestamp(), 1, packet),
            Err(error) => bail!("capture error on {interface}: {error}"),
        }
    }
    Ok(())
}
