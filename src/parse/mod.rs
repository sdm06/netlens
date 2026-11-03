pub mod dns;
pub mod ethernet;
pub mod ip;
pub mod tcp;
pub mod udp;

use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Transport<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

pub fn transport(protocol: u8, payload: &[u8]) -> Result<Option<Transport<'_>>> {
    match protocol {
        6 => {
            let segment = tcp::parse(payload)?;
            Ok(Some(Transport {
                src_port: segment.src_port,
                dst_port: segment.dst_port,
                payload: segment.payload,
            }))
        }
        17 => {
            let datagram = udp::parse(payload)?;
            Ok(Some(Transport {
                src_port: datagram.src_port,
                dst_port: datagram.dst_port,
                payload: datagram.payload,
            }))
        }
        _ => Ok(None),
    }
}
