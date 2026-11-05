use anyhow::{Result, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpDatagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

pub fn parse(data: &[u8]) -> Result<UdpDatagram<'_>> {
    if data.len() < 8 {
        bail!("udp datagram too short: {} bytes", data.len());
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let end = len.clamp(8, data.len());
    Ok(UdpDatagram {
        src_port,
        dst_port,
        payload: &data[8..end],
    })
}
