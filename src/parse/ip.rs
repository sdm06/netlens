use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail};

#[derive(Debug, Clone, Copy)]
pub struct IpPacket<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub payload: &'a [u8],
    pub total_len: u16,
    pub fragment_offset: u16,
}

pub fn parse_v4(data: &[u8]) -> Result<IpPacket<'_>> {
    if data.len() < 20 {
        bail!("ipv4 packet too short: {} bytes", data.len());
    }
    let header_len = (data[0] & 0x0f) as usize * 4;
    if header_len < 20 || data.len() < header_len {
        bail!("invalid ipv4 header length");
    }
    let total_len = u16::from_be_bytes([data[2], data[3]]);
    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let fragment_offset = u16::from_be_bytes([data[6], data[7]]) & 0x1fff;
    let end = (total_len as usize).clamp(header_len, data.len());
    Ok(IpPacket {
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        protocol: data[9],
        payload: &data[header_len..end],
        total_len,
        fragment_offset,
    })
}

pub fn parse_v6(data: &[u8]) -> Result<IpPacket<'_>> {
    if data.len() < 40 {
        bail!("ipv6 packet too short: {} bytes", data.len());
    }
    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let mut src = [0u8; 16];
    src.copy_from_slice(&data[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&data[24..40]);
    let end = (40 + payload_len).min(data.len());
    let mut offset = 40;
    let mut protocol = data[6];
    let mut fragment_offset = 0;

    while matches!(protocol, 0 | 43 | 44 | 60) {
        if offset + 8 > end {
            bail!("truncated ipv6 extension header");
        }
        let next = data[offset];
        let length = data[offset + 1] as usize * 8 + 8;
        if protocol == 44 && offset + 8 <= end {
            fragment_offset = u16::from_be_bytes([data[offset + 4], data[offset + 5]]) >> 3;
        }
        offset += length;
        if offset > end {
            bail!("ipv6 extension header exceeds payload");
        }
        protocol = next;
    }

    Ok(IpPacket {
        src: IpAddr::V6(Ipv6Addr::from(src)),
        dst: IpAddr::V6(Ipv6Addr::from(dst)),
        protocol,
        payload: &data[offset.min(end)..end],
        total_len: (40 + payload_len).min(u16::MAX as usize) as u16,
        fragment_offset,
    })
}
