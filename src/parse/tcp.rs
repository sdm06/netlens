use anyhow::{Result, bail};

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

pub fn parse(data: &[u8]) -> Result<TcpSegment<'_>> {
    if data.len() < 20 {
        bail!("tcp segment too short: {} bytes", data.len());
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let header_len = (data[12] >> 4) as usize * 4;
    if header_len < 20 || data.len() < header_len {
        bail!("invalid tcp header length");
    }
    Ok(TcpSegment {
        src_port,
        dst_port,
        seq,
        ack,
        flags: data[13],
        payload: &data[header_len..],
    })
}
