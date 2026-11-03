use anyhow::{Result, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl std::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    }
}

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
pub const ETHERTYPE_ARP: u16 = 0x0806;
const VLAN_TAGS: [u16; 2] = [0x8100, 0x88a8];

#[derive(Debug, Clone, Copy)]
pub struct EthernetFrame<'a> {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: u16,
    pub vlan: Option<u16>,
    pub payload: &'a [u8],
}

pub fn parse(data: &[u8]) -> Result<EthernetFrame<'_>> {
    if data.len() < 14 {
        bail!("ethernet frame too short: {} bytes", data.len());
    }
    let mut dst = [0u8; 6];
    dst.copy_from_slice(&data[0..6]);
    let mut src = [0u8; 6];
    src.copy_from_slice(&data[6..12]);
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = 14;
    let mut vlan = None;

    while VLAN_TAGS.contains(&ethertype) {
        if data.len() < offset + 4 {
            bail!("truncated vlan tag");
        }
        let tag = u16::from_be_bytes([data[offset], data[offset + 1]]);
        vlan = Some(tag & 0x0fff);
        ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
    }

    Ok(EthernetFrame {
        dst: MacAddr(dst),
        src: MacAddr(src),
        ethertype,
        vlan,
        payload: &data[offset..],
    })
}
