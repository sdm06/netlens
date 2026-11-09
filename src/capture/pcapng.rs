use anyhow::{Result, bail};

use super::Visitor;

const SECTION_HEADER: u32 = 0x0a0d_0d0a;
const INTERFACE_DESCRIPTION: u32 = 1;
const SIMPLE_PACKET: u32 = 3;
const ENHANCED_PACKET: u32 = 6;
const INTERFACE_STATISTICS: u32 = 5;
const BYTE_ORDER_MAGIC: u32 = 0x1a2b_3c4d;
const OPTION_TS_RESOLUTION: u16 = 9;
const OPTION_TS_OFFSET: u16 = 14;
const OPTION_END: u16 = 0;

#[derive(Debug, Clone, Copy)]
struct Interface {
    linktype: u32,
    divisor: f64,
    offset: i64,
}

fn read_u16(bytes: &[u8], le: bool) -> u16 {
    let arr = [bytes[0], bytes[1]];
    if le {
        u16::from_le_bytes(arr)
    } else {
        u16::from_be_bytes(arr)
    }
}

fn read_u32(bytes: &[u8], le: bool) -> u32 {
    let arr = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if le {
        u32::from_le_bytes(arr)
    } else {
        u32::from_be_bytes(arr)
    }
}

fn read_i64(bytes: &[u8], le: bool) -> i64 {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(bytes);
    if le {
        i64::from_le_bytes(arr)
    } else {
        i64::from_be_bytes(arr)
    }
}

fn options(body: &[u8], fixed: usize, le: bool) -> impl Iterator<Item = (u16, &[u8])> {
    let mut offset = fixed;
    std::iter::from_fn(move || {
        if offset + 4 > body.len() {
            return None;
        }
        let code = read_u16(&body[offset..offset + 2], le);
        let length = read_u16(&body[offset + 2..offset + 4], le) as usize;
        offset += 4;
        if code == OPTION_END {
            return None;
        }
        let end = offset + length;
        if end > body.len() {
            return None;
        }
        let value = &body[offset..end];
        offset = (end + 3) & !3;
        Some((code, value))
    })
}

fn resolution(value: u8) -> f64 {
    if value & 0x80 != 0 {
        2f64.powi((value & 0x7f) as i32)
    } else {
        10f64.powi(value as i32)
    }
}

pub fn read(data: &[u8], visitor: &mut impl Visitor) -> Result<()> {
    let mut le = true;
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut offset = 0;

    while offset + 12 <= data.len() {
        let is_section = data[offset..offset + 4] == [0x0a, 0x0d, 0x0d, 0x0a];
        if is_section {
            let marker = [
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
            ];
            if u32::from_le_bytes(marker) == BYTE_ORDER_MAGIC {
                le = true;
            } else if u32::from_be_bytes(marker) == BYTE_ORDER_MAGIC {
                le = false;
            } else {
                bail!("invalid pcapng byte-order magic");
            }
        }
        let block_type = read_u32(&data[offset..offset + 4], le);
        let length = read_u32(&data[offset + 4..offset + 8], le) as usize;
        if length < 12 || offset + length > data.len() {
            break;
        }
        if block_type != SECTION_HEADER {
            let trailing = read_u32(&data[offset + length - 4..offset + length], le);
            if trailing as usize != length {
                bail!("pcapng block length mismatch");
            }
        }
        let body = &data[offset + 8..offset + length - 4];

        match block_type {
            SECTION_HEADER => {
                if body.len() < 4 {
                    bail!("short pcapng section header");
                }
                let marker = [body[0], body[1], body[2], body[3]];
                le = u32::from_le_bytes(marker) == BYTE_ORDER_MAGIC;
                if !le && u32::from_be_bytes(marker) != BYTE_ORDER_MAGIC {
                    bail!("invalid pcapng byte-order magic");
                }
                interfaces.clear();
            }
            INTERFACE_DESCRIPTION => {
                if body.len() < 8 {
                    bail!("short interface description block");
                }
                let mut interface = Interface {
                    linktype: read_u16(&body[0..2], le) as u32,
                    divisor: 1_000_000.0,
                    offset: 0,
                };
                for (code, value) in options(body, 8, le) {
                    match code {
                        OPTION_TS_RESOLUTION if !value.is_empty() => {
                            interface.divisor = resolution(value[0]);
                        }
                        OPTION_TS_OFFSET if value.len() >= 8 => {
                            interface.offset = read_i64(&value[0..8], le);
                        }
                        _ => {}
                    }
                }
                interfaces.push(interface);
            }
            INTERFACE_STATISTICS => {
                if body.len() >= 4 {
                    let id = read_u32(&body[0..4], le) as usize;
                    if let Some(interface) = interfaces.get_mut(id) {
                        for (code, value) in options(body, 4, le) {
                            if code == OPTION_TS_OFFSET && value.len() >= 8 {
                                interface.offset = read_i64(&value[0..8], le);
                            }
                        }
                    }
                }
            }
            ENHANCED_PACKET => {
                if body.len() < 20 {
                    bail!("short enhanced packet block");
                }
                let id = read_u32(&body[0..4], le) as usize;
                let high = read_u32(&body[4..8], le) as u64;
                let low = read_u32(&body[8..12], le) as u64;
                let captured = read_u32(&body[12..16], le) as usize;
                if let Some(interface) = interfaces.get(id)
                    && body.len() >= 20 + captured
                {
                    let ticks = ((high << 32) | low) as f64;
                    let ts = ticks / interface.divisor + interface.offset as f64;
                    visitor.visit(ts, interface.linktype, &body[20..20 + captured]);
                }
            }
            SIMPLE_PACKET => {
                if body.len() < 4 {
                    bail!("short simple packet block");
                }
                let original = read_u32(&body[0..4], le) as usize;
                if let Some(interface) = interfaces.first() {
                    let captured = original.min(body.len() - 4);
                    visitor.visit(0.0, interface.linktype, &body[4..4 + captured]);
                }
            }
            _ => {}
        }
        offset += length;
    }
    Ok(())
}
