use anyhow::{Result, bail};

use super::Visitor;

const MAGIC_MICRO_LE: u32 = 0xa1b2_c3d4;
const MAGIC_NANO_LE: u32 = 0xa1b2_3c4d;

pub fn read(data: &[u8], visitor: &mut impl Visitor) -> Result<()> {
    if data.len() < 24 {
        bail!("pcap file too short");
    }
    let magic = [data[0], data[1], data[2], data[3]];
    let le = u32::from_le_bytes(magic);
    let be = u32::from_be_bytes(magic);
    let (little_endian, divisor) = if le == MAGIC_MICRO_LE {
        (true, 1_000_000.0)
    } else if le == MAGIC_NANO_LE {
        (true, 1_000_000_000.0)
    } else if be == MAGIC_MICRO_LE {
        (false, 1_000_000.0)
    } else if be == MAGIC_NANO_LE {
        (false, 1_000_000_000.0)
    } else {
        bail!("unrecognized pcap magic");
    };
    let linktype = read_u32(&data[20..24], little_endian);
    let mut offset = 24;

    while offset + 16 <= data.len() {
        let header = &data[offset..offset + 16];
        let seconds = read_u32(&header[0..4], little_endian) as f64;
        let fraction = read_u32(&header[4..8], little_endian) as f64;
        let captured = read_u32(&header[8..12], little_endian) as usize;
        offset += 16;
        if offset + captured > data.len() {
            break;
        }
        visitor.visit(
            seconds + fraction / divisor,
            linktype,
            &data[offset..offset + captured],
        );
        offset += captured;
    }
    Ok(())
}

fn read_u32(bytes: &[u8], little_endian: bool) -> u32 {
    let arr = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if little_endian {
        u32::from_le_bytes(arr)
    } else {
        u32::from_be_bytes(arr)
    }
}
