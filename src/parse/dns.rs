pub fn query_name(payload: &[u8]) -> Option<String> {
    if payload.len() < 13 {
        return None;
    }
    let questions = u16::from_be_bytes([payload[4], payload[5]]);
    if questions == 0 {
        return None;
    }
    let mut index = 12;
    let mut labels = Vec::new();
    let mut jumps = 0;
    loop {
        let label_len = *payload.get(index)? as usize;
        if label_len & 0xc0 == 0xc0 {
            let next = *payload.get(index + 1)? as usize;
            index = ((label_len & 0x3f) << 8) | next;
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            continue;
        }
        index += 1;
        if label_len == 0 {
            break;
        }
        let label = payload.get(index..index + label_len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        index += label_len;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}
