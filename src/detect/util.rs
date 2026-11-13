use std::collections::HashMap;

pub fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for character in value.chars() {
        *counts.entry(character).or_insert(0) += 1;
    }
    let total = value.chars().count() as f64;
    counts
        .values()
        .map(|&count| {
            let probability = count as f64 / total;
            -probability * probability.log2()
        })
        .sum()
}

pub fn is_syn(flags: u8) -> bool {
    flags & 0x02 != 0 && flags & 0x10 == 0
}

pub fn label_count(value: &str) -> usize {
    value.split('.').filter(|label| !label.is_empty()).count()
}
