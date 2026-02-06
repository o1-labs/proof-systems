/// Flip the last character of a base58 string to corrupt the checksum.
pub fn corrupt_last_char(b58: &str) -> String {
    let mut chars: Vec<char> = b58.chars().collect();
    let last = chars.last_mut().unwrap();
    *last = if *last == '1' { '2' } else { '1' };
    chars.into_iter().collect()
}
