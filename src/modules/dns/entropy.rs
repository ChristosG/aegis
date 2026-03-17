/// Calculate Shannon entropy of a string.
/// Higher entropy indicates more randomness (potential DGA).
/// Normal domains: ~2.5-3.0, DGA domains: ~3.5-4.5+
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let len = s.len() as f64;
    let mut freq = [0u32; 256];

    for &byte in s.as_bytes() {
        freq[byte as usize] += 1;
    }

    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_normal_domain() {
        // Normal domains have lower entropy
        let ent = shannon_entropy("google");
        assert!(ent < 3.0, "google entropy: {}", ent);

        let ent = shannon_entropy("facebook");
        assert!(ent < 3.5, "facebook entropy: {}", ent);
    }

    #[test]
    fn test_entropy_dga_domain() {
        // DGA-like random strings have higher entropy
        let ent = shannon_entropy("xk3jf9qm2nl8pw");
        assert!(ent > 3.5, "DGA entropy: {}", ent);

        let ent = shannon_entropy("a1b2c3d4e5f6g7h8");
        assert!(ent > 3.0, "Mixed entropy: {}", ent);
    }

    #[test]
    fn test_entropy_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn test_entropy_single_char() {
        assert_eq!(shannon_entropy("aaaa"), 0.0);
    }

    #[test]
    fn test_entropy_max() {
        // All unique characters = maximum entropy for that length
        let ent = shannon_entropy("abcdefgh");
        assert!(ent == 3.0, "8 unique chars entropy: {}", ent);
    }
}
