/// Extract the second-level domain from a FQDN.
/// e.g. "sub.evil.example.com" -> "example.com"
/// e.g. "example.com" -> "example.com"
pub fn extract_second_level_domain(domain: &str) -> String {
    let domain = domain.trim_end_matches('.');
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        domain.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sld_basic() {
        assert_eq!(extract_second_level_domain("example.com"), "example.com");
    }

    #[test]
    fn test_sld_subdomain() {
        assert_eq!(
            extract_second_level_domain("sub.evil.example.com"),
            "example.com"
        );
    }

    #[test]
    fn test_sld_trailing_dot() {
        assert_eq!(
            extract_second_level_domain("example.com."),
            "example.com"
        );
    }

    #[test]
    fn test_sld_single() {
        assert_eq!(extract_second_level_domain("localhost"), "localhost");
    }
}
