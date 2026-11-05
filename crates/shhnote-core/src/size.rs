const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

// Sizes are written with a unit so nobody has to count digits: 100B, 64K, 10M, 1G
// (powers of 1024, a trailing B after the unit letter is fine). Bare numbers are refused.
pub fn parse_size(value: &str) -> Result<u64, String> {
    let value = value.trim();
    let digits = value.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    let unit = &value[digits.len()..];
    let multiplier = match unit.to_ascii_uppercase().as_str() {
        "B" => 1,
        "K" | "KB" => KIB,
        "M" | "MB" => MIB,
        "G" | "GB" => GIB,
        "" => return Err("needs a unit: B, K, M or G (for example 10M)".to_string()),
        _ => return Err(format!("unknown unit {unit:?}, use B, K, M or G")),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err("must be a whole number followed by B, K, M or G".to_string());
    }
    let number: u64 = digits.parse().map_err(|_| "number too large".to_string())?;
    number
        .checked_mul(multiplier)
        .ok_or_else(|| "number too large".to_string())
}

// The reverse of `parse_size`, using the largest unit that divides the value exactly.
pub fn format_size(bytes: u64) -> String {
    for (unit, size) in [("G", GIB), ("M", MIB), ("K", KIB)] {
        if bytes >= size && bytes.is_multiple_of(size) {
            return format!("{}{unit}", bytes / size);
        }
    }
    format!("{bytes}B")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_take_a_unit() {
        assert_eq!(parse_size("100B"), Ok(100));
        assert_eq!(parse_size("64K"), Ok(64 * KIB));
        assert_eq!(parse_size("10M"), Ok(10 * MIB));
        assert_eq!(parse_size("1G"), Ok(GIB));
        assert_eq!(parse_size(" 2mb "), Ok(2 * MIB));
        assert!(parse_size("2097152").is_err());
        assert!(parse_size("M").is_err());
        assert!(parse_size("1.5M").is_err());
        assert!(parse_size("-1M").is_err());
        assert!(parse_size("1T").is_err());
        assert!(parse_size("99999999999999999999G").is_err());
    }

    #[test]
    fn sizes_format_with_the_largest_exact_unit() {
        assert_eq!(format_size(64 * KIB), "64K");
        assert_eq!(format_size(4 * GIB), "4G");
        assert_eq!(format_size(1500), "1500B");
        assert_eq!(format_size(0), "0B");
    }
}
