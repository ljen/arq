/// Converts an array of u8 into a string of hex.
pub fn convert_to_hex_string(array: &[u8]) -> String {
    array.iter().map(|a| format!("{:02x}", a)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_to_hex_string() {
        // Test mixed values
        let data = vec![12, 34, 11, 56, 78, 92];
        assert_eq!(convert_to_hex_string(&data), "0c220b384e5c");

        // Test empty array
        assert_eq!(convert_to_hex_string(&[]), "");

        // Test single byte
        assert_eq!(convert_to_hex_string(&[0]), "00");
        assert_eq!(convert_to_hex_string(&[15]), "0f");
        assert_eq!(convert_to_hex_string(&[16]), "10");
        assert_eq!(convert_to_hex_string(&[255]), "ff");

        // Test boundary values and leading zeros
        assert_eq!(convert_to_hex_string(&[0, 1, 2, 3]), "00010203");
        assert_eq!(convert_to_hex_string(&[252, 253, 254, 255]), "fcfdfeff");

        // Test full range of a few values
        let data2: Vec<u8> = (0..=15).collect();
        assert_eq!(convert_to_hex_string(&data2), "000102030405060708090a0b0c0d0e0f");
    }
}
