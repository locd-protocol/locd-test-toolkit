//! Encoding and decoding utilities

use base64ct::{Base64UrlUnpadded, Encoding};
use locd_core::{Error, Result};

/// Encode bytes to base64url (no padding)
///
/// This is the encoding used for keys and signatures in the Loc'd Protocol
pub fn base64url_encode(data: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(data)
}

/// Decode base64url (no padding)
pub fn base64url_decode(encoded: &str) -> Result<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(encoded)
        .map_err(|e| Error::Decoding(format!("Base64url decode failed: {}", e)))
}

/// Encode bytes to hexadecimal
pub fn hex_encode(data: &[u8]) -> String {
    hex::encode(data)
}

/// Decode hexadecimal string
pub fn hex_decode(encoded: &str) -> Result<Vec<u8>> {
    hex::decode(encoded).map_err(|e| Error::Decoding(format!("Hex decode failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64url_roundtrip() {
        let data = b"Hello, Loc'd Protocol!";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_base64url_no_padding() {
        let data = b"test"; // Would normally need padding
        let encoded = base64url_encode(data);
        assert!(!encoded.contains('='));
    }

    #[test]
    fn test_base64url_url_safe() {
        let data = vec![0xff, 0xfe, 0xfd];
        let encoded = base64url_encode(&data);
        // Should use URL-safe characters (- and _ instead of + and /)
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = b"test data";
        let encoded = hex_encode(data);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_hex_lowercase() {
        let data = vec![0xAB, 0xCD, 0xEF];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "abcdef");
    }

    #[test]
    fn test_invalid_base64url() {
        let result = base64url_decode("invalid!@#$");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_hex() {
        let result = hex_decode("not hex!");
        assert!(result.is_err());
    }

    #[test]
    fn test_known_base64url_vectors() {
        // Test vectors from RFC 4648
        assert_eq!(base64url_encode(b""), "");
        assert_eq!(base64url_encode(b"f"), "Zg");
        assert_eq!(base64url_encode(b"fo"), "Zm8");
        assert_eq!(base64url_encode(b"foo"), "Zm9v");
        assert_eq!(base64url_encode(b"foob"), "Zm9vYg");
        assert_eq!(base64url_encode(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url_encode(b"foobar"), "Zm9vYmFy");
    }
}
