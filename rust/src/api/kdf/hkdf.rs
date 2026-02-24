use flutter_rust_bridge::frb;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::api::error::CryptoError;

/// One-shot HKDF-SHA256: extract + expand in a single call.
/// Returns `output_len` bytes of derived key material.
///
/// # Security
/// Input key material (`ikm`, `salt`) is zeroed before the function returns.
/// The caller is responsible for zeroizing the returned `Vec<u8>`.
#[frb(sync)]
pub fn hkdf_derive(
    mut ikm: Vec<u8>,
    mut salt: Option<Vec<u8>>,
    info: Vec<u8>,
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    if output_len == 0 {
        ikm.zeroize();
        salt.zeroize();
        return Err(CryptoError::KdfFailed(String::from("Invalid OKM length")));
    }

    let salt_ref = salt.as_ref().map(Vec::as_slice);
    let hk = Hkdf::<Sha256>::new(salt_ref, &ikm);
    ikm.zeroize();
    salt.zeroize();

    let mut buf = vec![0u8; output_len];
    hk.expand(&info, &mut buf)
        .map_err(|_| CryptoError::KdfFailed(String::from("Invalid OKM length")))?;
    Ok(buf)
}

/// HKDF-Extract: produce a pseudorandom key (PRK) from input key material.
///
/// # Security
/// Input key material (`ikm`, `salt`) is zeroed before the function returns.
/// The caller is responsible for zeroizing the returned PRK.
#[frb(sync)]
pub fn hkdf_extract(
    mut ikm: Vec<u8>,
    mut salt: Option<Vec<u8>>,
) -> Result<Vec<u8>, CryptoError> {
    let salt_ref = salt.as_ref().map(Vec::as_slice);
    let (prk, _) = Hkdf::<Sha256>::extract(salt_ref, &ikm);
    ikm.zeroize();
    salt.zeroize();
    Ok(prk[..].to_vec())
}

/// HKDF-Expand: expand a PRK into `output_len` bytes of derived key material.
///
/// # Security
/// The input PRK is zeroed before the function returns.
/// The caller is responsible for zeroizing the returned key material.
pub fn hkdf_expand(
    mut prk: Vec<u8>,
    info: Vec<u8>,
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let hk = Hkdf::<Sha256>::from_prk(&prk);
    prk.zeroize();
    let hk = hk.map_err(|_| CryptoError::KdfFailed(String::from("PRK is not large enough")))?;

    let mut buf = vec![0u8; output_len];
    hk.expand(&info, &mut buf)
        .map_err(|_| CryptoError::KdfFailed(String::from("Invalid OKM length")))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    #[test]
    fn derive_returns_requested_length() {
        let ikm = b"test-key-material".to_vec();
        let info = b"m-security".to_vec();
        for len in [16, 32, 48, 64] {
            let out = hkdf_derive(ikm.clone(), None, info.clone(), len).unwrap();
            assert_eq!(out.len(), len);
        }
    }

    #[test]
    fn derive_zero_length_returns_error() {
        let res = hkdf_derive(b"ikm".into(), None, b"info".into(), 0);
        assert!(res.is_err());
    }

    #[test]
    fn derive_exceeding_max_length_returns_error() {
        // SHA-256 HKDF max = 255 * 32 = 8160
        let res = hkdf_derive(b"ikm".into(), None, b"info".into(), 8200);
        assert!(res.is_err());
    }

    #[test]
    fn derive_is_deterministic() {
        let ikm = b"same-key".to_vec();
        let salt = Some(b"same-salt".to_vec());
        let info = b"same-info".to_vec();
        let a = hkdf_derive(ikm.clone(), salt.clone(), info.clone(), 32).unwrap();
        let b = hkdf_derive(ikm, salt, info, 32).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_info_produces_different_keys() {
        let ikm = b"shared-ikm".to_vec();
        let salt = Some(b"salt".to_vec());
        let k1 = hkdf_derive(ikm.clone(), salt.clone(), b"context-a".into(), 32).unwrap();
        let k2 = hkdf_derive(ikm, salt, b"context-b".into(), 32).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn extract_then_expand_matches_derive() {
        let ikm = b"key-material".to_vec();
        let salt = Some(b"salt".to_vec());
        let info = b"info".to_vec();

        let one_shot = hkdf_derive(ikm.clone(), salt.clone(), info.clone(), 32).unwrap();
        let prk = hkdf_extract(ikm, salt).unwrap();
        let two_step = hkdf_expand(prk, info, 32).unwrap();
        assert_eq!(one_shot, two_step);
    }

    #[test]
    fn empty_salt_works() {
        let res = hkdf_derive(b"ikm".into(), None, b"info".into(), 32);
        assert!(res.is_ok());
        assert_eq!(res.unwrap().len(), 32);
    }

    // RFC 5869 Test Case 1 (HKDF-SHA256)
    #[test]
    fn rfc5869_test_case_1() {
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = Some(hex("000102030405060708090a0b0c"));
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let expected = hex(
            "3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865",
        );
        let result = hkdf_derive(ikm, salt, info, 42).unwrap();
        assert_eq!(result, expected);
    }

    // RFC 5869 Test Case 2 (long inputs)
    #[test]
    fn rfc5869_test_case_2() {
        let ikm = hex(
            "000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f\
             303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
        );
        let salt = Some(hex(
            "606162636465666768696a6b6c6d6e6f\
             707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f\
             909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        ));
        let info = hex(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
             c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
             e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        );
        let expected = hex(
            "b11e398dc80327a1c8e7f78c596a4934\
             4f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09\
             da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f\
             1d87",
        );
        let result = hkdf_derive(ikm, salt, info, 82).unwrap();
        assert_eq!(result, expected);
    }

    // RFC 5869 Test Case 3 (empty salt and info)
    #[test]
    fn rfc5869_test_case_3() {
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let info = vec![];
        let expected = hex(
            "8da4e775a563c18f715f802a063c5a31\
             b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        );
        let result = hkdf_derive(ikm, None, info, 42).unwrap();
        assert_eq!(result, expected);
    }
}
