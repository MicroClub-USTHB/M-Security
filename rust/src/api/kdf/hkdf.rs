use flutter_rust_bridge::frb;
use hkdf::{Hkdf, InvalidLength};
use sha2::Sha256;

use crate::{api::error::CryptoError, core::secret::SecretBuffer};

/// Derive a key using a [`Hkdf::<Sha256>`]. This internally does the extraction and expand into the
/// OKM. You can retreive the resulting key from the [`SecretBuffer`], which assured to contain
/// `output_len` bytes.
#[frb(sync)]
pub fn hkdf_derive(
    ikm: Vec<u8>,
    salt: Option<Vec<u8>>,
    info: Vec<u8>,
    output_len: usize,
) -> Result<SecretBuffer, CryptoError> {
    if (output_len == 0) {
        return Err(CryptoError::KdfFailed(String::from("Invalid OKM length")));
    }

    let salt = salt.as_ref().map(Vec::as_slice);
    let hk = Hkdf::<Sha256>::new(salt, &ikm);
    let mut buf = vec![0u8; output_len];
    hk.expand(&info, &mut buf)
        .map_err(|_| CryptoError::KdfFailed(String::from("Invalid OKM length")))?;
    Ok(SecretBuffer::new(buf))
}

/// Extract a pseudo-random key (PRK) using a [`Hdfk::<Sha256>`]. This is the first step of the
/// key-deriving process and you generally should just generate a final key using [`hkdf_derive`].
#[frb(sync)]
pub fn hkdf_extract(ikm: Vec<u8>, salt: Option<Vec<u8>>) -> Result<SecretBuffer, CryptoError> {
    let salt = salt.as_ref().map(Vec::as_slice);
    let (prk, _) = Hkdf::<Sha256>::extract(salt, &ikm);
    let prk = prk[..].to_vec();
    Ok(SecretBuffer::new(prk))
}

/// Expand an OKM (final key) from a PRK+info. This is the second step of the key-deriving process,
/// you should do this only when you generated a good-enough separate PRK using [`hkdf_extract`],
/// and want to start generating keys from it.
///
/// The result key from the [`SecretBuffer`] is assured to contain `output_len` bytes.
pub fn hkdf_expand(
    prk: Vec<u8>,
    info: Vec<u8>,
    output_len: usize,
) -> Result<SecretBuffer, CryptoError> {
    let hk = Hkdf::<Sha256>::from_prk(&prk)
        .map_err(|_| CryptoError::KdfFailed(String::from("PRK is not large enough")))?;
    let mut buf = vec![0u8; output_len];
    hk.expand(&info, &mut buf)
        .map_err(|_| CryptoError::KdfFailed(String::from("Invalid OKM length")))?;
    Ok(SecretBuffer::new(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creating_key_matches_output_len() {
        let ikm = b"bWljcm9jbHVi"; // "microclub" in base64
        let salt = b"c29tZXNhbHQ"; // "somesalt" in base64 no-pad
        let info = b"m-security";
        let hash = hkdf_derive(ikm.into(), Some(salt.into()), info.into(), 32).unwrap();
        let inner_len = hash.as_bytes().len();
        assert_eq!(inner_len, 32);
    }

    #[test]
    fn test_creating_key_with_size_zero() {
        let ikm = b"bWljcm9jbHVi"; // "microclub" in base64
        let salt = b"c29tZXNhbHQ"; // "somesalt" in base64 no-pad
        let info = b"m-security";
        let res = hkdf_derive(ikm.into(), Some(salt.into()), info.into(), 0);
        assert!(res.is_err(), "Key size is invalid (=8160)");
    }

    #[test]
    fn test_creating_key_with_size_8160() {
        let ikm = b"bWljcm9jbHVi"; // "microclub" in base64
        let salt = b"c29tZXNhbHQ"; // "somesalt" in base64 no-pad
        let info = b"m-security";
        let res = hkdf_derive(ikm.into(), Some(salt.into()), info.into(), 8200);
        assert!(res.is_err(), "Key size is invalid (>8160)");
    }
}
