//! Argon2id password hashing with platform presets and PHC format output.

use std::sync::atomic::{AtomicBool, Ordering};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::core::error::CryptoError;

/// Largest PHC string [`argon2id_verify`] will look at, in bytes.
pub const MAX_VERIFY_PHC_BYTES: usize = 1024;
/// Largest password [`argon2id_verify`] will look at, in UTF-8 bytes.
pub const MAX_VERIFY_PASSWORD_BYTES: usize = 1024;
/// Largest memory cost accepted from a PHC string, in KiB.
pub const MAX_VERIFY_MEMORY_KIB: u32 = 262_144;
/// Largest iteration count accepted from a PHC string.
pub const MAX_VERIFY_ITERATIONS: u32 = 4;
/// Largest lane count accepted from a PHC string.
pub const MAX_VERIFY_LANES: u32 = 8;
/// Smallest decoded salt accepted from a PHC string, in bytes.
pub const MIN_VERIFY_SALT_BYTES: usize = 8;
/// Decoded salt ceiling, in bytes. The PHC parser caps the encoded salt at 64
/// characters, so 48 decoded bytes is the largest that reaches a verifier.
pub const MAX_VERIFY_SALT_BYTES: usize = 64;
/// Smallest decoded hash output accepted from a PHC string, in bytes.
pub const MIN_VERIFY_OUTPUT_BYTES: usize = 16;
/// Largest decoded hash output accepted from a PHC string, in bytes.
pub const MAX_VERIFY_OUTPUT_BYTES: usize = 64;

const SUPPORTED_ALGORITHM: &str = "argon2id";
const SUPPORTED_VERSION_FIELD: &str = "v=19";
const SUPPORTED_VERSION: u32 = 0x13;

// Argon2 needs eight KiB blocks per lane, so this is the crate's own floor
// rather than an added policy bound.
const KIB_PER_LANE: u64 = 8;

static VERIFICATION_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

fn policy_error(reason: impl Into<String>) -> CryptoError {
    CryptoError::Argon2PolicyViolation(reason.into())
}

fn malformed_error(reason: impl Into<String>) -> CryptoError {
    CryptoError::InvalidParameter(reason.into())
}

/// Serializes verification so one caller cannot be starved of memory by another.
///
/// `Drop` hands the permit back on every return path, including the error ones.
/// A panic needs no handling: the release profile aborts, and nothing in the
/// crate catches an unwind to carry on while the permit is still held.
struct VerificationPermit;

impl VerificationPermit {
    fn try_acquire() -> Option<Self> {
        VERIFICATION_IN_FLIGHT
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for VerificationPermit {
    fn drop(&mut self) {
        VERIFICATION_IN_FLIGHT.store(false, Ordering::Release);
    }
}

/// Wipes the Rust-owned copy of a verification password when it goes out of scope.
///
/// It borrows rather than owns so a test can keep the allocation alive and read
/// it back after the wipe instead of inspecting freed memory.
struct PasswordGuard<'a> {
    password: &'a mut String,
}

impl<'a> PasswordGuard<'a> {
    fn new(password: &'a mut String) -> Self {
        Self { password }
    }

    fn as_bytes(&self) -> &[u8] {
        self.password.as_bytes()
    }
}

impl Drop for PasswordGuard<'_> {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

fn scan_decimal(name: &str, value: &str) -> Result<u32, CryptoError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(policy_error(format!(
            "parameter {name:?} is not a decimal number"
        )));
    }

    // A leading zero would give one work factor two spellings, and the PHC
    // parser rejects it further down, so reject it here where the error is typed.
    if value.len() > 1 && value.starts_with('0') {
        return Err(policy_error(format!(
            "parameter {name:?} has a leading zero"
        )));
    }

    value
        .parse::<u32>()
        .map_err(|_| policy_error(format!("parameter {name:?} does not fit in 32 bits")))
}

fn scan_work_factors(field: &str) -> Result<(u32, u32, u32), CryptoError> {
    // The PHC parser reads a field without '=' as the salt, which would leave
    // the work factors at library defaults instead of the ones we checked.
    if !field.contains('=') {
        return Err(policy_error("PHC string carries no Argon2 parameters"));
    }

    let (mut m_cost, mut t_cost, mut p_cost) = (None, None, None);

    for pair in field.split(',') {
        let (name, value) = pair
            .split_once('=')
            .ok_or_else(|| policy_error(format!("malformed parameter {pair:?}")))?;

        let slot = match name {
            "m" => &mut m_cost,
            "t" => &mut t_cost,
            "p" => &mut p_cost,
            other => return Err(policy_error(format!("unsupported parameter {other:?}"))),
        };

        // The PHC parser keeps duplicates and the verifier takes the last one,
        // while a reader checking the first would see a different work factor.
        if slot.is_some() {
            return Err(policy_error(format!("duplicate parameter {name:?}")));
        }

        *slot = Some(scan_decimal(name, value)?);
    }

    let m_cost = m_cost.ok_or_else(|| policy_error("missing parameter \"m\""))?;
    let t_cost = t_cost.ok_or_else(|| policy_error("missing parameter \"t\""))?;
    let p_cost = p_cost.ok_or_else(|| policy_error("missing parameter \"p\""))?;

    if !(1..=MAX_VERIFY_LANES).contains(&p_cost) {
        return Err(policy_error(format!(
            "lanes {p_cost} outside 1..={MAX_VERIFY_LANES}"
        )));
    }

    if !(1..=MAX_VERIFY_ITERATIONS).contains(&t_cost) {
        return Err(policy_error(format!(
            "iterations {t_cost} outside 1..={MAX_VERIFY_ITERATIONS}"
        )));
    }

    if m_cost > MAX_VERIFY_MEMORY_KIB {
        return Err(policy_error(format!(
            "memory {m_cost} KiB above {MAX_VERIFY_MEMORY_KIB} KiB"
        )));
    }

    if u64::from(m_cost) < u64::from(p_cost) * KIB_PER_LANE {
        return Err(policy_error(format!(
            "memory {m_cost} KiB below the {KIB_PER_LANE} KiB each of {p_cost} lanes needs"
        )));
    }

    Ok((m_cost, t_cost, p_cost))
}

fn scan_b64_len(label: &str, field: &str) -> Result<usize, CryptoError> {
    if !field
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    {
        return Err(malformed_error(format!(
            "Invalid PHC string: {label} is not unpadded B64"
        )));
    }

    let whole = field.len() / 4 * 3;
    match field.len() % 4 {
        0 => Ok(whole),
        2 => Ok(whole + 1),
        3 => Ok(whole + 2),
        // Unpadded B64 never leaves a single trailing character.
        _ => Err(malformed_error(format!(
            "Invalid PHC string: {label} has an impossible B64 length"
        ))),
    }
}

/// Reads the work factors and encoded lengths out of a PHC string.
///
/// Every value comes back as a checked integer, so nothing here builds a
/// verifier or reserves an Argon2 block.
fn scan_phc(phc_hash: &str) -> Result<(u32, u32, u32, usize, usize), CryptoError> {
    if phc_hash.len() > MAX_VERIFY_PHC_BYTES {
        return Err(policy_error(format!(
            "PHC string is {} bytes, above {MAX_VERIFY_PHC_BYTES}",
            phc_hash.len()
        )));
    }

    let mut fields = phc_hash.split('$');

    if fields.next() != Some("") {
        return Err(malformed_error(
            "Invalid PHC string: missing leading separator",
        ));
    }

    let algorithm = fields
        .next()
        .ok_or_else(|| malformed_error("Invalid PHC string: missing algorithm field"))?;
    if algorithm != SUPPORTED_ALGORITHM {
        return Err(policy_error(format!(
            "unsupported algorithm identifier {algorithm:?}"
        )));
    }

    // Only the canonical spelling of version 19 is accepted, so no other
    // encoding of the same number can slip past as a different version.
    let version = fields
        .next()
        .ok_or_else(|| policy_error("missing version field"))?;
    if version != SUPPORTED_VERSION_FIELD {
        return Err(policy_error(format!(
            "unsupported version field {version:?}"
        )));
    }

    let work_factors = fields
        .next()
        .ok_or_else(|| policy_error("missing parameter field"))?;
    let (m_cost, t_cost, p_cost) = scan_work_factors(work_factors)?;

    let salt = fields
        .next()
        .ok_or_else(|| policy_error("missing salt field"))?;
    let salt_bytes = scan_b64_len("salt", salt)?;
    if !(MIN_VERIFY_SALT_BYTES..=MAX_VERIFY_SALT_BYTES).contains(&salt_bytes) {
        return Err(policy_error(format!(
            "salt of {salt_bytes} bytes outside {MIN_VERIFY_SALT_BYTES}..={MAX_VERIFY_SALT_BYTES}"
        )));
    }

    let output = fields
        .next()
        .ok_or_else(|| policy_error("missing hash output field"))?;
    let output_bytes = scan_b64_len("hash output", output)?;
    if !(MIN_VERIFY_OUTPUT_BYTES..=MAX_VERIFY_OUTPUT_BYTES).contains(&output_bytes) {
        return Err(policy_error(format!(
            "hash output of {output_bytes} bytes outside {MIN_VERIFY_OUTPUT_BYTES}..={MAX_VERIFY_OUTPUT_BYTES}"
        )));
    }

    if fields.next().is_some() {
        return Err(malformed_error("Invalid PHC string: trailing data"));
    }

    Ok((m_cost, t_cost, p_cost, salt_bytes, output_bytes))
}

/// Validates a PHC string and returns the parameters the verifier will consume.
///
/// The hand-written scan produces the typed policy errors, then the PHC parser
/// runs and both readings are compared. A verifier is never built from a string
/// the two disagree about.
fn parse_within_policy(phc_hash: &str) -> Result<(Params, PasswordHash<'_>), CryptoError> {
    let (m_cost, t_cost, p_cost, salt_bytes, output_bytes) = scan_phc(phc_hash)?;

    let parsed = PasswordHash::new(phc_hash)
        .map_err(|e| CryptoError::InvalidParameter(format!("Invalid PHC string: {}", e)))?;

    if parsed.algorithm.as_str() != SUPPORTED_ALGORITHM {
        return Err(policy_error(format!(
            "unsupported algorithm identifier {:?}",
            parsed.algorithm.as_str()
        )));
    }

    if parsed.version != Some(SUPPORTED_VERSION) {
        return Err(policy_error("unsupported Argon2 version"));
    }

    // `Params::try_from` is what the verifier itself calls, so this is the exact
    // parameter set the Argon2 run would use.
    let params = Params::try_from(&parsed)
        .map_err(|e| policy_error(format!("unsupported Argon2 parameters: {}", e)))?;

    if params.m_cost() != m_cost
        || params.t_cost() != t_cost
        || params.p_cost() != p_cost
        || params.output_len() != Some(output_bytes)
    {
        return Err(policy_error(
            "PHC parameters disagree with the validated policy",
        ));
    }

    let salt = parsed
        .salt
        .ok_or_else(|| policy_error("missing salt field"))?;
    let mut decoded_salt = [0u8; MAX_VERIFY_SALT_BYTES];
    let decoded_len = salt
        .decode_b64(&mut decoded_salt)
        .map_err(|e| malformed_error(format!("Invalid PHC salt: {}", e)))?
        .len();

    if decoded_len != salt_bytes {
        return Err(policy_error("PHC salt disagrees with the validated policy"));
    }

    Ok((params, parsed))
}

fn verify_within_policy(phc_hash: &str, password: &PasswordGuard<'_>) -> Result<(), CryptoError> {
    let password_bytes = password.as_bytes();
    if password_bytes.len() > MAX_VERIFY_PASSWORD_BYTES {
        return Err(policy_error(format!(
            "password is {} bytes, above {MAX_VERIFY_PASSWORD_BYTES}",
            password_bytes.len()
        )));
    }

    let (params, parsed) = parse_within_policy(phc_hash)?;

    // Taken only once the input is inside policy, so a rejected request never
    // makes a legitimate caller wait for a permit it will not use.
    let _permit = VerificationPermit::try_acquire().ok_or(CryptoError::Argon2VerificationBusy)?;

    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .verify_password(password_bytes, &parsed)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Platform-appropriate parameter presets for Argon2id.
pub enum Argon2Preset {
    /// Optimized for mobile devices (64 MiB, 3 iterations, 4 threads).
    Mobile,
    /// Optimized for desktop/server (256 MiB, 4 iterations, 8 threads).
    Desktop,
}

impl Argon2Preset {
    fn params(&self) -> Params {
        match self {
            Self::Mobile => Params::new(64 * 1024, 3, 4, None),
            Self::Desktop => Params::new(256 * 1024, 4, 8, None),
        }
        // SAFETY: These are known-valid parameter combinations
        .expect("valid Argon2 params")
    }
}

/// Hash a password using Argon2id with the given preset.
///
/// Generates a random salt internally and returns a PHC-format string
/// containing the algorithm, parameters, salt, and hash.
pub fn argon2id_hash(password: String, preset: Argon2Preset) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut OsRng);
    let params = preset.params();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CryptoError::HashingFailed(e.to_string()))?;

    Ok(hash.to_string())
}

/// Hash a password using Argon2id with an explicit salt.
///
/// The salt must be valid base64 (no padding), between 1-64 bytes decoded.
/// Returns a PHC-format string.
pub fn argon2id_hash_with_salt(
    password: String,
    salt: String,
    preset: Argon2Preset,
) -> Result<String, CryptoError> {
    let salt = SaltString::from_b64(&salt)
        .map_err(|e| CryptoError::InvalidParameter(format!("Invalid salt: {}", e)))?;
    let params = preset.params();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CryptoError::HashingFailed(e.to_string()))?;

    Ok(hash.to_string())
}

/// Verify a password against an Argon2id PHC hash string.
///
/// The hash must be Argon2id version 19 within the published verification
/// limits, and the password must be at most 1024 UTF-8 bytes. A hash outside
/// those limits returns `Err(CryptoError::Argon2PolicyViolation)`, and one that
/// is not a well-formed PHC string returns `Err(CryptoError::InvalidParameter)`.
/// Both come back before any Argon2 memory is reserved. One verification runs
/// at a time; a caller arriving during another one gets
/// `Err(CryptoError::Argon2VerificationBusy)` rather than waiting.
///
/// Returns `Ok(())` if the password matches, or
/// `Err(CryptoError::AuthenticationFailed)` if it does not.
pub fn argon2id_verify(phc_hash: String, password: String) -> Result<(), CryptoError> {
    let mut password = password;
    let password = PasswordGuard::new(&mut password);

    verify_within_policy(&phc_hash, &password)
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::core::alloc_probe;

    // The permit is process wide, so tests whose outcome depends on holding it
    // must not overlap with each other.
    static VERIFY_SERIAL: Mutex<()> = Mutex::new(());

    fn serialized() -> MutexGuard<'static, ()> {
        VERIFY_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    const B64_ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    const CANONICAL_PARAMS: &str = "m=65536,t=3,p=4";

    // Hashes of VECTOR_PASSWORD produced by the released presets, kept here so
    // the compatibility cases verify shipped output instead of output this run
    // just made. The desktop vector sits on the memory ceiling.
    const VECTOR_PASSWORD: &str = "preset_vector";
    const MOBILE_VECTOR: &str =
        "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$rUYVKsKrcBrgqxhUdNkDIkzdd3Df9gC3RP6cEdFyM8k";
    const DESKTOP_VECTOR: &str =
        "$argon2id$v=19$m=262144,t=4,p=8$c29tZXNhbHQ$vMcxuT3HOzm0fXlb+51TYzxiWAK1mSnVS6PqVB761FI";

    fn b64(bytes: &[u8]) -> String {
        let mut encoded = String::new();

        for chunk in bytes.chunks(3) {
            let packed = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));

            for position in 0..chunk.len() + 1 {
                let index = (packed >> (18 - 6 * position)) as usize & 63;
                encoded.push(char::from(B64_ALPHABET[index]));
            }
        }

        encoded
    }

    fn b64_of_len(decoded_len: usize) -> String {
        b64(&(0..decoded_len).map(|i| i as u8).collect::<Vec<u8>>())
    }

    fn phc(params: &str, salt: &str, output: &str) -> String {
        format!("$argon2id$v=19${params}${salt}${output}")
    }

    fn canonical_phc() -> String {
        phc(CANONICAL_PARAMS, &b64_of_len(16), &b64_of_len(32))
    }

    fn policy_outcome(phc_hash: &str) -> Result<Params, CryptoError> {
        parse_within_policy(phc_hash).map(|(params, _)| params)
    }

    // Rejection cases are checked twice: once against the validator, and once
    // against the exported entry point, so a check inserted between the two
    // cannot change the public verdict while these still pass. Rejected input
    // never takes the permit, so neither call needs serializing.
    fn assert_policy_rejects(case: &str, phc_hash: &str) {
        match policy_outcome(phc_hash) {
            Err(CryptoError::Argon2PolicyViolation(_)) => {}
            other => panic!("{case}: expected a policy violation, got {other:?}"),
        }

        match argon2id_verify(phc_hash.to_string(), "password".into()) {
            Err(CryptoError::Argon2PolicyViolation(_)) => {}
            other => panic!("{case}: exported entry point gave {other:?}"),
        }
    }

    fn assert_malformed(case: &str, phc_hash: &str) {
        match policy_outcome(phc_hash) {
            Err(CryptoError::InvalidParameter(_)) => {}
            other => panic!("{case}: expected an invalid parameter error, got {other:?}"),
        }

        match argon2id_verify(phc_hash.to_string(), "password".into()) {
            Err(CryptoError::InvalidParameter(_)) => {}
            other => panic!("{case}: exported entry point gave {other:?}"),
        }
    }

    fn assert_accepted(case: &str, phc_hash: &str) {
        if let Err(e) = policy_outcome(phc_hash) {
            panic!("{case}: expected acceptance, got {e:?}");
        }
    }

    fn rejected_corpus() -> Vec<String> {
        let salt = b64_of_len(16);
        let output = b64_of_len(32);
        let with_params = |params: &str| phc(params, &salt, &output);

        vec![
            "not_a_phc_string".to_string(),
            "$".repeat(8),
            format!("$argon2i$v=19${CANONICAL_PARAMS}${salt}${output}"),
            format!("$argon2d$v=19${CANONICAL_PARAMS}${salt}${output}"),
            format!("$argon2id$v=16${CANONICAL_PARAMS}${salt}${output}"),
            format!("$argon2id$v=20${CANONICAL_PARAMS}${salt}${output}"),
            format!("$argon2id${CANONICAL_PARAMS}${salt}${output}"),
            with_params("m=262145,t=3,p=4"),
            with_params("m=4294967296,t=3,p=4"),
            with_params("m=99999999999999999999,t=3,p=4"),
            with_params("m=65536,t=5,p=4"),
            with_params("m=65536,t=3,p=9"),
            with_params("m=262144,t=3,p=4294967295"),
            with_params("m=65536,t=3,p=4,m=262144"),
            with_params("m=65536,t=3"),
            with_params("m=65536,t=3,p=4,keyid=Zm9v"),
            with_params("m=abc,t=3,p=4"),
            phc(CANONICAL_PARAMS, &b64_of_len(7), &output),
            phc(CANONICAL_PARAMS, &b64_of_len(65), &output),
            phc(CANONICAL_PARAMS, &salt, &b64_of_len(15)),
            phc(CANONICAL_PARAMS, &salt, &b64_of_len(65)),
            phc(CANONICAL_PARAMS, "", &output),
            phc(CANONICAL_PARAMS, &salt, ""),
            format!("{}$AAAA", canonical_phc()),
            format!(
                "$argon2id$v=19${CANONICAL_PARAMS}${salt}${}",
                "A".repeat(MAX_VERIFY_PHC_BYTES)
            ),
        ]
    }

    fn verify_and_observe_wipe(
        phc_hash: &str,
        password: &str,
    ) -> (Result<(), CryptoError>, Vec<u8>) {
        let mut owned = String::from(password);
        let len = owned.len();

        let outcome = {
            let guard = PasswordGuard::new(&mut owned);
            verify_within_policy(phc_hash, &guard)
        };

        // The wipe clears the length but keeps the allocation, so this reads
        // bytes the test still owns rather than freed memory.
        let observed = unsafe { std::slice::from_raw_parts(owned.as_ptr(), len) }.to_vec();
        (outcome, observed)
    }

    #[test]
    fn test_hash_produces_phc_string() {
        let hash = argon2id_hash("password123".into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");

        // PHC strings start with $argon2id$
        assert!(hash.starts_with("$argon2id$"), "Not a PHC string: {}", hash);
    }

    #[test]
    fn test_hash_contains_preset_params() {
        let hash =
            argon2id_hash("test".into(), Argon2Preset::Mobile).expect("hashing should succeed");

        // Mobile: m=65536 (64*1024), t=3, p=4
        assert!(hash.contains("m=65536"), "Missing memory param: {}", hash);
        assert!(hash.contains("t=3"), "Missing time param: {}", hash);
        assert!(hash.contains("p=4"), "Missing parallelism param: {}", hash);
    }

    #[test]
    fn test_hash_desktop_preset_params() {
        let hash =
            argon2id_hash("test".into(), Argon2Preset::Desktop).expect("hashing should succeed");

        // Desktop: m=262144 (256*1024), t=4, p=8
        assert!(hash.contains("m=262144"), "Missing memory param: {}", hash);
        assert!(hash.contains("t=4"), "Missing time param: {}", hash);
        assert!(hash.contains("p=8"), "Missing parallelism param: {}", hash);
    }

    #[test]
    fn test_verify_correct_password() {
        let _serial = serialized();
        let hash = argon2id_hash("correct_password".into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");

        let result = argon2id_verify(hash, "correct_password".into());
        assert!(result.is_ok(), "Should verify correct password");
    }

    #[test]
    fn test_verify_wrong_password() {
        let _serial = serialized();
        let hash = argon2id_hash("correct_password".into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");

        let result = argon2id_verify(hash, "wrong_password".into());
        assert!(result.is_err(), "Should reject wrong password");

        match result {
            Err(CryptoError::AuthenticationFailed) => {} // expected
            other => panic!("Expected AuthenticationFailed, got {:?}", other),
        }
    }

    #[test]
    fn test_hash_with_salt_deterministic() {
        let salt = "c29tZXNhbHQ"; // "somesalt" in base64 no-pad

        let hash1 = argon2id_hash_with_salt("password".into(), salt.into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");
        let hash2 = argon2id_hash_with_salt("password".into(), salt.into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");

        assert_eq!(
            hash1, hash2,
            "Same password + salt should produce same hash"
        );
    }

    #[test]
    fn test_hash_with_salt_different_passwords() {
        let salt = "c29tZXNhbHQ";

        let hash1 = argon2id_hash_with_salt("password1".into(), salt.into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");
        let hash2 = argon2id_hash_with_salt("password2".into(), salt.into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");

        assert_ne!(
            hash1, hash2,
            "Different passwords should produce different hashes"
        );
    }

    #[test]
    fn test_hash_with_salt_verify_roundtrip() {
        let _serial = serialized();
        let salt = "c29tZXNhbHQ";

        let hash = argon2id_hash_with_salt("mypassword".into(), salt.into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");

        assert!(argon2id_verify(hash.clone(), "mypassword".into()).is_ok());
        assert!(argon2id_verify(hash, "notmypassword".into()).is_err());
    }

    #[test]
    fn test_random_salt_uniqueness() {
        let hash1 = argon2id_hash("same_password".into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");
        let hash2 = argon2id_hash("same_password".into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");

        // Random salts make each hash unique
        assert_ne!(hash1, hash2, "Random salts should produce different hashes");
    }

    #[test]
    fn test_invalid_phc_string() {
        let result = argon2id_verify("not_a_phc_string".into(), "password".into());
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidParameter(_)) => {} // expected
            other => panic!("Expected InvalidParameter, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_salt() {
        let result = argon2id_hash_with_salt(
            "password".into(),
            "!!!invalid!!!".into(),
            Argon2Preset::Mobile,
        );
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidParameter(_)) => {} // expected
            other => panic!("Expected InvalidParameter, got {:?}", other),
        }
    }

    #[test]
    fn test_empty_password_hashes() {
        let _serial = serialized();
        // Empty password is valid — Argon2id should handle it
        let hash =
            argon2id_hash(String::new(), Argon2Preset::Mobile).expect("empty password should hash");
        assert!(hash.starts_with("$argon2id$"));
        assert!(argon2id_verify(hash, String::new()).is_ok());
    }

    #[test]
    fn phc_length_boundary_flips_at_the_ceiling() {
        let base = canonical_phc();

        for target in [MAX_VERIFY_PHC_BYTES - 1, MAX_VERIFY_PHC_BYTES] {
            let padded = format!("{base}${}", "A".repeat(target - base.len() - 1));
            assert_eq!(padded.len(), target);
            // Inside the ceiling the string is still read, and rejected for the
            // extra field rather than for its size.
            assert_malformed(&format!("{target}-byte PHC string"), &padded);
        }

        let target = MAX_VERIFY_PHC_BYTES + 1;
        let padded = format!("{base}${}", "A".repeat(target - base.len() - 1));
        assert_eq!(padded.len(), target);

        match policy_outcome(&padded) {
            Err(CryptoError::Argon2PolicyViolation(reason)) => {
                assert!(reason.contains("1025 bytes"), "unexpected reason: {reason}");
            }
            other => panic!("expected a length policy violation, got {other:?}"),
        }

        assert_policy_rejects("1025-byte PHC string", &padded);
    }

    #[test]
    fn password_length_boundary_flips_at_the_ceiling() {
        let _serial = serialized();

        for len in [MAX_VERIFY_PASSWORD_BYTES - 1, MAX_VERIFY_PASSWORD_BYTES] {
            let password = "a".repeat(len);
            assert_eq!(password.len(), len);

            match argon2id_verify(MOBILE_VECTOR.into(), password) {
                Err(CryptoError::AuthenticationFailed) => {}
                other => {
                    panic!("{len}-byte password: expected an authentication failure, got {other:?}")
                }
            }
        }

        match argon2id_verify(
            MOBILE_VECTOR.into(),
            "a".repeat(MAX_VERIFY_PASSWORD_BYTES + 1),
        ) {
            Err(CryptoError::Argon2PolicyViolation(reason)) => {
                assert!(reason.contains("1025 bytes"), "unexpected reason: {reason}");
            }
            other => panic!("expected a length policy violation, got {other:?}"),
        }
    }

    #[test]
    fn password_ceiling_counts_utf8_bytes_not_characters() {
        let password = "€".repeat(512);

        assert_eq!(password.chars().count(), 512);
        assert_eq!(password.len(), 1536);

        match argon2id_verify(MOBILE_VECTOR.into(), password) {
            Err(CryptoError::Argon2PolicyViolation(reason)) => {
                assert!(reason.contains("1536 bytes"), "unexpected reason: {reason}");
            }
            other => panic!("expected a length policy violation, got {other:?}"),
        }
    }

    #[test]
    fn salt_length_boundaries() {
        let output = b64_of_len(32);

        assert_policy_rejects(
            "7-byte salt",
            &phc(CANONICAL_PARAMS, &b64_of_len(7), &output),
        );
        assert_accepted(
            "8-byte salt",
            &phc(CANONICAL_PARAMS, &b64_of_len(8), &output),
        );
        assert_accepted(
            "9-byte salt",
            &phc(CANONICAL_PARAMS, &b64_of_len(9), &output),
        );
        assert_policy_rejects(
            "65-byte salt",
            &phc(CANONICAL_PARAMS, &b64_of_len(65), &output),
        );

        // 63 and 64 decoded bytes sit inside the stated ceiling but need more
        // than the 64 encoded characters the PHC parser takes, so they are
        // rejected there instead. Neither reaches a verifier.
        for len in [63, 64] {
            assert_malformed(
                &format!("{len}-byte salt"),
                &phc(CANONICAL_PARAMS, &b64_of_len(len), &output),
            );
        }
    }

    #[test]
    fn output_length_boundaries() {
        let salt = b64_of_len(16);

        assert_policy_rejects(
            "15-byte output",
            &phc(CANONICAL_PARAMS, &salt, &b64_of_len(15)),
        );

        for len in [16, 17, 63, 64] {
            assert_accepted(
                &format!("{len}-byte output"),
                &phc(CANONICAL_PARAMS, &salt, &b64_of_len(len)),
            );
        }

        assert_policy_rejects(
            "65-byte output",
            &phc(CANONICAL_PARAMS, &salt, &b64_of_len(65)),
        );
    }

    #[test]
    fn empty_and_malformed_salt_and_output_encodings_reject() {
        let salt = b64_of_len(16);
        let output = b64_of_len(32);

        assert_policy_rejects("empty salt", &phc(CANONICAL_PARAMS, "", &output));
        assert_policy_rejects("empty output", &phc(CANONICAL_PARAMS, &salt, ""));
        assert_malformed(
            "salt outside the B64 alphabet",
            &phc(CANONICAL_PARAMS, "not+b64!", &output),
        );
        assert_malformed(
            "output outside the B64 alphabet",
            &phc(CANONICAL_PARAMS, &salt, "****"),
        );
        assert_malformed(
            "impossible salt length",
            &phc(CANONICAL_PARAMS, "AAAAA", &output),
        );
        assert_malformed(
            "impossible output length",
            &phc(CANONICAL_PARAMS, &salt, "AAAAAAAAA"),
        );
    }

    #[test]
    fn only_argon2id_is_accepted() {
        let tail = format!(
            "v=19${CANONICAL_PARAMS}${}${}",
            b64_of_len(16),
            b64_of_len(32)
        );

        assert_accepted("argon2id", &format!("$argon2id${tail}"));

        for algorithm in ["argon2i", "argon2d", "argon2", "argon2ID", "scrypt", ""] {
            assert_policy_rejects(
                &format!("{algorithm:?} algorithm"),
                &format!("${algorithm}${tail}"),
            );
        }
    }

    #[test]
    fn only_version_19_is_accepted() {
        let salt = b64_of_len(16);
        let output = b64_of_len(32);

        assert_accepted("v=19", &phc(CANONICAL_PARAMS, &salt, &output));

        for version in ["v=16", "v=20", "v=0", "v=019", "v=abc", "v=", "version=19"] {
            assert_policy_rejects(
                &format!("{version:?}"),
                &format!("$argon2id${version}${CANONICAL_PARAMS}${salt}${output}"),
            );
        }

        // With no version field the parameters sit where the version belongs.
        assert_policy_rejects(
            "missing version",
            &format!("$argon2id${CANONICAL_PARAMS}${salt}${output}"),
        );
    }

    #[test]
    fn work_factor_boundaries() {
        let salt = b64_of_len(16);
        let output = b64_of_len(32);
        let with_params = |params: &str| phc(params, &salt, &output);

        assert_accepted("memory 262143 KiB", &with_params("m=262143,t=3,p=4"));
        assert_accepted("memory 262144 KiB", &with_params("m=262144,t=3,p=4"));
        assert_policy_rejects("memory 262145 KiB", &with_params("m=262145,t=3,p=4"));

        assert_accepted("3 iterations", &with_params("m=65536,t=3,p=4"));
        assert_accepted("4 iterations", &with_params("m=65536,t=4,p=4"));
        assert_policy_rejects("5 iterations", &with_params("m=65536,t=5,p=4"));

        assert_accepted("7 lanes", &with_params("m=65536,t=3,p=7"));
        assert_accepted("8 lanes", &with_params("m=65536,t=3,p=8"));
        assert_policy_rejects("9 lanes", &with_params("m=65536,t=3,p=9"));

        assert_policy_rejects("zero iterations", &with_params("m=65536,t=0,p=4"));
        assert_policy_rejects("zero lanes", &with_params("m=65536,t=3,p=0"));
        assert_policy_rejects("memory below the lane floor", &with_params("m=8,t=3,p=4"));
    }

    #[test]
    fn overflowing_duplicate_missing_and_unknown_parameters_reject() {
        let salt = b64_of_len(16);
        let output = b64_of_len(32);
        let with_params = |params: &str| phc(params, &salt, &output);

        for params in [
            "m=4294967296,t=3,p=4",
            "m=99999999999999999999,t=3,p=4",
            "m=65536,t=4294967296,p=4",
            "m=65536,t=3,p=99999999999",
        ] {
            assert_policy_rejects(&format!("overflow in {params:?}"), &with_params(params));
        }

        for params in [
            "m=65536,t=3,p=4,m=262144",
            "m=8,m=4194304,t=3,p=4",
            "m=65536,t=3,t=3,p=4",
        ] {
            assert_policy_rejects(&format!("duplicate in {params:?}"), &with_params(params));
        }

        for params in ["t=3,p=4", "m=65536,p=4", "m=65536,t=3", "m=65536"] {
            assert_policy_rejects(
                &format!("missing parameter in {params:?}"),
                &with_params(params),
            );
        }

        for params in [
            "m=65536,t=3,p=4,keyid=Zm9v",
            "m=65536,t=3,p=4,data=Zm9v",
            "m=65536,t=3,p=4,x=1",
        ] {
            assert_policy_rejects(
                &format!("unknown parameter in {params:?}"),
                &with_params(params),
            );
        }

        for params in [
            "m=,t=3,p=4",
            "m=abc,t=3,p=4",
            "m=065536,t=3,p=4",
            "m=-1,t=3,p=4",
            "m,t=3,p=4",
            "m=65536,,t=3,p=4",
        ] {
            assert_policy_rejects(
                &format!("malformed parameter in {params:?}"),
                &with_params(params),
            );
        }
    }

    #[test]
    fn a_huge_lane_count_is_rejected_before_the_argon2_parameter_check() {
        // The crate's own check multiplies the lane count by eight before it
        // range-tests the value, which overflows for this input.
        let phc_hash = phc(
            "m=262144,t=3,p=4294967295",
            &b64_of_len(16),
            &b64_of_len(32),
        );

        assert_policy_rejects("u32::MAX lanes", &phc_hash);

        match argon2id_verify(phc_hash, "password".into()) {
            Err(CryptoError::Argon2PolicyViolation(_)) => {}
            other => panic!("expected a policy violation, got {other:?}"),
        }
    }

    #[test]
    fn rejected_input_never_reserves_argon2_memory() {
        // Three orders of magnitude below the smallest preset's 64 MiB block.
        const REJECTION_BUDGET: u64 = 64 * 1024;

        for phc_hash in rejected_corpus() {
            let (outcome, requested) = alloc_probe::requested_bytes(|| {
                argon2id_verify(phc_hash.clone(), "password".into())
            });

            assert!(outcome.is_err(), "{phc_hash:?} was not rejected");
            assert!(
                requested < REJECTION_BUDGET,
                "{phc_hash:?} requested {requested} bytes"
            );
        }
    }

    #[test]
    fn an_accepted_verification_reserves_the_argon2_block() {
        let _serial = serialized();

        let (outcome, requested) = alloc_probe::requested_bytes(|| {
            argon2id_verify(MOBILE_VECTOR.into(), VECTOR_PASSWORD.into())
        });

        assert!(outcome.is_ok(), "verification failed: {outcome:?}");
        // The mobile preset reserves 64 MiB, so the probe would see it if any
        // rejection path ever reached this far.
        assert!(
            requested >= 64 * 1024 * 1024,
            "only {requested} bytes requested"
        );
    }

    #[test]
    fn rejection_returns_without_running_a_verification() {
        // Argon2 at the ceiling needs hundreds of milliseconds even in release,
        // so this only shows no verification ran. The tighter budget in the
        // requirement belongs to a resource-controlled harness, not this suite.
        const REJECTION_GUARD: Duration = Duration::from_millis(200);

        for phc_hash in rejected_corpus() {
            let started = Instant::now();
            let outcome = argon2id_verify(phc_hash.clone(), "password".into());
            let elapsed = started.elapsed();

            assert!(outcome.is_err(), "{phc_hash:?} was not rejected");
            assert!(elapsed < REJECTION_GUARD, "{phc_hash:?} took {elapsed:?}");
        }
    }

    #[test]
    fn released_preset_vectors_verify_within_policy() {
        let _serial = serialized();

        for vector in [MOBILE_VECTOR, DESKTOP_VECTOR] {
            assert!(
                argon2id_verify(vector.into(), VECTOR_PASSWORD.into()).is_ok(),
                "released vector {vector} did not verify"
            );

            match argon2id_verify(vector.into(), "wrong_password".into()) {
                Err(CryptoError::AuthenticationFailed) => {}
                other => panic!("{vector}: expected an authentication failure, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_verification_permit_is_exclusive_and_returned_on_drop() {
        let _serial = serialized();

        let held = VerificationPermit::try_acquire().expect("permit should be free");
        assert!(VerificationPermit::try_acquire().is_none());

        drop(held);
        assert!(VerificationPermit::try_acquire().is_some());
    }

    #[test]
    fn a_verification_arriving_during_another_one_is_busy() {
        let _serial = serialized();

        let stop = AtomicBool::new(false);
        let mut saw_busy = false;

        thread::scope(|scope| {
            let keeper = scope.spawn(|| {
                while !stop.load(Ordering::Acquire) {
                    let _ = argon2id_verify(MOBILE_VECTOR.into(), VECTOR_PASSWORD.into());
                }
            });

            let deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < deadline {
                if matches!(
                    argon2id_verify(MOBILE_VECTOR.into(), VECTOR_PASSWORD.into()),
                    Err(CryptoError::Argon2VerificationBusy)
                ) {
                    saw_busy = true;
                    break;
                }
            }

            stop.store(true, Ordering::Release);
            keeper.join().expect("keeper thread panicked");
        });

        assert!(saw_busy, "no contender ever saw a busy result");
        assert!(
            argon2id_verify(MOBILE_VECTOR.into(), VECTOR_PASSWORD.into()).is_ok(),
            "the permit was not released"
        );
    }

    #[test]
    fn the_verification_password_is_wiped_on_every_outcome() {
        let _serial = serialized();

        let (success, wiped) = verify_and_observe_wipe(MOBILE_VECTOR, VECTOR_PASSWORD);
        assert!(success.is_ok(), "verification failed: {success:?}");
        assert!(wiped.iter().all(|&b| b == 0), "success left {wiped:?}");

        let (mismatch, wiped) = verify_and_observe_wipe(MOBILE_VECTOR, "wrong_password");
        assert!(matches!(mismatch, Err(CryptoError::AuthenticationFailed)));
        assert!(wiped.iter().all(|&b| b == 0), "mismatch left {wiped:?}");

        let over_limit = "a".repeat(MAX_VERIFY_PASSWORD_BYTES + 1);
        let (rejected, wiped) = verify_and_observe_wipe(MOBILE_VECTOR, &over_limit);
        assert!(matches!(
            rejected,
            Err(CryptoError::Argon2PolicyViolation(_))
        ));
        assert!(wiped.iter().all(|&b| b == 0), "policy error left bytes");

        let (unparsed, wiped) = verify_and_observe_wipe("not_a_phc_string", VECTOR_PASSWORD);
        assert!(matches!(unparsed, Err(CryptoError::InvalidParameter(_))));
        assert!(wiped.iter().all(|&b| b == 0), "parse error left {wiped:?}");

        let held = VerificationPermit::try_acquire().expect("permit should be free");
        let (busy, wiped) = verify_and_observe_wipe(MOBILE_VECTOR, VECTOR_PASSWORD);
        drop(held);
        assert!(matches!(busy, Err(CryptoError::Argon2VerificationBusy)));
        assert!(wiped.iter().all(|&b| b == 0), "busy return left {wiped:?}");
    }
}
