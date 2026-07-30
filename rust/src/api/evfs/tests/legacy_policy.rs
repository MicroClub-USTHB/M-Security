//! Default denial for the unauthenticated v1/v2 vault format.
//!
//! A denied call has to fail before it opens, creates, locks or recovers
//! anything, so most of these tests rig the filesystem so that reaching the path
//! fails loudly, and then show the denial arrives instead of that failure. Each
//! hostile input is also run with the opt-in, which is what proves the rigging
//! works and that the oracle has any power at all.
//!
//! What the oracles here can see is a changed directory and a propagated I/O
//! error. A read-only `stat` that is discarded would slip past them, so the
//! statement that nothing touches the path before the check rests on the
//! source-order scan in `api::surface`, not on these tests.

use super::*;
use crate::core::evfs::format::{VAULT_MAGIC, VAULT_VERSION};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// One directory entry: name, kind, length, permissions and modification time.
type Snapshot = BTreeMap<String, String>;

/// Everything the parent directory holds, recorded as text so a mismatch prints
/// what changed.
fn snapshot(dir: &Path) -> Snapshot {
    let mut entries = BTreeMap::new();
    let listing = fs::read_dir(dir).expect("parent directory is unreadable");

    for entry in listing {
        let entry = entry.expect("directory entry is unreadable");
        let name = entry.file_name().to_string_lossy().to_string();
        let meta = entry
            .path()
            .symlink_metadata()
            .expect("directory entry has no metadata");

        let described = format!(
            "dir={} file={} link={} len={} readonly={} modified={:?}",
            meta.is_dir(),
            meta.is_file(),
            meta.file_type().is_symlink(),
            meta.len(),
            meta.permissions().readonly(),
            meta.modified().ok()
        );

        if meta.is_dir() {
            // A directory this test made unreadable on purpose still has to be
            // recorded, so its state is compared rather than skipped.
            match fs::read_dir(entry.path()) {
                Ok(_) => {
                    for (nested, described) in snapshot(&entry.path()) {
                        entries.insert(format!("{name}/{nested}"), described);
                    }
                }
                Err(error) => {
                    entries.insert(format!("{name}/<unreadable>"), error.to_string());
                }
            }
        }
        entries.insert(name, described);
    }

    entries
}

fn sidecars(vault_path: &str) -> Vec<String> {
    ["", ".lock", ".wal", ".rotating", ".defrag"]
        .iter()
        .map(|suffix| format!("{vault_path}{suffix}"))
        .filter(|path| Path::new(path).exists())
        .collect()
}

fn denied_create(path: &str) -> CryptoError {
    vault_create(
        path.to_string(),
        test_key(),
        "aes-256-gcm".into(),
        SIZE_MB,
        UnsafeLegacyEvfsPolicy::Deny,
    )
    .err()
    .expect("creation was allowed by default")
}

fn denied_open(path: &str) -> CryptoError {
    vault_open(path.to_string(), test_key(), UnsafeLegacyEvfsPolicy::Deny)
        .err()
        .expect("opening was allowed by default")
}

fn assert_denied(error: &CryptoError, case: &str) {
    assert!(
        matches!(error, CryptoError::UnsafeLegacyFormatDenied),
        "{case} returned {error:?} instead of a policy denial, so something ran first"
    );
}

/// Check that the denial happened without touching the directory, then show the
/// input really is hostile by running the same call with the opt-in.
///
/// The opted-in probe runs after the snapshot comparison on purpose: a failed
/// opted-in call gets as far as creating the `.lock` sidecar, which is exactly
/// the effect a denied call must not have.
fn assert_refused_without_a_trace(
    dir: &Path,
    case: &str,
    denied: impl FnOnce() -> CryptoError,
    opted_in: impl FnOnce() -> Result<VaultHandle, CryptoError>,
) {
    let before = snapshot(dir);
    let error = denied();
    let after = snapshot(dir);

    assert_denied(&error, case);
    assert_eq!(before, after, "{case} changed the directory");
    assert!(
        opted_in().is_err(),
        "{case} is not hostile after all, so it proves nothing"
    );
}

// -- Denial before any filesystem work ---------------------------------------

#[test]
fn creation_is_denied_by_default_and_leaves_the_directory_untouched() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);
    let before = snapshot(dir.path());

    let error = vault_create(
        path.clone(),
        test_key(),
        "aes-256-gcm".into(),
        SIZE_MB,
        UnsafeLegacyEvfsPolicy::Deny,
    )
    .err()
    .expect("creation was allowed by default");

    assert_denied(&error, "a plain create");
    assert_eq!(sidecars(&path), Vec::<String>::new());
    assert_eq!(before, snapshot(dir.path()), "the directory changed");
}

#[test]
fn opening_is_denied_by_default_and_leaves_the_vault_untouched() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);
    let handle = create_test_vault(&dir, SIZE_MB);
    vault_close(handle).expect("close");

    let before = snapshot(dir.path());

    let error = vault_open(path.clone(), test_key(), UnsafeLegacyEvfsPolicy::Deny)
        .err()
        .expect("opening was allowed by default");

    assert_denied(&error, "opening an existing vault");
    // Closing released the lock but left the checkpointed WAL, and a denied
    // open must not add either back.
    assert_eq!(sidecars(&path), vec![path.clone(), format!("{path}.wal")]);
    assert_eq!(before, snapshot(dir.path()), "the vault directory changed");
}

#[test]
fn a_denied_create_reports_no_io_error_for_a_path_it_cannot_use() {
    let dir = tempfile::tempdir().expect("tempdir");
    let existing = vault_path(&dir);
    vault_close(create_test_vault(&dir, SIZE_MB)).expect("close");

    let occupied = dir.path().join("occupied").to_string_lossy().to_string();
    fs::write(&occupied, b"not a vault").expect("write");

    // Each of these makes reaching the path fail for a different reason, and
    // none of the reasons depends on the process being unprivileged.
    let under_a_file = format!("{occupied}/inside.vault");
    let long_name = dir
        .path()
        .join("l".repeat(512))
        .to_string_lossy()
        .to_string();
    let mut cases = vec![
        ("an existing file", occupied.clone()),
        ("an existing vault", existing),
        ("a path under a file", under_a_file),
        ("an over-long name", long_name),
    ];
    #[cfg(unix)]
    {
        let loop_path = dir.path().join("loop").to_string_lossy().to_string();
        std::os::unix::fs::symlink(&loop_path, &loop_path).expect("symlink loop");
        cases.push(("a symlink loop", loop_path));
    }

    for (case, path) in cases {
        assert_refused_without_a_trace(
            dir.path(),
            case,
            || denied_create(&path),
            || optin_create(path.clone(), test_key(), "aes-256-gcm".into(), SIZE_MB),
        );
    }
}

#[test]
fn a_denied_open_reports_no_io_error_for_a_path_it_cannot_use() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir
        .path()
        .join("absent.vault")
        .to_string_lossy()
        .to_string();

    let not_a_vault = dir.path().join("plain.bin").to_string_lossy().to_string();
    fs::write(&not_a_vault, b"not a vault").expect("write");

    let a_directory = dir.path().join("dir.vault").to_string_lossy().to_string();
    fs::create_dir(&a_directory).expect("mkdir");

    let mut cases = vec![
        ("a missing file", missing),
        ("a file that is not a vault", not_a_vault),
        ("a directory", a_directory),
    ];
    #[cfg(unix)]
    {
        let dangling = dir.path().join("dangling").to_string_lossy().to_string();
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &dangling)
            .expect("dangling symlink");
        cases.push(("a dangling symlink", dangling));
    }

    for (case, path) in cases {
        assert_refused_without_a_trace(
            dir.path(),
            case,
            || denied_open(&path),
            || optin_open(path.clone(), test_key()),
        );
    }
}

#[cfg(unix)]
#[test]
fn a_denied_open_through_an_alias_of_a_real_vault_touches_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);
    vault_close(create_test_vault(&dir, SIZE_MB)).expect("close");

    // Both names reach the same vault, so unlike the cases above these are not
    // rigged to fail: the opt-in opens them. The denial is the only thing that
    // stops the default call.
    let hard_link = dir
        .path()
        .join("hard_link.vault")
        .to_string_lossy()
        .to_string();
    fs::hard_link(&path, &hard_link).expect("hard link");

    let symlink = dir
        .path()
        .join("symlink.vault")
        .to_string_lossy()
        .to_string();
    std::os::unix::fs::symlink(&path, &symlink).expect("symlink");

    for (case, alias) in [("a hard link", hard_link), ("a symlink", symlink)] {
        let before = snapshot(dir.path());
        let error = denied_open(&alias);
        let after = snapshot(dir.path());

        assert_denied(&error, case);
        assert_eq!(before, after, "{case} changed the directory");
        assert_eq!(
            sidecars(&alias),
            vec![alias.clone()],
            "{case} grew a sidecar"
        );

        let opened = optin_open(alias.clone(), test_key());
        assert!(opened.is_ok(), "{case} does not reach the vault at all");
        vault_close(opened.expect("checked above")).expect("close");
    }
}

#[cfg(unix)]
#[test]
fn a_denied_call_never_reaches_a_permission_trap() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let trap = dir.path().join("trap");
    fs::create_dir(&trap).expect("mkdir");
    let path = trap.join("test.vault").to_string_lossy().to_string();

    // Restored even if an assertion below panics, or the temp directory cannot
    // be cleaned up afterwards.
    struct RestoreMode<'a>(&'a Path);
    impl Drop for RestoreMode<'_> {
        fn drop(&mut self) {
            let _ = fs::set_permissions(self.0, fs::Permissions::from_mode(0o755));
        }
    }

    fs::set_permissions(&trap, fs::Permissions::from_mode(0o000)).expect("chmod");
    let _restore = RestoreMode(&trap);

    // Root ignores the mode bits, so the trap only proves something when the
    // test process cannot read through it.
    if fs::read_dir(&trap).is_err() {
        assert_refused_without_a_trace(
            dir.path(),
            "a create under an unreadable directory",
            || denied_create(&path),
            || optin_create(path.clone(), test_key(), "aes-256-gcm".into(), SIZE_MB),
        );
        assert_refused_without_a_trace(
            dir.path(),
            "an open under an unreadable directory",
            || denied_open(&path),
            || optin_open(path.clone(), test_key()),
        );
    }
}

#[test]
fn a_denied_open_never_acquires_the_lock() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);
    vault_close(create_test_vault(&dir, SIZE_MB)).expect("close");

    // Held on a separate descriptor, which is what an opted-in open collides
    // with. The denial has to arrive without that collision.
    let held = crate::core::evfs::wal::VaultLock::acquire(&path).expect("hold the lock");

    let error = vault_open(path.clone(), test_key(), UnsafeLegacyEvfsPolicy::Deny)
        .err()
        .expect("opening was allowed by default");
    assert_denied(&error, "an open against a locked vault");

    let collided = optin_open(path.clone(), test_key())
        .err()
        .expect("the lock was not held");
    assert!(
        matches!(collided, CryptoError::VaultLocked),
        "the lock oracle is not working: {collided:?}"
    );

    held.release().expect("release");
}

#[test]
fn a_denied_create_never_writes_a_wal_or_lock_sidecar() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    for _ in 0..3 {
        let error = vault_create(
            path.clone(),
            test_key(),
            "aes-256-gcm".into(),
            SIZE_MB,
            UnsafeLegacyEvfsPolicy::Deny,
        )
        .err()
        .expect("creation was allowed by default");
        assert_denied(&error, "a repeated create");
    }

    assert_eq!(sidecars(&path), Vec::<String>::new());
    assert!(
        snapshot(dir.path()).is_empty(),
        "the directory is not empty"
    );
}

#[test]
fn denial_wins_over_an_input_error() {
    let dir = tempfile::tempdir().expect("tempdir");

    let error = vault_create(
        vault_path(&dir),
        Vec::new(),
        "not-an-algorithm".into(),
        SIZE_MB,
        UnsafeLegacyEvfsPolicy::Deny,
    )
    .err()
    .expect("creation was allowed by default");

    // An empty key and an unknown algorithm are both rejected further in, so
    // seeing the denial proves the check runs before argument validation.
    assert_denied(&error, "a create with unusable arguments");

    // Both really are rejected, so the case is not vacuous.
    assert!(
        optin_create(vault_path(&dir), Vec::new(), "aes-256-gcm".into(), SIZE_MB).is_err(),
        "an empty key was accepted"
    );
    assert!(
        optin_create(
            vault_path(&dir),
            test_key(),
            "not-an-algorithm".into(),
            SIZE_MB
        )
        .is_err(),
        "an unknown algorithm was accepted"
    );
}

// -- The caller's key -------------------------------------------------------

/// Call the guarded entry point on a key the caller keeps, then read the
/// allocation back. `Vec::zeroize` clears the length but keeps the buffer, so
/// this reads live memory rather than freed memory.
fn observe_key_after(
    policy: UnsafeLegacyEvfsPolicy,
    call: impl FnOnce(&mut Vec<u8>, UnsafeLegacyEvfsPolicy) -> Result<VaultHandle, CryptoError>,
) -> (Result<VaultHandle, CryptoError>, Vec<u8>) {
    let mut owned = test_key();
    let len = owned.len();
    let outcome = call(&mut owned, policy);
    // SAFETY: the wipe shortened `owned` without releasing its allocation, so
    // the first `len` bytes are still inside it.
    let observed = unsafe { std::slice::from_raw_parts(owned.as_ptr(), len) }.to_vec();
    (outcome, observed)
}

#[test]
fn the_denied_call_wipes_the_key_it_was_handed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    let (created, wiped) = observe_key_after(UnsafeLegacyEvfsPolicy::Deny, |key, policy| {
        vault_create_guarded(path.clone(), key, "aes-256-gcm".into(), SIZE_MB, policy)
    });
    assert_denied(
        &created.err().expect("creation was allowed by default"),
        "a create",
    );
    assert!(wiped.iter().all(|&b| b == 0), "create left {wiped:?}");

    let (opened, wiped) = observe_key_after(UnsafeLegacyEvfsPolicy::Deny, |key, policy| {
        vault_open_guarded(path.clone(), key, policy)
    });
    assert_denied(
        &opened.err().expect("opening was allowed by default"),
        "an open",
    );
    assert!(wiped.iter().all(|&b| b == 0), "open left {wiped:?}");
}

#[test]
fn the_opted_in_call_wipes_the_key_it_was_handed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    let (created, wiped) = observe_key_after(
        UnsafeLegacyEvfsPolicy::AllowUnauthenticatedV1V2,
        |key, policy| {
            vault_create_guarded(path.clone(), key, "aes-256-gcm".into(), SIZE_MB, policy)
        },
    );
    vault_close(created.expect("create")).expect("close");
    assert!(wiped.iter().all(|&b| b == 0), "create left {wiped:?}");

    let (opened, wiped) = observe_key_after(
        UnsafeLegacyEvfsPolicy::AllowUnauthenticatedV1V2,
        |key, policy| vault_open_guarded(path.clone(), key, policy),
    );
    vault_close(opened.expect("open")).expect("close");
    assert!(wiped.iter().all(|&b| b == 0), "open left {wiped:?}");
}

#[test]
fn a_refused_rotation_wipes_the_new_key_it_was_handed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);
    let handle = create_test_vault(&dir, SIZE_MB);

    // Holding the rotation lock makes the rotation fail after the key has been
    // derived and before anything is copied.
    let held = crate::core::evfs::wal::VaultLock::acquire(&format!("{path}.rotating"))
        .expect("hold the rotation lock");

    let mut owned = test_key2();
    let len = owned.len();
    let outcome = vault_rotate_key_guarded(handle, &mut owned);
    // SAFETY: the wipe shortened `owned` without releasing its allocation, so
    // the first `len` bytes are still inside it.
    let observed = unsafe { std::slice::from_raw_parts(owned.as_ptr(), len) }.to_vec();

    assert!(outcome.is_err(), "the rotation lock was not held");
    assert!(
        observed.iter().all(|&b| b == 0),
        "the refused rotation left {observed:?}"
    );

    held.release().expect("release");
}

#[test]
fn a_failing_opted_in_call_still_wipes_the_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir
        .path()
        .join("absent.vault")
        .to_string_lossy()
        .to_string();

    let (opened, wiped) = observe_key_after(
        UnsafeLegacyEvfsPolicy::AllowUnauthenticatedV1V2,
        |key, policy| vault_open_guarded(missing.clone(), key, policy),
    );

    assert!(opened.is_err(), "a missing vault opened");
    assert!(
        wiped.iter().all(|&b| b == 0),
        "the failed open left {wiped:?}"
    );
}

// -- What the opt-in gets ----------------------------------------------------

#[test]
fn the_opt_in_round_trips_the_existing_format() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    let mut handle =
        optin_create(path.clone(), test_key(), "aes-256-gcm".into(), SIZE_MB).expect("create");
    vault_write(&mut handle, "note".into(), b"opted in".to_vec(), None, None).expect("write");
    vault_close(handle).expect("close");

    // Opting in writes the format that is already on disk, not a new one. The
    // bytes are spelled out rather than compared against the crate's own
    // constants, so writing a new version cannot keep this green.
    let header = fs::read(&path).expect("read vault");
    assert_eq!(&header[0..4], b"MVLT");
    assert_eq!(header[4], 2);
    assert_eq!(
        (VAULT_MAGIC, VAULT_VERSION),
        (b"MVLT", 2),
        "the writer's format identity changed under this test"
    );

    let mut reopened = optin_open(path, test_key()).expect("reopen");
    assert_eq!(
        vault_read(&mut reopened, "note".into()).expect("read").data,
        b"opted in".to_vec()
    );
    vault_close(reopened).expect("close");
}

#[test]
fn the_decision_carries_through_rotation_and_reopening() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    let mut handle =
        optin_create(path.clone(), test_key(), "aes-256-gcm".into(), SIZE_MB).expect("create");
    vault_write(&mut handle, "note".into(), b"carried".to_vec(), None, None).expect("write");

    let mut rotated = vault_rotate_key(handle, test_key2()).expect("rotate");
    assert_eq!(
        vault_read(&mut rotated, "note".into()).expect("read").data,
        b"carried".to_vec()
    );
    vault_close(rotated).expect("close");

    // The rotated file is still the old format, so a default reopen is refused.
    let error = vault_open(path.clone(), test_key2(), UnsafeLegacyEvfsPolicy::Deny)
        .err()
        .expect("opening was allowed by default");
    assert_denied(&error, "reopening a rotated vault");

    vault_close(optin_open(path, test_key2()).expect("reopen")).expect("close");
}

// -- No decision leaks between calls ----------------------------------------

#[test]
fn an_opted_in_call_does_not_authorize_a_later_default_call() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    let handle =
        optin_create(path.clone(), test_key(), "aes-256-gcm".into(), SIZE_MB).expect("create");
    vault_close(handle).expect("close");

    for _ in 0..5 {
        let error = vault_open(path.clone(), test_key(), UnsafeLegacyEvfsPolicy::Deny)
            .err()
            .expect("an earlier opt-in authorized a default open");
        assert_denied(&error, "an open after an opt-in");
    }

    // A live opted-in handle is not authority for a default call either.
    let held = optin_open(path.clone(), test_key()).expect("open");
    let error = vault_create(
        dir.path()
            .join("second.vault")
            .to_string_lossy()
            .to_string(),
        test_key(),
        "aes-256-gcm".into(),
        SIZE_MB,
        UnsafeLegacyEvfsPolicy::Deny,
    )
    .err()
    .expect("a live handle authorized a default create");
    assert_denied(&error, "a create while a handle is open");
    vault_close(held).expect("close");
}

#[test]
fn interleaved_denied_and_opted_in_calls_keep_their_own_answers() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Each thread works on its own vault, so the only thing they share is the
    // policy decision - which must not be shared at all.
    let paths: Vec<String> = (0..8)
        .map(|i| {
            dir.path()
                .join(format!("thread{i}.vault"))
                .to_string_lossy()
                .to_string()
        })
        .collect();

    let outcomes: Vec<(bool, Result<(), CryptoError>)> = std::thread::scope(|scope| {
        let handles: Vec<_> = paths
            .iter()
            .enumerate()
            .map(|(i, path)| {
                let opted_in = i % 2 == 0;
                scope.spawn(move || {
                    let outcome = if opted_in {
                        optin_create(path.clone(), test_key(), "aes-256-gcm".into(), SIZE_MB)
                            .and_then(vault_close)
                    } else {
                        vault_create(
                            path.clone(),
                            test_key(),
                            "aes-256-gcm".into(),
                            SIZE_MB,
                            UnsafeLegacyEvfsPolicy::Deny,
                        )
                        .and_then(vault_close)
                    };
                    (opted_in, outcome)
                })
            })
            .collect();

        handles
            .into_iter()
            .map(|handle| handle.join().expect("thread panicked"))
            .collect()
    });

    for (i, (opted_in, outcome)) in outcomes.iter().enumerate() {
        let exists = Path::new(&paths[i]).exists();
        if *opted_in {
            assert!(outcome.is_ok(), "opted-in thread {i} failed: {outcome:?}");
            assert!(exists, "opted-in thread {i} wrote no vault");
        } else {
            let error = outcome
                .as_ref()
                .expect_err("a denied thread created a vault");
            assert_denied(error, &format!("thread {i}"));
            assert!(!exists, "denied thread {i} left a file behind");
        }
    }
}

#[test]
fn a_denied_call_racing_an_opted_in_one_on_the_same_path_still_denies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    // Four rounds, so a decision leaking in either direction has room to show.
    for round in 0..4 {
        let denied = std::thread::scope(|scope| {
            let allowed = scope
                .spawn(|| optin_create(path.clone(), test_key(), "aes-256-gcm".into(), SIZE_MB));
            let refused = scope.spawn(|| denied_create(&path));

            let refused = refused.join().expect("thread panicked");
            // Both race for create_new, so either may lose. Only the refusal is
            // being asserted.
            if let Ok(handle) = allowed.join().expect("thread panicked") {
                vault_close(handle).expect("close");
            }
            refused
        });

        assert_denied(&denied, &format!("round {round}"));

        for suffix in ["", ".lock", ".wal"] {
            let _ = fs::remove_file(format!("{path}{suffix}"));
        }
    }
}

#[test]
fn repeated_calls_on_one_path_answer_each_on_its_own_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    // Deny, allow, deny, deny, allow against the same path in one thread. The
    // creation in the middle is the only one that may leave a file.
    let first = vault_create(
        path.clone(),
        test_key(),
        "aes-256-gcm".into(),
        SIZE_MB,
        UnsafeLegacyEvfsPolicy::Deny,
    )
    .err()
    .expect("creation was allowed by default");
    assert_denied(&first, "the first create");
    assert!(!Path::new(&path).exists());

    vault_close(
        optin_create(path.clone(), test_key(), "aes-256-gcm".into(), SIZE_MB).expect("create"),
    )
    .expect("close");

    for round in 0..2 {
        let error = vault_open(path.clone(), test_key(), UnsafeLegacyEvfsPolicy::Deny)
            .err()
            .expect("opening was allowed by default");
        assert_denied(&error, &format!("open round {round}"));
    }

    vault_close(optin_open(path, test_key()).expect("reopen")).expect("close");
}
