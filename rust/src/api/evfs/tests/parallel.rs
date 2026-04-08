use super::*;

// -- Parallel reads -------------------------------------------------------

// Compile-time assertion: VaultHandle must be Sync for &VaultHandle across rayon threads
#[allow(dead_code)]
trait AssertSync: Sync {}
impl AssertSync for super::types::VaultHandle {}

#[test]
fn test_parallel_read_matches_sequential() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 4_194_304);

    vault_write(&mut handle, "a.txt".into(), b"alpha".to_vec(), None, None).expect("write a");
    vault_write(&mut handle, "b.txt".into(), b"bravo".to_vec(), None, None).expect("write b");
    vault_write(&mut handle, "c.txt".into(), b"charlie".to_vec(), None, None).expect("write c");

    let seq_a = vault_read(&mut handle, "a.txt".into()).expect("read a").data;
    let seq_b = vault_read(&mut handle, "b.txt".into()).expect("read b").data;
    let seq_c = vault_read(&mut handle, "c.txt".into()).expect("read c").data;

    let results = vault_read_parallel(
        &handle,
        vec!["a.txt".into(), "b.txt".into(), "c.txt".into()],
    );

    assert_eq!(results.len(), 3);
    assert!(results[0].error.is_none());
    assert_eq!(results[0].data, seq_a);
    assert_eq!(results[1].data, seq_b);
    assert_eq!(results[2].data, seq_c);

    vault_close(handle).expect("close");
}

#[test]
fn test_parallel_read_10_segments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 4_194_304);

    let mut expected = Vec::new();
    for i in 0..10u8 {
        let name = format!("seg_{i}");
        let data = vec![i; 1024];
        vault_write(&mut handle, name, data.clone(), None, None).expect("write");
        expected.push(data);
    }

    let names: Vec<String> = (0..10).map(|i| format!("seg_{i}")).collect();
    let results = vault_read_parallel(&handle, names);

    assert_eq!(results.len(), 10);
    for (i, sr) in results.iter().enumerate() {
        assert!(sr.error.is_none(), "segment {i} had error: {:?}", sr.error);
        assert_eq!(sr.name, format!("seg_{i}"));
        assert_eq!(sr.data, expected[i]);
    }

    vault_close(handle).expect("close");
}

#[test]
fn test_parallel_read_mixed_monolithic_and_streaming() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 4_194_304);

    let mono_data = vec![0xAA; 512];
    vault_write(&mut handle, "mono".into(), mono_data.clone(), None, None).expect("write mono");

    let stream_data: Vec<u8> = (0..=255u8).cycle().take(100_000).collect();
    let stream_iter = stream_data.chunks(8192).map(|c| c.to_vec());
    vault_write_stream(
        &mut handle,
        "stream".into(),
        stream_data.len() as u64,
        stream_iter,
        None,
    )
    .expect("write stream");

    let results = vault_read_parallel(&handle, vec!["mono".into(), "stream".into()]);

    assert_eq!(results.len(), 2);
    assert!(results[0].error.is_none());
    assert_eq!(results[0].data, mono_data);
    assert!(results[1].error.is_none());
    assert_eq!(results[1].data, stream_data);

    vault_close(handle).expect("close");
}

#[test]
fn test_parallel_read_missing_segment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "exists".into(), vec![1, 2, 3], None, None).expect("write");

    let results = vault_read_parallel(&handle, vec!["exists".into(), "missing".into()]);

    assert_eq!(results.len(), 2);
    assert!(results[0].error.is_none());
    assert_eq!(results[0].data, vec![1, 2, 3]);
    assert!(results[1].error.is_some());
    assert!(
        results[1]
            .error
            .as_ref()
            .expect("error")
            .contains("missing"),
        "error should mention segment name"
    );
    assert!(results[1].data.is_empty());

    vault_close(handle).expect("close");
}

#[test]
fn test_parallel_read_empty_names() {
    let dir = tempfile::tempdir().expect("tempdir");
    let handle = create_test_vault(&dir, 1_048_576);

    let results = vault_read_parallel(&handle, vec![]);
    assert!(results.is_empty());

    vault_close(handle).expect("close");
}

#[test]
fn test_parallel_read_single_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "only".into(), b"solo".to_vec(), None, None).expect("write");

    let seq = vault_read(&mut handle, "only".into()).expect("sequential").data;
    let results = vault_read_parallel(&handle, vec!["only".into()]);

    assert_eq!(results.len(), 1);
    assert!(results[0].error.is_none());
    assert_eq!(results[0].data, seq);

    vault_close(handle).expect("close");
}

#[test]
fn test_parallel_read_preserves_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 4_194_304);

    for i in 0..10u8 {
        vault_write(&mut handle, format!("seg_{i}"), vec![i; 256], None, None).expect("write");
    }

    let names: Vec<String> = (0..10).rev().map(|i| format!("seg_{i}")).collect();
    let results = vault_read_parallel(&handle, names.clone());

    assert_eq!(results.len(), 10);
    for (i, sr) in results.iter().enumerate() {
        assert!(sr.error.is_none());
        assert_eq!(sr.name, names[i]);
    }

    vault_close(handle).expect("close");
}

#[test]
fn test_parallel_read_chacha20() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    let mut handle =
        vault_create(path, test_key(), "chacha20-poly1305".into(), 4_194_304).expect("create");

    vault_write(&mut handle, "x".into(), b"chacha-data".to_vec(), None, None).expect("write");
    vault_write(&mut handle, "y".into(), b"poly1305-data".to_vec(), None, None).expect("write");

    let results = vault_read_parallel(&handle, vec!["x".into(), "y".into()]);

    assert!(results[0].error.is_none());
    assert_eq!(results[0].data, b"chacha-data");
    assert!(results[1].error.is_none());
    assert_eq!(results[1].data, b"poly1305-data");

    vault_close(handle).expect("close");
}

#[test]
fn test_parallel_read_fallback_sequential() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 4_194_304);

    vault_write(&mut handle, "a".into(), b"alpha".to_vec(), None, None).expect("write a");
    vault_write(&mut handle, "b".into(), b"bravo".to_vec(), None, None).expect("write b");

    // Force no-mmap fallback
    handle.mmap = None;

    let results = vault_read_parallel(&handle, vec!["a".into(), "b".into()]);

    assert_eq!(results.len(), 2);
    assert!(results[0].error.is_none());
    assert_eq!(results[0].data, b"alpha");
    assert!(results[1].error.is_none());
    assert_eq!(results[1].data, b"bravo");

    vault_close(handle).expect("close");
}

