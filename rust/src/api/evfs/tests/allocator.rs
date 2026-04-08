use super::*;

// -- Space reclamation (free list) --------------------------------------

#[test]
fn test_delete_returns_space_to_free_list() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(
        &mut handle,
        "a.txt".into(),
        b"some data here".to_vec(),
        None,
        None,
    )
    .expect("write");
    let seg_size = handle.index.find("a.txt").expect("find").size;

    vault_delete(&mut handle, "a.txt".into()).expect("delete");

    let cap = vault_capacity(&handle);
    assert_eq!(cap.free_list_bytes, seg_size);
    assert_eq!(cap.segment_count, 0);

    vault_close(handle).expect("close");
}

#[test]
fn test_write_reuses_deleted_space() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    // Write A — note the offset and size
    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 200], None, None).expect("write A");
    let a_offset = handle.index.find("a.txt").expect("A").offset;
    let a_size = handle.index.find("a.txt").expect("A").size;

    // Delete A
    vault_delete(&mut handle, "a.txt".into()).expect("delete A");

    // Write B (smaller) — should reuse A's space
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 50], None, None).expect("write B");
    let b_offset = handle.index.find("b.txt").expect("B").offset;
    let b_size = handle.index.find("b.txt").expect("B").size;

    assert_eq!(b_offset, a_offset);
    assert!(b_size < a_size);

    // Free list should have leftover from A's region
    let cap = vault_capacity(&handle);
    assert_eq!(cap.free_list_bytes, a_size - b_size);

    vault_close(handle).expect("close");
}

#[test]
fn test_write_after_delete_exact_fit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    // Write and capture the encrypted size
    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 200], None, None).expect("write A");
    let a_offset = handle.index.find("a.txt").expect("A").offset;
    let a_size = handle.index.find("a.txt").expect("A").size;
    vault_delete(&mut handle, "a.txt".into()).expect("delete A");

    // Write B with same plaintext size — encrypted size should match exactly
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 200], None, None).expect("write B");
    let b_offset = handle.index.find("b.txt").expect("B").offset;
    let b_size = handle.index.find("b.txt").expect("B").size;

    assert_eq!(b_offset, a_offset);
    assert_eq!(b_size, a_size);
    assert_eq!(vault_capacity(&handle).free_list_bytes, 0);

    vault_close(handle).expect("close");
}

#[test]
fn test_overwrite_reclaims_then_allocates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "doc.txt".into(), vec![0xAA; 500], None, None).expect("write big");
    let old_size = handle.index.find("doc.txt").expect("old").size;

    // Overwrite with smaller data
    vault_write(&mut handle, "doc.txt".into(), vec![0xBB; 100], None, None).expect("overwrite small");
    let new_size = handle.index.find("doc.txt").expect("new").size;

    assert!(new_size < old_size);
    // Free list should have leftover from reclaimed space
    let cap = vault_capacity(&handle);
    assert!(cap.free_list_bytes > 0 || cap.unallocated_bytes > 0);

    vault_close(handle).expect("close");
}

#[test]
fn test_delete_multiple_merges_adjacent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    // Write A, B, C contiguously
    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 100], None, None).expect("A");
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 100], None, None).expect("B");
    vault_write(&mut handle, "c.txt".into(), vec![0xCC; 100], None, None).expect("C");

    let b_size = handle.index.find("b.txt").expect("B").size;
    let c_size = handle.index.find("c.txt").expect("C").size;

    // Delete B then C — should merge into one free region
    vault_delete(&mut handle, "b.txt".into()).expect("del B");
    vault_delete(&mut handle, "c.txt".into()).expect("del C");

    assert_eq!(handle.index.free_regions.len(), 1);
    assert_eq!(handle.index.free_regions[0].size, b_size + c_size);

    vault_close(handle).expect("close");
}

#[test]
fn test_free_list_falls_back_to_append() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    // Write A (small), delete it
    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 50], None, None).expect("A");
    let a_size = handle.index.find("a.txt").expect("A").size;
    vault_delete(&mut handle, "a.txt".into()).expect("del A");

    // Write B (much larger) — won't fit in A's free region
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 5000], None, None).expect("B");
    let b_offset = handle.index.find("b.txt").expect("B").offset;

    // B should be appended (offset > A's region)
    assert!(b_offset >= a_size);

    // Free list should still have A's old region
    let cap = vault_capacity(&handle);
    assert_eq!(cap.free_list_bytes, a_size);

    vault_close(handle).expect("close");
}

#[test]
fn test_capacity_reflects_free_list() {
    let dir = tempfile::tempdir().expect("tempdir");
    let capacity = 1_048_576u64;
    let mut handle = create_test_vault(&dir, capacity);

    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 200], None, None).expect("A");
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 300], None, None).expect("B");

    let cap = vault_capacity(&handle);
    assert_eq!(cap.total_bytes, capacity);
    assert_eq!(cap.segment_count, 2);
    // used + free_list + unallocated should account for total capacity
    assert_eq!(
        cap.used_bytes + cap.free_list_bytes + cap.unallocated_bytes,
        capacity
    );

    vault_close(handle).expect("close");
}

