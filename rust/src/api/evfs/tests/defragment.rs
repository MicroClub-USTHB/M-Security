use super::*;

// -- Defragmentation ----------------------------------------------------

#[test]
fn test_defragment_basic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 200], None, None).expect("A");
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 200], None, None).expect("B");
    vault_write(&mut handle, "c.txt".into(), vec![0xCC; 200], None, None).expect("C");

    let c_offset_before = handle.index.find("c.txt").expect("C").offset;

    // Delete B — creates free region between A and C
    vault_delete(&mut handle, "b.txt".into()).expect("del B");
    assert_eq!(handle.index.free_regions.len(), 1);

    let result = vault_defragment(&mut handle).expect("defrag");
    assert_eq!(result.segments_moved, 1); // C moved left
    assert_eq!(result.free_regions_before, 1);
    assert!(result.bytes_reclaimed > 0);

    // Free list should be empty, all free space is unallocated
    let cap = vault_capacity(&handle);
    assert_eq!(cap.free_list_bytes, 0);
    assert!(cap.unallocated_bytes > 0);
    assert_eq!(cap.segment_count, 2);

    // next_free_offset == sum of all segment sizes
    let total_used: u64 = handle.index.entries.iter().map(|e| e.size).sum();
    assert_eq!(handle.index.next_free_offset, total_used);
    assert_eq!(handle.index.free_regions.len(), 0);

    // C moved left
    let c_offset_after = handle.index.find("c.txt").expect("C").offset;
    assert!(c_offset_after < c_offset_before);

    // Data integrity preserved
    assert_eq!(
        vault_read(&mut handle, "a.txt".into()).expect("read A").data,
        vec![0xAA; 200]
    );
    assert_eq!(
        vault_read(&mut handle, "c.txt".into()).expect("read C").data,
        vec![0xCC; 200]
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_multiple_gaps() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 100], None, None).expect("A");
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 100], None, None).expect("B");
    vault_write(&mut handle, "c.txt".into(), vec![0xCC; 100], None, None).expect("C");
    vault_write(&mut handle, "d.txt".into(), vec![0xDD; 100], None, None).expect("D");
    vault_write(&mut handle, "e.txt".into(), vec![0xEE; 100], None, None).expect("E");

    // Delete B and D — two gaps
    vault_delete(&mut handle, "b.txt".into()).expect("del B");
    vault_delete(&mut handle, "d.txt".into()).expect("del D");
    assert_eq!(handle.index.free_regions.len(), 2);

    let result = vault_defragment(&mut handle).expect("defrag");
    assert_eq!(result.segments_moved, 2); // C and E moved
    assert_eq!(result.free_regions_before, 2);

    // All surviving segments readable
    assert_eq!(
        vault_read(&mut handle, "a.txt".into()).expect("A").data,
        vec![0xAA; 100]
    );
    assert_eq!(
        vault_read(&mut handle, "c.txt".into()).expect("C").data,
        vec![0xCC; 100]
    );
    assert_eq!(
        vault_read(&mut handle, "e.txt".into()).expect("E").data,
        vec![0xEE; 100]
    );

    assert_eq!(vault_capacity(&handle).free_list_bytes, 0);
    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_already_compact() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 100], None, None).expect("A");
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 100], None, None).expect("B");
    vault_write(&mut handle, "c.txt".into(), vec![0xCC; 100], None, None).expect("C");

    let result = vault_defragment(&mut handle).expect("defrag");
    assert_eq!(result.segments_moved, 0);
    assert_eq!(result.bytes_reclaimed, 0);
    assert_eq!(result.free_regions_before, 0);

    // All segments still readable
    assert_eq!(
        vault_read(&mut handle, "a.txt".into()).expect("A").data,
        vec![0xAA; 100]
    );
    assert_eq!(
        vault_read(&mut handle, "b.txt".into()).expect("B").data,
        vec![0xBB; 100]
    );
    assert_eq!(
        vault_read(&mut handle, "c.txt".into()).expect("C").data,
        vec![0xCC; 100]
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_empty_vault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let result = vault_defragment(&mut handle).expect("defrag");
    assert_eq!(result.segments_moved, 0);
    assert_eq!(result.bytes_reclaimed, 0);
    assert_eq!(result.free_regions_before, 0);

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_single_segment_at_gap() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 200], None, None).expect("A");
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 200], None, None).expect("B");

    // Delete A — gap at start, B remains at higher offset
    vault_delete(&mut handle, "a.txt".into()).expect("del A");

    let result = vault_defragment(&mut handle).expect("defrag");
    assert_eq!(result.segments_moved, 1);
    assert_eq!(result.free_regions_before, 1);

    // B moved to offset 0
    assert_eq!(handle.index.find("b.txt").expect("B").offset, 0);
    assert_eq!(
        vault_read(&mut handle, "b.txt".into()).expect("read B").data,
        vec![0xBB; 200]
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_crash_recovery() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    // Create vault with A, B, C. Delete B to create a gap.
    {
        let mut handle = vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576)
            .expect("create");
        vault_write(&mut handle, "a.txt".into(), vec![0xAA; 100], None, None).expect("A");
        vault_write(&mut handle, "b.txt".into(), vec![0xBB; 100], None, None).expect("B");
        vault_write(&mut handle, "c.txt".into(), vec![0xCC; 100], None, None).expect("C");
        vault_delete(&mut handle, "b.txt".into()).expect("del B");
        vault_close(handle).expect("close");
    }

    // Save pre-defrag encrypted index (the "good" state)
    let pre_defrag_index = {
        let mut f = File::open(&path).expect("open");
        read_encrypted_index(
            &mut f,
            PRIMARY_INDEX_OFFSET,
            encrypted_index_size(MIN_INDEX_PAD_SIZE),
        )
        .expect("read index")
    };

    // Simulate crash mid-defrag: write uncommitted WAL entry
    {
        let mut wal = WriteAheadLog::open(&path).expect("wal");
        wal.begin(WalOp::WriteSegment, &pre_defrag_index)
            .expect("begin");
        // Don't commit — simulates crash during defrag
    }

    // Reopen — WAL recovery should restore pre-defrag index
    let mut handle = vault_open(path, test_key()).expect("open after crash");

    // C should still be at its original (pre-defrag) offset, readable
    assert_eq!(
        vault_read(&mut handle, "c.txt".into()).expect("read C").data,
        vec![0xCC; 100]
    );
    assert_eq!(
        vault_read(&mut handle, "a.txt".into()).expect("read A").data,
        vec![0xAA; 100]
    );

    // Free region from deleted B should still exist
    assert!(!handle.index.free_regions.is_empty());

    // Now run actual defrag — should succeed normally
    let result = vault_defragment(&mut handle).expect("defrag");
    assert!(result.segments_moved > 0);

    assert_eq!(
        vault_read(&mut handle, "a.txt".into()).expect("A").data,
        vec![0xAA; 100]
    );
    assert_eq!(
        vault_read(&mut handle, "c.txt".into()).expect("C").data,
        vec![0xCC; 100]
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_crash_overlapping_move_recovers() {
    // Exercises the overlapping-move crash path: segment B is larger than
    // the gap created by deleting A, so moving B left overwrites part of
    // B's old position. A crash before WAL commit should still recover.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    // Create: [A: 100B] [B: 10KB] — deleting A creates a small gap
    // so B's move from offset(A.size) to 0 overlaps.
    {
        let mut handle =
            vault_create(path.clone(), test_key(), "aes-256-gcm".into(), SIZE_MB).expect("create");
        vault_write(&mut handle, "a.txt".into(), vec![0xAA; 100], None, None).expect("A");
        vault_write(&mut handle, "b.txt".into(), vec![0xBB; 10_000], None, None).expect("B");
        vault_delete(&mut handle, "a.txt".into()).expect("del A");
        vault_close(handle).expect("close");
    }

    // Save pre-defrag index and get B's offset/size
    let (pre_defrag_index, b_old_offset, b_size) = {
        let handle = vault_open(path.clone(), test_key()).expect("open");
        let mut f = File::open(&path).expect("open file");
        let idx = read_encrypted_index(
            &mut f,
            PRIMARY_INDEX_OFFSET,
            encrypted_index_size(MIN_INDEX_PAD_SIZE),
        )
        .expect("read idx");
        let entry = handle.index.find("b.txt").expect("B");
        let off = entry.offset;
        let sz = entry.size;
        vault_close(handle).expect("close");
        (idx, off, sz)
    };

    // Verify this IS an overlapping move: gap < size
    assert!(b_old_offset < b_size, "should be overlapping move");

    // Simulate crash mid-defrag: perform the overlapping write but don't commit WAL
    {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open rw");

        // Read B from old position
        let mut buf = vec![0u8; b_size as usize];
        f.seek(SeekFrom::Start(
            format::data_region_offset(MIN_INDEX_PAD_SIZE) + b_old_offset,
        ))
        .expect("seek");
        f.read_exact(&mut buf).expect("read B");

        // Write defrag backup (simulating what vault_defragment does)
        let backup_path = format!("{path}.defrag");
        let mut backup = File::create(&backup_path).expect("create backup");
        backup.write_all(&b_old_offset.to_le_bytes()).expect("off");
        backup.write_all(&b_size.to_le_bytes()).expect("sz");
        backup.write_all(&buf).expect("data");
        backup.sync_all().expect("sync backup");

        // Write B to new position (offset 0) — corrupts overlap zone
        f.seek(SeekFrom::Start(format::data_region_offset(
            MIN_INDEX_PAD_SIZE,
        )))
        .expect("seek 0");
        f.write_all(&buf).expect("write B to 0");
        f.sync_all().expect("sync");

        // Write uncommitted WAL entry
        let mut wal = WriteAheadLog::open(&path).expect("wal");
        wal.begin(WalOp::WriteSegment, &pre_defrag_index)
            .expect("begin");
        // Don't commit — crash
    }

    // Reopen — defrag backup + WAL recovery should restore to consistent state
    let mut handle = vault_open(path, test_key()).expect("open after crash");

    // B should be readable at old position (overlap zone restored)
    let b_data = vault_read(&mut handle, "b.txt".into()).expect("read B").data;
    assert_eq!(b_data, vec![0xBB; 10_000]);

    // Defrag should still work after recovery
    let result = vault_defragment(&mut handle).expect("defrag after recovery");
    assert!(result.segments_moved > 0);
    let b_data = vault_read(&mut handle, "b.txt".into()).expect("read B post-defrag").data;
    assert_eq!(b_data, vec![0xBB; 10_000]);

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_preserves_compression() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let zstd_data = b"zstd compressible data ".repeat(50);
    let raw_data = b"raw segment no compression".to_vec();

    let zstd_conf = CompressionConfig {
        algorithm: CompressionAlgorithm::Zstd,
        level: None,
    };
    vault_write(
        &mut handle,
        "text.txt".into(),
        zstd_data.clone(),
        Some(zstd_conf),
        None,
    )
    .expect("zstd");
    vault_write(&mut handle, "spacer.bin".into(), vec![0xFF; 300], None, None).expect("spacer");
    vault_write(&mut handle, "raw.dat".into(), raw_data.clone(), None, None).expect("raw");

    // Delete spacer — gap between text.txt and raw.dat
    vault_delete(&mut handle, "spacer.bin".into()).expect("del spacer");

    let result = vault_defragment(&mut handle).expect("defrag");
    assert_eq!(result.segments_moved, 1); // raw.dat moved

    // Compression metadata preserved
    let text_entry = handle.index.find("text.txt").expect("text");
    assert_eq!(text_entry.compression, CompressionAlgorithm::Zstd);
    let raw_entry = handle.index.find("raw.dat").expect("raw");
    assert_eq!(raw_entry.compression, CompressionAlgorithm::None);

    // Data integrity — decompression works after defrag
    assert_eq!(
        vault_read(&mut handle, "text.txt".into()).expect("text").data,
        zstd_data
    );
    assert_eq!(
        vault_read(&mut handle, "raw.dat".into()).expect("raw").data,
        raw_data
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_preserves_generation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 100], None, None).expect("A");
    // Overwrite A to bump its generation
    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 100], None, None).expect("A v2");
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 100], None, None).expect("B");

    let b_gen_before = handle.index.find("b.txt").expect("B").generation;

    // Delete A — B needs to move
    vault_delete(&mut handle, "a.txt".into()).expect("del A");

    let result = vault_defragment(&mut handle).expect("defrag");
    assert_eq!(result.segments_moved, 1);

    // Generation unchanged
    let b_gen_after = handle.index.find("b.txt").expect("B").generation;
    assert_eq!(b_gen_before, b_gen_after);

    // Nonce derivation still works (read succeeds)
    assert_eq!(
        vault_read(&mut handle, "b.txt".into()).expect("read B").data,
        vec![0xBB; 100]
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_large_gap_at_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 300], None, None).expect("A");
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 300], None, None).expect("B");
    vault_write(&mut handle, "c.txt".into(), vec![0xCC; 300], None, None).expect("C");

    let ab_size =
        handle.index.find("a.txt").expect("A").size + handle.index.find("b.txt").expect("B").size;

    // Delete A and B — large gap at start, C alone at end
    vault_delete(&mut handle, "a.txt".into()).expect("del A");
    vault_delete(&mut handle, "b.txt".into()).expect("del B");

    let result = vault_defragment(&mut handle).expect("defrag");
    assert_eq!(result.segments_moved, 1); // C moved to 0
    assert_eq!(result.bytes_reclaimed, ab_size);

    assert_eq!(handle.index.find("c.txt").expect("C").offset, 0);
    assert_eq!(
        vault_read(&mut handle, "c.txt".into()).expect("C").data,
        vec![0xCC; 300]
    );
    assert_eq!(vault_capacity(&handle).free_list_bytes, 0);

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_write_after_defrag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 200], None, None).expect("A");
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 200], None, None).expect("B");
    vault_write(&mut handle, "c.txt".into(), vec![0xCC; 200], None, None).expect("C");

    vault_delete(&mut handle, "b.txt".into()).expect("del B");
    vault_defragment(&mut handle).expect("defrag");

    // Allocator should work: new writes go after the packed segments
    vault_write(&mut handle, "d.txt".into(), vec![0xDD; 500], None, None).expect("D after defrag");

    // All segments readable
    assert_eq!(
        vault_read(&mut handle, "a.txt".into()).expect("A").data,
        vec![0xAA; 200]
    );
    assert_eq!(
        vault_read(&mut handle, "c.txt".into()).expect("C").data,
        vec![0xCC; 200]
    );
    assert_eq!(
        vault_read(&mut handle, "d.txt".into()).expect("D").data,
        vec![0xDD; 500]
    );

    // D should be allocated at the end (after A and C)
    let a_end =
        handle.index.find("a.txt").expect("A").offset + handle.index.find("a.txt").expect("A").size;
    let c_end =
        handle.index.find("c.txt").expect("C").offset + handle.index.find("c.txt").expect("C").size;
    let d_offset = handle.index.find("d.txt").expect("D").offset;
    let packed_end = std::cmp::max(a_end, c_end);
    assert!(d_offset >= packed_end);

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_ten_segments_delete_odd() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    // Write 10 segments (1KB each)
    for i in 0..10 {
        let name = format!("seg{i}.bin");
        let data = vec![(i as u8) | 0x10; 1024];
        vault_write(&mut handle, name, data, None, None).expect("write");
    }

    // Delete odd-numbered segments (1, 3, 5, 7, 9) — 5 gaps
    for i in (1..10).step_by(2) {
        let name = format!("seg{i}.bin");
        vault_delete(&mut handle, name).expect("delete");
    }
    assert_eq!(handle.index.entries.len(), 5);
    assert!(!handle.index.free_regions.is_empty());

    let result = vault_defragment(&mut handle).expect("defrag");

    // 4 of 5 even segments need to move (seg0 stays at 0)
    assert_eq!(result.segments_moved, 4);
    assert_eq!(handle.index.free_regions.len(), 0);

    // next_free_offset == sum of all segment sizes
    let total_used: u64 = handle.index.entries.iter().map(|e| e.size).sum();
    assert_eq!(handle.index.next_free_offset, total_used);

    // Segments are contiguous: sorted offsets form a gapless sequence
    let mut offsets: Vec<(u64, u64)> = handle
        .index
        .entries
        .iter()
        .map(|e| (e.offset, e.size))
        .collect();
    offsets.sort_by_key(|&(off, _)| off);
    assert_eq!(offsets[0].0, 0);
    for w in offsets.windows(2) {
        assert_eq!(w[0].0 + w[0].1, w[1].0, "gap between segments");
    }

    // All 5 surviving segments readable with correct data
    for i in (0..10).step_by(2) {
        let name = format!("seg{i}.bin");
        let expected = vec![(i as u8) | 0x10; 1024];
        let data = vault_read(&mut handle, name).expect("read").data;
        assert_eq!(data, expected);
    }

    vault_close(handle).expect("close");
}

#[test]
fn test_vault_health_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let handle = create_test_vault(&dir, 1_048_576);

    let h = vault_health(&handle);
    assert_eq!(h.segment_count, 0);
    assert_eq!(h.free_region_count, 0);
    assert_eq!(h.fragmentation_ratio, 0.0);
    assert_eq!(h.total_bytes, handle.index.capacity);
    assert_eq!(h.used_bytes, 0);
    assert_eq!(h.unallocated_bytes, handle.index.capacity);
}

#[test]
fn test_vault_health_after_write_delete_and_defrag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a".into(), vec![0xAA; 200], None, None).expect("A");
    vault_write(&mut handle, "b".into(), vec![0xBB; 500], None, None).expect("B");
    vault_write(&mut handle, "c".into(), vec![0xCC; 300], None, None).expect("C");

    let before = vault_health(&handle);
    assert!(before.used_bytes > 0);
    assert_eq!(
        before.unallocated_bytes + before.free_list_bytes + before.used_bytes,
        handle.index.capacity
    );

    vault_delete(&mut handle, "b".into()).expect("delete B");

    let after_delete = vault_health(&handle);
    assert_eq!(after_delete.free_region_count, 1);
    assert!(after_delete.fragmentation_ratio > 0.0);
    assert!(after_delete.largest_free_block > 0);
    assert_eq!(
        after_delete.used_bytes + after_delete.free_list_bytes + after_delete.unallocated_bytes,
        handle.index.capacity
    );

    vault_defragment(&mut handle).expect("defrag");

    let after_defrag = vault_health(&handle);
    assert_eq!(after_defrag.free_region_count, 0);
    assert_eq!(after_defrag.fragmentation_ratio, 0.0);
    assert_eq!(
        after_defrag.largest_free_block,
        after_defrag.unallocated_bytes
    );
    assert_eq!(
        after_defrag.used_bytes + after_defrag.free_list_bytes + after_defrag.unallocated_bytes,
        handle.index.capacity
    );
}

#[test]
fn test_largest_free_block_accounts_for_tail() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1024u64);

    vault_write(&mut handle, "s".into(), vec![0xAA; 100], None, None).expect("write");

    let h = vault_health(&handle);
    let free_list_max = handle
        .index
        .free_regions
        .iter()
        .map(|r| r.size)
        .max()
        .unwrap_or(0);
    let tail = handle
        .index
        .capacity
        .saturating_sub(handle.index.next_free_offset);

    assert_eq!(h.largest_free_block, std::cmp::max(free_list_max, tail));
}

#[test]
fn test_vault_health_full_capacity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    // Fill vault until full
    let mut i = 0;
    loop {
        let name = format!("seg_{i}");
        if vault_write(&mut handle, name, vec![0xAA; 8192], None, None).is_err() {
            break;
        }
        i += 1;
    }

    let h = vault_health(&handle);
    assert_eq!(h.free_region_count, 0);
    assert_eq!(h.fragmentation_ratio, 0.0);
    assert_eq!(
        h.used_bytes + h.free_list_bytes + h.unallocated_bytes,
        h.total_bytes
    );
}

