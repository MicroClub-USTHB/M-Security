//! Test-only allocation accounting.
//!
//! Counts the bytes a single thread asks the allocator for, so a test can show
//! that a rejected request never reaches an expensive allocation instead of
//! only showing that it returned an error.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static MEASURING: Cell<bool> = const { Cell::new(false) };
    static REQUESTED: Cell<u64> = const { Cell::new(0) };
}

#[global_allocator]
static PROBE: CountingAllocator = CountingAllocator;

pub struct CountingAllocator;

// Both cells are `const`-initialised and hold no destructor, so reading them
// from inside the allocator cannot allocate or re-enter.
fn record(size: usize) {
    let counted = MEASURING.try_with(Cell::get).unwrap_or(false);
    if counted {
        let _ = REQUESTED.try_with(|total| total.set(total.get().saturating_add(size as u64)));
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            record(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            record(layout.size());
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let grown = System.realloc(ptr, layout, new_size);
        if !grown.is_null() {
            record(new_size.saturating_sub(layout.size()));
        }
        grown
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

struct MeasurementGuard;

impl Drop for MeasurementGuard {
    fn drop(&mut self) {
        MEASURING.with(|measuring| measuring.set(false));
    }
}

/// Runs `f` and reports how many bytes it requested on the calling thread.
///
/// The total is cumulative rather than a live peak, so a freed allocation still
/// counts and the figure can never understate what `f` reserved.
pub fn requested_bytes<R>(f: impl FnOnce() -> R) -> (R, u64) {
    REQUESTED.with(|total| total.set(0));
    MEASURING.with(|measuring| measuring.set(true));
    let guard = MeasurementGuard;

    let result = f();

    drop(guard);
    (result, REQUESTED.with(Cell::get))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_a_known_allocation() {
        let (buffer, requested) = requested_bytes(|| vec![0u8; 4 * 1024 * 1024]);

        assert_eq!(buffer.len(), 4 * 1024 * 1024);
        assert!(
            requested >= 4 * 1024 * 1024,
            "probe missed the allocation, saw {requested} bytes"
        );
    }

    #[test]
    fn reports_almost_nothing_for_work_that_does_not_allocate() {
        let (sum, requested) = requested_bytes(|| (0u64..1000).sum::<u64>());

        assert_eq!(sum, 499_500);
        assert!(requested < 4096, "unexpected {requested} bytes requested");
    }

    #[test]
    fn stops_counting_after_the_measured_call() {
        let (_, first) = requested_bytes(|| vec![0u8; 1024 * 1024]);
        let _outside = vec![0u8; 8 * 1024 * 1024];
        let (_, second) = requested_bytes(|| ());

        assert!(first >= 1024 * 1024);
        assert!(second < 4096, "counting leaked, saw {second} bytes");
    }
}
