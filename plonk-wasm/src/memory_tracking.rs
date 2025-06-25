/// Memory tracking module for debugging memory leaks in WASM
#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(debug_assertions)]
use wasm_bindgen::prelude::*;

#[cfg(debug_assertions)]
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
#[cfg(debug_assertions)]
static DEALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

/// Track a memory allocation (debug builds only)
#[cfg(debug_assertions)]
pub fn track_allocation() {
    ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
}

/// Track a memory allocation (no-op in release builds)
#[cfg(not(debug_assertions))]
pub fn track_allocation() {}

/// Track a memory deallocation (debug builds only)
#[cfg(debug_assertions)]
pub fn track_deallocation() {
    DEALLOCATIONS.fetch_add(1, Ordering::Relaxed);
}

/// Track a memory deallocation (no-op in release builds)
#[cfg(not(debug_assertions))]
pub fn track_deallocation() {}

/// Get the current number of leaked allocations (debug builds only)
#[cfg(debug_assertions)]
#[wasm_bindgen]
pub fn get_leaked_allocation_count() -> usize {
    let allocs = ALLOCATIONS.load(Ordering::Relaxed);
    let deallocs = DEALLOCATIONS.load(Ordering::Relaxed);
    allocs.saturating_sub(deallocs)
}

/// Reset the allocation tracking counters (debug builds only)
#[cfg(debug_assertions)]
#[wasm_bindgen]
pub fn reset_allocation_tracking() {
    ALLOCATIONS.store(0, Ordering::Relaxed);
    DEALLOCATIONS.store(0, Ordering::Relaxed);
}

/// Log current allocation statistics (debug builds only)
#[cfg(debug_assertions)]
#[wasm_bindgen]
pub fn log_allocation_stats() {
    let allocs = ALLOCATIONS.load(Ordering::Relaxed);
    let deallocs = DEALLOCATIONS.load(Ordering::Relaxed);
    let leaked = allocs.saturating_sub(deallocs);
    
    crate::console_log(&format!(
        "Memory tracking: {} allocations, {} deallocations, {} leaked",
        allocs, deallocs, leaked
    ));
}