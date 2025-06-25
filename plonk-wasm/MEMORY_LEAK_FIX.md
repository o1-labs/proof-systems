# Memory Leak Fix for plonk-wasm

## Summary

Fixed critical memory leaks in the WASM bindings, particularly in the Lagrange commitment functions that were causing memory growth during proof generation from o1js.

## Issues Fixed

### 1. Use-After-Free in `lagrange_commitments_whole_domain_read_from_ptr`

**Problem**: The function was creating undefined behavior by deallocating memory while JavaScript still held the pointer.

**Fix**: Added three new functions:
- `lagrange_commitments_whole_domain_take`: Properly transfers ownership
- `lagrange_commitments_whole_domain_free`: Frees memory when data isn't needed
- `lagrange_commitments_whole_domain`: Direct version without raw pointers

The old function now re-leaks memory for backward compatibility to avoid crashes.

### 2. Memory Tracking

Added debug-mode memory tracking to help identify leaks:
- `get_leaked_allocation_count()`: Returns number of leaked allocations
- `reset_allocation_tracking()`: Resets counters
- `log_allocation_stats()`: Logs allocation statistics

### 3. Thread Pool Cleanup

Added documentation reminding that `exit_thread_pool()` must be called from JavaScript when disposing the WASM module.

## Migration Guide

### JavaScript/o1js Side

Replace this pattern:
```javascript
const ptr = srs.lagrange_commitments_whole_domain_ptr(domainSize);
// ... pass ptr to worker ...
const data = Module.lagrange_commitments_whole_domain_read_from_ptr(ptr);
```

With this:
```javascript
// Option 1: Use the take function (transfers ownership)
const ptr = srs.lagrange_commitments_whole_domain_ptr(domainSize);
// ... pass ptr to worker ...
const data = Module.lagrange_commitments_whole_domain_take(ptr);
// ptr is now invalid, memory is freed

// Option 2: Use direct version (single-threaded only)
const data = srs.lagrange_commitments_whole_domain(domainSize);

// Option 3: Free without using data
const ptr = srs.lagrange_commitments_whole_domain_ptr(domainSize);
Module.lagrange_commitments_whole_domain_free(ptr);
```

### Cleanup on Module Disposal

Always call when done with the WASM module:
```javascript
await Module.exit_thread_pool();
```

## Testing for Leaks

In debug builds, you can track memory leaks:
```javascript
// Reset tracking
Module.reset_allocation_tracking();

// Run your code...

// Check for leaks
const leakCount = Module.get_leaked_allocation_count();
if (leakCount > 0) {
    console.error(`Memory leak detected: ${leakCount} allocations`);
}

// Or log statistics
Module.log_allocation_stats();
```

## Technical Details

The leak occurred because:
1. `Box::into_raw` was used to pass data to JavaScript
2. The read function only cloned data instead of taking ownership
3. The Box was dropped, deallocating memory while JS still held the pointer
4. This caused both a memory leak AND undefined behavior

The fix ensures proper ownership transfer and provides multiple APIs for different use cases.