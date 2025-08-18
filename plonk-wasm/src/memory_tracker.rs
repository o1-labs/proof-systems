use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

// Global ID counter for unique allocation IDs
static ID_COUNTER: AtomicU64 = AtomicU64::new(1);

// Thread-safe ID generation
pub fn next_id() -> u64 {
    ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

// Size calculation helpers
pub fn calculate_vec_size<T>(vec: &Vec<T>) -> usize {
    vec.capacity() * std::mem::size_of::<T>()
}

pub fn calculate_nested_vec_size<T>(vecs: &Vec<Vec<T>>) -> usize {
    let outer_size = vecs.capacity() * std::mem::size_of::<Vec<T>>();
    let inner_size: usize = vecs.iter().map(|v| v.capacity() * std::mem::size_of::<T>()).sum();
    outer_size + inner_size
}

pub fn estimate_vec_size<T>(vec: &Vec<T>) -> usize {
    calculate_vec_size(vec)
}

pub fn estimate_nested_vec_size<T>(vecs: &Vec<Vec<T>>) -> usize {
    calculate_nested_vec_size(vecs)
}

// Calculate actual memory size of data structures
pub fn calculate_field_vec_size<F>(vec: &[F]) -> usize {
    vec.len() * std::mem::size_of::<F>()
}

pub fn calculate_actual_size_from_ptrs(base_struct_size: usize, heap_allocations: usize) -> usize {
    base_struct_size + heap_allocations
}

// Calculate size for ProverIndex
pub fn calculate_prover_index_size(domain_size: usize, gates_count: usize) -> usize {
    // Conservative calculation based on typical sizes
    let mut size = 0;
    
    // Constraint system with gates
    size += gates_count * 100; // ~100 bytes per gate
    
    // Domain polynomials (multiple evaluation domains)
    size += domain_size * 32 * 10; // Multiple polys at domain size
    
    // SRS reference (Arc, so just pointer)
    size += 8;
    
    // Various cached values and metadata
    size += 10 * 1024; // 10KB for misc data
    
    size
}

// Logging functions using JavaScript console
pub fn log_allocation(type_name: &str, size: usize, file: &str, line: u32, id: u64) {
    let msg = format!("@ALLOCATE {} {} {}:{} {}", type_name, size, file, line, id);
    crate::console_log(&msg);
}

pub fn log_deallocation(type_name: &str, size: usize, id: u64) {
    let msg = format!("@DROP {} {} {}", type_name, size, id);
    crate::console_log(&msg);
}

// Macro for easy allocation logging
#[macro_export]
macro_rules! log_alloc {
    ($type_name:expr, $size:expr, $id:expr) => {
        $crate::memory_tracker::log_allocation($type_name, $size, file!(), line!(), $id)
    };
}

// Macro for easy deallocation logging
#[macro_export]
macro_rules! log_drop {
    ($type_name:expr, $size:expr, $id:expr) => {
        $crate::memory_tracker::log_deallocation($type_name, $size, $id)
    };
}