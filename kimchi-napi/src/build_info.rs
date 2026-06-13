use std::sync::atomic::{AtomicU64, Ordering};

use napi_derive::napi;

#[cfg(target_os = "windows")]
#[napi]
pub const OS_NAME: &str = "Windows";

#[cfg(target_os = "linux")]
#[napi]
pub const OS_NAME: &str = "Linux";

#[cfg(target_os = "macos")]
#[napi]
pub const OS_NAME: &str = "macOS";

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
#[napi]
pub const OS_NAME: &str = "WASI";

#[cfg(target_arch = "x86_64")]
#[napi]
pub const ARCH_NAME: &str = "x86_64";

#[cfg(target_arch = "arm")]
#[napi]
pub const ARCH_NAME: &str = "ARM";

#[cfg(target_arch = "aarch64")]
#[napi]
pub const ARCH_NAME: &str = "AArch64";

#[cfg(target_arch = "wasm32")]
#[napi]
pub const ARCH_NAME: &str = "wasm32";

#[napi]
pub const BACKING: &str = "native";

static NATIVE_CALLS: AtomicU64 = AtomicU64::new(0);

#[napi]
pub fn get_native_calls() -> u64 {
    NATIVE_CALLS.load(Ordering::Relaxed)
}

pub(crate) fn _report_native_call() {
    NATIVE_CALLS.fetch_add(1, Ordering::Relaxed);
}

/// Initialize the global rayon thread pool with an explicit thread
/// count. REQUIRED on wasm32-wasip1-threads, where
/// `available_parallelism` reports 1 so the default pool would be
/// single-threaded — call once, before any proving/SRS entry point,
/// with e.g. `navigator.hardwareConcurrency` (browser) or
/// `os.cpus().length` (node). On native targets calling this is
/// optional (the default pool already matches the core count); calling
/// it after the pool exists is a no-op (the error is swallowed).
#[napi]
pub fn init_thread_pool(num_threads: u32) -> bool {
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads as usize)
        .build_global()
        .is_ok()
}
