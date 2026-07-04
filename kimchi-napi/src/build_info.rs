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

#[cfg(target_os = "wasi")]
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

#[cfg(not(target_arch = "wasm32"))]
#[napi]
pub const BACKING: &str = "native";

#[cfg(target_arch = "wasm32")]
#[napi]
pub const BACKING: &str = "wasm";

// Initialize the global rayon pool to run everything inline on the calling
// thread. Needed on browser main threads, which cannot block: with real
// thread support, rayon's join points call Atomics.wait and trap. rayon's
// own single-threaded fallback (rayon-core registry.rs, default_global_registry)
// is unreachable there because wasi-libc's pthread_create reports EAGAIN for
// every spawn failure, which rayon does not treat as "unsupported".
// Must be called before the first rayon use; returns false if the pool was
// already initialized.
#[napi]
pub fn caml_rayon_init_single_threaded() -> bool {
    rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .use_current_thread()
        .build_global()
        .is_ok()
}

// Build the global rayon pool with the given number of threads, counting
// each worker thread as it starts running. On the web, the module is hosted
// in a Web Worker whose nested (thread) workers cannot finish loading while
// the host is blocked inside a wasm call — so the pool must be spawned while
// the host's event loop is idle, and the loader polls
// `caml_rayon_started_threads` until the pool is actually up before
// accepting FFI calls.
static STARTED_POOL_THREADS: AtomicU64 = AtomicU64::new(0);

#[napi]
pub fn caml_rayon_spawn_pool(num_threads: u32) -> bool {
    // build_global blocks in wait_until_primed until every pool thread runs.
    // on the web the calling (host worker) thread must NOT block: its nested
    // workers only start while its event loop is responsive, and their own
    // spawn requests are serviced by it. so run the blocking build on a
    // helper thread and let the caller poll caml_rayon_started_threads.
    std::thread::Builder::new()
        .name("rayon-pool-builder".into())
        .spawn(move || {
            let _ = rayon::ThreadPoolBuilder::new()
                .num_threads(num_threads as usize)
                .start_handler(|_| {
                    STARTED_POOL_THREADS.fetch_add(1, Ordering::SeqCst);
                })
                .build_global();
        })
        .is_ok()
}

#[napi]
pub fn caml_rayon_started_threads() -> u32 {
    STARTED_POOL_THREADS.load(Ordering::SeqCst) as u32
}

static NATIVE_CALLS: AtomicU64 = AtomicU64::new(0);

#[napi]
pub fn get_native_calls() -> u64 {
    NATIVE_CALLS.load(Ordering::Relaxed)
}

pub(crate) fn _report_native_call() {
    NATIVE_CALLS.fetch_add(1, Ordering::Relaxed);
}
