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

<<<<<<< Updated upstream
=======
<<<<<<< Updated upstream
=======
>>>>>>> Stashed changes
#[cfg(target_arch = "wasm32")]
#[napi]
pub const BACKING: &str = "wasm";

<<<<<<< Updated upstream
=======
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

>>>>>>> Stashed changes
>>>>>>> Stashed changes
static NATIVE_CALLS: AtomicU64 = AtomicU64::new(0);

#[napi]
pub fn get_native_calls() -> u64 {
    NATIVE_CALLS.load(Ordering::Relaxed)
}

pub(crate) fn _report_native_call() {
    NATIVE_CALLS.fetch_add(1, Ordering::Relaxed);
}
