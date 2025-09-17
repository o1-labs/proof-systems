use std::sync::{Mutex, OnceLock};

use napi::bindgen_prelude::*;
use napi_derive::napi;
use once_cell::sync::Lazy;
use rayon::ThreadPool;

static THREAD_POOL: OnceLock<Mutex<Option<ThreadPool>>> = OnceLock::new();
static DEFAULT_POOL: Lazy<ThreadPool> = Lazy::new(|| {
    rayon::ThreadPoolBuilder::new()
        .build()
        .expect("failed to create default rayon pool")
});

fn pool_cell() -> &'static Mutex<Option<ThreadPool>> {
    THREAD_POOL.get_or_init(|| Mutex::new(None))
}

#[allow(dead_code)]
pub fn run_in_pool<OP, R>(op: OP) -> R
where
    OP: FnOnce() -> R + Send,
    R: Send,
{
    let guard = pool_cell().lock().expect("thread pool lock poisoned");
    if let Some(pool) = guard.as_ref() {
        pool.install(op)
    } else {
        DEFAULT_POOL.install(op)
    }
}

fn init_pool_inner(num_threads: Option<u32>) -> Result<()> {
    let mut guard = pool_cell()
        .lock()
        .map_err(|_| Error::new(Status::GenericFailure, "thread pool lock poisoned"))?;

    if guard.is_some() {
        return Ok(());
    }

    let desired = num_threads
        .filter(|value| *value > 0)
        .map(|value| value as usize)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|v| v.get())
                .unwrap_or(1)
        });

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(desired)
        .build()
        .map_err(|err| Error::new(Status::GenericFailure, err.to_string()))?;

    *guard = Some(pool);
    Ok(())
}

fn exit_pool_inner() -> Result<()> {
    let mut guard = pool_cell()
        .lock()
        .map_err(|_| Error::new(Status::GenericFailure, "thread pool lock poisoned"))?;
    *guard = None;
    Ok(())
}

#[napi(js_name = "initThreadPool")]
pub fn init_thread_pool(num_threads: Option<u32>, _worker_source: Option<String>) -> Result<()> {
    init_pool_inner(num_threads)
}

#[napi(js_name = "exitThreadPool")]
pub fn exit_thread_pool() -> Result<()> {
    exit_pool_inner()
}
