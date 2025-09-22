use std::sync::{Mutex, OnceLock};

use neon::{prelude::*, types::JsValue};
use once_cell::sync::Lazy;

/// Optional thread pool used to execute CPU intensive work off the V8 main thread.
///
/// We wrap the pool in a mutex so that `initThreadPool`/`exitThreadPool` can
/// safely update it while other threads are calling `run_in_pool`.
static THREAD_POOL: OnceLock<Mutex<Option<rayon::ThreadPool>>> = OnceLock::new();

fn pool_cell() -> &'static Mutex<Option<rayon::ThreadPool>> {
    THREAD_POOL.get_or_init(|| Mutex::new(None))
}

/// Fallback pool used when the custom pool has not been initialised yet.
#[allow(dead_code)]
static DEFAULT_POOL: Lazy<rayon::ThreadPool> = Lazy::new(|| {
    rayon::ThreadPoolBuilder::new()
        .build()
        .expect("failed to create default rayon thread pool")
});

/// Execute the provided closure inside the active Rayon pool. If the Neon
/// thread pool has not been initialised yet, fall back to a small global pool.
#[allow(dead_code)]
pub fn run_in_pool<OP, R>(op: OP) -> R
where
    OP: FnOnce() -> R + Send,
    R: Send,
{
    let guard = pool_cell().lock().expect("thread pool lock poisoned");

    if let Some(pool) = guard.as_ref() {
        return pool.install(op);
    }

    drop(guard);
    DEFAULT_POOL.install(op)
}

fn init_thread_pool_inner(num_threads: usize) -> Result<(), String> {
    let mut guard = pool_cell()
        .lock()
        .map_err(|_| "thread pool lock poisoned".to_string())?;

    if guard.is_some() {
        return Ok(());
    }

    let target_threads = if num_threads == 0 {
        std::thread::available_parallelism()
            .map(|v| v.get())
            .unwrap_or(1)
    } else {
        num_threads
    };

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(target_threads)
        .build()
        .map_err(|err| err.to_string())?;

    *guard = Some(pool);
    Ok(())
}

fn exit_thread_pool_inner() -> Result<(), String> {
    let mut guard = pool_cell()
        .lock()
        .map_err(|_| "thread pool lock poisoned".to_string())?;
    guard.take();
    Ok(())
}

pub fn init_thread_pool(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let threads = cx
        .argument_opt(0)
        .and_then(|arg| arg.downcast::<JsNumber, _>(&mut cx).ok())
        .map(|n| n.value(&mut cx) as usize)
        .unwrap_or(0);

    // Accept an optional worker source argument for API compatibility, but we
    // do not spawn Node workers when running natively.
    let _ = cx
        .argument_opt(1)
        .and_then(|arg| arg.downcast::<JsString, _>(&mut cx).ok());

    let (deferred, promise) = cx.promise();
    let channel = cx.channel();

    let result = init_thread_pool_inner(threads);
    deferred.settle_with(&channel, move |mut cx| match result {
        Ok(()) => Ok(cx.undefined().upcast::<JsValue>()),
        Err(err) => cx.throw_error(err),
    });

    Ok(promise)
}

pub fn exit_thread_pool(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let (deferred, promise) = cx.promise();
    let channel = cx.channel();

    let result = exit_thread_pool_inner();
    deferred.settle_with(&channel, move |mut cx| match result {
        Ok(()) => Ok(cx.undefined().upcast::<JsValue>()),
        Err(err) => cx.throw_error(err),
    });

    Ok(promise)
}
