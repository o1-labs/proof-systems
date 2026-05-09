use std::{
    any::type_name,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, OnceLock,
    },
    time::Instant,
};

#[derive(Clone)]
struct Entry {
    label: &'static str,
    curve: &'static str,
    n: usize,
    micros: u128,
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static ENTRIES: OnceLock<Mutex<Vec<Entry>>> = OnceLock::new();

pub fn reset() {
    let mut entries = entries().lock().expect("msm profiler lock poisoned");
    entries.clear();
    ENABLED.store(true, Ordering::Relaxed);
}

pub fn stop() {
    ENABLED.store(false, Ordering::Relaxed);
}

pub fn measure<G, R>(label: &'static str, n: usize, run: impl FnOnce() -> R) -> R {
    if !ENABLED.load(Ordering::Relaxed) {
        return run();
    }

    let start = Instant::now();
    let result = run();
    let micros = start.elapsed().as_micros();

    record_micros::<G>(label, n, micros);

    result
}

pub fn record_micros<G>(label: &'static str, n: usize, micros: u128) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }

    entries()
        .lock()
        .expect("msm profiler lock poisoned")
        .push(Entry {
            label,
            curve: type_name::<G>(),
            n,
            micros,
        });
}

pub fn snapshot_json() -> String {
    let entries = entries().lock().expect("msm profiler lock poisoned");
    let mut out = String::from("[");
    for (i, entry) in entries.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"label\":\"");
        push_json_string(&mut out, entry.label);
        out.push_str("\",\"curve\":\"");
        push_json_string(&mut out, entry.curve);
        out.push_str("\",\"n\":");
        out.push_str(&entry.n.to_string());
        out.push_str(",\"micros\":");
        out.push_str(&entry.micros.to_string());
        out.push('}');
    }
    out.push(']');
    out
}

fn entries() -> &'static Mutex<Vec<Entry>> {
    ENTRIES.get_or_init(|| Mutex::new(Vec::new()))
}

fn push_json_string(out: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
}
