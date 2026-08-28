//! Helpers for temporarily giving up the OCaml runtime lock.
//!
//! `ocaml-rs` 0.22 re-exported `ocaml_interop::OCamlRuntime`, which offered
//! `releasing_runtime`. `ocaml-rs` 1.x has its own `Runtime` and only exposes
//! the raw `caml_enter_blocking_section` / `caml_leave_blocking_section`
//! wrappers, so we rebuild the combinator here.

/// Re-enters the OCaml runtime when dropped, so the section is left even if
/// `f` unwinds.
struct BlockingSection<'a>(&'a ocaml::Runtime);

impl Drop for BlockingSection<'_> {
    fn drop(&mut self) {
        self.0.leave_blocking_section();
    }
}

/// Runs `f` with the OCaml runtime lock released, letting other threads (and,
/// on OCaml 5, other domains) make progress meanwhile.
///
/// # Safety
///
/// `f` must not touch any OCaml value or call into the OCaml runtime: the lock
/// is not held while it runs.
pub fn releasing_runtime<T, F: FnOnce() -> T>(rt: &ocaml::Runtime, f: F) -> T {
    rt.enter_blocking_section();
    let _guard = BlockingSection(rt);
    f()
}
