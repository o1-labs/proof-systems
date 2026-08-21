//! Error plumbing for the cached-index FFI wrappers.

use std::fmt;

/// Owned error raised through [`ocaml::Error::Error`] on the cached-index
/// FFI paths.
///
/// ocaml-rs raises that variant by calling `caml_failwith` on the boxed
/// error's `Debug` rendering, so `Debug` here must produce the plain
/// message — boxing the `String` directly would Debug-quote it and OCaml
/// would see `Failure "\"caml_...: ...\""`. Unlike `ocaml::Error::Message`
/// (which takes a `&'static str` and previously forced a `Box::leak` per
/// call), this owns its message and is freed when the error drops.
pub struct CacheFfiError(String);

impl CacheFfiError {
    /// Wraps `msg` into the `ocaml::Error` the FFI wrappers return.
    pub fn wrap(msg: String) -> ocaml::Error {
        ocaml::Error::Error(Box::new(Self(msg)))
    }
}

impl fmt::Debug for CacheFfiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for CacheFfiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CacheFfiError {}
