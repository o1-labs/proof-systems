//! A caller-provided byte buffer passed in from OCaml as a `Bigstring`
//! (`(char, int8_unsigned_elt, c_layout) Bigarray.Array1.t`).
//!
//! Stubs that take a [`CamlBigstring`] plus an offset can serialize into, or
//! deserialize from, the caller's buffer in place, without allocating an
//! intermediate `bytes` on the OCaml heap. This is what Mina's bin_prot
//! readers and writers for field elements need: `bin_write_t` gets a buffer
//! and a position, and `bin_read_t` gets the same.

use ocaml::{bigarray::Array1, CamlError, Error, FromValue, IntoValue, Runtime, Value};
use ocaml_gen::{const_random, Env, OCamlDesc};

pub struct CamlBigstring(pub Array1<u8>);

unsafe impl IntoValue for CamlBigstring {
    fn into_value(self, rt: &Runtime) -> Value {
        self.0.into_value(rt)
    }
}

unsafe impl<'a> FromValue<'a> for CamlBigstring {
    fn from_value(v: Value) -> Self {
        CamlBigstring(FromValue::from_value(v))
    }
}

impl OCamlDesc for CamlBigstring {
    fn ocaml_desc(_env: &Env, _generics: &[&str]) -> String {
        // Spelled out rather than `Bigstring.t` so the generated bindings do
        // not depend on Core being opened; this is exactly `Core.Bigstring.t`.
        "(char, Stdlib.Bigarray.int8_unsigned_elt, Stdlib.Bigarray.c_layout) \
         Stdlib.Bigarray.Array1.t"
            .to_string()
    }

    fn unique_id() -> u128 {
        const_random!(u128)
    }
}

/// Bounds-check `pos .. pos + len` against a buffer of `buf_len` bytes.
///
/// Returns `Invalid_argument fname` (as the OCaml `Bigstring` blit functions
/// do) when `pos` is negative or the window does not fit, so a bad offset
/// surfaces as an OCaml exception instead of a Rust panic across the FFI.
pub fn checked_range(
    buf_len: usize,
    pos: ocaml::Int,
    len: usize,
    fname: &'static str,
) -> Result<core::ops::Range<usize>, Error> {
    let out_of_bounds = || Error::Caml(CamlError::InvalidArgument(fname));
    let start: usize = pos.try_into().map_err(|_| out_of_bounds())?;
    let end = start.checked_add(len).ok_or_else(out_of_bounds)?;
    if end > buf_len {
        return Err(out_of_bounds());
    }
    Ok(start..end)
}

impl CamlBigstring {
    /// The `len` bytes starting at `pos`, or `Invalid_argument fname`.
    pub fn slice(&self, pos: ocaml::Int, len: usize, fname: &'static str) -> Result<&[u8], Error> {
        let range = checked_range(self.0.len(), pos, len, fname)?;
        Ok(&self.0.data()[range])
    }

    /// The `len` bytes starting at `pos`, mutably, or `Invalid_argument fname`.
    pub fn slice_mut(
        &mut self,
        pos: ocaml::Int,
        len: usize,
        fname: &'static str,
    ) -> Result<&mut [u8], Error> {
        let range = checked_range(self.0.len(), pos, len, fname)?;
        Ok(&mut self.0.data_mut()[range])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_invalid_argument(e: Error, fname: &str) -> bool {
        matches!(e, Error::Caml(CamlError::InvalidArgument(s)) if s == fname)
    }

    #[test]
    fn range_fits() {
        assert_eq!(checked_range(64, 0, 32, "f").unwrap(), 0..32);
        assert_eq!(checked_range(64, 32, 32, "f").unwrap(), 32..64);
        assert_eq!(checked_range(32, 0, 32, "f").unwrap(), 0..32);
        assert_eq!(checked_range(0, 0, 0, "f").unwrap(), 0..0);
    }

    #[test]
    fn range_rejects_overrun() {
        assert!(is_invalid_argument(
            checked_range(64, 33, 32, "f").unwrap_err(),
            "f"
        ));
        assert!(is_invalid_argument(
            checked_range(31, 0, 32, "f").unwrap_err(),
            "f"
        ));
        assert!(is_invalid_argument(
            checked_range(64, 64, 1, "f").unwrap_err(),
            "f"
        ));
    }

    #[test]
    fn range_rejects_negative_pos() {
        assert!(is_invalid_argument(
            checked_range(64, -1, 32, "f").unwrap_err(),
            "f"
        ));
    }

    #[test]
    fn range_rejects_overflow() {
        assert!(is_invalid_argument(
            checked_range(64, ocaml::Int::MAX, 32, "f").unwrap_err(),
            "f"
        ));
    }
}
