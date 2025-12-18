//! This modules implements some math helper functions.

/// Returns ceil(log2(d)) but panics if d = 0.
pub fn ceil_log2(d: usize) -> usize {
    // NOTE: should this really be usize, since usize is depended on the underlying system architecture?

    assert!(d != 0);
    let mut pow2 = 1;
    let mut ceil_log2 = 0;
    while d > pow2 {
        ceil_log2 += 1;
        pow2 = match pow2.checked_mul(2) {
            Some(x) => x,
            None => break,
        }
    }
    ceil_log2
}

/// Integer division rounding up.
/// This function is now stable in Rust 1.73+. See <https://github.com/rust-lang/rust/issues/88581>
/// We keep a manual implementation for compatibility with older Rust versions.
/// TODO: Remove when updating to Rust 1.85+. See <https://github.com/o1-labs/mina-rust/issues/1951>
#[rustversion::attr(since(1.85), allow(clippy::manual_div_ceil))]
pub const fn div_ceil(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

/// Check if `a` is a multiple of `b`.
/// This function is stable in Rust 1.85+.
/// We keep a manual implementation for compatibility with older Rust versions.
/// TODO: Remove when updating to Rust 1.85+. See <https://github.com/o1-labs/mina-rust/issues/1951>
#[rustversion::attr(since(1.85), allow(clippy::manual_is_multiple_of))]
pub const fn is_multiple_of(a: usize, b: usize) -> bool {
    a % b == 0
}
