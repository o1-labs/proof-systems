use ark_ff::Field;
use std::ops::Range;

// TODO(mimoo): this should move to the respective gates
pub const PSDN: Range<usize> = 0..15;
pub const PERM: Range<usize> = 15..18;
pub const COMPLETE_ADD: Range<usize> = 18..25;
pub const ENDML: Range<usize> = 25..36;
pub const MUL: Range<usize> = 36..59;
pub const ENDOMUL_SCALAR: Range<usize> = 59..70;
pub const CHACHA: Range<usize> = 70..(70 + 9);
pub const FOREIGN_MUL: Range<usize> = 79..82;

/// Computes the powers of alpha, starting with alpha^2
// TODO(mimoo): because of the way we do things, we never use alpha itself. This should instead return 1, alpha, alpha^2, etc. or better, an iterator
pub fn alpha_powers<F: Field>(x: F) -> Vec<F> {
    let mut y = x;
    (PSDN.start..CHACHA.end)
        .map(|_| {
            y *= x;
            y
        })
        .collect()
}
