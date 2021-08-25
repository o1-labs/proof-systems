use algebra::Field;
use std::ops::Range;

pub const PSDN: Range<usize> = 0..15;
pub const PERM: Range<usize> = 15..18;
pub const ADD: Range<usize> = 18..21;
pub const DBL: Range<usize> = 21..24;
pub const ENDML: Range<usize> = 24..35;
// pub const PACK  : Range<usize> = 19..24; // todo
pub const MUL: Range<usize> = 35..58;
// pub const MLPCK : Range<usize> = 29..34;

/// Computes the necessary powers of alpha for the lineariziation step.
// TODO(mimoo): because of the way we do things, we never use alpha itself. This should instead return 1, alpha, alpha^2, etc. or better, an iterator
pub fn alpha_powers<F: Field>(x: F) -> Vec<F> {
    let mut y = x;
    (PSDN.start..MUL.end)
        .map(|_| {
            y *= x;
            y
        })
        .collect()
}
