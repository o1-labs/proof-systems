use algebra::Field;
use std::ops::Range;

pub const PSDN: Range<usize> = 0..5;
pub const PERM: Range<usize> = 5..7;
pub const ADD: Range<usize> = 7..10;
pub const DBL: Range<usize> = 10..13;
pub const ENDML: Range<usize> = 13..19;
pub const PACK: Range<usize> = 19..24;
pub const MUL: Range<usize> = 24..29;
pub const MLPCK: Range<usize> = 29..34;

pub fn alpha_powers<F: Field>(x: F) -> Vec<F> {
    let mut y = x;
    (PSDN.start..MLPCK.end)
        .map(|_| {
            y *= x;
            y
        })
        .collect()
}
