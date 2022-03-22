//! This modules implements some math helper functions.

use std::ops::{Add, Mul};

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

fn evaluate_polynomial<F, I>(coefficients: I, zero: F, x: F) -> F
where
    I: Iterator<Item = F>,
    F: Mul<F, Output = F> + Add<F, Output = F> + Copy,
{
    coefficients.fold(zero, |acc, coeff| x * acc + coeff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eval() {
        /* [
            ([..coeffs..], (x, expected_y))
        ] */
        let tests = [
            (vec![5, 0, 7, 9], (2, 63)),
            (vec![0, 0, 0, 3], (2, 3)),
            (vec![16, 91, 23, 111], (32, 618_319)),
            (vec![8, 0, 2, 0], (16, 32_800)),
            (vec![3, 4, 1, -5], (3, 115)),
            (vec![3, 4, 1, -5], (-6, -515)),
        ];

        for (coeffes, (x, expected)) in tests {
            let actual = evaluate_polynomial(coeffes.into_iter(), 0, x);
            assert!(actual == expected)
        }
    }

    #[test]
    fn test_log2() {
        let tests = [
            (1, 0),
            (2, 1),
            (3, 2),
            (9, 4),
            (15, 4),
            (15430, 14),
            (usize::MAX, 64),
        ];
        for (d, expected_res) in tests.iter() {
            let res = ceil_log2(*d);
            println!("ceil(log2({})) = {}, expected = {}", d, res, expected_res);
        }
    }
}
