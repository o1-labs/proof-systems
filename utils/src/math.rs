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

pub fn evaluate_polynomial<F, I>(coefficients: I, zero: F, x: F) -> F
where
    I: Iterator<Item = F>,
    F: Mul<F, Output = F> + Add<F, Output = F> + Copy,
{
    coefficients.fold(zero, |acc, coeff| x * acc + coeff)
}

#[cfg(test)]
mod tests {

    use super::*;
    use mina_curves::pasta::Fp;

    #[test]
    fn test_eval() {
        let test_set = [
            ([5, 0, 7, 9], (2, 63)),
            ([0, 0, 0, 3], (2, 3)),
            ([16, 91, 23, 111], (32, 618_319)),
            ([8, 0, 2, 0], (16, 32_800)),
            ([0, 0, 0, 0], (11111, 0)),
        ];

        // runs the test_set with primitive i32 types
        for (coeffs, (x, expected)) in test_set {
            let actual = evaluate_polynomial(coeffs.into_iter(), 0, x);
            assert!(actual == expected)
        }

        // transforms test_set into Field types and runs the test, making sure generics are set correctly
        for (coeffs, (x, expected)) in test_set {
            let field_coeffs = coeffs.map(|i| Fp::from(i as u32));
            let actual =
                evaluate_polynomial(field_coeffs.into_iter(), Fp::from(0u32), Fp::from(x as u32));
            assert!(actual == Fp::from(expected as u32));
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
