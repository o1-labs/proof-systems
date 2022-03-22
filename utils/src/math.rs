//! This modules implements some math helper functions.

use ark_ff::Field;

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

/// Returns `num` powers of `x`, starting with and including 1.
/// For example, `(x, 4)` gives you `[1, 2, 4, 8]`
pub fn powers_of<F: Field>(x: F, num: usize) -> Vec<F> {
    let mut res = Vec::with_capacity(num);
    let mut last = F::one();
    for _ in 0..num {
        res.push(last);
        last *= x;
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

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
