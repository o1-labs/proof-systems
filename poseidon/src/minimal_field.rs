use ark_ff::{BitIteratorBE, One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::ops::{Add, AddAssign, Mul, MulAssign};

/**
 * Minimal Field trait needed to implement Poseidon
 */
pub trait MinimalField:
    'static
    + Copy
    + Clone
    + CanonicalSerialize
    + CanonicalDeserialize
    + Zero
    + One
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + for<'a> MulAssign<&'a Self>
{
    /// Squares `self` in place.
    fn square_in_place(&mut self) -> &mut Self;

    /// Returns `self^exp`, where `exp` is an integer represented with `u64` limbs,
    /// least significant limb first.
    fn pow<S: AsRef<[u64]>>(&self, exp: S) -> Self {
        let mut res = Self::one();

        for i in BitIteratorBE::without_leading_zeros(exp) {
            res.square_in_place();

            if i {
                res *= self;
            }
        }
        res
    }
}

impl<F: ark_ff::Field> MinimalField for F {
    fn square_in_place(&mut self) -> &mut Self {
        self.square_in_place()
    }
}
