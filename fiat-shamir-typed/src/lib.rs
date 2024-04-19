use ark_ff::Field;

pub trait Permutation<F: Field, const STATE_SIZE: usize> {
    fn get_state(&self) -> &[F; STATE_SIZE];

    /// Apply the permutation to the whole state.
    fn apply_permutation(&self);
}

/// A type should be absorbable by the sponge, i.e. it should be able to be
/// converted to a list of field elements so the permutation can be applied to
/// it.
pub trait Absorbable<F: Field, const N: usize, T> {
    fn to_field(&mut self, input: T) -> [F; N];
}

pub trait Sponge<F: Field, const STATE_SIZE: usize, P: Permutation<F, STATE_SIZE>> {
    fn absorb(&mut self);
    fn squeeze(&mut self);
}
