//! Constants used for poseidon.

use ark_ff::Field;
use mina_poseidon::poseidon::ArithmeticSpongeParams;

use crate::curve::KimchiCurve;

#[derive(Clone)]
pub struct Constants<F: Field> {
    pub poseidon: ArithmeticSpongeParams<F>,
    pub endo: F,
    pub base: (F, F),
}

impl<F> Constants<F>
where
    F: Field,
{
    pub fn new<Curve: KimchiCurve<ScalarField = F>>() -> Self {
        let poseidon = Curve::sponge_params().clone();
        let endo_q = Curve::other_curve_endo();
        let base = Curve::other_curve_prime_subgroup_generator();

        Self {
            poseidon,
            endo: *endo_q,
            base,
        }
    }
}
