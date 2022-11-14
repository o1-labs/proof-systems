//! Constants used for poseidon.

use ark_ec::AffineCurve;
use ark_ff::Field;
use commitment_dlog::commitment::CommitmentCurve;
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
        let (endo_q, _endo_r) = Curve::OtherCurve::endos();
        let base = Curve::OtherCurve::prime_subgroup_generator()
            .to_coordinates()
            .unwrap();

        Self {
            poseidon,
            endo: *endo_q,
            base,
        }
    }
}
