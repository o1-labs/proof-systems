use ark_ec::AffineCurve;
use ark_ff::Field;
use kimchi::curve::KimchiCurve;
use mina_curves::pasta::{Fp, Fq, Pallas as PallasAffine, Vesta as VestaAffine};
use mina_poseidon::poseidon::ArithmeticSpongeParams;
use poly_commitment::{commitment::CommitmentCurve, srs::endos};

/// The type of possible constants in the circuit
#[derive(Clone)]
pub struct Constants<F: Field + 'static> {
    pub poseidon: &'static ArithmeticSpongeParams<F>,
    pub endo: F,
    pub base: (F, F),
}

/// Constants for the base field of Pallas
/// ///
/// # Panics
///
/// Will panic if `PallasAffine::prime_subgroup_generator()` returns None.
pub fn fp_constants() -> Constants<Fp> {
    let (endo_q, _endo_r) = endos::<PallasAffine>();
    let base = PallasAffine::prime_subgroup_generator()
        .to_coordinates()
        .unwrap();
    Constants {
        poseidon: VestaAffine::sponge_params(),
        endo: endo_q,
        base,
    }
}

/// Constants for the base field of Vesta
///
/// # Panics
///
/// Will panic if `VestaAffine::prime_subgroup_generator()` returns None.
pub fn fq_constants() -> Constants<Fq> {
    let (endo_q, _endo_r) = endos::<VestaAffine>();
    let base = VestaAffine::prime_subgroup_generator()
        .to_coordinates()
        .unwrap();
    Constants {
        poseidon: PallasAffine::sponge_params(),
        endo: endo_q,
        base,
    }
}
