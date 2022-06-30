use ark_ec::AffineCurve;
use ark_ff::Field;
use commitment_dlog::{
    commitment::CommitmentCurve,
    srs::{endos, KimchiCurve},
};
use mina_curves::pasta::{pallas::Affine as PallasAffine, vesta::Affine as VestaAffine, Fp, Fq};
use oracle::poseidon::ArithmeticSpongeParams;

pub const GENERICS: usize = 3;
pub const SINGLE_GENERIC_COEFFS: usize = 5;
pub const GENERIC_ROW_COEFFS: usize = 2 * SINGLE_GENERIC_COEFFS;

#[derive(Clone)]
pub struct Constants<F: Field> {
    pub poseidon: ArithmeticSpongeParams<F>,
    pub endo: F,
    pub base: (F, F),
}

pub fn fp_constants() -> Constants<Fp> {
    let (endo_q, _endo_r) = endos::<PallasAffine>();
    let base = PallasAffine::prime_subgroup_generator()
        .to_coordinates()
        .unwrap();
    Constants {
        poseidon: VestaAffine::sponge_params().clone(),
        endo: endo_q,
        base,
    }
}

pub fn fq_constants() -> Constants<Fq> {
    let (endo_q, _endo_r) = endos::<VestaAffine>();
    let base = VestaAffine::prime_subgroup_generator()
        .to_coordinates()
        .unwrap();
    Constants {
        poseidon: oracle::pasta::fq_kimchi::params(),
        endo: endo_q,
        base,
    }
}
