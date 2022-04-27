use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{FftField, PrimeField, UniformRand};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
use circuit_construction::*;
use commitment_dlog::{
    commitment::{CommitmentCurve, PolyComm},
    srs::{endos, SRS},
};
use groupmap::GroupMap;
use kimchi::verifier::verify;
use mina_curves::pasta::{
    fp::Fp,
    fq::Fq,
    pallas::{Affine as Other, PallasParameters},
    vesta::{Affine, VestaParameters},
};
use o1_utils::types::fields::*;
use oracle::{
    constants::*,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use std::sync::Arc;

type SpongeQ = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
type SpongeR = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;

type PSpongeQ = DefaultFqSponge<PallasParameters, PlonkSpongeConstantsKimchi>;
type PSpongeR = DefaultFrSponge<Fq, PlonkSpongeConstantsKimchi>;

// Prove knowledge of discrete log
pub fn circuit<
    F: PrimeField + FftField,
    G: AffineCurve<BaseField = F> + CoordinateCurve,
    Sys: Cs<F>,
>(
    // The witness
    s: &Option<ScalarField<G>>,
    sys: &mut Sys,
    public_input: Vec<Var<F>>,
) {
    let zero = sys.constant(F::zero());

    let constant_curve_pt = |sys: &mut Sys, (x, y)| {
        let x = sys.constant(x);
        let y = sys.constant(y);
        (x, y)
    };

    let base = constant_curve_pt(sys, G::prime_subgroup_generator().to_coords().unwrap());
    let scalar = sys.scalar(G::ScalarField::size_in_bits(), || s.unwrap());
    let actual = sys.scalar_mul(zero, base, scalar);

    sys.assert_eq(actual.0, public_input[0]);
    sys.assert_eq(actual.1, public_input[1]);

    sys.zk()
}

const PUBLIC_INPUT_LENGTH: usize = 2;

fn main() {
    // 2^7 = 128
    let srs = {
        let mut srs = SRS::<Affine>::create(1 << 7);
        srs.add_lagrange_basis(D::new(srs.g.len()).unwrap());
        Arc::new(srs)
    };

    let proof_system_constants = fp_constants();
    let fq_poseidon = oracle::pasta::fq_kimchi::params();

    let prover_index = generate_prover_index::<FpInner, _>(
        srs,
        &proof_system_constants,
        &fq_poseidon,
        PUBLIC_INPUT_LENGTH,
        |sys, p| circuit::<_, Other, _>(&None, sys, p),
    );

    let group_map = <Affine as CommitmentCurve>::Map::setup();

    let mut rng = rand::thread_rng();

    // Example
    let private_key = ScalarField::<Other>::rand(&mut rng);
    let public_key = Other::prime_subgroup_generator()
        .mul(private_key)
        .into_affine();

    let proof = prove::<Affine, _, SpongeQ, SpongeR>(
        &prover_index,
        &group_map,
        None,
        vec![public_key.x, public_key.y],
        |sys, p| circuit::<Fp, Other, _>(&Some(private_key), sys, p),
    );

    let verifier_index = prover_index.verifier_index();

    verify::<_, SpongeQ, SpongeR>(&group_map, &verifier_index, &proof).unwrap();
}
