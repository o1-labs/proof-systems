use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{FftField, PrimeField, UniformRand};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
use commitment_dlog::{commitment::CommitmentCurve, srs::SRS};
use groupmap::GroupMap;
use kimchi::verifier::verify;
use mina_curves::pasta::{
    fp::Fp,
    pallas::Affine as Other,
    vesta::{Affine, VestaParameters},
};
use o1_utils::types::fields::*;
use oracle::{
    constants::*,
    poseidon::{ArithmeticSponge, Sponge},
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use std::sync::Arc;

use crate::{
    fp_constants, generate_prover_index, prove, Constants, CoordinateCurve, Cs, FpInner, Var,
};

type SpongeQ = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
type SpongeR = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;

pub struct Witness<G: AffineCurve> {
    pub s: ScalarField<G>,
    pub preimage: G::BaseField,
}

// Prove knowledge of discrete log and poseidon preimage of a hash
pub fn circuit<
    F: PrimeField + FftField,
    G: AffineCurve<BaseField = F> + CoordinateCurve,
    Sys: Cs<F>,
>(
    constants: &Constants<F>,
    // The witness
    witness: Option<&Witness<G>>,
    sys: Sys,
    public_input: Vec<Var<Sys, F>>,
) {
    let zero = sys.constant(F::zero());

    let constant_curve_pt = |sys: &Sys, (x, y)| {
        let x = sys.constant(x);
        let y = sys.constant(y);
        (x, y)
    };

    let base = constant_curve_pt(&sys, G::prime_subgroup_generator().to_coords().unwrap());
    let scalar = sys.scalar(G::ScalarField::size_in_bits(), || {
        witness.as_ref().unwrap().s
    });
    let actual = sys.scalar_mul(zero.clone(), base, scalar);

    let preimage = sys.var(|| witness.as_ref().unwrap().preimage);
    let actual_hash = sys.poseidon(constants, vec![preimage, zero.clone(), zero])[0].clone();

    sys.assert_eq(actual.0, public_input[0].clone());
    sys.assert_eq(actual.1, public_input[1].clone());
    sys.assert_eq(actual_hash, public_input[2].clone());

    sys.zk()
}

const PUBLIC_INPUT_LENGTH: usize = 3;

#[test]
fn test_poseidon_circuit() {
    // 2^8 = 256
    let srs = {
        let mut srs = SRS::<Affine>::create(1 << 8);
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
        |sys, p| circuit::<_, Other, _>(&proof_system_constants, None, sys, p),
    );

    let group_map = <Affine as CommitmentCurve>::Map::setup();

    let mut rng = rand::thread_rng();

    // Example
    let private_key = ScalarField::<Other>::rand(&mut rng);
    let public_key = Other::prime_subgroup_generator()
        .mul(private_key)
        .into_affine();

    let preimage = BaseField::<Other>::rand(&mut rng);

    let witness = Witness {
        s: private_key,
        preimage,
    };

    let hash = {
        let mut s: ArithmeticSponge<_, PlonkSpongeConstantsKimchi> =
            ArithmeticSponge::new(proof_system_constants.poseidon.clone());
        s.absorb(&[preimage]);
        s.squeeze()
    };

    let proof = prove::<Affine, _, SpongeQ, SpongeR>(
        &prover_index,
        &group_map,
        None,
        vec![public_key.x, public_key.y, hash],
        |sys, p| circuit::<Fp, Other, _>(&proof_system_constants, Some(&witness), sys, p),
    );

    let verifier_index = prover_index.verifier_index();

    verify::<_, SpongeQ, SpongeR>(&group_map, &verifier_index, &proof).unwrap();
}
