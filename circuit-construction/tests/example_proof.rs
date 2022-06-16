use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{FftField, PrimeField, UniformRand};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
use circuit_construction::*;
use commitment_dlog::{commitment::CommitmentCurve, srs::SRS};
use groupmap::GroupMap;
use kimchi::verifier::verify;
use mina_curves::pasta::{
    fp::Fp,
    pallas::Affine as Other,
    vesta::{Affine, VestaParameters},
};
use oracle::{
    constants::*,
    poseidon::{ArithmeticSponge, Sponge},
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use std::sync::Arc;

type SpongeQ = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
type SpongeR = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;

pub struct Witness<G: AffineCurve> {
    pub s: G::ScalarField,
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
    let scalar = sys.scalar(G::ScalarField::size_in_bits(), || {
        witness.as_ref().unwrap().s
    });
    let actual = sys.scalar_mul(zero, base, scalar);

    let preimage = sys.var(|| witness.as_ref().unwrap().preimage);
    let actual_hash = sys.poseidon(constants, vec![preimage, zero, zero])[0];

    sys.assert_eq(actual.0, public_input[0]);
    sys.assert_eq(actual.1, public_input[1]);
    sys.assert_eq(actual_hash, public_input[2]);
}

const PUBLIC_INPUT_LENGTH: usize = 3;

#[test]
fn test_example_circuit() {
    // create SRS
    let proof_system_constants = fp_constants();
    let srs = {
        let mut srs = SRS::<Affine>::create(1 << 7); // 2^7 = 128
        srs.add_lagrange_basis(D::new(srs.g.len()).unwrap());
        Arc::new(srs)
    };

    let fq_poseidon = oracle::pasta::fq_kimchi::params();

    // generate circuit and index
    let prover_index =
        generate_prover_index::<FpInner, _, _>(srs, &fq_poseidon, PUBLIC_INPUT_LENGTH, |sys, p| {
            circuit::<_, Other, _>(&proof_system_constants, None, sys, p)
        });

    let group_map = <Affine as CommitmentCurve>::Map::setup();

    let mut rng = rand::thread_rng();

    // create witness
    let private_key = <Other as AffineCurve>::ScalarField::rand(&mut rng);
    let preimage = <Other as AffineCurve>::BaseField::rand(&mut rng);

    let witness = Witness {
        s: private_key,
        preimage,
    };

    // create public input
    let public_key = Other::prime_subgroup_generator()
        .mul(private_key)
        .into_affine();
    let hash = {
        let mut s: ArithmeticSponge<_, PlonkSpongeConstantsKimchi> =
            ArithmeticSponge::new(proof_system_constants.poseidon.clone());
        s.absorb(&[preimage]);
        s.squeeze()
    };

    // generate proof
    let proof = prove::<Affine, _, SpongeQ, SpongeR, _>(
        &prover_index,
        &group_map,
        None,
        vec![public_key.x, public_key.y, hash],
        |sys, p| circuit::<Fp, Other, _>(&proof_system_constants, Some(&witness), sys, p),
    );

    // verify proof
    let verifier_index = prover_index.verifier_index();

    verify::<_, SpongeQ, SpongeR, _>(&group_map, &verifier_index, &proof).unwrap();
}
