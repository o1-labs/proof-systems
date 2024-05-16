use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use std::collections::BTreeMap;

use ark_ff::UniformRand;
use kimchi::circuits::domains::EvaluationDomains;
use kimchi_msm::{
    circuit_design::{ColWriteCap, ConstraintBuilderEnv, WitnessBuilderEnv},
    lookups::DummyLookupTable,
    prover::prove,
    verifier::verify,
    witness::Witness,
};
use poly_commitment::pairing_proof::{PairingProof, PairingSRS};
use rand::{CryptoRng, RngCore};

use self::columns::AdditionColumn;

mod columns;
mod folding;
mod interpreters;

pub type Fp = ark_bn254::Fr;
pub type BN254 = ark_ec::bn::Bn<ark_bn254::Parameters>;
pub type SpongeParams = PlonkSpongeConstantsKimchi;
pub type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;
pub type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
pub type OpeningProof = PairingProof<BN254>;

/// Obtains an SRS for a specific curve from disk, or generates it if absent.
pub fn get_bn254_srs<RNG: RngCore + CryptoRng>(
    rng: &mut RNG,
    domain: EvaluationDomains<Fp>,
) -> PairingSRS<BN254> {
    // Temporarily just generate it from scratch since SRS serialization is
    // broken.
    let trapdoor = Fp::rand(rng);
    let mut srs = PairingSRS::create(trapdoor, domain.d1.size as usize);
    srs.full_srs.add_lagrange_basis(domain.d1);
    srs
}

#[test]
pub fn test_simple_add() {
    let mut rng = o1_utils::tests::make_test_rng();
    let domain_size: usize = 1 << 5;
    let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

    let srs: PairingSRS<BN254> = get_bn254_srs(&mut rng, domain);

    let constraints = {
        let mut constraint_env = ConstraintBuilderEnv::<Fp, DummyLookupTable>::create();
        interpreters::interpreter_simple_add::<Fp, _>(&mut constraint_env);
        // Don't use lookups for now
        constraint_env.get_relation_constraints()
    };

    let mut witness_one: WitnessBuilderEnv<Fp, AdditionColumn, 3, 3, 0, 0, DummyLookupTable> =
        WitnessBuilderEnv::create();

    let mut witness_two: WitnessBuilderEnv<Fp, AdditionColumn, 3, 3, 0, 0, DummyLookupTable> =
        WitnessBuilderEnv::create();

    let empty_lookups = BTreeMap::new();

    // Witness one
    for _i in 0..domain_size {
        let a: Fp = Fp::rand(&mut rng);
        let b: Fp = Fp::rand(&mut rng);
        witness_one.write_column(AdditionColumn::A, &a);
        witness_one.write_column(AdditionColumn::B, &b);
        interpreters::interpreter_simple_add(&mut witness_one);
        witness_two.next_row();
    }

    // Witness two
    for _i in 0..domain_size {
        let a: Fp = Fp::rand(&mut rng);
        let b: Fp = Fp::rand(&mut rng);
        witness_two.write_column(AdditionColumn::A, &a);
        witness_two.write_column(AdditionColumn::B, &b);
        interpreters::interpreter_simple_add(&mut witness_two);
        witness_two.next_row();
    }

    // Verify individual witnesses before folding
    {
        let proof_inputs = witness_one.get_proof_inputs(domain, empty_lookups.clone());
        // generate the proof
        let proof =
            prove::<_, OpeningProof, BaseSponge, ScalarSponge, _, 3, 3, 0, 0, DummyLookupTable>(
                domain,
                &srs,
                &constraints,
                proof_inputs,
                &mut rng,
            )
            .unwrap();

        // verify the proof
        let verifies =
            verify::<_, OpeningProof, BaseSponge, ScalarSponge, 3, 3, 0, 0, 0, DummyLookupTable>(
                domain,
                &srs,
                &constraints,
                &proof,
                Witness::zero_vec(domain_size),
            );

        assert!(verifies);
    }

    // Verify individual witnesses before folding
    {
        let proof_inputs = witness_two.get_proof_inputs(domain, empty_lookups.clone());
        // generate the proof
        let proof =
            prove::<_, OpeningProof, BaseSponge, ScalarSponge, _, 3, 3, 0, 0, DummyLookupTable>(
                domain,
                &srs,
                &constraints,
                proof_inputs,
                &mut rng,
            )
            .unwrap();

        // verify the proof
        let verifies =
            verify::<_, OpeningProof, BaseSponge, ScalarSponge, 3, 3, 0, 0, 0, DummyLookupTable>(
                domain,
                &srs,
                &constraints,
                &proof,
                Witness::zero_vec(domain_size),
            );

        assert!(verifies);
    }

    // Folding + IVC
}
