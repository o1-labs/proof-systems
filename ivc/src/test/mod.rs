use ark_ec::bn::Bn;
use ark_poly::Evaluations;
use folding::{
    plonkish::{PlonkishInstance, PlonkishTrace},
    FoldingCompatibleExpr, FoldingScheme,
};
use kimchi::curve::KimchiCurve;
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use std::collections::BTreeMap;

use ark_ff::UniformRand;
use kimchi::circuits::domains::EvaluationDomains;
use kimchi_msm::{
    circuit_design::{ColWriteCap, ConstraintBuilderEnv, WitnessBuilderEnv},
    lookups::DummyLookupTable,
};
use poly_commitment::{srs::SRS, SRS as _};
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};

pub type Fp = ark_bn254::Fr;
pub type Curve = ark_bn254::G1Affine;

pub type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;
pub type SpongeParams = PlonkSpongeConstantsKimchi;

mod columns;
mod ifolding;
mod interpreters;

use crate::test::{columns::AdditionColumn, ifolding::addition};

use self::ifolding::addition::Config;

#[test]
pub fn test_simple_add() {
    let mut rng = o1_utils::tests::make_test_rng();
    let mut fq_sponge: BaseSponge = FqSponge::new(Curve::other_curve_sponge_params());
    let domain_size: usize = 1 << 5;
    let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

    // let srs: PairingSRS<BN254> = get_bn254_srs(&mut rng, domain);
    let mut srs = SRS::<Curve>::create(domain_size);
    srs.add_lagrange_basis(domain.d1);

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

    let proof_inputs_one = witness_one.get_proof_inputs(domain, empty_lookups.clone());
    let proof_inputs_two = witness_two.get_proof_inputs(domain, empty_lookups.clone());

    let folding_witness_one = ifolding::addition::Witness {
        witness: (proof_inputs_one.evaluations)
            .into_par_iter()
            .map(|w| Evaluations::from_vec_and_domain(w.to_vec(), domain.d1))
            .collect(),
    };

    let folding_instance_one = PlonkishInstance::from_witness(
        &folding_witness_one.witness,
        &mut fq_sponge,
        &srs,
        domain.d1,
    );

    let folding_witness_two = addition::Witness {
        witness: (proof_inputs_two.evaluations)
            .into_par_iter()
            .map(|w| Evaluations::from_vec_and_domain(w.to_vec(), domain.d1))
            .collect(),
    };

    let folding_instance_two = PlonkishInstance::from_witness(
        &folding_witness_two.witness,
        &mut fq_sponge,
        &srs,
        domain.d1,
    );

    let trace = PlonkishTrace {
        domain_size: domain.d1.size as usize,
    };

    let folding_compat_constraints: Vec<FoldingCompatibleExpr<Config>> = constraints
        .iter()
        .map(|x| FoldingCompatibleExpr::from(x.clone()))
        .collect();

    let (folding_scheme, _) =
        FoldingScheme::<Config>::new(folding_compat_constraints, &srs, domain.d1, &trace);

    // IVC
}
