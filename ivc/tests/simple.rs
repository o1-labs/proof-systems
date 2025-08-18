//! This is a simple example of how to use the folding crate with the IVC crate
//! to fold a simple addition circuit. The addition circuit consists of a single
//! constraint of degree 1 over 3 columns (A + B - C = 0).

use ark_ec::AffineRepr;
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_poly::{Evaluations, Radix2EvaluationDomain as R2D};
use core::ops::Index;
use folding::{
    eval_leaf::EvalLeaf, expressions::FoldingColumnTrait, instance_witness::ExtendedWitness,
    standard_config::StandardConfig, Alphas, FoldingCompatibleExpr, FoldingOutput, FoldingScheme,
};
use ivc::{
    self,
    expr_eval::{GenericVecStructure, SimpleEvalEnv},
    ivc::{
        columns::{IVCColumn, N_BLOCKS, N_FSEL_IVC},
        constraints::constrain_ivc,
        interpreter::{build_fixed_selectors, ivc_circuit, ivc_circuit_base_case},
        lookups::IVCLookupTable,
        N_ADDITIONAL_WIT_COL_QUAD as N_COL_QUAD_IVC, N_ALPHAS as N_ALPHAS_IVC,
    },
    plonkish_lang::{PlonkishChallenge, PlonkishInstance, PlonkishWitness},
    poseidon_8_56_5_3_2::bn254::PoseidonBN254Parameters,
};
use kimchi::{
    circuits::{domains::EvaluationDomains, expr::Variable, gate::CurrOrNext},
    curve::KimchiCurve,
};
use kimchi_msm::{
    circuit_design::{
        ColAccessCap, ColWriteCap, ConstraintBuilderEnv, HybridCopyCap, WitnessBuilderEnv,
    },
    columns::{Column, ColumnIndexer},
    expr::E,
    logup::LogupWitness,
    lookups::DummyLookupTable,
    proof::ProofInputs,
    witness::Witness as GenericWitness,
    BN254G1Affine, Fp,
};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use poly_commitment::{kzg::PairingSRS, PolyComm, SRS as _};
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};
use std::collections::BTreeMap;
use strum::EnumCount;
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};

/// The base field of the curve
/// Used to encode the polynomial commitments
pub type Fq = ark_bn254::Fq;
/// The curve we commit into
pub type Curve = BN254G1Affine;
pub type Pairing = ark_bn254::Bn254;

pub type BaseSponge = DefaultFqSponge<ark_bn254::g1::Config, SpongeParams>;
pub type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
pub type SpongeParams = PlonkSpongeConstantsKimchi;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, EnumIter, EnumCountMacro, Hash)]
pub enum AdditionColumn {
    A,
    B,
    C,
}

impl ColumnIndexer<usize> for AdditionColumn {
    const N_COL: usize = 3;

    fn to_column(self) -> Column<usize> {
        match self {
            AdditionColumn::A => Column::Relation(0),
            AdditionColumn::B => Column::Relation(1),
            AdditionColumn::C => Column::Relation(2),
        }
    }
}

impl FoldingColumnTrait for AdditionColumn {
    fn is_witness(&self) -> bool {
        true
    }
}

impl<const N_COL: usize, const N_FSEL: usize> Index<AdditionColumn>
    for PlonkishWitness<N_COL, N_FSEL, Fp>
{
    type Output = [Fp];

    fn index(&self, index: AdditionColumn) -> &Self::Output {
        match index {
            AdditionColumn::A => &self.witness.cols[0].evals,
            AdditionColumn::B => &self.witness.cols[1].evals,
            AdditionColumn::C => &self.witness.cols[2].evals,
        }
    }
}

/// Simply compute A + B - C
pub fn interpreter_simple_add<
    F: PrimeField,
    Env: ColAccessCap<F, AdditionColumn> + HybridCopyCap<F, AdditionColumn>,
>(
    env: &mut Env,
) {
    let a = env.read_column(AdditionColumn::A);
    let b = env.read_column(AdditionColumn::B);
    let c = env.read_column(AdditionColumn::C);
    let eq = a.clone() * a.clone() * b.clone() - c;
    env.assert_zero(eq);
}

// Ignoring this test for now.
// When run with the code coverage, it takes hours, and crashes the CI, even
// though it takes less than 10 minutes to run on a desktop without test
// coverage.
// The code isn't used, and we don't plan to use it in the short term, so it's
// not a big deal.
// Also, the code wasn't in a good state.
#[test]
#[ignore]
pub fn heavy_test_simple_add() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    // FIXME: this has to be 1 << 15. the 16 is temporary, since we
    // are at 35783 rows right now, but can only allow 32768. Light
    // future optimisations will get us back to 15.
    let domain_size: usize = 1 << 16;
    let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

    let mut fq_sponge: BaseSponge = FqSponge::new(Curve::other_curve_sponge_params());

    let srs = kimchi_msm::precomputed_srs::get_bn254_srs(domain);

    // Total number of fixed selectors in the circuit for APP + IVC.
    // There is no fixed selector in the APP circuit.
    const N_FSEL_TOTAL: usize = N_FSEL_IVC;

    // Total number of witness columns in IVC. The blocks are public selectors.
    const N_WIT_IVC: usize = <IVCColumn as ColumnIndexer<usize>>::N_COL - N_FSEL_IVC;

    // Number of witness columns in the circuit.
    // It consists of the columns of the inner circuit and the columns for the
    // IVC circuit.
    const N_COL_TOTAL: usize = AdditionColumn::COUNT + N_WIT_IVC;
    // One extra quad column in APP
    const N_COL_QUAD: usize = N_COL_QUAD_IVC + 1;
    const N_COL_TOTAL_QUAD: usize = N_COL_TOTAL + N_COL_QUAD;

    // Our application circuit has two constraints.
    const N_ALPHAS_APP: usize = 1;
    // Total number of challenges required by the circuit APP + IVC.
    // The number of challenges required by the IVC is defined by the library.
    // Therefore, we only need to add the challenges required by the specific
    // application.
    const N_ALPHAS: usize = N_ALPHAS_IVC + N_ALPHAS_APP;
    // Number of extra quad constraints happens to be the same as
    // extra quad columns.
    const N_ALPHAS_QUAD: usize = N_ALPHAS + N_COL_QUAD;

    // There are two more challenges though.
    // Not used at the moment as IVC circuit only handles alphas
    const _N_CHALS: usize = N_ALPHAS + PlonkishChallenge::COUNT;

    println!("N_FSEL_TOTAL: {N_FSEL_TOTAL}");
    println!("N_COL_TOTAL: {N_COL_TOTAL}");
    println!("N_COL_TOTAL_QUAD: {N_COL_TOTAL_QUAD}");
    println!("N_ALPHAS: {N_ALPHAS}");
    println!("N_ALPHAS_QUAD: {N_ALPHAS_QUAD}");

    // ---- Defining the folding configuration ----
    // FoldingConfig
    type AppWitnessBuilderEnv = WitnessBuilderEnv<
        Fp,
        AdditionColumn,
        { AdditionColumn::COUNT },
        { AdditionColumn::COUNT },
        0,
        0,
        DummyLookupTable,
    >;

    type Config<
        const N_COL_TOTAL: usize,
        const N_CHALS: usize,
        const N_FSEL: usize,
        const N_ALPHAS: usize,
    > = StandardConfig<
        Curve,
        Column<usize>,
        PlonkishChallenge,
        PlonkishInstance<Curve, N_COL_TOTAL, N_CHALS, N_ALPHAS>, // TODO check if it's quad or not
        PlonkishWitness<N_COL_TOTAL, N_FSEL, Fp>,
        PairingSRS<Pairing>,
        (),
        GenericVecStructure<Curve>,
    >;
    type MainTestConfig = Config<N_COL_TOTAL, 3, N_FSEL_TOTAL, N_ALPHAS_QUAD>;

    ////////////////////////////////////////////////////////////////////////////
    // Fixed Selectors
    ////////////////////////////////////////////////////////////////////////////

    // ---- Start build the witness environment for the IVC
    // Start building the constants of the circuit.
    // For the IVC, we have all the "block selectors" - which depends on the
    // number of columns of the circuit - and the poseidon round constants.
    let ivc_fixed_selectors: Vec<Vec<Fp>> =
        build_fixed_selectors::<N_COL_TOTAL_QUAD, N_ALPHAS_QUAD>(domain_size).to_vec();

    // Sanity check on the domain size, can be removed later
    assert_eq!(ivc_fixed_selectors.len(), N_FSEL_TOTAL);
    ivc_fixed_selectors.iter().for_each(|s| {
        assert_eq!(s.len(), domain_size);
    });

    let ivc_fixed_selectors_evals_d1: Vec<Evaluations<Fp, R2D<Fp>>> = (&ivc_fixed_selectors)
        .into_par_iter()
        .map(|w| Evaluations::from_vec_and_domain(w.to_vec(), domain.d1))
        .collect();

    let structure = GenericVecStructure(
        ivc_fixed_selectors_evals_d1
            .iter()
            .map(|x| x.evals.clone())
            .collect(),
    );

    ////////////////////////////////////////////////////////////////////////////
    // Constraints
    ////////////////////////////////////////////////////////////////////////////

    let app_constraints: Vec<E<Fp>> = {
        let mut constraint_env = ConstraintBuilderEnv::<Fp, DummyLookupTable>::create();
        interpreter_simple_add::<Fp, _>(&mut constraint_env);
        // Don't use lookups for now
        constraint_env.get_relation_constraints()
    };

    let ivc_constraints: Vec<E<Fp>> = {
        let mut ivc_constraint_env = ConstraintBuilderEnv::<Fp, IVCLookupTable<Fq>>::create();
        constrain_ivc::<Fq, _>(&mut ivc_constraint_env);
        ivc_constraint_env.get_relation_constraints()
    };

    // Sanity check: we want to verify that we only have maximum degree 5
    // constraints.
    // FIXME: we only want degree 2 (+1 for the selector in IVC).
    // FIXME: we do have degree 5 as the fold iteration and the public selectors
    // add one
    assert_eq!(
        app_constraints
            .iter()
            .chain(ivc_constraints.iter())
            .map(|c| c.degree(1, 0))
            .max(),
        Some(4)
    );

    // Make the constraints folding compatible
    let app_compat_constraints: Vec<FoldingCompatibleExpr<MainTestConfig>> = app_constraints
        .into_iter()
        .map(|x| FoldingCompatibleExpr::from(x.clone()))
        .collect();

    let ivc_compat_constraints: Vec<FoldingCompatibleExpr<MainTestConfig>> = {
        let ivc_compat_constraints: Vec<FoldingCompatibleExpr<MainTestConfig>> = ivc_constraints
            .into_iter()
            .map(|x| FoldingCompatibleExpr::from(x.clone()))
            .collect();

        // IVC column expression should be shifted to the right to accommodate
        // app witness.
        let ivc_mapper = &(|Variable { col, row }| {
            let rel_offset: usize = AdditionColumn::COUNT;
            let fsel_offset: usize = 0;
            let dsel_offset: usize = 0;
            use kimchi_msm::columns::Column::*;
            let new_col = match col {
                Relation(i) => Relation(i + rel_offset),
                FixedSelector(i) => FixedSelector(i + fsel_offset),
                DynamicSelector(i) => DynamicSelector(i + dsel_offset),
                c @ LookupPartialSum(_) => c,
                c @ LookupMultiplicity(_) => c,
                c @ LookupFixedTable(_) => c,
                c @ LookupAggregation => c,
            };
            Variable { col: new_col, row }
        });

        ivc_compat_constraints
            .into_iter()
            .map(|e| e.map_variable(ivc_mapper))
            .collect()
    };

    let folding_compat_constraints: Vec<FoldingCompatibleExpr<MainTestConfig>> =
        app_compat_constraints
            .into_iter()
            .chain(ivc_compat_constraints)
            .collect();

    // We have as many alphas as constraints
    assert!(
        folding_compat_constraints.len() == N_ALPHAS,
        "Folding compat constraints: expected {N_ALPHAS:?} got {}",
        folding_compat_constraints.len()
    );

    // real_folding_compat_constraint is actual constraint
    // it cannot be mapped back to Fp
    // has some u and {alpha^i}
    // this one needs to be used in prover(..).
    let (folding_scheme, real_folding_compat_constraint) = FoldingScheme::<MainTestConfig>::new(
        folding_compat_constraints.clone(),
        &srs,
        domain.d1,
        &structure,
    );

    let additional_columns = folding_scheme.get_number_of_additional_columns();

    assert_eq!(
        additional_columns, N_COL_QUAD,
        "Expected {N_COL_QUAD} additional quad columns, got {additional_columns}"
    );

    ////////////////////////////////////////////////////////////////////////////
    // Witness step 1 (APP + IVC)
    ////////////////////////////////////////////////////////////////////////////

    println!("Building witness step 1");

    type IVCWitnessBuilderEnvRaw<LT> =
        WitnessBuilderEnv<Fp, IVCColumn, N_WIT_IVC, N_WIT_IVC, 0, N_BLOCKS, LT>;
    type LT = IVCLookupTable<Fq>;

    let mut ivc_witness_env_0 = IVCWitnessBuilderEnvRaw::<LT>::create();

    let mut app_witness_one: AppWitnessBuilderEnv = WitnessBuilderEnv::create();

    let empty_logups: BTreeMap<LT, LogupWitness<Fp, LT>> = BTreeMap::new();

    // Witness one
    for _i in 0..domain_size {
        let a: Fp = Fp::rand(&mut rng);
        let b: Fp = Fp::rand(&mut rng);
        app_witness_one.write_column(AdditionColumn::A, &a);
        app_witness_one.write_column(AdditionColumn::B, &b);
        app_witness_one.write_column(AdditionColumn::C, &(a * a * b));
        interpreter_simple_add(&mut app_witness_one);
        app_witness_one.next_row();
    }

    let proof_inputs_one = ProofInputs {
        evaluations: app_witness_one.get_relation_witness(domain_size),
        logups: empty_logups.clone(),
    };
    assert!(proof_inputs_one.evaluations.len() == 3);

    ivc_witness_env_0.set_fixed_selectors(ivc_fixed_selectors.clone());
    ivc_circuit_base_case::<Fp, _, N_COL_TOTAL_QUAD, N_ALPHAS_QUAD>(
        &mut ivc_witness_env_0,
        domain_size,
    );
    let ivc_proof_inputs_0 = ProofInputs {
        evaluations: ivc_witness_env_0.get_relation_witness(domain_size),
        logups: empty_logups.clone(),
    };
    assert!(ivc_proof_inputs_0.evaluations.len() == N_WIT_IVC);
    for i in 0..10 {
        assert!(
            ivc_proof_inputs_0.evaluations[0][i] == Fp::zero(),
            "Iteration column row #{i:?} must be zero"
        );
    }

    // FIXME this merely concatenates two witnesses. Most likely, we
    // want to intersperse them in a smarter way later. Our witness is
    // Relation || dynamic.
    let joint_witness_one: Vec<_> = proof_inputs_one
        .evaluations
        .into_iter()
        .chain(ivc_proof_inputs_0.evaluations.clone())
        .collect();

    assert!(joint_witness_one.len() == N_COL_TOTAL);

    let folding_witness_one = PlonkishWitness {
        witness: joint_witness_one
            .into_par_iter()
            .map(|w| Evaluations::from_vec_and_domain(w.to_vec(), domain.d1))
            .collect(),
        fixed_selectors: ivc_fixed_selectors_evals_d1.clone().try_into().unwrap(),
        phantom: std::marker::PhantomData,
    };

    let folding_instance_one = PlonkishInstance::from_witness(
        &folding_witness_one.witness,
        &mut fq_sponge,
        &srs.full_srs,
        domain.d1,
    );

    ////////////////////////////////////////////////////////////////////////////
    // Witness step 2
    ////////////////////////////////////////////////////////////////////////////

    println!("Building witness step 2");

    let mut app_witness_two: AppWitnessBuilderEnv = WitnessBuilderEnv::create();

    // Witness two
    for _i in 0..domain_size {
        let a: Fp = Fp::rand(&mut rng);
        let b: Fp = Fp::rand(&mut rng);
        app_witness_two.write_column(AdditionColumn::A, &a);
        app_witness_two.write_column(AdditionColumn::B, &b);
        app_witness_two.write_column(AdditionColumn::C, &(a * a * b));
        interpreter_simple_add(&mut app_witness_two);
        app_witness_two.next_row();
    }

    let proof_inputs_two = ProofInputs {
        evaluations: app_witness_two.get_relation_witness(domain_size),
        logups: empty_logups.clone(),
    };

    // IVC for the second witness is the same as for the first one,
    // since they're both height 0.
    let joint_witness_two: Vec<_> = proof_inputs_two
        .evaluations
        .into_iter()
        .chain(ivc_proof_inputs_0.evaluations)
        .collect();

    let folding_witness_two_evals: GenericWitness<N_COL_TOTAL, Evaluations<Fp, R2D<Fp>>> =
        joint_witness_two
            .into_par_iter()
            .map(|w| Evaluations::from_vec_and_domain(w.to_vec(), domain.d1))
            .collect();
    let folding_witness_two = PlonkishWitness {
        witness: folding_witness_two_evals.clone(),
        fixed_selectors: ivc_fixed_selectors_evals_d1.clone().try_into().unwrap(),
        phantom: std::marker::PhantomData,
    };

    let folding_instance_two = PlonkishInstance::from_witness(
        &folding_witness_two.witness,
        &mut fq_sponge,
        &srs.full_srs,
        domain.d1,
    );

    ////////////////////////////////////////////////////////////////////////////
    // Folding 1
    ////////////////////////////////////////////////////////////////////////////

    println!("Folding 1");

    // To start, we only fold two instances.
    // We must call fold_instance_witness_pair in a nested call `fold`.
    // Something like:
    // ```
    // instances.tail().fold(instances.head(), |acc, two| {
    //     let folding_output = folding_scheme.fold_instance_witness_pair(acc, two, &mut fq_sponge);
    //     // Compute IVC
    //     // ...
    //     // We return the folding instance, which will be used in the next
    //     // iteration, which is the folded value `acc` with `two`.
    //     folding_instance
    // });
    // ```
    println!("fold_instance_witness_pair");
    let folding_output_one = folding_scheme.fold_instance_witness_pair(
        (folding_instance_one, folding_witness_one),
        (folding_instance_two, folding_witness_two),
        &mut fq_sponge,
    );
    println!("Folding 1 succeeded");

    let FoldingOutput {
        folded_instance: folded_instance_one,
        // Should not be required for the IVC circuit as it is encoding the
        // verifier.
        folded_witness: folded_witness_one,
        ..
    } = folding_output_one;

    // The polynomial of the computation is linear, therefore, the error terms
    // are zero
    assert_ne!(folding_output_one.t_0.get_first_chunk(), Curve::zero());
    assert_ne!(folding_output_one.t_1.get_first_chunk(), Curve::zero());

    // Sanity check that the u values are the same. The u value is there to
    // homogeneoize the polynomial describing the NP relation.
    assert_eq!(
        folding_output_one.relaxed_extended_left_instance.u,
        folding_output_one.relaxed_extended_right_instance.u
    );

    // 1. Get all the commitments from the left instance.
    // We want a way to get also the potential additional columns.
    let mut comms_left: Vec<Curve> = Vec::with_capacity(N_COL_TOTAL_QUAD);
    comms_left.extend(
        folding_output_one
            .relaxed_extended_left_instance
            .extended_instance
            .instance
            .commitments,
    );

    // Additional columns of quadri
    {
        let extended = folding_output_one
            .relaxed_extended_left_instance
            .extended_instance
            .extended;
        let extended_comms: Vec<_> = extended.iter().map(|x| x.get_first_chunk()).collect();
        comms_left.extend(extended_comms.clone());
        extended_comms.iter().enumerate().for_each(|(i, x)| {
            assert_ne!(
                x,
                &Curve::zero(),
                "Left extended commitment number {i:?} is zero"
            );
        });
    }
    assert_eq!(comms_left.len(), N_COL_TOTAL_QUAD);
    // Checking they are all not zero.
    comms_left.iter().enumerate().for_each(|(i, c)| {
        assert_ne!(c, &Curve::zero(), "Left commitment number {i:?} is zero");
    });

    // IVC is expecting the coordinates.
    let comms_left: [(Fq, Fq); N_COL_TOTAL_QUAD] =
        std::array::from_fn(|i| (comms_left[i].x, comms_left[i].y));

    // 2. Get all the commitments from the right instance.
    // We want a way to get also the potential additional columns.
    let mut comms_right = Vec::with_capacity(N_COL_TOTAL_QUAD);
    comms_right.extend(
        folding_output_one
            .relaxed_extended_left_instance
            .extended_instance
            .instance
            .commitments,
    );
    {
        let extended = folding_output_one
            .relaxed_extended_right_instance
            .extended_instance
            .extended;
        comms_right.extend(extended.iter().map(|x| x.get_first_chunk()));
    }
    assert_eq!(comms_right.len(), N_COL_TOTAL_QUAD);
    // Checking they are all not zero.
    comms_right.iter().enumerate().for_each(|(i, c)| {
        assert_ne!(c, &Curve::zero(), "Right commitment number {i:?} is zero");
    });

    // IVC is expecting the coordinates.
    let comms_right: [(Fq, Fq); N_COL_TOTAL_QUAD] =
        std::array::from_fn(|i| (comms_right[i].x, comms_right[i].y));

    // 3. Get all the commitments from the folded instance.
    // We want a way to get also the potential additional columns.
    let mut comms_out = Vec::with_capacity(AdditionColumn::N_COL + additional_columns);
    comms_out.extend(folded_instance_one.extended_instance.instance.commitments);
    {
        let extended = folded_instance_one.extended_instance.extended.clone();
        comms_out.extend(extended.iter().map(|x| x.get_first_chunk()));
    }
    // Checking they are all not zero.
    comms_out.iter().for_each(|c| {
        assert_ne!(c, &Curve::zero());
    });

    // IVC is expecting the coordinates.
    let comms_out: [(Fq, Fq); N_COL_TOTAL_QUAD] =
        std::array::from_fn(|i| (comms_out[i].x, comms_out[i].y));

    // FIXME: Should be handled in folding
    let left_error_term = srs
        .full_srs
        .mask_custom(
            folding_output_one
                .relaxed_extended_left_instance
                .error_commitment,
            &PolyComm::new(vec![Fp::one()]),
        )
        .unwrap()
        .commitment;

    // FIXME: Should be handled in folding
    let right_error_term = srs
        .full_srs
        .mask_custom(
            folding_output_one
                .relaxed_extended_right_instance
                .error_commitment,
            &PolyComm::new(vec![Fp::one()]),
        )
        .unwrap()
        .commitment;

    let error_terms = [
        left_error_term.get_first_chunk(),
        right_error_term.get_first_chunk(),
        folded_instance_one.error_commitment.get_first_chunk(),
    ];
    error_terms.iter().for_each(|c| {
        assert_ne!(c, &Curve::zero());
    });

    let error_terms: [(Fq, Fq); 3] = std::array::from_fn(|i| (error_terms[i].x, error_terms[i].y));

    let t_terms = [
        folding_output_one.t_0.get_first_chunk(),
        folding_output_one.t_1.get_first_chunk(),
    ];
    t_terms.iter().for_each(|c| {
        assert_ne!(c, &Curve::zero());
    });
    let t_terms: [(Fq, Fq); 2] = std::array::from_fn(|i| (t_terms[i].x, t_terms[i].y));

    let u = folding_output_one.relaxed_extended_left_instance.u;

    // FIXME: add columns of the previous IVC circuit in the comms_left,
    // comms_right and comms_out. Can be faked. We should have 400 + 3 columns
    let all_ivc_comms_left: [(Fq, Fq); N_COL_TOTAL_QUAD] = std::array::from_fn(|i| {
        if i < IVCColumn::N_COL {
            comms_left[0]
        } else {
            comms_left[i - IVCColumn::N_COL]
        }
    });
    let all_ivc_comms_right: [(Fq, Fq); N_COL_TOTAL_QUAD] = std::array::from_fn(|i| {
        if i < IVCColumn::N_COL {
            comms_right[0]
        } else {
            comms_right[i - IVCColumn::N_COL]
        }
    });
    let all_ivc_comms_out: [(Fq, Fq); N_COL_TOTAL_QUAD] = std::array::from_fn(|i| {
        if i < IVCColumn::N_COL {
            comms_out[0]
        } else {
            comms_out[i - IVCColumn::N_COL]
        }
    });

    let mut ivc_witness_env_1 = IVCWitnessBuilderEnvRaw::<LT>::create();
    ivc_witness_env_1.set_fixed_selectors(ivc_fixed_selectors.clone());

    let alphas: Vec<_> = folded_instance_one
        .extended_instance
        .instance
        .alphas
        .clone()
        .powers();
    assert!(
        alphas.len() == N_ALPHAS_QUAD,
        "Alphas length mismatch: expected {N_ALPHAS_QUAD} got {:?}",
        alphas.len()
    );

    ivc_circuit::<Fp, Fq, _, _, N_COL_TOTAL_QUAD, N_ALPHAS_QUAD>(
        &mut ivc_witness_env_1,
        1,
        Box::new(all_ivc_comms_left),
        Box::new(all_ivc_comms_right),
        Box::new(all_ivc_comms_out),
        error_terms,
        t_terms,
        u,
        o1_utils::array::vec_to_boxed_array(alphas),
        &PoseidonBN254Parameters,
        domain_size,
    );

    let ivc_proof_inputs_1 = ProofInputs {
        evaluations: ivc_witness_env_1.get_relation_witness(domain_size),
        logups: empty_logups.clone(),
    };
    assert!(ivc_proof_inputs_1.evaluations.len() == N_WIT_IVC);

    ////////////////////////////////////////////////////////////////////////////
    // Witness step 3
    ////////////////////////////////////////////////////////////////////////////

    println!("Witness step 3");

    let mut app_witness_three: WitnessBuilderEnv<Fp, AdditionColumn, 3, 3, 0, 0, DummyLookupTable> =
        WitnessBuilderEnv::create();

    // Witness three
    for _i in 0..domain_size {
        let a: Fp = Fp::rand(&mut rng);
        let b: Fp = Fp::rand(&mut rng);
        app_witness_three.write_column(AdditionColumn::A, &a);
        app_witness_three.write_column(AdditionColumn::B, &b);
        app_witness_three.write_column(AdditionColumn::C, &(a * a * b));
        interpreter_simple_add(&mut app_witness_three);
        app_witness_three.next_row();
    }

    let proof_inputs_three = ProofInputs {
        evaluations: app_witness_three.get_relation_witness(domain_size),
        logups: empty_logups.clone(),
    };

    // Here we concatenate with ivc_proof_inputs 1, inductive case
    let joint_witness_three: Vec<_> = (proof_inputs_three.evaluations)
        .into_iter()
        .chain(ivc_proof_inputs_1.evaluations)
        .collect();

    assert!(joint_witness_three.len() == N_COL_TOTAL);

    let folding_witness_three_evals: Vec<Evaluations<Fp, R2D<Fp>>> = (&joint_witness_three)
        .into_par_iter()
        .map(|w| Evaluations::from_vec_and_domain(w.to_vec(), domain.d1))
        .collect();
    let folding_witness_three = PlonkishWitness {
        witness: folding_witness_three_evals.clone().try_into().unwrap(),
        fixed_selectors: ivc_fixed_selectors_evals_d1.clone().try_into().unwrap(),
        phantom: std::marker::PhantomData,
    };

    let mut fq_sponge_before_instance_three = fq_sponge.clone();

    let folding_instance_three = PlonkishInstance::from_witness(
        &folding_witness_three.witness,
        &mut fq_sponge,
        &srs.full_srs,
        domain.d1,
    );

    ////////////////////////////////////////////////////////////////////////////
    // Folding 2
    ////////////////////////////////////////////////////////////////////////////

    println!("Folding two");

    let mut fq_sponge_before_last_fold = fq_sponge.clone();

    let folding_output_two = folding_scheme.fold_instance_witness_pair(
        (folded_instance_one.clone(), folded_witness_one.clone()),
        (
            folding_instance_three.clone(),
            folding_witness_three.clone(),
        ),
        &mut fq_sponge,
    );

    let folded_instance_two = folding_output_two.folded_instance;
    let folded_witness_two = folding_output_two.folded_witness;

    ////////////////////////////////////////////////////////////////////////////
    // Testing folding exprs validity for last  fold
    ////////////////////////////////////////////////////////////////////////////

    let enlarge_to_domain_generic = |evaluations: &Evaluations<Fp, R2D<Fp>>,
                                     new_domain: R2D<Fp>| {
        assert!(evaluations.domain() == domain.d1);
        evaluations
            .interpolate_by_ref()
            .evaluate_over_domain(new_domain)
    };

    {
        println!("Testing individual expressions validity; creating evaluations");

        let simple_eval_env: SimpleEvalEnv<Curve, N_COL_TOTAL, N_FSEL_TOTAL> = {
            let enlarge_to_domain = |evaluations: &Evaluations<Fp, R2D<Fp>>| {
                enlarge_to_domain_generic(evaluations, domain.d8)
            };

            let alpha = fq_sponge.challenge();
            let alphas = Alphas::new_sized(alpha, N_ALPHAS);
            assert!(
                alphas.clone().powers().len() == N_ALPHAS,
                "Expected N_ALPHAS = {N_ALPHAS:?}, got {}",
                alphas.clone().powers().len()
            );

            let beta = fq_sponge.challenge();
            let gamma = fq_sponge.challenge();
            let joint_combiner = fq_sponge.challenge();
            let challenges = [beta, gamma, joint_combiner];

            SimpleEvalEnv {
                ext_witness: ExtendedWitness {
                    witness: PlonkishWitness {
                        witness: (&folding_witness_three_evals)
                            .into_par_iter()
                            .map(enlarge_to_domain)
                            .collect(),
                        fixed_selectors: (&ivc_fixed_selectors_evals_d1)
                            .into_par_iter()
                            .map(enlarge_to_domain)
                            .collect(),
                        phantom: std::marker::PhantomData,
                    },
                    extended: BTreeMap::new(), // No extended columns at this point
                },
                alphas,
                challenges,
                error_vec: Evaluations::from_vec_and_domain(vec![], domain.d1),
                u: Fp::zero(),
            }
        };

        {
            let target_expressions: Vec<FoldingCompatibleExpr<MainTestConfig>> =
                folding_compat_constraints.clone();

            for (expr_i, expr) in target_expressions.iter().enumerate() {
                let eval_leaf = simple_eval_env.eval_naive_fcompat(expr);

                let evaluations_d8 = match eval_leaf {
                    EvalLeaf::Result(evaluations_d8) => evaluations_d8,
                    EvalLeaf::Col(evaluations_d8) => evaluations_d8.to_vec(),
                    _ => panic!("eval_leaf is not Result"),
                };

                let interpolated =
                    Evaluations::from_vec_and_domain(evaluations_d8.clone(), domain.d8)
                        .interpolate();
                if !interpolated.is_zero() {
                    let (_, remainder) = interpolated.divide_by_vanishing_poly(domain.d1);
                    if !remainder.is_zero() {
                        panic!("Remainder is not zero for expression #{expr_i}: {}", expr,);
                    }
                }
            }

            println!("All folding_compat_constraints for APP+(nontrivial) IVC satisfy FoldingExps");
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Testing folding exprs validity with quadraticization
    ////////////////////////////////////////////////////////////////////////////

    {
        println!("Testing joint folding expression validity /with quadraticization/; creating evaluations");

        // We can evaluate on d1, and then if the interpolated
        // polynomial is 0, the expression holds. This is fast to do,
        // and it effectively checks if the expressions hold.
        //
        // However this is not enough for computing quotient, since
        // folding expressions are degree ... 2 or 3? So when this
        // variable is set to domain.d8, all the evaluations will
        // happen over d8, and quotient_polyonmial computation becomes
        // possible. But this is 8 times slower.
        let evaluation_domain = domain.d1;

        let enlarge_to_domain = |evaluations: &Evaluations<Fp, R2D<Fp>>| {
            enlarge_to_domain_generic(evaluations, evaluation_domain)
        };

        let simple_eval_env: SimpleEvalEnv<Curve, N_COL_TOTAL, N_FSEL_TOTAL> = {
            let ext_witness = ExtendedWitness {
                witness: PlonkishWitness {
                    witness: (&folded_witness_two.extended_witness.witness.witness)
                        .into_par_iter()
                        .map(enlarge_to_domain)
                        .collect(),
                    fixed_selectors: (&ivc_fixed_selectors_evals_d1)
                        .into_par_iter()
                        .map(enlarge_to_domain)
                        .collect(),
                    phantom: std::marker::PhantomData,
                },
                extended: folded_witness_two
                    .extended_witness
                    .extended
                    .iter()
                    .map(|(ix, evals)| (*ix, enlarge_to_domain(evals)))
                    .collect(),
            };

            SimpleEvalEnv {
                ext_witness,
                alphas: folded_instance_two
                    .extended_instance
                    .instance
                    .alphas
                    .clone(),
                challenges: folded_instance_two.extended_instance.instance.challenges,
                error_vec: enlarge_to_domain(&folded_witness_two.error_vec),
                u: folded_instance_two.u,
            }
        };

        {
            let expr: FoldingCompatibleExpr<MainTestConfig> =
                real_folding_compat_constraint.clone();

            let eval_leaf = simple_eval_env.eval_naive_fcompat(&expr);

            let evaluations_big = match eval_leaf {
                EvalLeaf::Result(evaluations) => evaluations,
                EvalLeaf::Col(evaluations) => evaluations.to_vec(),
                _ => panic!("eval_leaf is not Result"),
            };

            let interpolated =
                Evaluations::from_vec_and_domain(evaluations_big, evaluation_domain).interpolate();
            if !interpolated.is_zero() {
                let (_, remainder) = interpolated.divide_by_vanishing_poly(domain.d1);
                if !remainder.is_zero() {
                    panic!(
                        "ERROR: Remainder is not zero for joint expression: {}",
                        expr
                    );
                } else {
                    println!("Interpolated expression is divisible by vanishing poly d1");
                }
            } else {
                println!("Interpolated expression is zero");
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // SNARKing everything
    ////////////////////////////////////////////////////////////////////////////

    // quad columns become regular witness columns
    let real_folding_compat_constraint_quad_merged: FoldingCompatibleExpr<MainTestConfig> = {
        let noquad_mapper = &(|quad_index: usize| {
            let col = kimchi_msm::columns::Column::Relation(N_COL_TOTAL + quad_index);
            Variable {
                col,
                row: CurrOrNext::Curr,
            }
        });

        real_folding_compat_constraint
            .clone()
            .flatten_quad_columns(noquad_mapper)
    };

    println!("Creating a proof");

    let proof = ivc::prover::prove::<
        BaseSponge,
        ScalarSponge,
        MainTestConfig,
        _,
        N_COL_TOTAL,
        N_COL_TOTAL_QUAD,
        N_COL_TOTAL,
        0,
        N_FSEL_TOTAL,
        N_ALPHAS_QUAD,
    >(
        domain,
        &srs,
        &real_folding_compat_constraint,
        folded_instance_two.clone(),
        folded_witness_two.clone(),
        &mut rng,
    )
    .unwrap();

    ////////////////////////////////////////////////////////////////////////////
    // Verifying;
    //   below is everything one needs to do to verify the whole computation
    ////////////////////////////////////////////////////////////////////////////

    println!("Verifying a proof");

    let fixed_selectors_verifier = folded_witness_two
        .extended_witness
        .witness
        .fixed_selectors
        .cols;

    // Check that the last SNARK is correct
    let verifies = ivc::verifier::verify::<
        BaseSponge,
        ScalarSponge,
        MainTestConfig,
        N_COL_TOTAL_QUAD,
        N_COL_TOTAL_QUAD,
        0,
        N_FSEL_TOTAL,
        0,
    >(
        domain,
        &srs,
        &real_folding_compat_constraint_quad_merged,
        fixed_selectors_verifier,
        &proof,
    );

    assert!(verifies, "The proof does not verify");

    // Check that the last fold is correct

    println!("Checking last fold was done correctly");

    {
        assert!(
            folded_instance_two
                == folding_scheme.fold_instance_pair(
                    folding_output_two.relaxed_extended_left_instance,
                    folding_output_two.relaxed_extended_right_instance,
                    [folding_output_two.t_0, folding_output_two.t_1],
                    &mut fq_sponge_before_last_fold,
                ),
            "Last fold must (natively) verify"
        );
    }

    // We have to check that:
    // 1. `folding_instance_three` is relaxed (E = 0, u = 1)
    // 2. u.x = Hash(n, z0, zn, U)

    // We don't yet do (2) because we don't support public input yet.
    //
    // And (1) we achieve automatically because
    // `folding_instance_three` is a `PlonkishInstance` and not
    // `RelaxedInstance`. We only have to check that its `alphas` are
    // powers (and not arbitrary elements):

    // Check that `folding_instance_three` vas relaxed.
    assert_eq!(
        Ok(()),
        folding_instance_three.verify_from_witness(&mut fq_sponge_before_instance_three)
    );
}
