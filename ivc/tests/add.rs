//! This is a simple example of how to use the folding crate with the IVC crate
//! to fold a simple addition circuit. The addition circuit consists of a single
//! constraint of degree 1 over 3 columns (A + B - C = 0).

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_poly::{Evaluations, Radix2EvaluationDomain as R2D};
use folding::{
    expressions::FoldingColumnTrait, instance_witness::Foldable, standard_config::StandardConfig,
    Alphas, FoldingCompatibleExpr, FoldingScheme, Instance, Witness,
};
use ivc::{
    self,
    ivc::{
        columns::{IVCColumn, N_BLOCKS, N_FSEL_IVC},
        constraints::constrain_ivc,
        interpreter::{build_selectors, ivc_circuit_base_case},
        lookups::IVCLookupTable,
        N_ADDITIONAL_WIT_COL_QUAD as N_COL_QUAD_IVC, N_ALPHAS as N_ALPHAS_IVC,
    },
};
use kimchi::{
    circuits::{
        domains::EvaluationDomains,
        expr::{ChallengeTerm, Variable},
    },
    curve::KimchiCurve,
};
use kimchi_msm::{
    circuit_design::{
        ColAccessCap, ColWriteCap, ConstraintBuilderEnv, HybridCopyCap, WitnessBuilderEnv,
    },
    columns::{Column, ColumnIndexer},
    expr::E,
    lookups::DummyLookupTable,
    witness::Witness as GenericWitness,
    BN254G1Affine, Fp,
};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge, FqSponge};
use poly_commitment::{
    commitment::absorb_commitment, lagrange_cache, srs::SRS, PolyComm, SRS as _,
};
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};
use std::{array, collections::BTreeMap, ops::Index};
use strum::EnumCount;
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};

use itertools::Itertools;

/// The base field of the curve
/// Used to encode the polynomial commitments
pub type Fq = ark_bn254::Fq;
/// The curve we commit into
pub type Curve = BN254G1Affine;

pub type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;
pub type SpongeParams = PlonkSpongeConstantsKimchi;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, EnumIter, EnumCountMacro, Hash)]
pub enum AdditionColumn {
    A,
    B,
    C,
}

impl ColumnIndexer for AdditionColumn {
    const N_COL: usize = 3;

    fn to_column(self) -> Column {
        match self {
            AdditionColumn::A => Column::Relation(0),
            AdditionColumn::B => Column::Relation(1),
            AdditionColumn::C => Column::Relation(2),
        }
    }
}

#[derive(Clone)]
/// Generic structure containing column vectors.
pub struct GenericVecStructure<G: KimchiCurve>(Vec<Vec<G::ScalarField>>);

impl<G: KimchiCurve> Index<Column> for GenericVecStructure<G> {
    type Output = Vec<G::ScalarField>;

    fn index(&self, index: Column) -> &Self::Output {
        match index {
            Column::FixedSelector(i) => &self.0[i],
            _ => panic!("should not happen"),
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
    env.hcopy(&(a.clone() + b.clone()), AdditionColumn::C);
    let c = env.read_column(AdditionColumn::C);
    let eq = a.clone() + b.clone() - c;
    env.assert_zero(eq);
}

#[test]
pub fn heavy_test_simple_add() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    // FIXME: this has to be 1 << 15. the 16 is temporary, since we
    // are at 35783 rows right now, but can only allow 32768. Light
    // future optimisations will get us back to 15.
    let domain_size: usize = 1 << 16;
    let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

    let mut fq_sponge: BaseSponge = FqSponge::new(Curve::other_curve_sponge_params());

    let mut srs = SRS::<Curve>::create(domain_size);
    srs.add_lagrange_basis_with_cache(domain.d1, &lagrange_cache::test_caches::get_file_cache());

    // Total number of witness columns in IVC. The blocks are public selectors.
    const N_WIT_IVC: usize = <IVCColumn as ColumnIndexer>::N_COL - N_BLOCKS;
    // Total number of fixed selectors in the circuit for APP + IVC.
    // There is no fixed selector in the APP circuit.
    const N_FSEL_TOTAL: usize = N_FSEL_IVC;

    // Our application circuit has two constraints.
    const N_ALPHAS_APP: usize = 2;
    // Total number of challenges required by the circuit APP + IVC.
    // The number of challenges required by the IVC is defined by the library.
    // Therefore, we only need to add the challenges required by the specific
    // application.
    const N_ALPHAS: usize = N_ALPHAS_IVC + N_ALPHAS_APP;
    // There are two more challenges though.
    const N_CHALS: usize = N_ALPHAS + Challenge::COUNT;

    // Number of witness columns in the circuit.
    // It consists of the columns of the inner circuit and the columns for the
    // IVC circuit.
    const N_COL_TOTAL: usize = AdditionColumn::COUNT + N_WIT_IVC;
    // No quad in APP.
    const N_COL_QUAD: usize = N_COL_QUAD_IVC;
    const N_COL_TOTAL_QUAD: usize = N_COL_TOTAL + N_COL_QUAD;

    // ---- Defining the folding configuration ----
    // FoldingConfig
    impl FoldingColumnTrait for AdditionColumn {
        fn is_witness(&self) -> bool {
            true
        }
    }

    type AppWitnessBuilderEnv = WitnessBuilderEnv<
        Fp,
        AdditionColumn,
        { AdditionColumn::COUNT },
        { AdditionColumn::COUNT },
        0,
        0,
        DummyLookupTable,
    >;

    // Folding Witness
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct PlonkishWitness<const N_COL: usize, const N_FSEL: usize> {
        pub witness: GenericWitness<N_COL, Evaluations<Fp, R2D<Fp>>>,
        pub fixed_selectors: GenericWitness<N_FSEL, Evaluations<Fp, R2D<Fp>>>,
    }

    // Trait required for folding

    impl<const N_COL: usize, const N_FSEL: usize> Foldable<Fp> for PlonkishWitness<N_COL, N_FSEL> {
        fn combine(mut a: Self, b: Self, challenge: Fp) -> Self {
            for (a, b) in (*a.witness.cols).iter_mut().zip(*(b.witness.cols)) {
                for (a, b) in a.evals.iter_mut().zip(b.evals) {
                    *a += challenge * b;
                }
            }
            a
        }
    }

    impl<const N_COL: usize, const N_FSEL: usize> Witness<Curve> for PlonkishWitness<N_COL, N_FSEL> {}

    impl<const N_COL: usize, const N_FSEL: usize> Index<AdditionColumn>
        for PlonkishWitness<N_COL, N_FSEL>
    {
        type Output = Vec<Fp>;

        fn index(&self, index: AdditionColumn) -> &Self::Output {
            match index {
                AdditionColumn::A => &self.witness.cols[0].evals,
                AdditionColumn::B => &self.witness.cols[1].evals,
                AdditionColumn::C => &self.witness.cols[2].evals,
            }
        }
    }

    impl<const N_COL: usize, const N_FSEL: usize> Index<Column> for PlonkishWitness<N_COL, N_FSEL> {
        type Output = Vec<Fp>;

        /// Map a column alias to the corresponding witness column.
        fn index(&self, index: Column) -> &Self::Output {
            match index {
                Column::Relation(i) => &self.witness.cols[i].evals,
                Column::FixedSelector(i) => &self.fixed_selectors[i].evals,
                other => panic!("Invalid column index: {other:?}"),
            }
        }
    }

    // for selectors, () in this case as we have none
    impl<const N_COL: usize, const N_FSEL: usize> Index<()> for PlonkishWitness<N_COL, N_FSEL> {
        type Output = Vec<Fp>;

        fn index(&self, _index: ()) -> &Self::Output {
            unreachable!()
        }
    }

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EnumIter, EnumCountMacro)]
    pub enum Challenge {
        Beta,
        Gamma,
        JointCombiner,
    }

    impl From<ChallengeTerm> for Challenge {
        fn from(chal: ChallengeTerm) -> Self {
            match chal {
                ChallengeTerm::Beta => Challenge::Beta,
                ChallengeTerm::Gamma => Challenge::Gamma,
                ChallengeTerm::JointCombiner => Challenge::JointCombiner,
                ChallengeTerm::Alpha => panic!("Alpha not allowed in folding expressions"),
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct PlonkishInstance<const N_COL: usize> {
        commitments: [Curve; N_COL],
        challenges: [Fp; Challenge::COUNT],
        alphas: Alphas<Fp>,
        blinder: Fp,
    }

    impl<const N_COL: usize> Foldable<Fp> for PlonkishInstance<N_COL> {
        fn combine(a: Self, b: Self, challenge: Fp) -> Self {
            Self {
                commitments: array::from_fn(|i| {
                    a.commitments[i] + b.commitments[i].mul(challenge).into_affine()
                }),
                challenges: array::from_fn(|i| a.challenges[i] + challenge * b.challenges[i]),
                alphas: Alphas::combine(a.alphas, b.alphas, challenge),
                blinder: a.blinder + challenge * b.blinder,
            }
        }
    }

    impl<const N_COL: usize> Index<Challenge> for PlonkishInstance<N_COL> {
        type Output = Fp;

        fn index(&self, index: Challenge) -> &Self::Output {
            match index {
                Challenge::Beta => &self.challenges[0],
                Challenge::Gamma => &self.challenges[1],
                Challenge::JointCombiner => &self.challenges[2],
            }
        }
    }

    impl<const N_COL: usize> Instance<Curve> for PlonkishInstance<N_COL> {
        fn to_absorb(&self) -> (Vec<Fp>, Vec<Curve>) {
            // FIXME: check!!!!
            let mut scalars = Vec::new();
            let mut points = Vec::new();
            points.extend(self.commitments);
            scalars.extend(self.challenges);
            scalars.extend(self.alphas.clone().powers());
            (scalars, points)
        }

        fn get_alphas(&self) -> &Alphas<Fp> {
            &self.alphas
        }

        fn get_blinder(&self) -> Fp {
            self.blinder
        }
    }

    impl<const N_COL: usize> PlonkishInstance<N_COL> {
        #[allow(dead_code)]
        pub fn from_witness(
            w: &GenericWitness<N_COL, Evaluations<Fp, R2D<Fp>>>,
            fq_sponge: &mut BaseSponge,
            srs: &SRS<Curve>,
            domain: R2D<Fp>,
        ) -> Self {
            let blinder = Fp::one();

            let commitments: GenericWitness<N_COL, PolyComm<Curve>> = w
                .into_par_iter()
                .map(|w| {
                    let blinder = PolyComm::new(vec![blinder; 1]);
                    let unblinded = srs.commit_evaluations_non_hiding(domain, w);
                    srs.mask_custom(unblinded, &blinder).unwrap().commitment
                })
                .collect();

            // Absorbing commitments
            (&commitments)
                .into_iter()
                .for_each(|c| absorb_commitment(fq_sponge, c));

            let commitments: [Curve; N_COL] = commitments
                .into_iter()
                .map(|c| c.elems[0])
                .collect_vec()
                .try_into()
                .unwrap();

            let beta = fq_sponge.challenge();
            let gamma = fq_sponge.challenge();
            let joint_combiner = fq_sponge.challenge();
            let challenges = [beta, gamma, joint_combiner];

            let alpha = fq_sponge.challenge();
            let alphas = Alphas::new(alpha);

            Self {
                commitments,
                challenges,
                alphas,
                blinder,
            }
        }
    }

    type Config = StandardConfig<
        Curve,
        Column,
        Challenge,
        PlonkishInstance<N_COL_TOTAL>,
        PlonkishWitness<N_COL_TOTAL, N_FSEL_TOTAL>,
        (),
        GenericVecStructure<Curve>,
    >;

    ////////////////////////////////////////////////////////////////////////////
    // Fixed Selectors
    ////////////////////////////////////////////////////////////////////////////

    // ---- Start build the witness environment for the IVC
    // Start building the constants of the circuit.
    // For the IVC, we have all the "block selectors" - which depends on the
    // number of columns of the circuit - and the poseidon round constants.
    // FIXME: N_COL_TOTAL is not correct, it is missing the columns required to
    // reduce the IVC constraints to degree 2.
    let ivc_fixed_selectors: Vec<Vec<Fp>> =
        build_selectors::<N_COL_TOTAL_QUAD, N_CHALS>(domain_size).to_vec();

    // Sanity check on the domain size, can be removed later
    assert_eq!(ivc_fixed_selectors.len(), N_FSEL_TOTAL);
    ivc_fixed_selectors.iter().for_each(|s| {
        assert_eq!(s.len(), domain_size);
    });

    let ivc_fixed_selectors_evals_d1: Vec<Evaluations<Fp, R2D<Fp>>> = ivc_fixed_selectors
        .clone()
        .into_par_iter()
        .map(|w| Evaluations::from_vec_and_domain(w, domain.d1))
        .collect();

    let structure = GenericVecStructure(
        ivc_fixed_selectors_evals_d1
            .clone()
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
    let app_compat_constraints: Vec<FoldingCompatibleExpr<Config>> = app_constraints
        .into_iter()
        .map(|x| FoldingCompatibleExpr::from(x.clone()))
        .collect();

    let ivc_compat_constraints: Vec<FoldingCompatibleExpr<Config>> = {
        let ivc_compat_constraints: Vec<FoldingCompatibleExpr<Config>> = ivc_constraints
            .into_iter()
            .map(|x| FoldingCompatibleExpr::from(x.clone()))
            .collect();

        // IVC column expression should be shifted to the right to accomodate
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

    let folding_compat_constraints: Vec<FoldingCompatibleExpr<Config>> = app_compat_constraints
        .into_iter()
        .chain(ivc_compat_constraints)
        .collect();

    // We have as many alphas as constraints
    assert!(
        folding_compat_constraints.len() == N_ALPHAS,
        "Folding compat constraints: expected {N_ALPHAS:?} got {}",
        folding_compat_constraints.len()
    );

    let (folding_scheme, _real_folding_compat_constraints) =
        FoldingScheme::<Config>::new(folding_compat_constraints, &srs, domain.d1, &structure);

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

    let empty_lookups_app = BTreeMap::new();
    let empty_lookups_ivc = BTreeMap::new();

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

    let proof_inputs_one = app_witness_one.get_proof_inputs(domain_size, empty_lookups_app.clone());
    assert!(proof_inputs_one.evaluations.len() == 3);

    ivc_witness_env_0.set_fixed_selectors(ivc_fixed_selectors.clone());
    ivc_circuit_base_case::<Fp, _, N_COL_TOTAL, N_CHALS>(&mut ivc_witness_env_0, domain_size);
    let ivc_proof_inputs_0 =
        ivc_witness_env_0.get_proof_inputs(domain_size, empty_lookups_ivc.clone());
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
        .clone()
        .into_iter()
        .chain(ivc_proof_inputs_0.evaluations.clone())
        .collect();

    for i in 0..10 {
        assert!(
            ivc_proof_inputs_0.evaluations[0][i] == Fp::zero(),
            "Iteration column row #{i:?} must be zero"
        );
    }

    assert!(joint_witness_one.len() == N_COL_TOTAL);

    let folding_witness_one = PlonkishWitness {
        witness: joint_witness_one
            .into_par_iter()
            .map(|w| Evaluations::from_vec_and_domain(w.to_vec(), domain.d1))
            .collect(),
        fixed_selectors: ivc_fixed_selectors_evals_d1.clone().try_into().unwrap(),
    };

    let folding_instance_one = PlonkishInstance::from_witness(
        &folding_witness_one.witness,
        &mut fq_sponge,
        &srs,
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

    let proof_inputs_two = app_witness_two.get_proof_inputs(domain_size, empty_lookups_app.clone());

    // IVC for the second witness is the same as for the first one,
    // since they're both height 0.
    let joint_witness_two: Vec<_> = proof_inputs_two
        .evaluations
        .clone()
        .into_iter()
        .chain(ivc_proof_inputs_0.evaluations)
        .collect();

    let folding_witness_two_evals: GenericWitness<N_COL_TOTAL, Evaluations<Fp, R2D<Fp>>> =
        joint_witness_two
            .clone()
            .into_par_iter()
            .map(|w| Evaluations::from_vec_and_domain(w.to_vec(), domain.d1))
            .collect();
    let folding_witness_two = PlonkishWitness {
        witness: folding_witness_two_evals.clone(),
        fixed_selectors: ivc_fixed_selectors_evals_d1.clone().try_into().unwrap(),
    };

    let folding_instance_two = PlonkishInstance::from_witness(
        &folding_witness_two.witness,
        &mut fq_sponge,
        &srs,
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
    let one = (folding_instance_one, folding_witness_one);
    let two = (folding_instance_two, folding_witness_two);
    println!("fold_instance_witness_pair");
    let _folding_output = folding_scheme.fold_instance_witness_pair(one, two, &mut fq_sponge);
    println!("Folding 1 succeeded");
}
