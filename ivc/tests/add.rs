//! This is a simple example of how to use the folding crate with the IVC crate
//! to fold a simple addition circuit. The addition circuit consists of a single
//! constraint of degree 1 over 3 columns (A + B - C = 0).

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_poly::Evaluations;
use folding::{
    expressions::FoldingColumnTrait,
    instance_witness::Foldable,
    standard_config::{EmptyStructure, StandardConfig},
    Alphas, FoldingCompatibleExpr, FoldingScheme, Instance, Witness,
};
use ivc::{
    ivc::{
        columns::{IVCColumn, IVC_NB_TOTAL_FIXED_SELECTORS, N_BLOCKS},
        constraints::constrain_ivc,
        interpreter::build_selectors,
        lookups::IVCLookupTable,
        IVC_NB_CHALLENGES,
    },
    poseidon_8_56_5_3_2::{
        bn254::{PoseidonBN254Parameters, STATE_SIZE as IVC_POSEIDON_STATE_SIZE},
        interpreter::PoseidonParams,
    },
};
use kimchi::circuits::expr::{ChallengeTerm, Variable};
use kimchi_msm::{columns::ColumnIndexer, witness::Witness as GenericWitness};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge, FqSponge};
use rayon::iter::IntoParallelIterator as _;
use std::{array, ops::Index};
use strum::EnumCount;
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};

use ark_ff::{One, UniformRand};
use ark_poly::Radix2EvaluationDomain;
use kimchi::circuits::domains::EvaluationDomains;
use kimchi_msm::{
    circuit_design::{ColWriteCap, ConstraintBuilderEnv, WitnessBuilderEnv},
    columns::Column,
    expr::E,
    lookups::DummyLookupTable,
};
use poly_commitment::{commitment::absorb_commitment, srs::SRS, PolyComm, SRS as _};
use rayon::iter::ParallelIterator as _;

use itertools::Itertools;

/// The scalar field of the curve
pub type Fp = ark_bn254::Fr;
/// The base field of the curve
/// Used to encode the polynomial commitments
pub type Fq = ark_bn254::Fq;
/// The curve we commit into
pub type Curve = ark_bn254::G1Affine;

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

use ark_ff::PrimeField;
use kimchi_msm::circuit_design::{ColAccessCap, HybridCopyCap};

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
pub fn test_simple_add() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let domain_size: usize = 1 << 15;
    let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

    let mut srs = SRS::<Curve>::create(domain_size);
    srs.add_lagrange_basis(domain.d1);

    // ---- Defining the folding configuration ----
    // FoldingConfig
    impl FoldingColumnTrait for AdditionColumn {
        fn is_witness(&self) -> bool {
            true
        }
    }

    type AppWitnessBuildEnv = WitnessBuilderEnv<
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
        pub witness: GenericWitness<N_COL, Evaluations<Fp, Radix2EvaluationDomain<Fp>>>,
        pub fixed_selectors: GenericWitness<N_FSEL, Evaluations<Fp, Radix2EvaluationDomain<Fp>>>,
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
            w: &GenericWitness<N_COL, Evaluations<Fp, Radix2EvaluationDomain<Fp>>>,
            fq_sponge: &mut BaseSponge,
            srs: &SRS<Curve>,
            domain: Radix2EvaluationDomain<Fp>,
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

    // Total number of witness columns in IVC. The blocks are public selectors.
    const N_WIT_IVC: usize = <IVCColumn as ColumnIndexer>::N_COL - N_BLOCKS;
    // Total number of fixed selectors in the circuit for APP + IVC.
    // There is no fixed selector in the APP circuit.
    const N_FSEL_TOTAL: usize = IVC_NB_TOTAL_FIXED_SELECTORS;

    // Total number of challenges required by the circuit APP + IVC.
    // The number of challenges required by the IVC is defined by the library.
    // Therefore, we only need to add the challenges required by the specific
    // application.
    const N_CHALS: usize = IVC_NB_CHALLENGES + Challenge::COUNT;

    // Number of witness columns in the circuit.
    // It consists of the columns of the inner circuit and the columns for the
    // IVC circuit.
    pub const N_COL_TOTAL: usize = AdditionColumn::COUNT + N_WIT_IVC;

    type Config = StandardConfig<
        Curve,
        Column,
        Challenge,
        PlonkishInstance<N_COL_TOTAL>,
        PlonkishWitness<N_COL_TOTAL, N_FSEL_TOTAL>,
    >;

    // ---- End of folding configuration ----

    // ---- Start folding configuration with IVC ----
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

    // Sanity check: we want to verify that we only have maximum degree 4
    // constraints.
    // FIXME: we only want degree 2 (+1 for the selector in IVC).
    app_constraints
        .iter()
        .chain(ivc_constraints.iter())
        .enumerate()
        .for_each(|(i, c)| {
            assert!(
                c.degree(1, 0) <= 4,
                "Constraint {} has degree > 4: {:}",
                i,
                c
            );
        });

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

    let structure = EmptyStructure::default();

    let (folding_scheme, _real_folding_compat_constraints) =
        FoldingScheme::<Config>::new(folding_compat_constraints, &srs, domain.d1, &structure);

    println!("Additional columns: {:?}", folding_scheme.get_number_of_additional_columns());

    // End of folding configuration for IVC + APP

    // Starting building witnesses. We start with the application witnesses. It
    // will be used after that to build the witness for the IVC
    let mut _app_witness_one: AppWitnessBuildEnv = {
        let mut env = WitnessBuilderEnv::create();

        for _i in 0..domain_size {
            let a: Fp = Fp::rand(&mut rng);
            let b: Fp = Fp::rand(&mut rng);
            env.write_column(AdditionColumn::A, &a);
            env.write_column(AdditionColumn::B, &b);
            interpreter_simple_add(&mut env);
            env.next_row();
        }
        env
    };

    let mut _app_witness_two: AppWitnessBuildEnv = {
        let mut env = WitnessBuilderEnv::create();

        for _i in 0..domain_size {
            let a: Fp = Fp::rand(&mut rng);
            let b: Fp = Fp::rand(&mut rng);
            env.write_column(AdditionColumn::A, &a);
            env.write_column(AdditionColumn::B, &b);
            interpreter_simple_add(&mut env);
            env.next_row();
        }
        env
    };

    // ---- Start build the witness environment for the IVC
    // Start building the constants of the circuit.
    // For the IVC, we have all the "block selectors" - which depends on the
    // number of columns of the circuit - and the poseidon round constants.
    // FIXME: N_COL_TOTAL is not correct, it is missing the columns required to
    // reduce the IVC constraints to degree 2.
    let mut ivc_fixed_selectors: Vec<Vec<Fp>> =
        build_selectors::<_, N_COL_TOTAL, N_CHALS>(domain_size).to_vec();

    // FIXME: we should have a function in the poseidon crate to fill a vector
    // of selectors
    {
        let rc = PoseidonBN254Parameters.constants();
        rc.iter().enumerate().for_each(|(round, rcs)| {
            rcs.iter().enumerate().for_each(|(state_index, rc)| {
                ivc_fixed_selectors[N_BLOCKS + round * IVC_POSEIDON_STATE_SIZE + state_index] =
                    vec![*rc; domain_size];
            });
        });
    }

    // Sanity check on the domain size, can be removed later
    assert_eq!(ivc_fixed_selectors.len(), N_FSEL_TOTAL);
    ivc_fixed_selectors.iter().for_each(|s| {
        assert_eq!(s.len(), domain_size);
    });

    let _ivc_fixed_selectors_evals_d1: Vec<Evaluations<Fp, Radix2EvaluationDomain<Fp>>> =
        ivc_fixed_selectors
            .into_par_iter()
            .map(|w| Evaluations::from_vec_and_domain(w, domain.d1))
            .collect();
}
