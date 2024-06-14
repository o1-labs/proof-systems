//! This is a simple example of how to use the folding crate with the IVC crate
//! to fold a simple addition circuit. The addition circuit consists of a single
//! constraint of degree 1 over 3 columns (A + B - C = 0).

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{One, UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain as R2D};
use folding::{
    expressions::{FoldingColumnTrait, FromFoldingConversionError},
    instance_witness::Foldable,
    Alphas, FoldingCompatibleExpr, FoldingConfig, FoldingEnv, FoldingOutput, FoldingScheme,
    Instance, Side, Witness,
};
use itertools::Itertools;
use ivc::{
    ivc::{
        columns::{IVCColumn, N_BLOCKS},
        interpreter::{build_selectors, constrain_ivc, ivc_circuit, ivc_circuit_base_case},
    },
    poseidon::interpreter::PoseidonParams,
};
use kimchi::{
    circuits::{
        domains::EvaluationDomains,
        expr::{l0_1, ChallengeTerm, Challenges, Constants, Variable},
        gate::CurrOrNext,
    },
    curve::KimchiCurve,
};
use kimchi_msm::{
    circuit_design::{ColWriteCap, ConstraintBuilderEnv, WitnessBuilderEnv},
    column_env::ColumnEnvironment,
    columns::{Column, ColumnIndexer},
    expr::E,
    lookups::DummyLookupTable,
    witness::Witness as GenericWitness,
    BN254G1Affine, Fp,
};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge, FqSponge};
use poly_commitment::{commitment::absorb_commitment, srs::SRS, PolyComm, SRS as _};
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};
use std::{array, collections::BTreeMap, ops::Index};
use strum::EnumCount;
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};

pub type Fq = ark_bn254::Fq;
//pub type Fp = ark_bn254::Fr;
//pub type Curve = ark_bn254::G1Affine;
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
use ivc::ivc::lookups::IVCLookupTable;
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
    let mut rng = o1_utils::tests::make_test_rng();
    let domain_size: usize = 1 << 15;
    let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

    let srs = {
        let pairing_srs = kimchi_msm::precomputed_srs::get_bn254_srs(domain);
        let mut srs = pairing_srs.full_srs;
        srs.add_lagrange_basis(domain.d2); // not added if already present.
        srs.add_lagrange_basis(domain.d4); // not added if already present.
        srs.add_lagrange_basis(domain.d8); // not added if already present.
        srs
    };

    let mut fq_sponge: BaseSponge = FqSponge::new(BN254G1Affine::other_curve_sponge_params());

    // ---- Defining the folding configuration ----
    // FoldingConfig
    #[derive(Clone, Debug, Copy, Eq, PartialEq, Hash)]
    pub struct Config;

    impl FoldingColumnTrait for AdditionColumn {
        fn is_witness(&self) -> bool {
            true
        }
    }

    let ivc_fixed_selectors: Vec<Vec<Fp>> =
        build_selectors::<_, N_COL_TOTAL, N_CHALS>(domain_size).to_vec();
    let ivc_fixed_selectors_evals: Vec<Evaluations<Fp, R2D<Fp>>> = ivc_fixed_selectors
        .clone()
        .into_par_iter()
        .map(|w| Evaluations::from_vec_and_domain(w, domain.d1))
        .collect();

    // Total number of witness columns in IVC (400 - 6) where 6 is block number.
    const N_WIT_IVC: usize = <IVCColumn as ColumnIndexer>::N_COL - N_BLOCKS;

    // The total number of columns in our circuit.
    const N_COL_TOTAL: usize = 3 + N_WIT_IVC;

    // Folding Witness
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct PlonkishWitness {
        pub witness: GenericWitness<N_COL_TOTAL, Evaluations<Fp, R2D<Fp>>>,
        // This does not have to be part of the witness... can be a static precompiled object.
        pub fixed_selectors: Vec<Evaluations<Fp, R2D<Fp>>>,
    }

    // Trait required for folding

    impl Foldable<Fp> for PlonkishWitness {
        fn combine(mut a: Self, b: Self, challenge: Fp) -> Self {
            for (a, b) in (*a.witness.cols).iter_mut().zip(*(b.witness.cols)) {
                for (a, b) in a.evals.iter_mut().zip(b.evals) {
                    *a += challenge * b;
                }
            }
            a
        }
    }

    impl Witness<BN254G1Affine> for PlonkishWitness {}

    impl Index<AdditionColumn> for PlonkishWitness {
        type Output = Evaluations<Fp, R2D<Fp>>;

        fn index(&self, index: AdditionColumn) -> &Self::Output {
            match index {
                AdditionColumn::A => &self.witness.cols[0],
                AdditionColumn::B => &self.witness.cols[1],
                AdditionColumn::C => &self.witness.cols[2],
            }
        }
    }

    impl Index<Column> for PlonkishWitness {
        type Output = Evaluations<Fp, R2D<Fp>>;

        /// Map a column alias to the corresponding witness column.
        fn index(&self, index: Column) -> &Self::Output {
            match index {
                Column::Relation(i) => &self.witness.cols[i],
                Column::FixedSelector(i) => &self.fixed_selectors[i],
                other => panic!("Invalid column index: {other:?}"),
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EnumIter, EnumCountMacro)]
    pub enum Challenge {
        Beta,
        Gamma,
        JointCombiner,
    }

    impl TryFrom<Challenge> for ChallengeTerm {
        type Error = FromFoldingConversionError;
        fn try_from(chal: Challenge) -> Result<Self, Self::Error> {
            match chal {
                Challenge::Beta => Ok(ChallengeTerm::Beta),
                Challenge::Gamma => Ok(ChallengeTerm::Gamma),
                Challenge::JointCombiner => Ok(ChallengeTerm::JointCombiner),
            }
        }
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
    pub struct PlonkishInstance {
        commitments: [BN254G1Affine; N_COL_TOTAL],
        challenges: [Fp; Challenge::COUNT],
        alphas: Alphas<Fp>,
        blinder: Fp,
    }

    impl Foldable<Fp> for PlonkishInstance {
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

    impl Instance<BN254G1Affine> for PlonkishInstance {
        fn to_absorb(&self) -> (Vec<Fp>, Vec<BN254G1Affine>) {
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

    impl PlonkishInstance {
        pub fn from_witness(
            w: &GenericWitness<N_COL_TOTAL, Evaluations<Fp, R2D<Fp>>>,
            fq_sponge: &mut BaseSponge,
            srs: &SRS<BN254G1Affine>,
            domain: R2D<Fp>,
        ) -> Self {
            // This fails when we try to have it on domain 8.
            let commitments: GenericWitness<N_COL_TOTAL, PolyComm<BN254G1Affine>> = w
                .into_iter() // into_par_iter
                .map(|w| {
                    let unblinded = srs.commit_evaluations_non_hiding(domain, w);
                    srs.mask_custom(unblinded, &PolyComm::new(vec![Fp::one()]))
                        .unwrap()
                        .commitment
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            // Absorbing commitments
            (&commitments)
                .into_iter()
                .for_each(|c| absorb_commitment(fq_sponge, c));

            let commitments: [BN254G1Affine; N_COL_TOTAL] = commitments
                .into_iter()
                .map(|c| c.elems[0])
                .collect_vec()
                .try_into()
                .unwrap();

            let alpha = fq_sponge.challenge();
            let alphas = Alphas::new(alpha, N_ALPHAS_INIT);
            assert!(
                alphas.clone().powers().len() == N_ALPHAS_INIT,
                "Expected N_ALPHAS_INIT = {N_ALPHAS_INIT:?}, got {}",
                alphas.clone().powers().len()
            );

            let beta = fq_sponge.challenge();
            let gamma = fq_sponge.challenge();
            let joint_combiner = fq_sponge.challenge();
            let challenges = [beta, gamma, joint_combiner];

            let blinder = Fp::one();

            Self {
                commitments,
                challenges,
                alphas,
                blinder,
            }
        }
    }
    pub struct PlonkishEnvironment {
        /// Structure of the folded circuit
        pub structure: (),
        /// Commitments to the witness columns, for both sides
        pub instances: [PlonkishInstance; 2],
        /// Corresponds to the omega evaluations, for both sides
        pub curr_witnesses: [PlonkishWitness; 2],
        /// Corresponds to the zeta*omega evaluations, for both sides
        /// This is curr_witness but left shifted by 1
        pub next_witnesses: [PlonkishWitness; 2],
    }

    impl FoldingEnv<Fp, PlonkishInstance, PlonkishWitness, Column, Challenge, ()>
        for PlonkishEnvironment
    where
        PlonkishWitness: Index<Column, Output = Evaluations<Fp, R2D<Fp>>>,
    {
        type Structure = ();

        fn new(
            structure: &(),
            instances: [&PlonkishInstance; 2],
            witnesses: [&PlonkishWitness; 2],
        ) -> Self {
            let curr_witnesses = [witnesses[0].clone(), witnesses[1].clone()];
            let mut next_witnesses = curr_witnesses.clone();
            for side in next_witnesses.iter_mut() {
                for col in side.witness.cols.iter_mut() {
                    col.evals.rotate_left(1);
                }
            }
            PlonkishEnvironment {
                structure: *structure,
                instances: [instances[0].clone(), instances[1].clone()],
                curr_witnesses,
                next_witnesses,
            }
        }

        fn col(&self, col: Column, curr_or_next: CurrOrNext, side: Side) -> &Vec<Fp> {
            let wit = match curr_or_next {
                CurrOrNext::Curr => &self.curr_witnesses[side as usize],
                CurrOrNext::Next => &self.next_witnesses[side as usize],
            };
            // The following is possible because Index is implemented for our
            // circuit witnesses
            &wit[col].evals
        }

        fn challenge(&self, challenge: Challenge, side: Side) -> Fp {
            match challenge {
                Challenge::Beta => self.instances[side as usize].challenges[0],
                Challenge::Gamma => self.instances[side as usize].challenges[1],
                Challenge::JointCombiner => self.instances[side as usize].challenges[2],
            }
        }

        fn selector(&self, _s: &(), _side: Side) -> &Vec<Fp> {
            unimplemented!("Selector not implemented for FoldingEnvironment. No selectors are supposed to be used when it is Plonkish relations.")
        }
    }

    impl FoldingConfig for Config {
        type Column = Column;
        type Selector = ();
        type Challenge = Challenge;
        type Curve = BN254G1Affine;
        type Srs = SRS<BN254G1Affine>;
        type Instance = PlonkishInstance;
        type Witness = PlonkishWitness;
        type Structure = ();
        type Env = PlonkishEnvironment;
    }
    // ---- End of folding configuration ----

    // Poseidon parameters
    pub struct PoseidonBN254Parameters;

    pub const STATE_SIZE: usize = 3;
    pub const NB_FULL_ROUND: usize = 55;

    impl PoseidonParams<Fp, STATE_SIZE, NB_FULL_ROUND> for PoseidonBN254Parameters {
        fn constants(&self) -> [[Fp; STATE_SIZE]; NB_FULL_ROUND] {
            let rc = &ivc::poseidon::params::static_params().round_constants;
            std::array::from_fn(|i| std::array::from_fn(|j| Fp::from(rc[i][j])))
        }

        fn mds(&self) -> [[Fp; STATE_SIZE]; STATE_SIZE] {
            let mds = &ivc::poseidon::params::static_params().mds;
            std::array::from_fn(|i| std::array::from_fn(|j| Fp::from(mds[i][j])))
        }
    }

    type IVCWitnessBuilderEnvRaw<LT> =
        WitnessBuilderEnv<Fp, IVCColumn, N_WIT_IVC, N_WIT_IVC, 0, N_BLOCKS, LT>;
    type LT = IVCLookupTable<Fq>;

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
        constrain_ivc::<Fp, Fq, _>(&mut ivc_constraint_env);
        ivc_constraint_env.get_relation_constraints()
    };

    let app_compat_constraints: Vec<FoldingCompatibleExpr<Config>> = app_constraints
        .into_iter()
        .map(|x| FoldingCompatibleExpr::from(x.clone()))
        .collect();
    let ivc_compat_constraints: Vec<FoldingCompatibleExpr<Config>> = ivc_constraints
        .into_iter()
        .map(|x| FoldingCompatibleExpr::from(x.clone()))
        .collect();

    // IVC column expression should be shifted to the right to accomodate app witness.
    let ivc_mapper = &(|Variable { col, row }| {
        // ADD circuit only has 3 relation columns, and no other columns, so it's easy for now.
        let rel_offset: usize = 3;
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
    let ivc_compat_constraints: Vec<FoldingCompatibleExpr<Config>> = ivc_compat_constraints
        .into_iter()
        .map(|e| e.map_variable(ivc_mapper))
        .collect();

    // Don't contain any U or alphas
    // can be mapped back to E<Fp>
    let folding_compat_constraints: Vec<FoldingCompatibleExpr<Config>> = app_compat_constraints
        .clone()
        .into_iter()
        .chain(ivc_compat_constraints.clone())
        .collect();

    // We have as many alphas as constraints
    assert!(
        folding_compat_constraints.len() == N_ALPHAS_INIT,
        "expected {N_ALPHAS:?} got {}",
        folding_compat_constraints.len()
    );

    // real_folding_compat_constraints is actual constraint
    let (folding_scheme, real_folding_compat_constraints) =
        FoldingScheme::<Config>::new(folding_compat_constraints.clone(), &srs, domain.d1, &());

    // this cannot be mapped back to Fp
    // has some u and {alpha^i}
    // this one needs to be used in prover(..).
    let _real_folding_compat_constraints: FoldingCompatibleExpr<Config> =
        real_folding_compat_constraints;

    ////////////////////////////////////////////////////////////////////////////
    // Witness step 1
    ////////////////////////////////////////////////////////////////////////////

    let mut ivc_witness_env_0 = IVCWitnessBuilderEnvRaw::<LT>::create();

    let mut app_witness_one: WitnessBuilderEnv<Fp, AdditionColumn, 3, 3, 0, 0, DummyLookupTable> =
        WitnessBuilderEnv::create();

    let empty_lookups_app = BTreeMap::new();
    let empty_lookups_ivc = BTreeMap::new();

    // Witness one
    for _i in 0..domain_size {
        let a: Fp = Fp::rand(&mut rng);
        let b: Fp = Fp::rand(&mut rng);
        app_witness_one.write_column(AdditionColumn::A, &a);
        app_witness_one.write_column(AdditionColumn::B, &b);
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
        fixed_selectors: ivc_fixed_selectors_evals.clone(),
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

    let mut app_witness_two: WitnessBuilderEnv<Fp, AdditionColumn, 3, 3, 0, 0, DummyLookupTable> =
        WitnessBuilderEnv::create();

    // Witness two
    for _i in 0..domain_size {
        let a: Fp = Fp::rand(&mut rng);
        let b: Fp = Fp::rand(&mut rng);
        app_witness_two.write_column(AdditionColumn::A, &a);
        app_witness_two.write_column(AdditionColumn::B, &b);
        interpreter_simple_add(&mut app_witness_two);
        app_witness_two.next_row();
    }

    let proof_inputs_two = app_witness_two.get_proof_inputs(domain_size, empty_lookups_app.clone());

    // IVC for the second witness is the same as for the first one,
    // since they're both height 0.
    let joint_witness_two: Vec<_> = proof_inputs_two
        .evaluations
        .into_iter()
        .chain(ivc_proof_inputs_0.evaluations)
        .collect();

    let folding_witness_two = PlonkishWitness {
        witness: joint_witness_two
            .into_par_iter()
            .map(|w| Evaluations::from_vec_and_domain(w.to_vec(), domain.d1))
            .collect(),
        fixed_selectors: ivc_fixed_selectors_evals.clone(),
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
    let folding_output = folding_scheme.fold_instance_witness_pair(one, two, &mut fq_sponge);
    let FoldingOutput {
        folded_instance,
        // Should not be required for the IVC circuit as it is encoding the
        // verifier.
        folded_witness,
        t_0,
        t_1,
        relaxed_extended_left_instance,
        relaxed_extended_right_instance,
        to_absorb: _,
    } = folding_output;

    // The polynomial of the computation is linear, therefore, the error terms
    // are zero
    assert_ne!(t_0.elems[0], BN254G1Affine::zero());
    assert_ne!(t_1.elems[0], BN254G1Affine::zero());

    // Sanity check that the u values are the same. The u value is there to
    // homogeneoize the polynomial describing the NP relation.
    assert_eq!(
        relaxed_extended_left_instance.u,
        relaxed_extended_right_instance.u
    );

    // -- Sanity check regarding folding.
    let additional_columns = folding_scheme.get_number_of_additional_columns();
    println!("additional columns: {:?}", additional_columns);
    //// No additional columns should be created.
    // @volhovm no longer true: the IVC circuit is degree 3
    //assert_eq!(additional_columns, 0);

    const N_COL_QUAD: usize = 109;
    assert_eq!(additional_columns, N_COL_QUAD);

    const N_COL_TOTAL_QUAD: usize = N_COL_TOTAL + N_COL_QUAD;

    // 1. Get all the commitments from the left instance.
    // We want a way to get also the potential additional columns.
    let mut comms_left: Vec<BN254G1Affine> = Vec::with_capacity(N_COL_TOTAL_QUAD);
    comms_left.extend(
        relaxed_extended_left_instance
            .extended_instance
            .instance
            .commitments,
    );

    // Additional columns of quadri
    {
        let extended = relaxed_extended_left_instance.extended_instance.extended;
        let extended_comms: Vec<_> = extended.iter().map(|x| x.elems[0]).collect();
        comms_left.extend(extended_comms.clone());
        extended_comms.iter().enumerate().for_each(|(i, x)| {
            assert_ne!(
                x,
                &BN254G1Affine::zero(),
                "Left extended commitment number {i:?} is zero"
            );
        });
    }
    assert_eq!(comms_left.len(), N_COL_TOTAL_QUAD);
    // Checking they are all not zero.
    comms_left.iter().enumerate().for_each(|(i, c)| {
        assert_ne!(
            c,
            &BN254G1Affine::zero(),
            "Left commitment number {i:?} is zero"
        );
    });

    // IVC is expecting the coordinates.
    let comms_left: [(Fq, Fq); N_COL_TOTAL_QUAD] =
        std::array::from_fn(|i| (comms_left[i].x, comms_left[i].y));

    // 2. Get all the commitments from the right instance.
    // We want a way to get also the potential additional columns.
    let mut comms_right = Vec::with_capacity(N_COL_TOTAL_QUAD);
    comms_right.extend(
        relaxed_extended_left_instance
            .extended_instance
            .instance
            .commitments,
    );
    {
        let extended = relaxed_extended_right_instance.extended_instance.extended;
        comms_right.extend(extended.iter().map(|x| x.elems[0]));
    }
    assert_eq!(comms_right.len(), N_COL_TOTAL_QUAD);
    // Checking they are all not zero.
    comms_right.iter().enumerate().for_each(|(i, c)| {
        assert_ne!(
            c,
            &BN254G1Affine::zero(),
            "Right commitment number {i:?} is zero"
        );
    });

    // IVC is expecting the coordinates.
    let comms_right: [(Fq, Fq); N_COL_TOTAL_QUAD] =
        std::array::from_fn(|i| (comms_right[i].x, comms_right[i].y));

    // 3. Get all the commitments from the folded instance.
    // We want a way to get also the potential additional columns.
    let mut comms_out = Vec::with_capacity(AdditionColumn::N_COL + additional_columns);
    comms_out.extend(folded_instance.extended_instance.instance.commitments);
    {
        let extended = folded_instance.extended_instance.extended.clone();
        comms_out.extend(extended.iter().map(|x| x.elems[0]));
    }
    // Checking they are all not zero.
    comms_out.iter().for_each(|c| {
        assert_ne!(c, &BN254G1Affine::zero());
    });

    // IVC is expecting the coordinates.
    let comms_out: [(Fq, Fq); N_COL_TOTAL_QUAD] =
        std::array::from_fn(|i| (comms_out[i].x, comms_out[i].y));

    // FIXME: Should be handled in folding
    let left_error_term = srs
        .mask_custom(
            relaxed_extended_left_instance.error_commitment,
            &PolyComm::new(vec![Fp::one()]),
        )
        .unwrap()
        .commitment;

    // FIXME: Should be handled in folding
    let right_error_term = srs
        .mask_custom(
            relaxed_extended_right_instance.error_commitment,
            &PolyComm::new(vec![Fp::one()]),
        )
        .unwrap()
        .commitment;

    let error_terms = [
        left_error_term.elems[0],
        right_error_term.elems[0],
        folded_instance.error_commitment.elems[0],
    ];
    error_terms.iter().for_each(|c| {
        assert_ne!(c, &BN254G1Affine::zero());
    });

    let error_terms: [(Fq, Fq); 3] = std::array::from_fn(|i| (error_terms[i].x, error_terms[i].y));

    let t_terms = [t_0.elems[0], t_1.elems[0]];
    t_terms.iter().for_each(|c| {
        assert_ne!(c, &BN254G1Affine::zero());
    });
    let t_terms: [(Fq, Fq); 2] = std::array::from_fn(|i| (t_terms[i].x, t_terms[i].y));

    let u = relaxed_extended_left_instance.u;

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

    // FIXME: add
    // - u
    // - there is no alpha, so ok
    // - ?
    // TODO
    const N_ALPHAS_INIT: usize = 58; // number of constraints we have before quad
    const N_ALPHAS: usize = N_ALPHAS_INIT + N_COL_QUAD; // number of constrainst w/ quad
    const N_CHALS: usize = N_ALPHAS; // alphas + 3 ({beta gamma joint_combiner})

    let mut ivc_witness_env_1 = IVCWitnessBuilderEnvRaw::<LT>::create();
    ivc_witness_env_1.set_fixed_selectors(ivc_fixed_selectors.clone());

    ivc_circuit::<Fp, Fq, _, _, N_COL_TOTAL_QUAD, N_CHALS>(
        &mut ivc_witness_env_1,
        Box::new(all_ivc_comms_left),
        Box::new(all_ivc_comms_right),
        Box::new(all_ivc_comms_out),
        error_terms,
        t_terms,
        u,
        o1_utils::array::vec_to_boxed_array(
            folded_instance
                .extended_instance
                .instance
                .alphas
                .clone()
                .powers(),
        ),
        1,
        &PoseidonBN254Parameters,
        domain_size,
    );

    let ivc_proof_inputs_1 =
        ivc_witness_env_1.get_proof_inputs(domain_size, empty_lookups_ivc.clone());
    assert!(ivc_proof_inputs_1.evaluations.len() == N_WIT_IVC);

    ////////////////////////////////////////////////////////////////////////////
    // Witness step 3
    ////////////////////////////////////////////////////////////////////////////

    let mut app_witness_three: WitnessBuilderEnv<Fp, AdditionColumn, 3, 3, 0, 0, DummyLookupTable> =
        WitnessBuilderEnv::create();

    // Witness three
    for _i in 0..domain_size {
        let a: Fp = Fp::rand(&mut rng);
        let b: Fp = Fp::rand(&mut rng);
        app_witness_three.write_column(AdditionColumn::A, &a);
        app_witness_three.write_column(AdditionColumn::B, &b);
        interpreter_simple_add(&mut app_witness_three);
        app_witness_three.next_row();
    }

    let proof_inputs_three =
        app_witness_three.get_proof_inputs(domain_size, empty_lookups_app.clone());

    // IVC for the second witness is the same as for the first one,
    // since they're both height 0.
    let joint_witness_three: Vec<_> = proof_inputs_three
        .evaluations
        .clone()
        .into_iter()
        .chain(ivc_proof_inputs_1.evaluations.clone())
        .collect();

    assert!(joint_witness_three.len() == N_COL_TOTAL);

    let folding_witness_three_evals: Vec<Evaluations<Fp, R2D<Fp>>> = joint_witness_three
        .clone()
        .into_par_iter()
        .map(|w| Evaluations::from_vec_and_domain(w.to_vec(), domain.d1))
        .collect();
    let folding_witness_three = PlonkishWitness {
        witness: folding_witness_three_evals.clone().try_into().unwrap(),
        fixed_selectors: ivc_fixed_selectors_evals.clone(),
    };

    let folding_instance_three = PlonkishInstance::from_witness(
        &folding_witness_three.witness,
        &mut fq_sponge,
        &srs,
        domain.d1,
    );

    ////////////////////////////////////////////////////////////////////////////
    // Folding 2
    ////////////////////////////////////////////////////////////////////////////

    let _folding_output_two = folding_scheme.fold_instance_witness_pair(
        (folded_instance, folded_witness),
        (
            folding_instance_three.clone(),
            folding_witness_three.clone(),
        ),
        &mut fq_sponge,
    );

    //   one     two      (w/ dummy IVC)
    //      \   /
    //       folded_1      three        (w/ real IVC)
    //           \         /
    //            folded_2

    ////////////////////////////////////////////////////////////////////////////
    // Testing via folding exprs
    ////////////////////////////////////////////////////////////////////////////

    {
        let interpolate = |evals: Evaluations<Fp, R2D<Fp>>| evals.interpolate();

        //let folding_witness_three_polys: Vec<DensePolynomial<Fp>> = {
        //    (proof_inputs_three.evaluations.cols.clone())
        //        .into_iter()
        //        .map(|w| interpolate(Evaluations::from_vec_and_domain(w, domain.d1)))
        //        .collect()
        //};

        let folding_witness_three_polys: Vec<DensePolynomial<Fp>> = {
            folding_witness_three_evals
                .clone()
                .into_par_iter()
                .map(interpolate)
                .collect::<Vec<DensePolynomial<Fp>>>()
        };
        let folding_witness_three_evals_d8: Vec<Evaluations<Fp, R2D<Fp>>> =
            (folding_witness_three_polys)
                .into_par_iter()
                .map(|evals| evals.evaluate_over_domain_by_ref(domain.d8))
                .collect();

        let ivc_fixed_selectors_polys: Vec<DensePolynomial<Fp>> = {
            ivc_fixed_selectors_evals
                .clone()
                .into_par_iter()
                .map(interpolate)
                .collect()
        };
        let ivc_fixed_selectors_evals_d8: Vec<Evaluations<Fp, R2D<Fp>>> =
            (ivc_fixed_selectors_polys)
                .into_par_iter()
                .map(|evals| evals.evaluate_over_domain_by_ref(domain.d8))
                .collect();

        let folding_witness_three_d8 = PlonkishWitness {
            witness: folding_witness_three_evals_d8.try_into().unwrap(),
            fixed_selectors: ivc_fixed_selectors_evals_d8,
        };

        let folding_instance_three_d8 = PlonkishInstance::from_witness(
            &folding_witness_three.witness,
            &mut fq_sponge,
            &srs,
            domain.d8,
        );

        for (expr_i, expr) in app_compat_constraints.iter().enumerate() {
            //for (expr_i, expr) in folding_compat_constraints.iter().enumerate() {
            use folding::{
                error_term::{eval_sided, ExtendedEnv, Side},
                eval_leaf::EvalLeaf,
                expressions::FoldingExp,
                instance_witness::RelaxablePair,
            };

            println!("Expression #{expr_i}: {}", expr.to_string());

            let expr: FoldingExp<Config> = expr.clone().simplify();

            //println!("Expression (foldingExp): {}", expr.to_string());

            //  (i1,w1)       (i2,w2)         (+ trivial IVC)
            //         (i3,w3)                (+ nontrivial IVC)
            //
            //
            // APP + IVC
            let relaxable_pair = (
                folding_instance_three_d8.clone(),
                folding_witness_three_d8.clone(),
            );
            let relaxed_pair = relaxable_pair.relax(&folding_scheme.zero_vec);
            let relaxed_pair_copy = (relaxed_pair.0.clone(), relaxed_pair.1.clone());

            let eval_env = ExtendedEnv::new(
                &(),
                [relaxed_pair.0, relaxed_pair_copy.0],
                [relaxed_pair.1, relaxed_pair_copy.1],
                domain.d1,
                None,
            );

            println!("Eval_leaf");
            let eval_leaf = eval_sided(&expr, &eval_env, Side::Left);
            println!("Eval_leaf done");

            match eval_leaf {
                EvalLeaf::Result(evaluations_d8) => {
                    let (_, remainder) =
                        Evaluations::from_vec_and_domain(evaluations_d8, domain.d8)
                            .interpolate()
                            .divide_by_vanishing_poly(domain.d1)
                            .unwrap_or_else(|| panic!("Cannot divide by vanishing polynomial"));
                    if !remainder.is_zero() {
                        panic!("Remainder is not zero")
                    }
                }
                _ => panic!("eval_leaf is not Result"),
            }
        }
    }
}
