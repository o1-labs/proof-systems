//! This is a simple example of how to use the folding crate with the IVC crate
//! to fold a simple addition circuit. The addition circuit consists of a single
//! constraint of degree 1 over 3 columns (A + B - C = 0).

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_poly::Evaluations;
use folding::{
    expressions::FoldingColumnTrait, instance_witness::Foldable, Alphas, FoldingCompatibleExpr,
    FoldingConfig, FoldingEnv, FoldingScheme, Instance, Side, Witness,
};
use kimchi::{
    circuits::{expr::ChallengeTerm, gate::CurrOrNext},
    curve::KimchiCurve,
};
use kimchi_msm::{columns::ColumnIndexer, witness::Witness as GenericWitness};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge, FqSponge};
use rayon::iter::IntoParallelIterator as _;
use std::{array, collections::BTreeMap, ops::Index};
use strum::EnumCount;
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};

use ark_ff::UniformRand;
use ark_poly::Radix2EvaluationDomain;
use kimchi::circuits::domains::EvaluationDomains;
use kimchi_msm::{
    circuit_design::{ColWriteCap, ConstraintBuilderEnv, WitnessBuilderEnv},
    columns::Column,
    lookups::DummyLookupTable,
};
use poly_commitment::{commitment::absorb_commitment, srs::SRS, PolyComm, SRS as _};
use rayon::iter::ParallelIterator as _;

use itertools::Itertools;

pub type Fp = ark_bn254::Fr;
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
    let mut rng = o1_utils::tests::make_test_rng();
    let domain_size: usize = 1 << 5;
    let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

    let mut fq_sponge: BaseSponge = FqSponge::new(Curve::other_curve_sponge_params());
    let mut srs = SRS::<Curve>::create(domain_size);
    srs.add_lagrange_basis(domain.d1);

    // ---- Defining the folding configuration ----
    // FoldingConfig
    #[derive(Clone, Debug, Copy, Eq, PartialEq, Hash)]
    pub struct Config;

    impl FoldingColumnTrait for AdditionColumn {
        fn is_witness(&self) -> bool {
            true
        }
    }

    // Folding Witness
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct PlonkishWitness {
        pub witness: GenericWitness<3, Evaluations<Fp, Radix2EvaluationDomain<Fp>>>,
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

    impl Witness<Curve> for PlonkishWitness {}

    impl Index<AdditionColumn> for PlonkishWitness {
        type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

        fn index(&self, index: AdditionColumn) -> &Self::Output {
            match index {
                AdditionColumn::A => &self.witness.cols[0],
                AdditionColumn::B => &self.witness.cols[1],
                AdditionColumn::C => &self.witness.cols[2],
            }
        }
    }

    impl Index<Column> for PlonkishWitness {
        type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

        /// Map a column alias to the corresponding witness column.
        fn index(&self, index: Column) -> &Self::Output {
            match index {
                Column::Relation(0) => &self.witness.cols[0],
                Column::Relation(1) => &self.witness.cols[1],
                Column::Relation(2) => &self.witness.cols[2],
                _ => panic!("Invalid column index"),
            }
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
    pub struct PlonkishInstance {
        commitments: [Curve; AdditionColumn::COUNT],
        challenges: [Fp; Challenge::COUNT],
        alphas: Alphas<Fp>,
    }

    impl Foldable<Fp> for PlonkishInstance {
        fn combine(a: Self, b: Self, challenge: Fp) -> Self {
            Self {
                commitments: array::from_fn(|i| {
                    a.commitments[i] + b.commitments[i].mul(challenge).into_affine()
                }),
                challenges: array::from_fn(|i| a.challenges[i] + challenge * b.challenges[i]),
                alphas: Alphas::combine(a.alphas, b.alphas, challenge),
            }
        }
    }

    impl Instance<Curve> for PlonkishInstance {
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
    }

    impl PlonkishInstance {
        pub fn from_witness(
            w: &GenericWitness<3, Evaluations<Fp, Radix2EvaluationDomain<Fp>>>,
            fq_sponge: &mut BaseSponge,
            srs: &SRS<Curve>,
            domain: Radix2EvaluationDomain<Fp>,
        ) -> Self {
            let commitments: GenericWitness<3, PolyComm<Curve>> = w
                .into_par_iter()
                .map(|w| srs.commit_evaluations_non_hiding(domain, w))
                .collect();

            // Absorbing commitments
            (&commitments)
                .into_iter()
                .for_each(|c| absorb_commitment(fq_sponge, c));

            let commitments: [Curve; 3] = commitments
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
        PlonkishWitness: Index<Column, Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>>,
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
        type Curve = Curve;
        type Srs = SRS<Curve>;
        type Instance = PlonkishInstance;
        type Witness = PlonkishWitness;
        type Structure = ();
        type Env = PlonkishEnvironment;
    }
    // ---- End of folding configuration ----

    let constraints = {
        let mut constraint_env = ConstraintBuilderEnv::<Fp, DummyLookupTable>::create();
        interpreter_simple_add::<Fp, _>(&mut constraint_env);
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
        interpreter_simple_add(&mut witness_one);
        witness_two.next_row();
    }

    // Witness two
    for _i in 0..domain_size {
        let a: Fp = Fp::rand(&mut rng);
        let b: Fp = Fp::rand(&mut rng);
        witness_two.write_column(AdditionColumn::A, &a);
        witness_two.write_column(AdditionColumn::B, &b);
        interpreter_simple_add(&mut witness_two);
        witness_two.next_row();
    }

    let proof_inputs_one = witness_one.get_proof_inputs(domain_size, empty_lookups.clone());
    let proof_inputs_two = witness_two.get_proof_inputs(domain_size, empty_lookups.clone());

    let folding_witness_one = PlonkishWitness {
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

    let folding_witness_two = PlonkishWitness {
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

    let folding_compat_constraints: Vec<FoldingCompatibleExpr<Config>> = constraints
        .iter()
        .map(|x| FoldingCompatibleExpr::from(x.clone()))
        .collect();

    let (folding_scheme, _) =
        FoldingScheme::<Config>::new(folding_compat_constraints, &srs, domain.d1, &());

    let one = (folding_instance_one, folding_witness_one);
    let two = (folding_instance_two, folding_witness_two);
    let _folding_output = folding_scheme.fold_instance_witness_pair(one, two, &mut fq_sponge);
}
