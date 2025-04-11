use ark_ec::AffineRepr;
use ark_ff::{One, UniformRand};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use folding::{
    checker::{Checker, ExtendedProvider},
    expressions::{FoldingColumnTrait, FoldingCompatibleExprInner},
    instance_witness::Foldable,
    Alphas, FoldingCompatibleExpr, FoldingConfig, FoldingEnv, Instance, Side, Witness,
};
use itertools::Itertools;
use kimchi::circuits::{expr::Variable, gate::CurrOrNext};
use poly_commitment::{ipa::SRS, SRS as _};
use rand::thread_rng;
use std::{collections::BTreeMap, ops::Index};

use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};

// Trick to print debug message while testing, as we in the test config env
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
use folding::{decomposable_folding::DecomposableFoldingScheme, FoldingOutput};
use kimchi::curve::KimchiCurve;
use mina_poseidon::FqSponge;
use std::println as debug;

type Fp = ark_bn254::Fr;
type Curve = ark_bn254::G1Affine;
type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<ark_bn254::g1::Config, SpongeParams>;

// the type representing our columns, in this case we have 3 witness columns
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TestColumn {
    A,
    B,
    C,
}

// the type for the dynamic selectors, which are essentially witness columns, but
// get special treatment to enable optimizations
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum DynamicSelector {
    SelecAdd,
    SelecSub,
}

impl FoldingColumnTrait for TestColumn {
    //in this case we have only witness, the other example shows non-witness columns
    fn is_witness(&self) -> bool {
        match self {
            TestColumn::A | TestColumn::B | TestColumn::C => true,
        }
    }
}

/// The instance is the commitments to the polynomials and the challenges
#[derive(Debug, Clone)]
pub struct TestInstance {
    // 3 from the normal witness + 2 from the dynamic selectors
    commitments: [Curve; 5],
    // for illustration only, no constraint in this example uses challenges
    challenges: [Fp; 3],
    // also challenges, but segregated as folding gives them special treatment
    alphas: Alphas<Fp>,
    // Used for the blinding factor in the commitment
    blinder: Fp,
}

impl Foldable<Fp> for TestInstance {
    fn combine(a: Self, b: Self, challenge: Fp) -> Self {
        TestInstance {
            commitments: std::array::from_fn(|i| {
                (a.commitments[i] + b.commitments[i] * challenge).into()
            }),
            challenges: std::array::from_fn(|i| a.challenges[i] + challenge * b.challenges[i]),
            alphas: Alphas::combine(a.alphas, b.alphas, challenge),
            blinder: a.blinder + challenge * b.blinder,
        }
    }
}

impl Instance<Curve> for TestInstance {
    fn to_absorb(&self) -> (Vec<Fp>, Vec<Curve>) {
        // FIXME?
        (vec![], vec![])
    }

    fn get_alphas(&self) -> &Alphas<Fp> {
        &self.alphas
    }

    fn get_blinder(&self) -> Fp {
        self.blinder
    }
}

/// Our witness is going to be the polynomials that we will commit too.
/// Vec<Fp> will be the evaluations of each x_1, x_2 and x_3 over the domain.
/// This witness includes not only the 3 normal witness columns, but also the
/// 2 dynamic selector columns that are essentially witness
#[derive(Clone)]
pub struct TestWitness([Evaluations<Fp, Radix2EvaluationDomain<Fp>>; 5]);

impl Foldable<Fp> for TestWitness {
    fn combine(mut a: Self, b: Self, challenge: Fp) -> Self {
        for (a, b) in a.0.iter_mut().zip(b.0) {
            for (a, b) in a.evals.iter_mut().zip(b.evals) {
                *a += challenge * b;
            }
        }
        a
    }
}

impl Witness<Curve> for TestWitness {}

// our environment, the way in which we provide access to the actual values in the
// witness and instances, when folding evaluates expressions and reaches leaves (Atom)
// it will call methods from here to resolve the types we have in the config like the
// columns into the actual values.
pub struct TestFoldingEnv {
    instances: [TestInstance; 2],
    // Corresponds to the omega evaluations, for both sides
    curr_witnesses: [TestWitness; 2],
    // Corresponds to the zeta*omega evaluations, for both sides
    // This is curr_witness but left shifted by 1
    next_witnesses: [TestWitness; 2],
}

// implementing the an environment trait compatible with our config
impl FoldingEnv<Fp, TestInstance, TestWitness, TestColumn, TestChallenge, DynamicSelector>
    for TestFoldingEnv
{
    type Structure = ();

    fn new(
        _structure: &Self::Structure,
        instances: [&TestInstance; 2],
        witnesses: [&TestWitness; 2],
    ) -> Self {
        // here it is mostly storing the pairs into self, and also computing other things we may need
        // later like the shifted versions, note there are more efficient ways of handling the rotated
        // witnesses, which are just for example as no constraint uses them anyway
        let curr_witnesses = [witnesses[0].clone(), witnesses[1].clone()];
        let mut next_witnesses = curr_witnesses.clone();
        for side in next_witnesses.iter_mut() {
            for col in side.0.iter_mut() {
                //TODO: check this, while not relevant for this example I think it should be right rotation
                col.evals.rotate_left(1);
            }
        }
        TestFoldingEnv {
            instances: [instances[0].clone(), instances[1].clone()],
            curr_witnesses,
            next_witnesses,
        }
    }

    // provide access to columns, here side refers to one of the two pairs you
    // got in new()
    fn col(&self, col: TestColumn, curr_or_next: CurrOrNext, side: Side) -> &[Fp] {
        let with = match curr_or_next {
            CurrOrNext::Curr => &self.curr_witnesses[side as usize],
            CurrOrNext::Next => &self.next_witnesses[side as usize],
        };
        match col {
            TestColumn::A => &with.0[0].evals,
            TestColumn::B => &with.0[1].evals,
            TestColumn::C => &with.0[2].evals,
        }
    }

    // same as column but for challenges, challenges are not constants
    fn challenge(&self, challenge: TestChallenge, side: Side) -> Fp {
        match challenge {
            TestChallenge::Beta => self.instances[side as usize].challenges[0],
            TestChallenge::Gamma => self.instances[side as usize].challenges[1],
            TestChallenge::JointCombiner => self.instances[side as usize].challenges[2],
        }
    }

    // This is exclusively for dynamic selectors aiming to make use of optimization
    // as classic static selectors will be handled as normal structure columns in col().
    // The implementation of this if the same as col(), it is just separated as they
    // have different types to resolve
    fn selector(&self, s: &DynamicSelector, side: Side) -> &[Fp] {
        let with = &self.curr_witnesses[side as usize];
        match s {
            DynamicSelector::SelecAdd => &with.0[3].evals,
            DynamicSelector::SelecSub => &with.0[4].evals,
        }
    }
}

// this creates 2 single-constraint gates, each with a selector,
// an addition gate, and a subtraction gate
fn constraints() -> BTreeMap<DynamicSelector, Vec<FoldingCompatibleExpr<TestFoldingConfig>>> {
    let get_col = |col| {
        FoldingCompatibleExpr::Atom(FoldingCompatibleExprInner::Cell(Variable {
            col,
            row: CurrOrNext::Curr,
        }))
    };
    let a = Box::new(get_col(TestColumn::A));
    let b = Box::new(get_col(TestColumn::B));
    let c = Box::new(get_col(TestColumn::C));

    let add = FoldingCompatibleExpr::Add(a.clone(), b.clone());
    let add = FoldingCompatibleExpr::Sub(add.into(), c.clone());
    let add = FoldingCompatibleExpr::Sub(
        add.into(),
        Box::new(FoldingCompatibleExpr::Atom(
            FoldingCompatibleExprInner::Constant(Fp::one()),
        )),
    );
    // a + b - c - 1 = 0

    let sub = FoldingCompatibleExpr::Sub(a.clone(), b.clone());
    let sub = FoldingCompatibleExpr::Sub(sub.into(), c.clone());

    [
        (DynamicSelector::SelecAdd, vec![add]),
        (DynamicSelector::SelecSub, vec![sub]),
    ]
    .into_iter()
    .collect()
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TestFoldingConfig;

// Does not contain alpha because it should be added to the expressions by folding
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TestChallenge {
    Beta,
    Gamma,
    JointCombiner,
}

impl FoldingConfig for TestFoldingConfig {
    type Structure = ();
    type Column = TestColumn;
    type Selector = DynamicSelector;
    type Challenge = TestChallenge;
    type Curve = Curve;
    type Srs = SRS<Curve>;
    type Instance = TestInstance;
    type Witness = TestWitness;
    type Env = TestFoldingEnv;
}

//creates an instance from its witness
fn instance_from_witness(
    witness: &TestWitness,
    srs: &<TestFoldingConfig as FoldingConfig>::Srs,
    domain: Radix2EvaluationDomain<Fp>,
) -> TestInstance {
    let commitments = witness
        .0
        .iter()
        .map(|w| srs.commit_evaluations_non_hiding(domain, w))
        .map(|c| c.get_first_chunk())
        .collect_vec();
    let commitments: [_; 5] = commitments.try_into().unwrap();

    // here we should absorb the commitments and similar things to later compute challenges
    // but for this example I just use random values
    let mut rng = thread_rng();
    let mut challenge = || Fp::rand(&mut rng);
    let challenges = [(); 3].map(|_| challenge());
    let alpha = challenge();
    let alphas = Alphas::new(alpha);
    let blinder = Fp::one();
    TestInstance {
        commitments,
        challenges,
        alphas,
        blinder,
    }
}

impl Checker<TestFoldingConfig> for ExtendedProvider<TestFoldingConfig> {}

impl Index<TestChallenge> for TestInstance {
    type Output = Fp;

    fn index(&self, index: TestChallenge) -> &Self::Output {
        match index {
            TestChallenge::Beta => &self.challenges[0],
            TestChallenge::Gamma => &self.challenges[1],
            TestChallenge::JointCombiner => &self.challenges[2],
        }
    }
}

impl Index<TestColumn> for TestWitness {
    type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

    fn index(&self, index: TestColumn) -> &Self::Output {
        match index {
            TestColumn::A => &self.0[0],
            TestColumn::B => &self.0[1],
            TestColumn::C => &self.0[2],
        }
    }
}

impl Index<DynamicSelector> for TestWitness {
    type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

    fn index(&self, index: DynamicSelector) -> &Self::Output {
        match index {
            DynamicSelector::SelecAdd => &self.0[3],
            DynamicSelector::SelecSub => &self.0[4],
        }
    }
}

// two functions to create the entire witness from just the a and b columns
fn add_witness(a: [u32; 2], b: [u32; 2]) -> [[u32; 2]; 5] {
    let [a1, a2] = a;
    let [b1, b2] = b;
    let c = [a1 + b1 - 1, a2 + b2 - 1];
    [a, b, c, [1, 1], [0, 0]]
}

fn sub_witness(a: [u32; 2], b: [u32; 2]) -> [[u32; 2]; 5] {
    let [a1, a2] = a;
    let [b1, b2] = b;
    let c = [a1 - b1, a2 - b2];
    [a, b, c, [0, 0], [1, 1]]
}
fn int_to_witness(x: [[u32; 2]; 5], domain: Radix2EvaluationDomain<Fp>) -> TestWitness {
    TestWitness(x.map(|row| Evaluations::from_vec_and_domain(row.map(Fp::from).to_vec(), domain)))
}

// in this test we will create 2 add witnesses, fold them together, create 2
// sub witnesses,
// fold them together, and then further fold the 2 resulting pairs into one
// mixed add-sub witnes
// instances are also folded, but not that relevant in the examples as we
// don't make a proof for them
// and instead directly check the witness
#[test]
fn test_decomposable_folding() {
    let constraints = constraints();
    let domain = D::<Fp>::new(2).unwrap();
    let srs = SRS::<Curve>::create(2);
    srs.get_lagrange_basis(domain);

    let mut fq_sponge = BaseSponge::new(Curve::other_curve_sponge_params());

    // initialize the scheme, also getting the final single expression for
    // the entire constraint system
    let (scheme, final_constraint) = DecomposableFoldingScheme::<TestFoldingConfig>::new(
        constraints.clone(),
        vec![],
        &srs,
        domain,
        &(),
    );

    // some inputs to be used by both add and sub
    let inputs1 = [[4u32, 2u32], [2u32, 1u32]];
    let inputs2 = [[5u32, 6u32], [4u32, 3u32]];

    // creates an instance witness pair
    let make_pair = |with: TestWitness| {
        let ins = instance_from_witness(&with, &srs, domain);
        (with, ins)
    };

    // fold adds
    debug!("fold add");
    let left = {
        let [a, b] = inputs1;
        let wit1 = add_witness(a, b);
        let (witness1, instance1) = make_pair(int_to_witness(wit1, domain));

        let [a, b] = inputs2;
        let wit2 = add_witness(a, b);
        let (witness2, instance2) = make_pair(int_to_witness(wit2, domain));

        let left = (instance1, witness1);
        let right = (instance2, witness2);
        // here we provide normal instance-witness pairs, which will be
        // automatically relaxed
        let folded = scheme.fold_instance_witness_pair(
            left,
            right,
            Some(DynamicSelector::SelecAdd),
            &mut fq_sponge,
        );
        let FoldingOutput {
            folded_instance,
            folded_witness,
            t_0: _,
            t_1: _,
            relaxed_extended_left_instance: _,
            relaxed_extended_right_instance: _,
            to_absorb: _,
        } = folded;
        let checker = ExtendedProvider::new(folded_instance, folded_witness);
        debug!("exp: \n {:#?}", final_constraint.to_string());
        checker.check(&final_constraint, domain);
        let ExtendedProvider {
            instance, witness, ..
        } = checker;
        (instance, witness)
    };
    //fold subs
    debug!("fold subs");
    let right = {
        let [a, b] = inputs1;
        let wit1 = sub_witness(a, b);
        let (witness1, instance1) = make_pair(int_to_witness(wit1, domain));

        let [a, b] = inputs2;
        let wit2 = sub_witness(a, b);
        let (witness2, instance2) = make_pair(int_to_witness(wit2, domain));

        let left = (instance1, witness1);
        let right = (instance2, witness2);
        let folded = scheme.fold_instance_witness_pair(
            left,
            right,
            Some(DynamicSelector::SelecSub),
            &mut fq_sponge,
        );
        let FoldingOutput {
            folded_instance,
            folded_witness,
            t_0: _,
            t_1: _,
            relaxed_extended_left_instance: _,
            relaxed_extended_right_instance: _,
            to_absorb: _,
        } = folded;

        let checker = ExtendedProvider::new(folded_instance, folded_witness);
        debug!("exp: \n {:#?}", final_constraint.to_string());

        checker.check(&final_constraint, domain);
        let ExtendedProvider {
            instance, witness, ..
        } = checker;
        (instance, witness)
    };
    //fold mixed
    debug!("fold mixed");
    {
        // here we use already relaxed pairs, which have a trivial x -> x implementation
        let folded = scheme.fold_instance_witness_pair(left, right, None, &mut fq_sponge);
        let FoldingOutput {
            folded_instance,
            folded_witness,
            t_0,
            t_1,
            relaxed_extended_left_instance: _,
            relaxed_extended_right_instance: _,
            to_absorb: _,
        } = folded;

        // Verifying that error terms are not points at infinity
        // It doesn't test that the computation happens correctly, but at least
        // show that there is some non trivial computation.
        assert_eq!(t_0.len(), 1);
        assert_eq!(t_1.len(), 1);
        assert!(!t_0.get_first_chunk().is_zero());
        assert!(!t_1.get_first_chunk().is_zero());

        let checker = ExtendedProvider::new(folded_instance, folded_witness);
        debug!("exp: \n {:#?}", final_constraint.to_string());

        checker.check(&final_constraint, domain);
    };
}
