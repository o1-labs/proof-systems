use crate::{
    circuits::{
        expr::{Op2, Variable},
        gate::CurrOrNext,
    },
    folding::{
        error_term::Side,
        expressions::{FoldingColumnTrait, FoldingCompatibleExprInner},
        ExpExtension, FoldingCompatibleExpr, FoldingConfig, FoldingEnv, Instance, RelaxedInstance,
        RelaxedWitness, Witness,
    },
};
use ark_bn254;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, UniformRand, Zero};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use itertools::Itertools;
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};
use poly_commitment::SRS;
use rand::thread_rng;
use std::{
    collections::BTreeMap,
    iter::successors,
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering},
};

type Fp = ark_bn254::Fr;
type Curve = ark_bn254::G1Affine;
type SpongeParams = PlonkSpongeConstantsKimchi;
pub type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;

// the type representing our columns, in this case we have 3 witness columns
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TestColumn {
    A,
    B,
    C,
}

// the type for the dynamic selectors, which are esentially witness columns, but
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

/// The alphas are exceptional, their number cannot be known ahead of time as it will be defined by
/// folding.
/// The values will be computed as powers in new instances, but after folding each alfa will be a
/// linear combination of other alphas, instand of a power of other element.
/// This type represents that, allowing to also recognize which case is present
#[derive(Debug, Clone)]
pub enum Alphas {
    Powers(Fp, Rc<AtomicUsize>),
    Combinations(Vec<Fp>),
}

impl Alphas {
    pub fn new(alpha: Fp) -> Self {
        Self::Powers(alpha, Rc::new(AtomicUsize::from(0)))
    }
    pub fn get(&self, i: usize) -> Option<Fp> {
        match self {
            Alphas::Powers(alpha, count) => {
                let _ = count.fetch_max(i + 1, Ordering::Relaxed);
                let i = [i as u64];
                Some(alpha.pow(i))
            }
            Alphas::Combinations(alphas) => alphas.get(i).cloned(),
        }
    }
    pub fn powers(self) -> Vec<Fp> {
        match self {
            Alphas::Powers(alpha, count) => {
                let n = count.load(Ordering::Relaxed);
                let alphas = successors(Some(Fp::one()), |last| Some(*last * alpha));
                alphas.take(n).collect()
            }
            Alphas::Combinations(c) => c,
        }
    }
    pub fn combine(a: Self, b: Self, challenge: Fp) -> Self {
        let a = a.powers();
        let b = b.powers();
        assert_eq!(a.len(), b.len());
        let comb = a
            .into_iter()
            .zip(b)
            .map(|(a, b)| a + b * challenge)
            .collect();
        Self::Combinations(comb)
    }
}

/// The instance is the commitments to the polynomials and the challenges
#[derive(Debug, Clone)]
pub struct TestInstance {
    // 3 from the normal witness + 2 from the dynamic selectors
    commitments: [Curve; 5],
    // for ilustration only, no constraint in this example uses challenges
    challenges: [Fp; 3],
    // also challenges, but segregated as folding gives them special treatment
    alphas: Alphas,
}

impl Instance<Curve> for TestInstance {
    fn combine(a: Self, b: Self, challenge: Fp) -> Self {
        TestInstance {
            commitments: [
                a.commitments[0] + b.commitments[0].mul(challenge).into_affine(),
                a.commitments[1] + b.commitments[1].mul(challenge).into_affine(),
                a.commitments[2] + b.commitments[2].mul(challenge).into_affine(),
                a.commitments[3] + b.commitments[3].mul(challenge).into_affine(),
                a.commitments[4] + b.commitments[4].mul(challenge).into_affine(),
            ],
            challenges: [
                a.challenges[0] + challenge * b.challenges[0],
                a.challenges[1] + challenge * b.challenges[1],
                a.challenges[2] + challenge * b.challenges[2],
            ],
            alphas: Alphas::combine(a.alphas, b.alphas, challenge),
        }
    }
}

/// Our witness is going to be the polynomials that we will commit too.
/// Vec<Fp> will be the evaluations of each x_1, x_2 and x_3 over the domain.
/// This witness includes not only the 3 normal witness columns, but also the
/// 2 dynamic selector columns that are esentially witness
type TestWitness = [Evaluations<Fp, Radix2EvaluationDomain<Fp>>; 5];

impl Witness<Curve> for TestWitness {
    fn combine(mut a: Self, b: Self, challenge: Fp) -> Self {
        for (a, b) in a.iter_mut().zip(b) {
            for (a, b) in a.evals.iter_mut().zip(b.evals) {
                *a += challenge * b;
            }
        }
        a
    }
}

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

// implementing the an envionment trait compatible with our config
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
        // witnesses, which are just for example as no contraint uses them anyway
        let curr_witnesses = [witnesses[0].clone(), witnesses[1].clone()];
        let mut next_witnesses = curr_witnesses.clone();
        for side in next_witnesses.iter_mut() {
            for col in side.iter_mut() {
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

    fn zero_vec(&self) -> Vec<Fp> {
        //this works in the example but is not the best way as the envionment could get circuits of any size
        vec![Fp::zero(); 2]
    }

    //provide access to columns, here side refers to one of the two pairs you got in new()
    fn col(&self, col: TestColumn, curr_or_next: CurrOrNext, side: Side) -> &Vec<Fp> {
        let wit = match curr_or_next {
            CurrOrNext::Curr => &self.curr_witnesses[side as usize],
            CurrOrNext::Next => &self.next_witnesses[side as usize],
        };
        match col {
            TestColumn::A => &wit[0].evals,
            TestColumn::B => &wit[1].evals,
            TestColumn::C => &wit[2].evals,
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

    // not used, you can generate it here, or if you only want to compute once use
    // something like HashMap<usize,OnceCell<Vec<Fp>>> to compute once and reuse
    fn lagrange_basis(&self, _i: usize) -> &Vec<Fp> {
        todo!()
    }

    // access to the alphas, while folding will decide how many there are and how do
    // they appear in the expressions, the instances should store them, and the environment
    // should provide acces to them like this
    fn alpha(&self, i: usize, side: Side) -> Fp {
        let instance = &self.instances[side as usize];
        instance.alphas.get(i).unwrap()
    }

    // this is exclusively for dynamic selectors aiming to make use of optimization
    // as clasic static selectors will be handle as normal structure columns in col()
    // the implementation of this if the same as col(), it is just separated as they
    // have different types to resolve
    fn selector(&self, s: &DynamicSelector, side: Side) -> &Vec<Fp> {
        let wit = &self.curr_witnesses[side as usize];
        match s {
            DynamicSelector::SelecAdd => &wit[3].evals,
            DynamicSelector::SelecSub => &wit[4].evals,
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

    type E = Box<FoldingCompatibleExpr<TestFoldingConfig>>;
    let op = |a: E, b: E, op| Box::new(FoldingCompatibleExpr::BinOp(op, a, b));

    let add = op(a.clone(), b.clone(), Op2::Add);
    let add = op(add, c.clone(), Op2::Sub);

    let sub = op(a, b, Op2::Sub);
    let sub = op(sub, c, Op2::Sub);

    [
        (DynamicSelector::SelecAdd, vec![*add]),
        (DynamicSelector::SelecSub, vec![*sub]),
    ]
    .into_iter()
    .collect()
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TestFoldingConfig;

#[allow(dead_code)]
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
    type S = DynamicSelector;
    type Challenge = TestChallenge;
    type Curve = Curve;
    type Srs = poly_commitment::srs::SRS<Curve>;
    type Sponge = BaseSponge;
    type Instance = TestInstance;
    type Witness = TestWitness;
    type Env = TestFoldingEnv;

    fn rows() -> usize {
        2
    }
}

//creates an instance from its witness
fn instance_from_witness(
    witness: &TestWitness,
    srs: &<TestFoldingConfig as FoldingConfig>::Srs,
    domain: Radix2EvaluationDomain<Fp>,
) -> TestInstance {
    let commitments = witness
        .iter()
        .map(|w| srs.commit_evaluations_non_hiding(domain, w))
        .map(|c| c.elems[0])
        .collect_vec();
    let commitments: [_; 5] = commitments.try_into().unwrap();

    // here we should absorve the commitments and similar things to later compute challenges
    // but for this example I just use random values
    let mut rng = thread_rng();
    let mut challenge = || Fp::rand(&mut rng);
    let challenges = [(); 3].map(|_| challenge());
    let alpha = challenge();
    let alphas = Alphas::new(alpha);
    TestInstance {
        commitments,
        challenges,
        alphas,
    }
}

/// A kind of pseudo-prover, will compute the expressions over the witness a check row by row
/// for a zero result.
mod checker {
    use super::*;
    pub struct Provider {
        instance: TestInstance,
        witness: TestWitness,
        rows: usize,
    }

    impl Provider {
        pub(super) fn new(instance: TestInstance, witness: TestWitness) -> Self {
            let rows = TestFoldingConfig::rows();
            Self {
                instance,
                witness,
                rows,
            }
        }
    }

    pub(super) trait Provide {
        fn resolve(&self, inner: FoldingCompatibleExprInner<TestFoldingConfig>) -> Vec<Fp>;
    }
    impl Provide for Provider {
        fn resolve(&self, inner: FoldingCompatibleExprInner<TestFoldingConfig>) -> Vec<Fp> {
            match inner {
                FoldingCompatibleExprInner::Constant(c) => {
                    vec![c; self.rows]
                }
                FoldingCompatibleExprInner::Challenge(chall) => {
                    let chals = self.instance.challenges;
                    let v = match chall {
                        TestChallenge::Beta => chals[0],
                        TestChallenge::Gamma => chals[1],
                        TestChallenge::JointCombiner => chals[2],
                    };
                    vec![v; self.rows]
                }
                FoldingCompatibleExprInner::Cell(var) => {
                    let Variable { col, row } = var;
                    let col = match col {
                        TestColumn::A => &self.witness[0].evals,
                        TestColumn::B => &self.witness[1].evals,
                        TestColumn::C => &self.witness[2].evals,
                    };

                    let mut col = col.clone();
                    //check this, while not relevant in this case I think it should be right rotation
                    if let CurrOrNext::Next = row {
                        col.rotate_left(1);
                    }
                    col
                }
                FoldingCompatibleExprInner::VanishesOnZeroKnowledgeAndPreviousRows => todo!(),
                FoldingCompatibleExprInner::UnnormalizedLagrangeBasis(_) => todo!(),
                FoldingCompatibleExprInner::Extensions(_) => {
                    panic!("not handled here");
                }
            }
        }
    }
    pub struct ExtendedProvider {
        inner_provider: Provider,
        pub instance: RelaxedInstance<<TestFoldingConfig as FoldingConfig>::Curve, TestInstance>,
        pub witness: RelaxedWitness<<TestFoldingConfig as FoldingConfig>::Curve, TestWitness>,
    }

    impl ExtendedProvider {
        pub(super) fn new(
            instance: RelaxedInstance<<TestFoldingConfig as FoldingConfig>::Curve, TestInstance>,
            witness: RelaxedWitness<<TestFoldingConfig as FoldingConfig>::Curve, TestWitness>,
        ) -> Self {
            let inner_provider = {
                let instance = instance.inner_instance().inner.clone();
                let witness = witness.inner().inner.clone();
                Provider::new(instance, witness)
            };
            Self {
                inner_provider,
                instance,
                witness,
            }
        }
    }
    impl Provide for ExtendedProvider {
        fn resolve(&self, inner: FoldingCompatibleExprInner<TestFoldingConfig>) -> Vec<Fp> {
            match inner {
                FoldingCompatibleExprInner::Extensions(ext) => match ext {
                    ExpExtension::U => {
                        let u = self.instance.u;
                        vec![u; self.inner_provider.rows]
                    }
                    ExpExtension::Error => self.witness.error_vec.evals.clone(),
                    ExpExtension::ExtendedWitness(i) => {
                        self.witness.inner().extended.get(&i).unwrap().evals.clone()
                    }
                    ExpExtension::Alpha(i) => {
                        let alpha = self.instance.inner_instance().inner.alphas.get(i).unwrap();
                        vec![alpha; self.inner_provider.rows]
                    }
                    ExpExtension::Selector(s) => {
                        let col = match s {
                            DynamicSelector::SelecAdd => &self.inner_provider.witness[3].evals,
                            DynamicSelector::SelecSub => &self.inner_provider.witness[4].evals,
                        };
                        col.clone()
                    }
                },
                e => self.inner_provider.resolve(e),
            }
        }
    }

    pub(super) trait Checker: Provide {
        fn check_rec(&self, exp: FoldingCompatibleExpr<TestFoldingConfig>, debug: bool) -> Vec<Fp> {
            let e2 = exp.clone();
            let res = match exp {
                FoldingCompatibleExpr::Atom(inner) => self.resolve(inner),
                FoldingCompatibleExpr::Double(e) => {
                    let v = self.check_rec(*e, debug);
                    v.into_iter().map(|x| x.double()).collect()
                }
                FoldingCompatibleExpr::Square(e) => {
                    let v = self.check_rec(*e, debug);
                    v.into_iter().map(|x| x.square()).collect()
                }
                FoldingCompatibleExpr::BinOp(op, e1, e2) => {
                    let v1 = self.check_rec(*e1, debug);
                    let v2 = self.check_rec(*e2, debug);
                    let op = match op {
                        Op2::Add => |(a, b)| a + b,
                        Op2::Mul => |(a, b)| a * b,
                        Op2::Sub => |(a, b)| a - b,
                    };
                    v1.into_iter().zip(v2).map(op).collect()
                }
                FoldingCompatibleExpr::Pow(e, exp) => {
                    let v = self.check_rec(*e, debug);
                    v.into_iter().map(|x| x.pow([exp])).collect()
                }
            };
            if debug {
                println!("exp: {:?}", e2);
                println!("res: [\n");
                for e in res.iter() {
                    println!("{e}\n");
                }
                println!("]");
            }
            res
        }
        fn check(&self, exp: &FoldingCompatibleExpr<TestFoldingConfig>, debug: bool) {
            let res = self.check_rec(exp.clone(), debug);
            for (i, row) in res.iter().enumerate() {
                if !row.is_zero() {
                    panic!("check in row {i} failed, {row} != 0");
                }
            }
        }
    }
    impl<T: Provide> Checker for T {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::folding::{
        decomposable_folding::DecomposableFoldingScheme, example2::checker::ExtendedProvider,
    };
    use ark_poly::{EvaluationDomain, Evaluations};

    //two functions to create the entire witness from just the a and b columns
    fn add_witness(a: [u32; 2], b: [u32; 2]) -> [[u32; 2]; 5] {
        let [a1, a2] = a;
        let [b1, b2] = b;
        let c = [a1 + b1, a2 + b2];
        [a, b, c, [1, 1], [0, 0]]
    }
    fn sub_witness(a: [u32; 2], b: [u32; 2]) -> [[u32; 2]; 5] {
        let [a1, a2] = a;
        let [b1, b2] = b;
        let c = [a1 - b1, a2 - b2];
        [a, b, c, [0, 0], [1, 1]]
    }
    fn int_to_witness(x: [[u32; 2]; 5], domain: Radix2EvaluationDomain<Fp>) -> TestWitness {
        x.map(|row| Evaluations::from_vec_and_domain(row.map(Fp::from).to_vec(), domain))
    }

    // in this test we will create 2 add witnesses, fold them together, create 2 sub witnesses,
    // fold them together, and then further fold the 2 resulting pairs into one mixed add-sub witnes
    // instances are also folded, but not that relevant in the examples as we don't make a proof for them
    // and instead directly check the witness
    #[test]
    fn test_decomposable_folding() {
        use ark_poly::Radix2EvaluationDomain as D;
        use checker::Checker;

        let constraints = constraints();
        let domain = D::<Fp>::new(2).unwrap();
        let mut srs = poly_commitment::srs::SRS::<Curve>::create(2);
        srs.add_lagrange_basis(domain);

        //initiallize the scheme, also getting the final single expression for the entire constraint system
        let (scheme, final_constraint) = DecomposableFoldingScheme::<TestFoldingConfig>::new(
            constraints.clone(),
            vec![],
            srs.clone(),
            domain,
            (),
        );

        //some inputs to be used by both add and sub
        let inputs1 = [[4u32, 2u32], [2u32, 1u32]];
        let inputs2 = [[5u32, 6u32], [4u32, 3u32]];

        //creates an instance witness pair
        let make_pair = |wit: TestWitness| {
            let ins = instance_from_witness(&wit, &srs, domain);
            (wit, ins)
        };

        //fold adds
        // println!("fold add");
        let left = {
            let [a, b] = inputs1;
            let wit1 = add_witness(a, b);
            let (witness1, instance1) = make_pair(int_to_witness(wit1, domain));

            let [a, b] = inputs2;
            let wit2 = add_witness(a, b);
            let (witness2, instance2) = make_pair(int_to_witness(wit2, domain));

            let left = (instance1, witness1);
            let right = (instance2, witness2);
            // here we provide normal instance-witness pairs, which will be automatically relaxed
            let folded = scheme.fold_instance_witness_pair::<TestInstance, TestWitness, _, _>(
                left,
                right,
                Some(DynamicSelector::SelecAdd),
            );
            let (folded_instance, folded_witness, [_t0, _t1]) = folded;
            let checker = ExtendedProvider::new(folded_instance, folded_witness);
            // println!("exp: \n {:#?}", final_constraint);
            checker.check(&final_constraint, false);
            let ExtendedProvider {
                instance, witness, ..
            } = checker;
            (instance, witness)
        };
        //fold subs
        // println!("fold subs");
        let right = {
            let [a, b] = inputs1;
            let wit1 = sub_witness(a, b);
            let (witness1, instance1) = make_pair(int_to_witness(wit1, domain));

            let [a, b] = inputs2;
            let wit2 = sub_witness(a, b);
            let (witness2, instance2) = make_pair(int_to_witness(wit2, domain));

            let left = (instance1, witness1);
            let right = (instance2, witness2);
            let folded = scheme.fold_instance_witness_pair::<TestInstance, TestWitness, _, _>(
                left,
                right,
                Some(DynamicSelector::SelecSub),
            );
            let (folded_instance, folded_witness, [_t0, _t1]) = folded;

            let checker = ExtendedProvider::new(folded_instance, folded_witness);
            // println!("exp: \n {:#?}", final_constraint);

            checker.check(&final_constraint, false);
            let ExtendedProvider {
                instance, witness, ..
            } = checker;
            (instance, witness)
        };
        //fold mixed
        // println!("fold mixed");
        {
            // here we use already relaxed pairs, which have a trival x -> x implementation
            let folded = scheme
                .fold_instance_witness_pair::<TestInstance, TestWitness, _, _>(left, right, None);
            let (folded_instance, folded_witness, [_t0, _t1]) = folded;

            let checker = ExtendedProvider::new(folded_instance, folded_witness);
            // println!("exp: \n {:#?}", final_constraint);

            checker.check(&final_constraint, false);
        };
    }
}
