use crate::{
    circuits::{
        expr::{Op2, Variable},
        gate::CurrOrNext,
    },
    curve::KimchiCurve,
    folding::{
        error_term::Side, expressions::FoldingColumnTrait, FoldingConfig, FoldingEnv, Instance,
        Sponge, Witness,
    },
};
use ark_bn254;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, UniformRand, Zero};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use itertools::Itertools;
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, ScalarChallenge},
    FqSponge,
};
use poly_commitment::{PolyComm, SRS};
use rand::thread_rng;
use std::{
    iter::successors,
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering},
};

use super::{
    expressions::FoldingCompatibleExprInner, ExpExtension, FoldingCompatibleExpr, RelaxedInstance,
    RelaxedWitness,
};

/// Field = BN254 prime field
/// Statement: I know w such that C(x, y, w) = 0
///   public
///     |
///   ----  |--- private
/// C(x, y, w) = x + y - w
/// I want to fold two instances

/// (A Z) . (B Z) = (C Z)
/// Z = (x, y, z)
/// A = (1 1 -1)
/// B = (0, 0, 0)
/// C = (1 1 -1)

type Fp = ark_bn254::Fr;
type Curve = ark_bn254::G1Affine;
type SpongeParams = PlonkSpongeConstantsKimchi;
pub type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TestColumn {
    A,
    B,
    C,
    SelecAdd,
    SelecMul,
}

impl FoldingColumnTrait for TestColumn {
    fn is_witness(&self) -> bool {
        match self {
            TestColumn::A | TestColumn::B | TestColumn::C => true,
            TestColumn::SelecAdd | TestColumn::SelecMul => false,
        }
    }
}

// TODO: get rid of trait Sponge in folding, and use the one from kimchi
impl Sponge<Curve> for BaseSponge {
    fn challenge(absorb: &[PolyComm<Curve>; 2]) -> Fp {
        // This function does not have a &self because it is meant to absorb and squeeze only once
        let mut s = BaseSponge::new(Curve::other_curve_sponge_params());
        s.absorb_g(&absorb[0].elems);
        s.absorb_g(&absorb[1].elems);
        // Squeeze sponge
        let chal = ScalarChallenge(s.challenge());
        let (_, endo_r) = Curve::endos();
        chal.to_field(endo_r)
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
struct TestInstance {
    commitments: [Curve; 3],
    challenges: [Fp; 3],
    alphas: Alphas,
}

impl Instance<Curve> for TestInstance {
    fn combine(a: Self, b: Self, challenge: Fp) -> Self {
        TestInstance {
            commitments: [
                a.commitments[0] + b.commitments[0].mul(challenge).into_affine(),
                a.commitments[1] + b.commitments[1].mul(challenge).into_affine(),
                a.commitments[2] + b.commitments[2].mul(challenge).into_affine(),
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
type TestWitness = [Evaluations<Fp, Radix2EvaluationDomain<Fp>>; 3];

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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TestStructure<F: Clone> {
    s_add: Vec<F>,
    s_mul: Vec<F>,
}

struct TestFoldingEnv {
    structure: TestStructure<Fp>,
    instances: [TestInstance; 2],
    // Corresponds to the omega evaluations, for both sides
    curr_witnesses: [TestWitness; 2],
    // Corresponds to the zeta*omega evaluations, for both sides
    // This is curr_witness but left shifted by 1
    next_witnesses: [TestWitness; 2],
}

impl FoldingEnv<Fp, TestInstance, TestWitness, TestColumn, TestChallenge> for TestFoldingEnv {
    type Structure = TestStructure<Fp>;

    fn new(
        structure: &Self::Structure,
        instances: [&TestInstance; 2],
        witnesses: [&TestWitness; 2],
    ) -> Self {
        let curr_witnesses = [witnesses[0].clone(), witnesses[1].clone()];
        let mut next_witnesses = curr_witnesses.clone();
        for side in next_witnesses.iter_mut() {
            for col in side.iter_mut() {
                //TODO: check this, while not relevant for this example I think it should be right rotation
                col.evals.rotate_left(1);
            }
        }
        TestFoldingEnv {
            structure: structure.clone(),
            instances: [instances[0].clone(), instances[1].clone()],
            curr_witnesses,
            next_witnesses,
        }
    }

    fn zero_vec(&self) -> Vec<Fp> {
        vec![Fp::zero(); 2]
    }

    fn col(&self, col: TestColumn, curr_or_next: CurrOrNext, side: Side) -> &Vec<Fp> {
        let wit = match curr_or_next {
            CurrOrNext::Curr => &self.curr_witnesses[side as usize],
            CurrOrNext::Next => &self.next_witnesses[side as usize],
        };
        match col {
            TestColumn::A => &wit[0].evals,
            TestColumn::B => &wit[1].evals,
            TestColumn::C => &wit[2].evals,
            TestColumn::SelecAdd => &self.structure.s_add,
            TestColumn::SelecMul => &self.structure.s_mul,
        }
    }

    fn challenge(&self, challenge: TestChallenge, side: Side) -> Fp {
        match challenge {
            TestChallenge::Beta => self.instances[side as usize].challenges[0],
            TestChallenge::Gamma => self.instances[side as usize].challenges[1],
            TestChallenge::JointCombiner => self.instances[side as usize].challenges[2],
        }
    }

    fn lagrange_basis(&self, _i: usize) -> &Vec<Fp> {
        todo!()
    }

    fn alpha(&self, i: usize, side: Side) -> Fp {
        let instance = &self.instances[side as usize];
        instance.alphas.get(i).unwrap()
    }
}

fn constraints() -> Vec<FoldingCompatibleExpr<TestFoldingConfig>> {
    let get_col = |col| {
        FoldingCompatibleExpr::Atom(FoldingCompatibleExprInner::Cell(Variable {
            col,
            row: CurrOrNext::Curr,
        }))
    };
    let a = Box::new(get_col(TestColumn::A));
    let b = Box::new(get_col(TestColumn::B));
    let c = Box::new(get_col(TestColumn::C));
    let s_add = Box::new(get_col(TestColumn::SelecAdd));
    let s_mul = Box::new(get_col(TestColumn::SelecMul));

    type E = Box<FoldingCompatibleExpr<TestFoldingConfig>>;
    let op = |a: E, b: E, op| Box::new(FoldingCompatibleExpr::BinOp(op, a, b));

    let add = op(a.clone(), b.clone(), Op2::Add);
    let add = op(add, c.clone(), Op2::Sub);
    let add = op(add, s_add, Op2::Mul);

    let mul = op(a, b, Op2::Mul);
    let mul = op(mul, c, Op2::Sub);
    let mul = op(mul, s_mul, Op2::Mul);

    vec![*add, *mul]
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TestFoldingConfig;

// Does not contain alpha because this one should be provided by folding itself
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum TestChallenge {
    Beta,
    Gamma,
    JointCombiner,
}

impl FoldingConfig for TestFoldingConfig {
    type Structure = TestStructure<Fp>;
    type Column = TestColumn;
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
    let commitments: [_; 3] = commitments.try_into().unwrap();

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
fn circuit() -> [Vec<Fp>; 2] {
    [vec![Fp::one(), Fp::zero()], vec![Fp::zero(), Fp::one()]]
}

/// A kind of pseudo-prover, will compute the expressions over the witness a check row by row
/// for a zero result.
mod checker {
    use super::*;
    pub struct Provider {
        structure: TestStructure<Fp>,
        instance: TestInstance,
        witness: TestWitness,
        rows: usize,
    }

    impl Provider {
        pub(super) fn new(
            structure: TestStructure<Fp>,
            instance: TestInstance,
            witness: TestWitness,
        ) -> Self {
            let rows = TestFoldingConfig::rows();
            Self {
                structure,
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
                        TestColumn::SelecAdd => &self.structure.s_add,
                        TestColumn::SelecMul => &self.structure.s_mul,
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
                    panic!("not handled")
                }
            }
        }
    }
    pub struct ExtendedProvider {
        inner_provider: Provider,
        instance: RelaxedInstance<<TestFoldingConfig as FoldingConfig>::Curve, TestInstance>,
        witness: RelaxedWitness<<TestFoldingConfig as FoldingConfig>::Curve, TestWitness>,
        rows: usize,
    }

    impl ExtendedProvider {
        pub(super) fn new(
            structure: TestStructure<Fp>,
            instance: RelaxedInstance<<TestFoldingConfig as FoldingConfig>::Curve, TestInstance>,
            witness: RelaxedWitness<<TestFoldingConfig as FoldingConfig>::Curve, TestWitness>,
        ) -> Self {
            let inner_provider = {
                let instance = instance.inner_instance().inner.clone();
                let witness = witness.inner().inner.clone();
                Provider::new(structure, instance, witness)
            };
            let rows = inner_provider.rows;
            Self {
                inner_provider,
                instance,
                witness,
                rows,
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
        fn check(&self, exp: FoldingCompatibleExpr<TestFoldingConfig>, debug: bool) {
            let res = self.check_rec(exp, debug);
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
    use crate::folding::{example::checker::ExtendedProvider, FoldingScheme};
    use ark_poly::{EvaluationDomain, Evaluations};

    // this checks a single folding, it would be good to expand it in the future to do several foldings,
    // as a few thigs are trivial in the first fold
    #[test]
    fn test_folding_instance() {
        use ark_poly::Radix2EvaluationDomain as D;
        use checker::{Checker, Provider};

        let constraints = constraints();
        let domain = D::<Fp>::new(2).unwrap();
        let mut srs = poly_commitment::srs::SRS::<Curve>::create(2);
        srs.add_lagrange_basis(domain);
        let [s_add, s_mul] = circuit();
        let structure = TestStructure { s_add, s_mul };

        let (scheme, final_constraint) = FoldingScheme::<TestFoldingConfig>::new(
            constraints.clone(),
            srs.clone(),
            domain,
            structure.clone(),
        );

        // We have a 2 row circuit with and addition gate in the first row, and a multiplication gate in the second

        // Left: 1 + 2 - 3 = 0
        let left_witness = [
            vec![Fp::from(1u32), Fp::from(2u32)],
            vec![Fp::from(2u32), Fp::from(3u32)],
            vec![Fp::from(3u32), Fp::from(6u32)],
        ];
        let left_witness: TestWitness =
            left_witness.map(|evals| Evaluations::from_vec_and_domain(evals, domain));
        // Right: 4 + 5 - 9 = 0
        let right_witness = [
            vec![Fp::from(4u32), Fp::from(3u32)],
            vec![Fp::from(5u32), Fp::from(6u32)],
            vec![Fp::from(9u32), Fp::from(18u32)],
        ];
        let right_witness: TestWitness =
            right_witness.map(|evals| Evaluations::from_vec_and_domain(evals, domain));

        //instances
        let left_instance = instance_from_witness(&left_witness, &srs, domain);
        let right_instance = instance_from_witness(&left_witness, &srs, domain);

        //check left
        {
            // println!("check left");
            let checker = Provider::new(
                structure.clone(),
                left_instance.clone(),
                left_witness.clone(),
            );
            for constraint in &constraints {
                checker.check(constraint.clone(), false)
            }
        }
        //check right
        {
            // println!("check right");
            let checker = Provider::new(
                structure.clone(),
                right_instance.clone(),
                right_witness.clone(),
            );
            for constraint in &constraints {
                checker.check(constraint.clone(), false)
            }
        }

        //pairs
        let left = (left_instance, left_witness);
        let right = (right_instance, right_witness);

        let folded =
            scheme.fold_instance_witness_pair::<TestInstance, TestWitness, _, _>(left, right);
        let (folded_instance, folded_witness, [_t0, _t1]) = folded;
        {
            let checker = ExtendedProvider::new(structure, folded_instance, folded_witness);
            // println!("exp: \n {:#?}", final_constraint);
            // println!("check folded");
            checker.check(final_constraint, false);
        }
    }
}
