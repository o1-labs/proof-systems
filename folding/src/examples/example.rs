/// This file shows how to use the folding trait with a simple configuration of
/// 3 columns, and two selectors. See [tests::test_folding_instance] at the end
/// for a test.
/// The test requires the features `bn254`, therefore use the following command
/// to execute it:
/// ```text
/// cargo nextest run examples::example::tests::test_folding_instance --release --all-features
/// ```
use crate::{
    error_term::Side,
    examples::generic::{Alphas, BaseSponge, Checker, Column, Curve, Fp, Provide},
    expressions::FoldingCompatibleExprInner,
    ExpExtension, FoldingCompatibleExpr, FoldingConfig, FoldingEnv, Instance, RelaxedInstance,
    RelaxedWitness, Witness,
};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{One, UniformRand, Zero};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use itertools::Itertools;
use kimchi::circuits::{expr::Variable, gate::CurrOrNext};
use poly_commitment::SRS;
use rand::thread_rng;

/// The instance is the commitments to the polynomials and the challenges
/// There are 3 commitments and challanges because there are 3 columns, A, B and
/// C.
#[derive(Debug, Clone)]
struct TestInstance {
    commitments: [Curve; 3],
    challenges: [Fp; 3],
    alphas: Alphas,
}

impl Instance<Curve> for TestInstance {
    fn combine(a: Self, b: Self, challenge: Fp) -> Self {
        TestInstance {
            commitments: std::array::from_fn(|i| {
                a.commitments[i] + b.commitments[i].mul(challenge).into_affine()
            }),
            challenges: std::array::from_fn(|i| a.challenges[i] + challenge * b.challenges[i]),
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
    constants: Vec<F>,
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

impl FoldingEnv<Fp, TestInstance, TestWitness, Column, TestChallenge, ()> for TestFoldingEnv {
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
                // TODO: check this, while not relevant for this example I think
                // it should be right rotation
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

    fn col(&self, col: Column, curr_or_next: CurrOrNext, side: Side) -> &Vec<Fp> {
        let wit = match curr_or_next {
            CurrOrNext::Curr => &self.curr_witnesses[side as usize],
            CurrOrNext::Next => &self.next_witnesses[side as usize],
        };
        match col {
            Column::X(0) => &wit[0].evals,
            Column::X(1) => &wit[1].evals,
            Column::X(2) => &wit[2].evals,
            Column::Selector(0) => &self.structure.s_add,
            Column::Selector(1) => &self.structure.s_mul,
            // Only 3 columns and 2 selectors
            Column::X(_) => unreachable!(),
            Column::Selector(_) => unreachable!(),
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

    fn selector(&self, _s: &(), _side: Side) -> &Vec<Fp> {
        unreachable!()
    }
}

fn constraints() -> Vec<FoldingCompatibleExpr<TestFoldingConfig>> {
    let get_col = |col| {
        FoldingCompatibleExpr::Atom(FoldingCompatibleExprInner::Cell(Variable {
            col,
            row: CurrOrNext::Curr,
        }))
    };
    let a = Box::new(get_col(Column::X(0)));
    let b = Box::new(get_col(Column::X(1)));
    let c = Box::new(get_col(Column::X(2)));
    let s_add = Box::new(get_col(Column::Selector(0)));
    let s_mul = Box::new(get_col(Column::Selector(1)));

    let add = FoldingCompatibleExpr::Add(a.clone(), b.clone());
    let add = FoldingCompatibleExpr::Sub(add.into(), c.clone());
    let add = FoldingCompatibleExpr::Mul(add.into(), s_add.clone());

    let mul = FoldingCompatibleExpr::Mul(a.clone(), b.clone());
    let mul = FoldingCompatibleExpr::Sub(mul.into(), c.clone());
    let mul = FoldingCompatibleExpr::Mul(mul.into(), s_mul.clone());

    vec![add, mul]
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TestFoldingConfig;

// Does not contain alpha because this one should be provided by folding itself
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum TestChallenge {
    Beta,
    Gamma,
    JointCombiner,
}

impl FoldingConfig for TestFoldingConfig {
    type Structure = TestStructure<Fp>;
    type Column = Column;
    type Selector = ();
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

/// A kind of pseudo-prover, will compute the expressions over the witness a
/// check row by row for a zero result.
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

    impl Provide<TestFoldingConfig> for Provider {
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
                        Column::X(0) => &self.witness[0].evals,
                        Column::X(1) => &self.witness[1].evals,
                        Column::X(2) => &self.witness[2].evals,
                        Column::Selector(0) => &self.structure.s_add,
                        Column::Selector(1) => &self.structure.s_mul,
                        // Only 3 columns and 2 selectors
                        Column::X(_) => unreachable!(),
                        Column::Selector(_) => unreachable!(),
                    };

                    let mut col = col.clone();
                    // check this, while not relevant in this case I think it
                    // should be right rotation
                    if let CurrOrNext::Next = row {
                        col.rotate_left(1);
                    }
                    col
                }
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
            Self {
                inner_provider,
                instance,
                witness,
            }
        }
    }

    impl Provide<TestFoldingConfig> for ExtendedProvider {
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
                    ExpExtension::Selector(_) => panic!("unused"),
                },
                e => self.inner_provider.resolve(e),
            }
        }
    }

    impl Checker<TestFoldingConfig> for Provider {}
    impl Checker<TestFoldingConfig> for ExtendedProvider {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FoldingScheme;
    use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain as D};
    use checker::{ExtendedProvider, Provider};
    use std::println as debug;

    // this checks a single folding, it would be good to expand it in the future
    // to do several foldings, as a few thigs are trivial in the first fold
    #[test]
    fn test_folding_instance() {
        let constraints = constraints();
        let domain = D::<Fp>::new(2).unwrap();
        let mut srs = poly_commitment::srs::SRS::<Curve>::create(2);
        srs.add_lagrange_basis(domain);
        let [s_add, s_mul] = circuit();
        let structure = TestStructure {
            s_add,
            s_mul,
            constants: vec![],
        };

        let (scheme, final_constraint) = FoldingScheme::<TestFoldingConfig>::new(
            constraints.clone(),
            &srs,
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

        // instances
        let left_instance = instance_from_witness(&left_witness, &srs, domain);
        let right_instance = instance_from_witness(&left_witness, &srs, domain);

        // check left
        {
            debug!("check left");
            let checker = Provider::new(
                structure.clone(),
                left_instance.clone(),
                left_witness.clone(),
            );
            constraints
                .iter()
                .for_each(|constraint| checker.check(constraint));
        }
        // check right
        {
            debug!("check right");
            let checker = Provider::new(
                structure.clone(),
                right_instance.clone(),
                right_witness.clone(),
            );
            constraints
                .iter()
                .for_each(|constraint| checker.check(constraint));
        }

        // pairs
        let left = (left_instance, left_witness);
        let right = (right_instance, right_witness);

        let folded = scheme.fold_instance_witness_pair(left, right);
        let (folded_instance, folded_witness, [_t0, _t1]) = folded;
        {
            let checker = ExtendedProvider::new(structure, folded_instance, folded_witness);
            debug!("exp: \n {:#?}", final_constraint);
            debug!("check folded");
            checker.check(&final_constraint);
        }
    }
}
