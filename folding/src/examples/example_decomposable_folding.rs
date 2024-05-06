use crate::{
    checker::{Alphas, BaseSponge, Checker, Curve, Fp, Provide},
    error_term::Side,
    expressions::{FoldingColumnTrait, FoldingCompatibleExprInner},
    ExpExtension, FoldingCompatibleExpr, FoldingConfig, FoldingEnv, Instance, RelaxedInstance,
    RelaxedWitness, Witness,
};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{UniformRand, Zero};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use itertools::Itertools;
use kimchi::circuits::{expr::Variable, gate::CurrOrNext};
use poly_commitment::SRS;
use rand::thread_rng;
use std::collections::BTreeMap;

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

/// The instance is the commitments to the polynomials and the challenges
#[derive(Debug, Clone)]
pub struct TestInstance {
    // 3 from the normal witness + 2 from the dynamic selectors
    commitments: [Curve; 5],
    // for ilustration only, no constraint in this example uses challenges
    challenges: [Fp; 3],
    // also challenges, but segregated as folding gives them special treatment
    alphas: Alphas<Curve>,
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

    fn alphas(&self) -> &Alphas<Curve> {
        &self.alphas
    }

    fn challenges(&self) -> &[Fp] {
        &self.challenges
    }
}

/// Our witness is going to be the polynomials that we will commit too.
/// Vec<Fp> will be the evaluations of each x_1, x_2 and x_3 over the domain.
/// This witness includes not only the 3 normal witness columns, but also the
/// 2 dynamic selector columns that are esentially witness
pub type TestWitness = [Evaluations<Fp, Radix2EvaluationDomain<Fp>>; 5];

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
        // this works in the example but is not the best way as the envionment
        // could get circuits of any size
        vec![Fp::zero(); 2]
    }

    // provide access to columns, here side refers to one of the two pairs you
    // got in new()
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

    let add = FoldingCompatibleExpr::Add(a.clone(), b.clone());
    let add = FoldingCompatibleExpr::Sub(add.into(), c.clone());

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
    type Selector = DynamicSelector;
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

    // here we should absorb the commitments and similar things to later compute challenges
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

    impl Checker<TestFoldingConfig> for ExtendedProvider {}
}

#[cfg(test)]
mod tests {
    use super::*;
    // Trick to print debug message while testing, as we in the test config env
    use crate::decomposable_folding::DecomposableFoldingScheme;
    use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain as D};
    use checker::ExtendedProvider;
    use std::println as debug;

    // two functions to create the entire witness from just the a and b columns
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
        let mut srs = poly_commitment::srs::SRS::<Curve>::create(2);
        srs.add_lagrange_basis(domain);

        // initiallize the scheme, also getting the final single expression for
        // the entire constraint system
        let (scheme, final_constraint) = DecomposableFoldingScheme::<TestFoldingConfig>::new(
            constraints.clone(),
            vec![],
            &srs,
            domain,
            (),
        );

        // some inputs to be used by both add and sub
        let inputs1 = [[4u32, 2u32], [2u32, 1u32]];
        let inputs2 = [[5u32, 6u32], [4u32, 3u32]];

        // creates an instance witness pair
        let make_pair = |wit: TestWitness| {
            let ins = instance_from_witness(&wit, &srs, domain);
            (wit, ins)
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
            let folded =
                scheme.fold_instance_witness_pair(left, right, Some(DynamicSelector::SelecAdd));
            let (folded_instance, folded_witness, [_t0, _t1]) = folded;
            let checker = ExtendedProvider::new(folded_instance, folded_witness);
            debug!("exp: \n {:#?}", final_constraint.to_string());
            checker.check(&final_constraint);
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
            let folded =
                scheme.fold_instance_witness_pair(left, right, Some(DynamicSelector::SelecSub));
            let (folded_instance, folded_witness, [_t0, _t1]) = folded;

            let checker = ExtendedProvider::new(folded_instance, folded_witness);
            debug!("exp: \n {:#?}", final_constraint.to_string());

            checker.check(&final_constraint);
            let ExtendedProvider {
                instance, witness, ..
            } = checker;
            (instance, witness)
        };
        //fold mixed
        debug!("fold mixed");
        {
            // here we use already relaxed pairs, which have a trival x -> x implementation
            let folded = scheme.fold_instance_witness_pair(left, right, None);
            let (folded_instance, folded_witness, [_t0, _t1]) = folded;

            let checker = ExtendedProvider::new(folded_instance, folded_witness);
            debug!("exp: \n {:#?}", final_constraint.to_string());

            checker.check(&final_constraint);
        };
    }
}
