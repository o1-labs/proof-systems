/// This file shows how to use the folding trait with a simple configuration of
/// 3 columns, and two selectors. See [tests::test_folding_instance] at the end
/// for a test.
/// The test requires the features `bn254`, therefore use the following command
/// to execute it:
/// ```text
/// cargo nextest run test_folding_instance --release --all-features
/// ```
use ark_ec::AffineRepr;
use ark_ff::{One, UniformRand, Zero};
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain};
use checker::{ExtendedProvider, Provider};
use folding::{
    checker::{Checker, Column, Provide},
    expressions::FoldingCompatibleExprInner,
    instance_witness::Foldable,
    Alphas, ExpExtension, FoldingCompatibleExpr, FoldingConfig, FoldingEnv, FoldingOutput,
    FoldingScheme, Instance, RelaxedInstance, RelaxedWitness, Side, Witness,
};
use itertools::Itertools;
use kimchi::{
    circuits::{expr::Variable, gate::CurrOrNext},
    curve::KimchiCurve,
};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge, FqSponge};
use poly_commitment::{ipa::SRS, SRS as _};
use rand::thread_rng;
use std::println as debug;

type Fp = ark_bn254::Fr;
type Curve = ark_bn254::G1Affine;
type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<ark_bn254::g1::Config, SpongeParams>;

/// The instance is the commitments to the polynomials and the challenges
/// There are 3 commitments and challenges because there are 3 columns, A, B and
/// C.
#[derive(PartialEq, Eq, Debug, Clone)]
struct TestInstance {
    commitments: [Curve; 3],
    challenges: [Fp; 3],
    alphas: Alphas<Fp>,
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
        let mut fields = Vec::with_capacity(3 + 2);
        fields.extend(self.challenges);
        fields.extend(self.alphas.clone().powers());
        assert_eq!(fields.len(), 5);
        let points = self.commitments.to_vec();
        (fields, points)
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
#[derive(Clone)]
struct TestWitness([Evaluations<Fp, Radix2EvaluationDomain<Fp>>; 3]);

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
            for col in side.0.iter_mut() {
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

    fn col(&self, col: Column, curr_or_next: CurrOrNext, side: Side) -> &[Fp] {
        let with = match curr_or_next {
            CurrOrNext::Curr => &self.curr_witnesses[side as usize],
            CurrOrNext::Next => &self.next_witnesses[side as usize],
        };
        match col {
            Column::X(0) => &with.0[0].evals,
            Column::X(1) => &with.0[1].evals,
            Column::X(2) => &with.0[2].evals,
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

    fn selector(&self, _s: &(), _side: Side) -> &[Fp] {
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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
// Flag used as the challenges are never built.
// FIXME: should we use unit?
#[allow(dead_code)]
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
    type Srs = SRS<Curve>;
    type Instance = TestInstance;
    type Witness = TestWitness;
    type Env = TestFoldingEnv;
}

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
    let commitments: [_; 3] = commitments.try_into().unwrap();

    // here we should absorb the commitments and similar things to later
    // compute challenges but for this example I just use random values
    let mut rng = thread_rng();
    let mut challenge = || Fp::rand(&mut rng);
    let challenges = [(); 3].map(|_| challenge());
    let alpha = challenge();
    let alphas = Alphas::new(alpha);
    // We suppose we always have a blinder to one.
    let blinder = Fp::one();
    TestInstance {
        commitments,
        challenges,
        alphas,
        blinder,
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
    }

    impl Provider {
        pub(super) fn new(
            structure: TestStructure<Fp>,
            instance: TestInstance,
            witness: TestWitness,
        ) -> Self {
            Self {
                structure,
                instance,
                witness,
            }
        }
    }

    impl Provide<TestFoldingConfig> for Provider {
        fn resolve(
            &self,
            inner: FoldingCompatibleExprInner<TestFoldingConfig>,
            domain: Radix2EvaluationDomain<Fp>,
        ) -> Vec<Fp> {
            let domain_size = domain.size as usize;
            match inner {
                FoldingCompatibleExprInner::Constant(c) => {
                    vec![c; domain_size]
                }
                FoldingCompatibleExprInner::Challenge(chall) => {
                    let chals = self.instance.challenges;
                    let v = match chall {
                        TestChallenge::Beta => chals[0],
                        TestChallenge::Gamma => chals[1],
                        TestChallenge::JointCombiner => chals[2],
                    };
                    vec![v; domain_size]
                }
                FoldingCompatibleExprInner::Cell(var) => {
                    let Variable { col, row } = var;
                    let col = match col {
                        Column::X(0) => &self.witness.0[0].evals,
                        Column::X(1) => &self.witness.0[1].evals,
                        Column::X(2) => &self.witness.0[2].evals,
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
                let instance = instance.extended_instance.instance.clone();
                let witness = witness.extended_witness.witness.clone();
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
        fn resolve(
            &self,
            inner: FoldingCompatibleExprInner<TestFoldingConfig>,
            domain: Radix2EvaluationDomain<Fp>,
        ) -> Vec<Fp> {
            let domain_size = domain.size as usize;
            match inner {
                FoldingCompatibleExprInner::Extensions(ext) => match ext {
                    ExpExtension::U => {
                        let u = self.instance.u;
                        vec![u; domain_size]
                    }
                    ExpExtension::Error => self.witness.error_vec.evals.clone(),
                    ExpExtension::ExtendedWitness(i) => self
                        .witness
                        .extended_witness
                        .extended
                        .get(&i)
                        .unwrap()
                        .evals
                        .clone(),
                    ExpExtension::Alpha(i) => {
                        let alpha = self
                            .instance
                            .extended_instance
                            .instance
                            .alphas
                            .get(i)
                            .unwrap();
                        vec![alpha; domain_size]
                    }
                    ExpExtension::Selector(_) => panic!("unused"),
                },
                e => self.inner_provider.resolve(e, domain),
            }
        }
    }

    impl Checker<TestFoldingConfig> for Provider {}
    impl Checker<TestFoldingConfig> for ExtendedProvider {}
}

// this checks a single folding, it would be good to expand it in the future
// to do several foldings, as a few thigs are trivial in the first fold
#[test]
fn test_folding_instance() {
    let constraints = constraints();
    let domain = Radix2EvaluationDomain::<Fp>::new(2).unwrap();
    let srs = poly_commitment::ipa::SRS::<Curve>::create(2);
    srs.get_lagrange_basis(domain);

    let mut fq_sponge = BaseSponge::new(Curve::other_curve_sponge_params());

    let [s_add, s_mul] = circuit();
    let structure = TestStructure {
        s_add,
        s_mul,
        constants: vec![],
    };

    let (scheme, final_constraint) =
        FoldingScheme::<TestFoldingConfig>::new(constraints.clone(), &srs, domain, &structure);

    // We have a 2 row circuit with and addition gate in the first row, and a multiplication gate in the second

    // Left: 1 + 2 - 3 = 0
    let left_witness = [
        vec![Fp::from(1u32), Fp::from(2u32)],
        vec![Fp::from(2u32), Fp::from(3u32)],
        vec![Fp::from(3u32), Fp::from(6u32)],
    ];
    let left_witness: TestWitness =
        TestWitness(left_witness.map(|evals| Evaluations::from_vec_and_domain(evals, domain)));
    // Right: 4 + 5 - 9 = 0
    let right_witness = [
        vec![Fp::from(4u32), Fp::from(3u32)],
        vec![Fp::from(5u32), Fp::from(6u32)],
        vec![Fp::from(9u32), Fp::from(18u32)],
    ];
    let right_witness: TestWitness =
        TestWitness(right_witness.map(|evals| Evaluations::from_vec_and_domain(evals, domain)));

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
            .for_each(|constraint| checker.check(constraint, domain));
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
            .for_each(|constraint| checker.check(constraint, domain));
    }

    // pairs
    let left = (left_instance.clone(), left_witness);
    let right = (right_instance.clone(), right_witness);

    let folded = scheme.fold_instance_witness_pair(left, right, &mut fq_sponge);
    let FoldingOutput {
        folded_instance,
        folded_witness,
        t_0,
        t_1,
        relaxed_extended_left_instance,
        relaxed_extended_right_instance,
        to_absorb,
    } = folded;

    {
        let folded_instance_explicit = {
            let mut fq_sponge_inst = BaseSponge::new(Curve::other_curve_sponge_params());
            scheme.fold_instance_pair(
                relaxed_extended_left_instance,
                relaxed_extended_right_instance,
                [t_0.clone(), t_1.clone()],
                &mut fq_sponge_inst,
            )
        };

        assert!(folded_instance == folded_instance_explicit);
    }

    // Verifying that error terms are not points at infinity
    // It doesn't test that the computation happens correctly, but at least
    // show that there is some non trivial computation.
    assert_eq!(t_0.len(), 1);
    assert_eq!(t_1.len(), 1);
    assert!(!t_0.get_first_chunk().is_zero());
    assert!(!t_1.get_first_chunk().is_zero());

    // checking that we have the expected number of elements to absorb
    // 3+2 from each instance + 1 from u, times 2 instances
    assert_eq!(to_absorb.0.len(), (3 + 2 + 1) * 2);
    // 3 from each instance + 1 from E, times 2 instances + t_0 + t_1
    assert_eq!(to_absorb.1.len(), (3 + 1) * 2 + 2);
    {
        let checker = ExtendedProvider::new(structure, folded_instance, folded_witness);
        debug!("exp: \n {:#?}", final_constraint);
        debug!("check folded");
        checker.check(&final_constraint, domain);
    }
}
