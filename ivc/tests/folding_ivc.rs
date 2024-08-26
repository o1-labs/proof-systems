use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use folding::{
    instance_witness::Foldable, Alphas, FoldingCompatibleExpr, FoldingConfig, FoldingEnv,
    FoldingScheme, Instance, Side, Witness,
};
use ivc::ivc::{constraints::constrain_ivc, lookups::IVCLookupTable, N_ADDITIONAL_WIT_COL_QUAD};
use kimchi::circuits::{expr::ChallengeTerm, gate::CurrOrNext};
use kimchi_msm::{circuit_design::ConstraintBuilderEnv, columns::Column, Ff1};
use poly_commitment::srs::SRS;

#[test]
fn test_regression_additional_columns_reduction_to_degree_2() {
    pub type Fp = ark_bn254::Fr;
    pub type Curve = ark_bn254::G1Affine;

    // ---- Folding fake structures ----
    #[derive(Hash, Clone, Debug, PartialEq, Eq)]
    struct TestConfig;

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

    #[derive(Debug, Clone)]
    struct TestInstance;

    impl Foldable<Fp> for TestInstance {
        fn combine(_a: Self, _b: Self, _challenge: Fp) -> Self {
            unimplemented!()
        }
    }

    impl Instance<Curve> for TestInstance {
        fn get_alphas(&self) -> &Alphas<Fp> {
            todo!()
        }

        fn to_absorb(&self) -> (Vec<Fp>, Vec<Curve>) {
            todo!()
        }

        fn get_blinder(&self) -> Fp {
            todo!()
        }
    }

    #[derive(Clone)]
    struct TestWitness;

    impl Foldable<Fp> for TestWitness {
        fn combine(_a: Self, _b: Self, _challenge: Fp) -> Self {
            unimplemented!()
        }
    }

    impl Witness<Curve> for TestWitness {}

    impl FoldingConfig for TestConfig {
        type Column = Column;

        type Selector = ();

        type Challenge = Challenge;

        type Curve = Curve;

        type Srs = SRS<Curve>;

        type Instance = TestInstance;

        type Witness = TestWitness;

        type Structure = ();

        type Env = Env;
    }

    struct Env;

    impl FoldingEnv<Fp, TestInstance, TestWitness, Column, Challenge, ()> for Env {
        type Structure = ();

        fn new(
            _structure: &Self::Structure,
            _instances: [&TestInstance; 2],
            _witnesses: [&TestWitness; 2],
        ) -> Self {
            todo!()
        }

        fn col(&self, _col: Column, _curr_or_next: CurrOrNext, _side: Side) -> &[Fp] {
            todo!()
        }

        fn challenge(&self, _challenge: Challenge, _side: Side) -> Fp {
            todo!()
        }

        fn selector(&self, _s: &(), _side: Side) -> &[Fp] {
            todo!()
        }
    }

    // ---- Folding fake structures ----

    let mut constraint_env = ConstraintBuilderEnv::<Fp, IVCLookupTable<Ff1>>::create();
    constrain_ivc::<Ff1, _>(&mut constraint_env);
    let constraints = constraint_env.get_relation_constraints();

    let domain = Radix2EvaluationDomain::<Fp>::new(2).unwrap();
    let mut srs = SRS::<Curve>::create(2);
    srs.add_lagrange_basis(domain);

    let folding_compat_expresions: Vec<FoldingCompatibleExpr<TestConfig>> = constraints
        .into_iter()
        .map(FoldingCompatibleExpr::from)
        .collect();
    let (scheme, _) =
        FoldingScheme::<TestConfig>::new(folding_compat_expresions, &srs, domain, &());
    assert_eq!(
        scheme.get_number_of_additional_columns(),
        N_ADDITIONAL_WIT_COL_QUAD,
        "Expected {N_ADDITIONAL_WIT_COL_QUAD}, got {}",
        scheme.get_number_of_additional_columns(),
    );
}
