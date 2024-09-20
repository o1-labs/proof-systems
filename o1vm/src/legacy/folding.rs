use ark_ec::AffineRepr;
use ark_ff::FftField;
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use folding::{
    instance_witness::Foldable, Alphas, FoldingConfig, FoldingEnv, Instance, Side, Witness,
};
use kimchi::circuits::{expr::BerkeleyChallengeTerm, gate::CurrOrNext};
use kimchi_msm::witness::Witness as GenericWitness;
use poly_commitment::commitment::CommitmentCurve;
use std::{array, ops::Index};
use strum::EnumCount;
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};

// Simple type alias as ScalarField/BaseField is often used. Reduce type
// complexity for clippy.
// Should be moved into FoldingConfig, but associated type defaults are unstable
// at the moment.
pub(crate) type ScalarField<C> = <<C as FoldingConfig>::Curve as AffineRepr>::ScalarField;
pub(crate) type BaseField<C> = <<C as FoldingConfig>::Curve as AffineRepr>::BaseField;

// Does not contain alpha because this one should be provided by folding itself
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EnumIter, EnumCountMacro)]
pub enum Challenge {
    Beta,
    Gamma,
    JointCombiner,
}

// Needed to transform from expressions to folding expressions
impl From<BerkeleyChallengeTerm> for Challenge {
    fn from(chal: BerkeleyChallengeTerm) -> Self {
        match chal {
            BerkeleyChallengeTerm::Beta => Challenge::Beta,
            BerkeleyChallengeTerm::Gamma => Challenge::Gamma,
            BerkeleyChallengeTerm::JointCombiner => Challenge::JointCombiner,
            BerkeleyChallengeTerm::Alpha => panic!("Alpha not allowed in folding expressions"),
        }
    }
}

/// Folding instance containing the commitment to a witness of N columns,
/// challenges for the proof, and the alphas
#[derive(Debug, Clone)]
pub struct FoldingInstance<const N: usize, G: CommitmentCurve> {
    /// Commitments to the witness columns, including the dynamic selectors
    pub commitments: [G; N],
    /// Challenges for the proof.
    /// We do use 3 challenges:
    /// - β as the evaluation point for the logup argument
    /// - j: the joint combiner for vector lookups
    /// - γ (set to 0 for now)
    pub challenges: [<G as AffineRepr>::ScalarField; Challenge::COUNT],
    /// Reuses the Alphas defined in the example of folding
    pub alphas: Alphas<<G as AffineRepr>::ScalarField>,

    /// Blinder used in the polynomial commitment scheme
    pub blinder: <G as AffineRepr>::ScalarField,
}

impl<const N: usize, G: CommitmentCurve> Foldable<G::ScalarField> for FoldingInstance<N, G> {
    fn combine(a: Self, b: Self, challenge: G::ScalarField) -> Self {
        FoldingInstance {
            commitments: array::from_fn(|i| {
                (a.commitments[i] + b.commitments[i].mul(challenge)).into()
            }),
            challenges: array::from_fn(|i| a.challenges[i] + challenge * b.challenges[i]),
            alphas: Alphas::combine(a.alphas, b.alphas, challenge),
            blinder: a.blinder + challenge * b.blinder,
        }
    }
}

impl<const N: usize, G: CommitmentCurve> Instance<G> for FoldingInstance<N, G> {
    fn to_absorb(&self) -> (Vec<<G>::ScalarField>, Vec<G>) {
        // FIXME: check!!!!
        let mut scalars = Vec::new();
        let mut points = Vec::new();
        points.extend(self.commitments);
        scalars.extend(self.challenges);
        scalars.extend(self.alphas.clone().powers());
        (scalars, points)
    }

    fn get_alphas(&self) -> &Alphas<G::ScalarField> {
        &self.alphas
    }

    fn get_blinder(&self) -> <G>::ScalarField {
        self.blinder
    }
}

impl<const N: usize, G: CommitmentCurve> Index<Challenge> for FoldingInstance<N, G> {
    type Output = G::ScalarField;

    fn index(&self, index: Challenge) -> &Self::Output {
        match index {
            Challenge::Beta => &self.challenges[0],
            Challenge::Gamma => &self.challenges[1],
            Challenge::JointCombiner => &self.challenges[2],
        }
    }
}

/// Includes the data witness columns and also the dynamic selector columns
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FoldingWitness<const N: usize, F: FftField> {
    pub witness: GenericWitness<N, Evaluations<F, Radix2EvaluationDomain<F>>>,
}

impl<const N: usize, F: FftField> Foldable<F> for FoldingWitness<N, F> {
    fn combine(a: Self, b: Self, challenge: F) -> Self {
        Self {
            witness: GenericWitness::combine(a.witness, b.witness, challenge),
        }
    }
}

impl<const N: usize, G: CommitmentCurve> Witness<G> for FoldingWitness<N, G::ScalarField> {}

/// Environment for the decomposable folding protocol, for a given number of
/// witness columns and selectors.
pub struct DecomposedFoldingEnvironment<
    const N: usize,
    const N_REL: usize,
    const N_DSEL: usize,
    C: FoldingConfig,
    Structure,
> {
    pub structure: Structure,
    /// Commitments to the witness columns, for both sides
    pub instances: [FoldingInstance<N, C::Curve>; 2],
    /// Corresponds to the omega evaluations, for both sides
    pub curr_witnesses: [FoldingWitness<N, ScalarField<C>>; 2],
    /// Corresponds to the zeta*omega evaluations, for both sides
    /// This is curr_witness but left shifted by 1
    pub next_witnesses: [FoldingWitness<N, ScalarField<C>>; 2],
}

impl<
        const N: usize,
        const N_REL: usize,
        const N_SEL: usize,
        C: FoldingConfig,
        // FIXME: Clone should not be used. Only a reference should be stored
        Structure: Clone,
    >
    FoldingEnv<
        ScalarField<C>,
        FoldingInstance<N, C::Curve>,
        FoldingWitness<N, ScalarField<C>>,
        C::Column,
        Challenge,
        C::Selector,
    > for DecomposedFoldingEnvironment<N, N_REL, N_SEL, C, Structure>
where
    // Used by col and selector
    FoldingWitness<N, ScalarField<C>>: Index<
        C::Column,
        Output = Evaluations<ScalarField<C>, Radix2EvaluationDomain<ScalarField<C>>>,
    >,
    FoldingWitness<N, ScalarField<C>>: Index<
        C::Selector,
        Output = Evaluations<ScalarField<C>, Radix2EvaluationDomain<ScalarField<C>>>,
    >,
{
    type Structure = Structure;

    fn new(
        structure: &Self::Structure,
        instances: [&FoldingInstance<N, C::Curve>; 2],
        witnesses: [&FoldingWitness<N, ScalarField<C>>; 2],
    ) -> Self {
        let curr_witnesses = [witnesses[0].clone(), witnesses[1].clone()];
        let mut next_witnesses = curr_witnesses.clone();
        for side in next_witnesses.iter_mut() {
            for col in side.witness.cols.iter_mut() {
                col.evals.rotate_left(1);
            }
        }
        DecomposedFoldingEnvironment {
            // FIXME: This is a clone, but it should be a reference
            structure: structure.clone(),
            instances: [instances[0].clone(), instances[1].clone()],
            curr_witnesses,
            next_witnesses,
        }
    }

    fn col(&self, col: C::Column, curr_or_next: CurrOrNext, side: Side) -> &[ScalarField<C>] {
        let wit = match curr_or_next {
            CurrOrNext::Curr => &self.curr_witnesses[side as usize],
            CurrOrNext::Next => &self.next_witnesses[side as usize],
        };
        // The following is possible because Index is implemented for our circuit witnesses
        &wit[col].evals
    }

    fn challenge(&self, challenge: Challenge, side: Side) -> ScalarField<C> {
        match challenge {
            Challenge::Beta => self.instances[side as usize].challenges[0],
            Challenge::Gamma => self.instances[side as usize].challenges[1],
            Challenge::JointCombiner => self.instances[side as usize].challenges[2],
        }
    }

    fn selector(&self, s: &C::Selector, side: Side) -> &[ScalarField<C>] {
        let witness = &self.curr_witnesses[side as usize];
        &witness[*s].evals
    }
}

pub struct FoldingEnvironment<const N: usize, C: FoldingConfig, Structure> {
    /// Structure of the folded circuit
    pub structure: Structure,
    /// Commitments to the witness columns, for both sides
    pub instances: [FoldingInstance<N, C::Curve>; 2],
    /// Corresponds to the evaluations at ω, for both sides
    pub curr_witnesses: [FoldingWitness<N, ScalarField<C>>; 2],
    /// Corresponds to the evaluations at ζω, for both sides
    /// This is curr_witness but left shifted by 1
    pub next_witnesses: [FoldingWitness<N, ScalarField<C>>; 2],
}

impl<
        const N: usize,
        C: FoldingConfig,
        // FIXME: Clone should not be used. Only a reference should be stored
        Structure: Clone,
    >
    FoldingEnv<
        ScalarField<C>,
        FoldingInstance<N, C::Curve>,
        FoldingWitness<N, ScalarField<C>>,
        C::Column,
        Challenge,
        (),
    > for FoldingEnvironment<N, C, Structure>
where
    // Used by col and selector
    FoldingWitness<N, ScalarField<C>>: Index<
        C::Column,
        Output = Evaluations<ScalarField<C>, Radix2EvaluationDomain<ScalarField<C>>>,
    >,
{
    type Structure = Structure;

    fn new(
        structure: &Self::Structure,
        instances: [&FoldingInstance<N, C::Curve>; 2],
        witnesses: [&FoldingWitness<N, ScalarField<C>>; 2],
    ) -> Self {
        let curr_witnesses = [witnesses[0].clone(), witnesses[1].clone()];
        let mut next_witnesses = curr_witnesses.clone();
        for side in next_witnesses.iter_mut() {
            for col in side.witness.cols.iter_mut() {
                col.evals.rotate_left(1);
            }
        }
        FoldingEnvironment {
            // FIXME: This is a clone, but it should be a reference
            structure: structure.clone(),
            instances: [instances[0].clone(), instances[1].clone()],
            curr_witnesses,
            next_witnesses,
        }
    }

    fn col(&self, col: C::Column, curr_or_next: CurrOrNext, side: Side) -> &[ScalarField<C>] {
        let wit = match curr_or_next {
            CurrOrNext::Curr => &self.curr_witnesses[side as usize],
            CurrOrNext::Next => &self.next_witnesses[side as usize],
        };
        // The following is possible because Index is implemented for our circuit witnesses
        &wit[col].evals
    }

    fn challenge(&self, challenge: Challenge, side: Side) -> ScalarField<C> {
        match challenge {
            Challenge::Beta => self.instances[side as usize].challenges[0],
            Challenge::Gamma => self.instances[side as usize].challenges[1],
            Challenge::JointCombiner => self.instances[side as usize].challenges[2],
        }
    }

    fn selector(&self, _s: &(), _side: Side) -> &[ScalarField<C>] {
        unimplemented!("Selector not implemented for FoldingEnvironment. No selectors are supposed to be used when there is only one instruction.")
    }
}

pub mod keccak {
    use std::ops::Index;

    use ark_poly::{Evaluations, Radix2EvaluationDomain};
    use folding::{
        checker::{Checker, ExtendedProvider, Provider},
        expressions::FoldingColumnTrait,
        FoldingConfig,
    };
    use kimchi_msm::columns::Column;
    use poly_commitment::srs::SRS;

    use crate::{
        interpreters::keccak::{
            column::{
                ColumnAlias as KeccakColumn, N_ZKVM_KECCAK_COLS, N_ZKVM_KECCAK_REL_COLS,
                N_ZKVM_KECCAK_SEL_COLS,
            },
            Steps,
        },
        Curve, Fp,
    };

    use super::{Challenge, DecomposedFoldingEnvironment, FoldingInstance, FoldingWitness};

    pub type KeccakFoldingEnvironment = DecomposedFoldingEnvironment<
        N_ZKVM_KECCAK_COLS,
        N_ZKVM_KECCAK_REL_COLS,
        N_ZKVM_KECCAK_SEL_COLS,
        KeccakConfig,
        (),
    >;

    pub type KeccakFoldingWitness = FoldingWitness<N_ZKVM_KECCAK_COLS, Fp>;
    pub type KeccakFoldingInstance = FoldingInstance<N_ZKVM_KECCAK_COLS, Curve>;

    impl Index<KeccakColumn> for KeccakFoldingWitness {
        type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

        fn index(&self, index: KeccakColumn) -> &Self::Output {
            &self.witness.cols[usize::from(index)]
        }
    }

    // Implemented for decomposable folding compatibility
    impl Index<Steps> for KeccakFoldingWitness {
        type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

        /// Map a selector column to the corresponding witness column.
        fn index(&self, index: Steps) -> &Self::Output {
            &self.witness.cols[usize::from(index)]
        }
    }

    // Implementing this so that generic constraints can be used in folding
    impl Index<Column> for KeccakFoldingWitness {
        type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

        /// Map a column alias to the corresponding witness column.
        fn index(&self, index: Column) -> &Self::Output {
            match index {
                Column::Relation(ix) => &self.witness.cols[ix],
                // Even if `Column::DynamicSelector(ix)` would correspond to
                // `&self.witness.cols[N_ZKVM_KECCAK_REL_COLS + ix]`, the
                // current design of constraints should not include the dynamic
                // selectors. Instead, folding will add them in the
                // `DecomposableFoldingScheme` as extended selector columns, and
                // the `selector()` function inside the `FoldingEnv` will return
                // the actual witness column values.
                _ => panic!("Undesired column type inside expressions"),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct KeccakConfig;

    impl FoldingColumnTrait for KeccakColumn {
        fn is_witness(&self) -> bool {
            // dynamic selectors KeccakColumn::Selector() count as witnesses
            true
        }
    }

    impl FoldingConfig for KeccakConfig {
        type Column = Column;
        type Selector = Steps;
        type Challenge = Challenge;
        type Curve = Curve;
        type Srs = SRS<Curve>;
        type Instance = KeccakFoldingInstance;
        type Witness = KeccakFoldingWitness;
        type Structure = ();
        type Env = KeccakFoldingEnvironment;
    }

    // IMPLEMENT CHECKER TRAITS

    impl Checker<KeccakConfig> for ExtendedProvider<KeccakConfig> {}
    impl Checker<KeccakConfig> for Provider<KeccakConfig> {}
}

pub mod mips {
    use std::ops::Index;

    use ark_poly::{Evaluations, Radix2EvaluationDomain};
    use folding::{expressions::FoldingColumnTrait, FoldingConfig};
    use kimchi_msm::columns::Column;
    use poly_commitment::srs::SRS;

    use crate::{
        interpreters::mips::{
            column::{ColumnAlias as MIPSColumn, N_MIPS_COLS, N_MIPS_REL_COLS, N_MIPS_SEL_COLS},
            Instruction,
        },
        Curve, Fp,
    };

    use super::{Challenge, DecomposedFoldingEnvironment, FoldingInstance, FoldingWitness};

    // Decomposable folding compatibility
    pub type DecomposableMIPSFoldingEnvironment = DecomposedFoldingEnvironment<
        N_MIPS_COLS,
        N_MIPS_REL_COLS,
        N_MIPS_SEL_COLS,
        DecomposableMIPSFoldingConfig,
        (),
    >;

    pub type MIPSFoldingWitness = FoldingWitness<N_MIPS_COLS, Fp>;
    pub type MIPSFoldingInstance = FoldingInstance<N_MIPS_COLS, Curve>;

    // -- Start indexer implementations
    // Implement indexers over columns and selectors to implement an abstract
    // folding environment over selectors, see [crate::folding::FoldingEnvironment]
    // for more details

    impl Index<Column> for FoldingWitness<N_MIPS_REL_COLS, Fp> {
        type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

        fn index(&self, index: Column) -> &Self::Output {
            match index {
                Column::Relation(ix) => &self.witness.cols[ix],
                _ => panic!("Invalid column type"),
            }
        }
    }

    impl Index<MIPSColumn> for MIPSFoldingWitness {
        type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

        fn index(&self, index: MIPSColumn) -> &Self::Output {
            &self.witness.cols[usize::from(index)]
        }
    }

    // Implemented for decomposable folding compatibility
    impl Index<Instruction> for MIPSFoldingWitness {
        type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

        /// Map a selector column to the corresponding witness column.
        fn index(&self, index: Instruction) -> &Self::Output {
            &self.witness.cols[usize::from(index)]
        }
    }

    // Implementing this so that generic constraints can be used in folding
    impl Index<Column> for MIPSFoldingWitness {
        type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

        /// Map a column alias to the corresponding witness column.
        fn index(&self, index: Column) -> &Self::Output {
            match index {
                Column::Relation(ix) => &self.witness.cols[ix],
                Column::DynamicSelector(ix) => &self.witness.cols[N_MIPS_REL_COLS + ix],
                _ => panic!("Invalid column type"),
            }
        }
    }
    // -- End of indexer implementations

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct DecomposableMIPSFoldingConfig;

    impl FoldingColumnTrait for MIPSColumn {
        fn is_witness(&self) -> bool {
            // All MIPS columns are witness columns
            true
        }
    }

    impl FoldingConfig for DecomposableMIPSFoldingConfig {
        type Column = Column;
        type Selector = Instruction;
        type Challenge = Challenge;
        type Curve = Curve;
        type Srs = SRS<Curve>;
        type Instance = MIPSFoldingInstance;
        type Witness = MIPSFoldingWitness;
        type Structure = ();
        type Env = DecomposableMIPSFoldingEnvironment;
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        legacy::folding::{FoldingInstance, FoldingWitness, *},
        Curve, Fp,
    };
    use ark_poly::{Evaluations, Radix2EvaluationDomain};
    use folding::{
        expressions::{FoldingColumnTrait, FoldingCompatibleExpr, FoldingCompatibleExprInner},
        FoldingConfig,
    };
    use kimchi::{
        circuits::expr::{
            ConstantExprInner, ConstantTerm, Constants, Expr, ExprInner, Literal, Variable,
        },
        curve::KimchiCurve,
    };
    use poly_commitment::srs::SRS;
    use std::ops::Index;

    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialOrd, PartialEq)]
    enum TestColumn {
        X,
        Y,
        Z,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct TestConfig;

    type TestWitness<T> = kimchi_msm::witness::Witness<3, T>;
    type TestFoldingWitness = FoldingWitness<3, Fp>;
    type TestFoldingInstance = FoldingInstance<3, Curve>;
    type TestFoldingEnvironment = FoldingEnvironment<3, TestConfig, ()>;

    impl Index<TestColumn> for TestFoldingWitness {
        type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

        fn index(&self, index: TestColumn) -> &Self::Output {
            &self.witness[index]
        }
    }

    impl FoldingColumnTrait for TestColumn {
        fn is_witness(&self) -> bool {
            true
        }
    }

    impl<T: Clone> Index<TestColumn> for TestWitness<T> {
        type Output = T;
        fn index(&self, index: TestColumn) -> &Self::Output {
            match index {
                TestColumn::X => &self.cols[0],
                TestColumn::Y => &self.cols[1],
                TestColumn::Z => &self.cols[2],
            }
        }
    }

    impl FoldingConfig for TestConfig {
        type Column = TestColumn;
        type Challenge = Challenge;
        type Selector = ();
        type Curve = Curve;
        type Srs = SRS<Curve>;
        type Instance = TestFoldingInstance;
        type Witness = TestFoldingWitness;
        type Structure = ();
        type Env = TestFoldingEnvironment;
    }

    #[test]
    fn test_conversion() {
        use super::*;
        use kimchi::circuits::expr::BerkeleyChallengeTerm;

        // Check that the conversion from ChallengeTerm to Challenge works as expected
        assert_eq!(Challenge::Beta, BerkeleyChallengeTerm::Beta.into());
        assert_eq!(Challenge::Gamma, BerkeleyChallengeTerm::Gamma.into());
        assert_eq!(
            Challenge::JointCombiner,
            BerkeleyChallengeTerm::JointCombiner.into()
        );

        // Create my special constants
        let constants = Constants {
            endo_coefficient: Fp::from(3),
            mds: &Curve::sponge_params().mds,
            zk_rows: 0,
        };

        // Define variables to be used in larger expressions
        let x = Expr::Atom(ExprInner::Cell::<
            ConstantExprInner<Fp, BerkeleyChallengeTerm>,
            TestColumn,
        >(Variable {
            col: TestColumn::X,
            row: CurrOrNext::Curr,
        }));
        let y = Expr::Atom(ExprInner::Cell::<
            ConstantExprInner<Fp, BerkeleyChallengeTerm>,
            TestColumn,
        >(Variable {
            col: TestColumn::Y,
            row: CurrOrNext::Curr,
        }));
        let z = Expr::Atom(ExprInner::Cell::<
            ConstantExprInner<Fp, BerkeleyChallengeTerm>,
            TestColumn,
        >(Variable {
            col: TestColumn::Z,
            row: CurrOrNext::Curr,
        }));
        let endo = Expr::Atom(ExprInner::<
            ConstantExprInner<Fp, BerkeleyChallengeTerm>,
            TestColumn,
        >::Constant(ConstantExprInner::Constant(
            ConstantTerm::EndoCoefficient,
        )));

        // Define variables with folding expressions
        let x_f =
            FoldingCompatibleExpr::<TestConfig>::Atom(FoldingCompatibleExprInner::Cell(Variable {
                col: TestColumn::X,
                row: CurrOrNext::Curr,
            }));
        let y_f =
            FoldingCompatibleExpr::<TestConfig>::Atom(FoldingCompatibleExprInner::Cell(Variable {
                col: TestColumn::Y,
                row: CurrOrNext::Curr,
            }));
        let z_f =
            FoldingCompatibleExpr::<TestConfig>::Atom(FoldingCompatibleExprInner::Cell(Variable {
                col: TestColumn::Z,
                row: CurrOrNext::Curr,
            }));

        // Check conversion of general expressions
        let xyz = x.clone() * y * z;
        let xyz_f = FoldingCompatibleExpr::<TestConfig>::Mul(
            Box::new(FoldingCompatibleExpr::<TestConfig>::Mul(
                Box::new(x_f.clone()),
                Box::new(y_f),
            )),
            Box::new(z_f),
        );
        assert_eq!(FoldingCompatibleExpr::<TestConfig>::from(xyz), xyz_f);

        let x_endo = x + endo;
        let x_endo_f = FoldingCompatibleExpr::<TestConfig>::Add(
            Box::new(x_f),
            Box::new(FoldingCompatibleExpr::<TestConfig>::Atom(
                FoldingCompatibleExprInner::Constant(constants.endo_coefficient),
            )),
        );
        let x_endo_lit = x_endo.as_literal(&constants);
        assert_eq!(
            FoldingCompatibleExpr::<TestConfig>::from(x_endo_lit),
            x_endo_f
        );
    }
}
