use crate::{
    folding::{Challenge, DecomposableFoldingEnvironment, FoldingInstance, FoldingWitness},
    keccak::{
        column::{N_ZKVM_KECCAK_COLS, N_ZKVM_KECCAK_REL_COLS, N_ZKVM_KECCAK_SEL_COLS},
        KeccakColumn, Steps,
    },
    trace::Indexer,
    Curve, Fp,
};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use folding::{
    checker::{Checker, ExtendedProvider, Provider},
    expressions::FoldingColumnTrait,
    FoldingConfig,
};
use kimchi_msm::columns::Column;
use poly_commitment::srs::SRS;
use std::ops::Index;

use super::trace::KeccakTrace;

pub type KeccakFoldingEnvironment = DecomposableFoldingEnvironment<
    N_ZKVM_KECCAK_COLS,
    N_ZKVM_KECCAK_REL_COLS,
    N_ZKVM_KECCAK_SEL_COLS,
    KeccakConfig,
>;

pub type KeccakFoldingWitness = FoldingWitness<N_ZKVM_KECCAK_COLS, Fp>;
pub type KeccakFoldingInstance = FoldingInstance<N_ZKVM_KECCAK_COLS, Curve>;

impl Index<KeccakColumn> for KeccakFoldingWitness {
    type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

    fn index(&self, index: KeccakColumn) -> &Self::Output {
        &self.witness.cols[index.ix()]
    }
}

// Implemented for decomposable folding compatibility
impl Index<Steps> for KeccakFoldingWitness {
    type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

    /// Map a selector column to the corresponding witness column.
    fn index(&self, index: Steps) -> &Self::Output {
        &self.witness.cols[index.ix()]
    }
}

// Implementing this so that generic constraints can be used in folding
impl Index<Column> for KeccakFoldingWitness {
    type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

    /// Map a column alias to the corresponding witness column.
    fn index(&self, index: Column) -> &Self::Output {
        match index {
            Column::Relation(ix) => &self.witness.cols[ix],
            // Even if `Column::DynamicSelector(ix)` would correspond to `&self.witness.cols[N_ZKVM_KECCAK_REL_COLS + ix]`,
            // the current design of constraints should not include the dynamic selectors. Instead, folding will add them
            // in the `DecomposableFoldingScheme` as extended selector columns, and the `selector()` function inside the
            // `FoldingEnv` will return the actual witness column values.
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
    type Structure = KeccakTrace;
    type Env = KeccakFoldingEnvironment;
}

// IMPLEMENT CHECKER TRAITS

impl Checker<KeccakConfig> for ExtendedProvider<KeccakConfig> {}
impl Checker<KeccakConfig> for Provider<KeccakConfig> {}
