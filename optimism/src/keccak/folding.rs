use crate::{
    folding::{Challenge, FoldingEnvironment, FoldingInstance, FoldingWitness},
    keccak::{column::ZKVM_KECCAK_COLS, KeccakColumn, Steps},
    trace::Indexer,
    Curve, Fp, DOMAIN_SIZE,
};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use folding::{
    checker::{Checker, ExtendedProvider},
    expressions::FoldingColumnTrait,
    FoldingConfig,
};
use kimchi_msm::columns::Column;
use poly_commitment::srs::SRS;
use std::ops::Index;

use super::column::ZKVM_KECCAK_REL;

pub type KeccakFoldingWitness = FoldingWitness<ZKVM_KECCAK_COLS, Fp>;
pub type KeccakFoldingInstance = FoldingInstance<ZKVM_KECCAK_COLS, Curve>;

pub type KeccakFoldingEnvironment = FoldingEnvironment<ZKVM_KECCAK_COLS, Curve>;

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
            Column::DynamicSelector(ix) => &self.witness.cols[ZKVM_KECCAK_REL + ix],
            _ => panic!("Invalid column type"),
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
    // The structure is empty as we don't need to store any additional
    // information that is static for the relation
    type Structure = ();
    type Env = KeccakFoldingEnvironment;

    fn rows() -> usize {
        DOMAIN_SIZE
    }
}

// IMPLEMENT CHECKER TRAITS

impl Checker<KeccakConfig> for ExtendedProvider<KeccakConfig> {}
