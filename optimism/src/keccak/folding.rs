use crate::{
    folding::{Challenge, Curve, FoldingEnvironment, FoldingInstance, FoldingWitness, Fp},
    keccak::{column::ZKVM_KECCAK_COLS, KeccakColumn, Steps},
    DOMAIN_SIZE,
};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use kimchi::folding::{expressions::FoldingColumnTrait, BaseSponge, FoldingConfig};
use std::ops::Index;

pub(crate) type KeccakFoldingWitness = FoldingWitness<ZKVM_KECCAK_COLS>;
pub(crate) type KeccakFoldingInstance = FoldingInstance<ZKVM_KECCAK_COLS>;
pub(crate) type KeccakFoldingEnvironment = FoldingEnvironment<ZKVM_KECCAK_COLS, KeccakStructure>;

impl Index<KeccakColumn> for KeccakFoldingWitness {
    type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

    fn index(&self, index: KeccakColumn) -> &Self::Output {
        &self.witness[index]
    }
}

// Implemented for decomposable folding compatibility
impl Index<Steps> for KeccakFoldingWitness {
    type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

    /// Map a selector column to the corresponding witness column.
    fn index(&self, index: Steps) -> &Self::Output {
        &self.witness.cols[KeccakColumn::Selector(index).ix()]
    }
}

// TODO: will contain information about the circuit structure
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct KeccakStructure;

// TODO
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct KeccakConfig;

impl FoldingColumnTrait for KeccakColumn {
    fn is_witness(&self) -> bool {
        // dynamic selectors KeccakColumn::Selector() count as witnesses
        true
    }
}

impl FoldingConfig for KeccakConfig {
    type Column = KeccakColumn;
    type Selector = Steps;
    type Challenge = Challenge;
    type Curve = Curve;
    type Srs = poly_commitment::srs::SRS<Curve>;
    type Sponge = BaseSponge;
    type Instance = KeccakFoldingInstance;
    type Witness = KeccakFoldingWitness;
    type Structure = KeccakStructure;
    type Env = KeccakFoldingEnvironment;

    fn rows() -> usize {
        DOMAIN_SIZE
    }
}
