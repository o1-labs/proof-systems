use crate::{
    // FIXME: using BaseSponge from folding as it does require a struct, but we
    // should simply have a type by modifying how folding uses the sponge
    folding::BaseSponge,
    folding::{Challenge, FoldingEnvironment, FoldingInstance, FoldingWitness},
    mips::{
        column::{ColumnAlias as MIPSColumn, MIPS_COLUMNS},
        Instruction,
    },
    trace::Indexer,
    Curve,
    Fp,
    DOMAIN_SIZE,
};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use folding::{expressions::FoldingColumnTrait, FoldingConfig};
use kimchi_msm::columns::Column;
use std::ops::Index;

use super::column::MIPS_REL_COLS;

pub type MIPSFoldingWitness = FoldingWitness<MIPS_COLUMNS>;
pub type MIPSFoldingInstance = FoldingInstance<MIPS_COLUMNS>;
pub type MIPSFoldingEnvironment = FoldingEnvironment<MIPS_COLUMNS, MIPSStructure>;

impl Index<MIPSColumn> for MIPSFoldingWitness {
    type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

    fn index(&self, index: MIPSColumn) -> &Self::Output {
        &self.witness.cols[index.ix()]
    }
}

// Implemented for decomposable folding compatibility
impl Index<Instruction> for MIPSFoldingWitness {
    type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

    /// Map a selector column to the corresponding witness column.
    fn index(&self, index: Instruction) -> &Self::Output {
        &self.witness.cols[index.ix()]
    }
}

// Implementing this so that generic constraints can be used in folding
impl Index<Column> for MIPSFoldingWitness {
    type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

    /// Map a column alias to the corresponding witness column.
    fn index(&self, index: Column) -> &Self::Output {
        match index {
            Column::Relation(ix) => &self.witness.cols[ix],
            Column::DynamicSelector(ix) => &self.witness.cols[MIPS_REL_COLS + ix],
            _ => panic!("Invalid column type"),
        }
    }
}

// TODO: will contain information about the circuit structure
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MIPSStructure;

// TODO
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MIPSFoldingConfig;

impl FoldingColumnTrait for MIPSColumn {
    fn is_witness(&self) -> bool {
        // All MIPS columns are witness columns
        true
    }
}

impl FoldingConfig for MIPSFoldingConfig {
    type Column = Column;
    type Selector = Instruction;
    type Challenge = Challenge;
    type Curve = Curve;
    type Srs = poly_commitment::srs::SRS<Curve>;
    type Sponge = BaseSponge;
    type Instance = MIPSFoldingInstance;
    type Witness = MIPSFoldingWitness;
    type Structure = MIPSStructure;
    type Env = MIPSFoldingEnvironment;

    fn rows() -> usize {
        DOMAIN_SIZE
    }
}
