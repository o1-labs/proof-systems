use crate::{
    folding::{Challenge, FoldingEnvironment, FoldingInstance, FoldingWitness},
    mips::{
        column::{ColumnAlias as MIPSColumn, MIPS_COLUMNS},
        Instruction,
    },
    trace::Indexer,
    Curve, Fp,
};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use folding::{expressions::FoldingColumnTrait, FoldingConfig};
use kimchi_msm::columns::Column;
use std::ops::Index;

use super::{
    column::{MIPS_REL_COLS, MIPS_SEL_COLS},
    trace::MIPSTrace,
};
use poly_commitment::srs::SRS;

pub type MIPSFoldingWitness = FoldingWitness<MIPS_COLUMNS, Fp>;
pub type MIPSFoldingInstance = FoldingInstance<MIPS_COLUMNS, Curve>;
pub type MIPSFoldingEnvironment =
    FoldingEnvironment<MIPS_COLUMNS, MIPS_REL_COLS, MIPS_SEL_COLS, MIPSFoldingConfig>;

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
    type Srs = SRS<Curve>;
    type Instance = MIPSFoldingInstance;
    type Witness = MIPSFoldingWitness;
    type Structure = MIPSTrace;
    type Env = MIPSFoldingEnvironment;
}
