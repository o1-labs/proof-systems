use ark_ff::FftField;
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use kimchi_msm::columns::Column;

use crate::{
    interpreters::mips::column::{N_MIPS_SEL_COLS, SCRATCH_SIZE, SCRATCH_SIZE_INVERSE},
    pickles::proof::WitnessColumns,
};
use kimchi::circuits::{
    berkeley_columns::{BerkeleyChallengeTerm, BerkeleyChallenges},
    domains::{Domain, EvaluationDomains},
    expr::{ColumnEnvironment as TColumnEnvironment, Constants},
};

type Evals<F> = Evaluations<F, Radix2EvaluationDomain<F>>;

#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
pub enum RelationColumnType {
    Scratch(usize),
    ScratchInverse(usize),
    LookupState(usize),
    InstructionCounter,
    Error,
}

/// The collection of polynomials (all in evaluation form) and constants
/// required to evaluate an expression as a polynomial.
///
/// All are evaluations.
pub struct ColumnEnvironment<'a, F: FftField> {
    /// The witness column polynomials. Includes relation columns and dynamic
    /// selector columns.
    pub witness: &'a WitnessColumns<Evals<F>, [Evals<F>; N_MIPS_SEL_COLS]>,
    /// The value `prod_{j != 1} (1 - ω^j)`, used for efficiently
    /// computing the evaluations of the unnormalized Lagrange basis
    /// polynomials.
    pub l0_1: F,
    /// Constant values required
    pub constants: Constants<F>,
    /// Challenges from the IOP.
    // FIXME: change for other challenges
    pub challenges: BerkeleyChallenges<F>,
    /// The domains used in the PLONK argument.
    pub domain: EvaluationDomains<F>,
}

pub fn get_all_columns(num_lookup_columns: usize) -> Vec<Column<RelationColumnType>> {
    let mut cols = Vec::<Column<RelationColumnType>>::with_capacity(
        SCRATCH_SIZE + SCRATCH_SIZE_INVERSE + num_lookup_columns + 2 + N_MIPS_SEL_COLS,
    );
    for i in 0..SCRATCH_SIZE {
        cols.push(Column::Relation(RelationColumnType::Scratch(i)));
    }
    for i in 0..SCRATCH_SIZE_INVERSE {
        cols.push(Column::Relation(RelationColumnType::ScratchInverse(i)));
    }
    for i in 0..num_lookup_columns {
        cols.push(Column::Relation(RelationColumnType::LookupState(i)));
    }
    cols.push(Column::Relation(RelationColumnType::InstructionCounter));
    cols.push(Column::Relation(RelationColumnType::Error));
    for i in 0..N_MIPS_SEL_COLS {
        cols.push(Column::DynamicSelector(i));
    }
    cols
}

impl<G> WitnessColumns<G, [G; N_MIPS_SEL_COLS]> {
    pub fn get_column(&self, col: &Column<RelationColumnType>) -> Option<&G> {
        match *col {
            Column::Relation(i) => match i {
                RelationColumnType::Scratch(i) => Some(&self.scratch[i]),
                RelationColumnType::ScratchInverse(i) => Some(&self.scratch_inverse[i]),
                RelationColumnType::LookupState(i) => Some(&self.lookup_state[i]),
                RelationColumnType::InstructionCounter => Some(&self.instruction_counter),
                RelationColumnType::Error => Some(&self.error),
            },
            Column::DynamicSelector(i) => {
                assert!(
                    i < N_MIPS_SEL_COLS,
                    "We do not have that many dynamic selector columns. We have {} columns and index {} was given",
                    N_MIPS_SEL_COLS,
                    i
                );
                let res = &self.selector[i];
                Some(res)
            }
            _ => {
                panic!(
                    "We should not have any other type of columns. The column {:?} was given",
                    col
                );
            }
        }
    }
}

impl<'a, F: FftField> TColumnEnvironment<'a, F, BerkeleyChallengeTerm, BerkeleyChallenges<F>>
    for ColumnEnvironment<'a, F>
{
    type Column = Column<RelationColumnType>;

    fn get_column(&self, col: &Self::Column) -> Option<&'a Evals<F>> {
        self.witness.get_column(col)
    }

    fn get_domain(&self, d: Domain) -> Radix2EvaluationDomain<F> {
        match d {
            Domain::D1 => self.domain.d1,
            Domain::D2 => self.domain.d2,
            Domain::D4 => self.domain.d4,
            Domain::D8 => self.domain.d8,
        }
    }

    fn get_constants(&self) -> &Constants<F> {
        &self.constants
    }

    fn get_challenges(&self) -> &BerkeleyChallenges<F> {
        &self.challenges
    }

    fn vanishes_on_zero_knowledge_and_previous_rows(
        &self,
    ) -> &'a Evaluations<F, Radix2EvaluationDomain<F>> {
        panic!("Not supposed to be used in MIPS. We do not support zero-knowledge for now")
    }

    fn l0_1(&self) -> F {
        self.l0_1
    }
}
