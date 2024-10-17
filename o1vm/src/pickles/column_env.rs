use ark_ff::FftField;
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use kimchi_msm::columns::Column;

use crate::{
    interpreters::mips::{column::N_MIPS_SEL_COLS, witness::SCRATCH_SIZE},
    pickles::proof::WitnessColumns,
};
use kimchi::circuits::{
    berkeley_columns::{BerkeleyChallengeTerm, BerkeleyChallenges},
    domains::{Domain, EvaluationDomains},
    expr::{ColumnEnvironment as TColumnEnvironment, Constants},
};

type Evals<F> = Evaluations<F, Radix2EvaluationDomain<F>>;

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

pub fn get_all_columns() -> Vec<Column> {
    let mut cols = Vec::<Column>::with_capacity(SCRATCH_SIZE + 2 + N_MIPS_SEL_COLS);
    for i in 0..SCRATCH_SIZE + 2 {
        cols.push(Column::Relation(i));
    }
    for i in 0..N_MIPS_SEL_COLS {
        cols.push(Column::DynamicSelector(i));
    }
    cols
}

impl<G> WitnessColumns<G, [G; N_MIPS_SEL_COLS]> {
    pub fn get_column(&self, col: &Column) -> Option<&G> {
        match *col {
            Column::Relation(i) => {
                if i < SCRATCH_SIZE {
                    let res = &self.scratch[i];
                    Some(res)
                } else if i == SCRATCH_SIZE {
                    let res = &self.instruction_counter;
                    Some(res)
                } else if i == SCRATCH_SIZE + 1 {
                    let res = &self.error;
                    Some(res)
                } else {
                    panic!("We should not have that many relation columns");
                }
            }
            Column::DynamicSelector(i) => {
                assert!(
                    i < N_MIPS_SEL_COLS,
                    "We do not have that many dynamic selector columns"
                );
                let res = &self.selector[i];
                Some(res)
            }
            _ => {
                panic!("We should not have any other type of columns")
            }
        }
    }
}

impl<'a, F: FftField> TColumnEnvironment<'a, F, BerkeleyChallengeTerm, BerkeleyChallenges<F>>
    for ColumnEnvironment<'a, F>
{
    // FIXME: do we change to the MIPS column type?
    // We do not want to keep kimchi_msm/generic prover
    type Column = Column;

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

    fn column_domain(&self, _col: &Self::Column) -> Domain {
        Domain::D8
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
