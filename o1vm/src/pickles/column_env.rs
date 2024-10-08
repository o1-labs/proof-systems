use ark_ff::FftField;
use ark_poly::{Evaluations, Radix2EvaluationDomain};

use crate::interpreters::mips::{column::N_MIPS_SEL_COLS, witness::SCRATCH_SIZE};
use kimchi::circuits::{
    berkeley_columns::{BerkeleyChallengeTerm, BerkeleyChallenges},
    domains::EvaluationDomains,
    expr::{ColumnEnvironment as TColumnEnvironment, Constants, Domain},
};

use super::proof::WitnessColumns;

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

impl<'a, F: FftField> TColumnEnvironment<'a, F, BerkeleyChallengeTerm, BerkeleyChallenges<F>>
    for ColumnEnvironment<'a, F>
{
    // FIXME: do we change to the MIPS column type?
    // We do not want to keep kimchi_msm/generic prover
    type Column = kimchi_msm::columns::Column;

    fn get_column(
        &self,
        col: &Self::Column,
    ) -> Option<&'a Evaluations<F, Radix2EvaluationDomain<F>>> {
        match *col {
            Self::Column::Relation(i) => {
                if i < SCRATCH_SIZE {
                    let res = &self.witness.scratch[i];
                    Some(res)
                } else if i == SCRATCH_SIZE {
                    let res = &self.witness.instruction_counter;
                    Some(res)
                } else if i == SCRATCH_SIZE + 1 {
                    let res = &self.witness.error;
                    Some(res)
                } else {
                    panic!("We should not have that many relation columns");
                }
            }
            Self::Column::DynamicSelector(_i) => {
                // FIXME: add selectors
                panic!("Not implemented yet");
            }
            _ => {
                panic!("We should not have any other type of columns")
            }
        }
    }

    fn get_domain(&self, d: Domain) -> Radix2EvaluationDomain<F> {
        match d {
            Domain::D8 => self.domain.d8,
            Domain::D1 | Domain::D2 | Domain::D4 => {
                panic!("Not supposed to be in MIPS. All columns are evaluated on d8")
            }
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
