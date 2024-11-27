use ark_ff::FftField;
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use kimchi_msm::{columns::Column, logup::prover::QuotientPolynomialEnvironment, LookupTableID};

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

/// The collection of polynomials (all in evaluation form) and constants
/// required to evaluate an expression as a polynomial.
///
/// All are evaluations.
pub struct ColumnEnvironment<'a, F: FftField, ID: LookupTableID> {
    /// The witness column polynomials. Includes relation columns and dynamic
    /// selector columns.
    pub witness: &'a WitnessColumns<Evals<F>, [Evals<F>; N_MIPS_SEL_COLS], ID>,
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

    /// Lookup specific polynomials
    pub lookup: Option<QuotientPolynomialEnvironment<'a, F, ID>>,
}

pub fn get_all_columns() -> Vec<Column> {
    let mut cols =
        Vec::<Column>::with_capacity(SCRATCH_SIZE + SCRATCH_SIZE_INVERSE + 2 + N_MIPS_SEL_COLS);
    for i in 0..SCRATCH_SIZE + SCRATCH_SIZE_INVERSE + 2 {
        cols.push(Column::Relation(i));
    }
    for i in 0..N_MIPS_SEL_COLS {
        cols.push(Column::DynamicSelector(i));
    }
    cols
}

pub fn get_column<'a, F: Clone, ID: LookupTableID>(
    env: &'a WitnessColumns<F, [F; N_MIPS_SEL_COLS], ID>,
    col: &Column,
) -> Option<&'a F> {
    match *col {
        Column::Relation(i) => {
            if i < SCRATCH_SIZE {
                let res = &env.scratch[i];
                Some(res)
            } else if i < SCRATCH_SIZE + SCRATCH_SIZE_INVERSE {
                let res = &env.scratch_inverse[i - SCRATCH_SIZE];
                Some(res)
            } else if i == SCRATCH_SIZE + SCRATCH_SIZE_INVERSE {
                let res = &env.instruction_counter;
                Some(res)
            } else if i == SCRATCH_SIZE + 1 {
                let res = &env.error;
                Some(res)
            } else {
                panic!("We should not have that many relation columns. We have {} columns and index {} was given", SCRATCH_SIZE + SCRATCH_SIZE_INVERSE + 2, i);
            }
        }
        Column::DynamicSelector(i) => {
            assert!(
                i < N_MIPS_SEL_COLS,
                "We do not have that many dynamic selector columns, given {i} but only have {N_MIPS_SEL_COLS}"
            );
            let res = &env.selector[i];
            Some(res)
        }
        Column::LookupPartialSum((table_id, i)) => {
            let table_id = ID::from_u32(table_id);
            Some(&env.lookup[&table_id].f[i])
        }
        Column::LookupAggregation => Some(&env.lookup_agg),
        Column::LookupMultiplicity((table_id, i)) => {
            let table_id = ID::from_u32(table_id);
            Some(&env.lookup[&table_id].m[i])
        }
        Column::LookupFixedTable(table_id) => {
            let table_id = ID::from_u32(table_id);
            Some(&env.lookup[&table_id].t)
        }
        _ => {
            panic!(
                "We should not have any other type of columns. The column {:?} was given",
                col
            )
        }
    }
}

impl<'a, F: FftField, ID: LookupTableID>
    TColumnEnvironment<'a, F, BerkeleyChallengeTerm, BerkeleyChallenges<F>>
    for ColumnEnvironment<'a, F, ID>
{
    // FIXME: do we change to the MIPS column type?
    // We do not want to keep kimchi_msm/generic prover
    type Column = Column;

    fn get_column(&self, col: &Self::Column) -> Option<&'a Evals<F>> {
        get_column(self.witness, col)
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
