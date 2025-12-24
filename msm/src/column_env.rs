use ark_ff::FftField;
use ark_poly::{Evaluations, Radix2EvaluationDomain};

use crate::{logup, logup::LookupTableID, witness::Witness};
use kimchi::circuits::{
    berkeley_columns::{BerkeleyChallengeTerm, BerkeleyChallenges},
    domains::{Domain, EvaluationDomains},
    expr::{ColumnEnvironment as TColumnEnvironment, Constants},
};

/// The collection of polynomials (all in evaluation form) and constants
/// required to evaluate an expression as a polynomial.
///
/// All are evaluations.
pub struct ColumnEnvironment<
    'a,
    const N: usize,
    const N_REL: usize,
    const N_DSEL: usize,
    const N_FSEL: usize,
    F: FftField,
    ID: LookupTableID,
> {
    /// The witness column polynomials. Includes relation columns,
    /// fixed selector columns, and dynamic selector columns.
    pub witness: &'a Witness<N, Evaluations<F, Radix2EvaluationDomain<F>>>,
    /// Fixed selectors. These are "predefined" with the circuit, and,
    /// unlike public input or dynamic selectors, are not part of the
    /// witness that users are supposed to change after the circuit is
    /// fixed.
    pub fixed_selectors: &'a [Evaluations<F, Radix2EvaluationDomain<F>>; N_FSEL],
    /// The value `prod_{j != 1} (1 - omega^j)`, used for efficiently
    /// computing the evaluations of the unnormalized Lagrange basis polynomials.
    pub l0_1: F,
    /// Constant values required
    pub constants: Constants<F>,
    /// Challenges from the IOP.
    pub challenges: BerkeleyChallenges<F>,
    /// The domains used in the PLONK argument.
    pub domain: EvaluationDomains<F>,

    /// Lookup specific polynomials
    pub lookup: Option<logup::prover::QuotientPolynomialEnvironment<'a, F, ID>>,
}

impl<
        'a,
        const N_WIT: usize,
        const N_REL: usize,
        const N_DSEL: usize,
        const N_FSEL: usize,
        F: FftField,
        ID: LookupTableID,
    > TColumnEnvironment<'a, F, BerkeleyChallengeTerm, BerkeleyChallenges<F>>
    for ColumnEnvironment<'a, N_WIT, N_REL, N_DSEL, N_FSEL, F, ID>
{
    type Column = crate::columns::Column<usize>;

    fn get_column(
        &self,
        col: &Self::Column,
    ) -> Option<&'a Evaluations<F, Radix2EvaluationDomain<F>>> {
        // TODO: when non-literal constant generics are available, substitute N with N_REG + N_DSEL + N_FSEL
        assert!(N_WIT == N_REL + N_DSEL);
        assert!(N_WIT == self.witness.len());
        match *col {
            // Handling the "relation columns" at the beginning of the witness columns
            Self::Column::Relation(i) => {
                // TODO: add a test for this
                assert!(i < N_REL,"Requested column with index {:?} but the given witness is meant for {:?} relation columns", i, N_REL);
                let res = &self.witness[i];
                Some(res)
            }
            // Handling the "dynamic selector columns" at the end of the witness columns
            Self::Column::DynamicSelector(i) => {
                assert!(i < N_DSEL, "Requested dynamic selector with index {:?} but the given witness is meant for {:?} dynamic selector columns", i, N_DSEL);
                let res = &self.witness[N_REL + i];
                Some(res)
            }
            Self::Column::FixedSelector(i) => {
                assert!(i < N_FSEL, "Requested fixed selector with index {:?} but the given witness is meant for {:?} fixed selector columns", i, N_FSEL);
                let res = &self.fixed_selectors[i];
                Some(res)
            }
            Self::Column::LookupPartialSum((table_id, i)) => {
                if let Some(ref lookup) = self.lookup {
                    let table_id = ID::from_u32(table_id);
                    Some(&lookup.lookup_terms_evals_d8[&table_id][i])
                } else {
                    panic!("No lookup provided")
                }
            }
            Self::Column::LookupAggregation => {
                if let Some(ref lookup) = self.lookup {
                    Some(lookup.lookup_aggregation_evals_d8)
                } else {
                    panic!("No lookup provided")
                }
            }
            Self::Column::LookupMultiplicity((table_id, i)) => {
                if let Some(ref lookup) = self.lookup {
                    Some(&lookup.lookup_counters_evals_d8[&ID::from_u32(table_id)][i])
                } else {
                    panic!("No lookup provided")
                }
            }
            Self::Column::LookupFixedTable(table_id) => {
                if let Some(ref lookup) = self.lookup {
                    Some(&lookup.fixed_tables_evals_d8[&ID::from_u32(table_id)])
                } else {
                    panic!("No lookup provided")
                }
            }
        }
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
        panic!("Not supposed to be used in MSM")
    }

    fn l0_1(&self) -> F {
        self.l0_1
    }
}
