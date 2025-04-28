use crate::lookups::{FixedLookup, FixedLookupTables, LookupTable};

use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain};
use kimchi::{circuits::domains::EvaluationDomains, curve::KimchiCurve};
use poly_commitment::{ipa::SRS, PolyComm, SRS as _};

/// This is what the prover needs to rembember
/// while doing individual proofs, in order
/// to prove the lookup protocol we do in the end
#[derive(Clone)]
pub struct LookupEnvironment<G: KimchiCurve> {
    /// fixed tables pre-existing the protocol
    pub tables: FixedLookup<Vec<Vec<G::ScalarField>>>,
    pub tables_transposed: FixedLookup<Vec<Vec<G::ScalarField>>>,
    pub tables_poly: FixedLookup<Vec<DensePolynomial<G::ScalarField>>>,
    pub tables_comm: FixedLookup<Vec<PolyComm<G>>>,
    ///multiplicities
    pub multiplicities: FixedLookup<Vec<u64>>,
    /// Commitments to the lookup state
    /// Separated by the proof they come from.
    /// It is empty at creation and filled as we perform
    /// the first iteration of proving.
    /// It is then consumed at the second iteration,
    /// when proving the lookup argument.
    pub cms: Vec<Vec<PolyComm<G>>>,
}

/// The persistent envirionement accross all proofs.
/// It stores the some fixed values (fixed lookup),
/// and some proof dependant values: an accumulation
/// of the multiplicities and the commitments to the lookup state
impl<G: KimchiCurve> LookupEnvironment<G> {
    /// Create a new prover environment, which interpolates the fixed tables
    /// and commit to them.
    /// Fills the multiplicities with zeroes
    pub fn new(srs: &SRS<G>, domain: EvaluationDomains<G::ScalarField>) -> Self {
        let tables = LookupTable::<G::ScalarField>::get_formated_tables(domain.d1.size);

        let eval_one = |evals: Vec<G::ScalarField>| {
            Evaluations::<G::ScalarField, Radix2EvaluationDomain<G::ScalarField>>::from_vec_and_domain(evals, domain.d1)
                .interpolate()
        };
        let eval_multiple =
            |evals: Vec<Vec<G::ScalarField>>| evals.into_iter().map(eval_one).collect::<Vec<_>>();
        let tables_poly = tables.clone().map(eval_multiple);
        let tables_comm = tables_poly.clone().map(|poly_vec: Vec<_>| {
            poly_vec
                .into_iter()
                .map(|poly| srs.commit_non_hiding(&poly, 1))
                .collect()
        });
        LookupEnvironment {
            tables,
            tables_transposed: LookupTable::<G::ScalarField>::get_formated_tables_transposed(
                domain.d1.size,
            ),
            tables_poly,
            tables_comm,
            multiplicities: FixedLookup::<Vec<u64>>::new(),
            cms: vec![],
        }
    }

    /// Take a prover environment, a multiplicities, and returns
    /// a prover environment with the multiplicities being the addition of both
    pub fn add_multiplicities(&mut self, multiplicities: FixedLookup<Vec<u64>>) {
        for (x, y) in self
            .multiplicities
            .pad_lookup
            .iter_mut()
            .zip(multiplicities.pad_lookup.iter())
        {
            *x += y
        }

        for (x, y) in self
            .multiplicities
            .round_constants_lookup
            .iter_mut()
            .zip(multiplicities.round_constants_lookup.iter())
        {
            *x += y
        }

        for (x, y) in self
            .multiplicities
            .at_most_4_lookup
            .iter_mut()
            .zip(multiplicities.at_most_4_lookup.iter())
        {
            *x += y
        }

        for (x, y) in self
            .multiplicities
            .byte_lookup
            .iter_mut()
            .zip(multiplicities.byte_lookup.iter())
        {
            *x += y
        }

        for (x, y) in self
            .multiplicities
            .range_check_16_lookup
            .iter_mut()
            .zip(multiplicities.range_check_16_lookup.iter())
        {
            *x += y
        }

        for (x, y) in self
            .multiplicities
            .sparse_lookup
            .iter_mut()
            .zip(multiplicities.sparse_lookup.iter())
        {
            *x += y
        }

        for (x, y) in self
            .multiplicities
            .reset_lookup
            .iter_mut()
            .zip(multiplicities.reset_lookup.iter())
        {
            *x += y
        }
    }

    /// Cherry picks the commimtments to the lookup state from a proof
    /// and add it to the env
    pub fn add_cms(&mut self, cms: &[PolyComm<G>]) {
        self.cms.push(cms.to_vec())
    }
}
