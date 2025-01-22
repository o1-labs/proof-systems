use crate::{
    interpreters::mips::witness::LookupMultiplicities,
    lookups::{FixedLookupTables, LookupTable},
};
use ark_ff::One;
use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain};
use kimchi::{circuits::domains::EvaluationDomains, curve::KimchiCurve};
use poly_commitment::{commitment::BlindedCommitment, ipa::SRS, PolyComm, SRS as _};

/// This is what the prover needs to rembember
/// while doing individual proofs, in order
/// to prove the lookup protocol we do in the end
pub struct LookupEnvironment<G: KimchiCurve> {
    /// fixed tables pre-existing the protocol
    pub tables_poly: Vec<Vec<DensePolynomial<G::ScalarField>>>,
    pub tables_comm: Vec<Vec<BlindedCommitment<G>>>,
    ///multiplicities
    pub multiplicities: LookupMultiplicities,
}

/// Create a new prover environment, which interpolates the fixed tables
/// and commit to them.
/// Fills the multiplicities with zeroes
impl<G: KimchiCurve> LookupEnvironment<G> {
    pub fn new(srs: &SRS<G>, domain: EvaluationDomains<G::ScalarField>) -> Self {
        let tables: Vec<LookupTable<G::ScalarField>> =
            LookupTable::<G::ScalarField>::get_all_tables();
        let eval_col = |evals: Vec<G::ScalarField>| {
            Evaluations::<G::ScalarField, Radix2EvaluationDomain<G::ScalarField>>::from_vec_and_domain(evals, domain.d1)
                .interpolate()
        };
        let eval_columns =
            |evals: Vec<Vec<G::ScalarField>>| evals.into_iter().map(eval_col).collect();
        let tables_poly: Vec<Vec<DensePolynomial<G::ScalarField>>> = tables
            .into_iter()
            .map(|lookup| eval_columns(lookup.entries))
            .collect();
        let tables_comm: Vec<Vec<BlindedCommitment<G>>> = tables_poly
            .iter()
            .map(|poly_vec| {
                poly_vec
                    .iter()
                    .map(|poly| {
                        srs.commit_custom(poly, 1, &PolyComm::new(vec![G::ScalarField::one()]))
                            .unwrap()
                    })
                    .collect()
            })
            .collect();
        LookupEnvironment {
            tables_poly,
            tables_comm,
            multiplicities: LookupMultiplicities::new(),
        }
    }
    /// Take a prover environment, a multiplicities, and returns
    /// a prover environment with the multiplicities being the addition of both
    pub fn add_multiplicities(&mut self, multiplicities: LookupMultiplicities) {
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
}
