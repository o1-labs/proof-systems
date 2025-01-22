use crate::interpreters::mips::witness::LookupMultiplicities;
use crate::lookups::{FixedLookupTables, LookupTable};
use ark_ff::One;
use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain};
use kimchi::circuits::domains::EvaluationDomains;
use kimchi::curve::KimchiCurve;
use poly_commitment::commitment::BlindedCommitment;
use poly_commitment::ipa::SRS;
use poly_commitment::{PolyComm, SRS as _};

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

impl<G: KimchiCurve> LookupEnvironment<G> {
    fn new(srs: &SRS<G>, domain: EvaluationDomains<G::ScalarField>) -> Self {
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

}
