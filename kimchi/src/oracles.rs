//! This type and logic only exists for the OCaml side.
//! As we move more code to the Rust side,
//! we hope to be able to remove this code in the future.

use crate::{alphas::Alphas, circuits::scalars::RandomOracles};
use commitment_dlog::commitment::{CommitmentCurve, PolyComm};
use oracle::FqSponge;

/// The result of running the oracle protocol
pub struct OraclesResult<G, EFqSponge>
where
    G: CommitmentCurve,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
{
    /// A sponge that acts on the base field of a curve
    pub fq_sponge: EFqSponge,
    /// the last evaluation of the Fq-Sponge in this protocol
    pub digest: G::ScalarField,
    /// the challenges produced in the protocol
    pub oracles: RandomOracles<G::ScalarField>,
    /// the computed powers of alpha
    pub all_alphas: Alphas<G::ScalarField>,
    /// public polynomial evaluations
    pub p_eval: Vec<Vec<G::ScalarField>>,
    /// zeta^n and (zeta * omega)^n
    pub powers_of_eval_points_for_chunks: [G::ScalarField; 2],
    /// recursion data
    #[allow(clippy::type_complexity)]
    pub polys: Vec<(PolyComm<G>, Vec<Vec<G::ScalarField>>)>,
    /// pre-computed zeta^n
    pub zeta1: G::ScalarField,
    /// The evaluation f(zeta) - t(zeta) * Z_H(zeta)
    pub ft_eval0: G::ScalarField,
    /// Used by the OCaml side
    pub combined_inner_product: G::ScalarField,
}
