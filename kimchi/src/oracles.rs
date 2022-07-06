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

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use ark_ff::PrimeField;
    use commitment_dlog::commitment::shift_scalar;

    use crate::{
        circuits::scalars::caml::CamlRandomOracles, error::VerifyError, plonk_sponge::FrSponge,
        proof::ProverProof, verifier_index::VerifierIndex,
    };

    use super::*;

    pub struct CamlOracles<F> {
        pub o: CamlRandomOracles<F>,
        pub p_eval: (F, F),
        pub opening_prechallenges: Vec<F>,
        pub digest_before_evaluations: F,
    }

    pub fn create_caml_oracles<G, EFqSponge, EFrSponge, CurveParams>(
        lgr_comm: Vec<PolyComm<G>>,
        index: VerifierIndex<G>,
        proof: ProverProof<G>,
    ) -> Result<CamlOracles<G::ScalarField>, VerifyError>
    where
        G: CommitmentCurve,
        G::BaseField: PrimeField,
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
        EFrSponge: FrSponge<G::ScalarField>,
    {
        let lgr_comm: Vec<PolyComm<G>> = lgr_comm.into_iter().take(proof.public.len()).collect();
        let lgr_comm_refs: Vec<_> = lgr_comm.iter().collect();

        let negated_public: Vec<_> = proof.public.iter().map(|s| -*s).collect();

        let p_comm = PolyComm::<G>::multi_scalar_mul(&lgr_comm_refs, &negated_public);

        let oracles_result = proof.oracles::<EFqSponge, EFrSponge>(&index, &p_comm)?;

        let (mut sponge, combined_inner_product, p_eval, digest, oracles) = (
            oracles_result.fq_sponge,
            oracles_result.combined_inner_product,
            oracles_result.p_eval,
            oracles_result.digest,
            oracles_result.oracles,
        );

        sponge.absorb_fr(&[shift_scalar::<G>(combined_inner_product)]);

        let opening_prechallenges = proof
            .proof
            .prechallenges(&mut sponge)
            .into_iter()
            .map(|x| x.0.into())
            .collect();

        Ok(CamlOracles {
            o: oracles.into(),
            p_eval: (p_eval[0][0].into(), p_eval[1][0].into()),
            opening_prechallenges,
            digest_before_evaluations: digest.into(),
        })
    }
}
