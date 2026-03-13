//! This type and logic only exists for the OCaml side.
//! As we move more code to the Rust side,
//! we hope to be able to remove this code in the future.

use crate::{alphas::Alphas, circuits::scalars::RandomOracles, proof::PointEvaluations};
use mina_poseidon::FqSponge;
use poly_commitment::commitment::{CommitmentCurve, PolyComm};

/// The result of running the oracle protocol
pub struct OraclesResult<const FULL_ROUNDS: usize, G, EFqSponge>
where
    G: CommitmentCurve,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField, FULL_ROUNDS>,
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
    pub public_evals: [Vec<G::ScalarField>; 2],
    /// zeta^n and (zeta * omega)^n
    pub powers_of_eval_points_for_chunks: PointEvaluations<G::ScalarField>,
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
    use mina_poseidon::poseidon::ArithmeticSpongeParams;
    use poly_commitment::{commitment::shift_scalar, ipa::OpeningProof};

    use crate::{
        circuits::scalars::caml::CamlRandomOracles, curve::KimchiCurve, error::VerifyError,
        plonk_sponge::FrSponge, proof::ProverProof, verifier_index::VerifierIndex,
    };

    use super::*;

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlOracles<CamlF> {
        pub o: CamlRandomOracles<CamlF>,
        pub public_evals: (CamlF, CamlF),
        pub opening_prechallenges: Vec<CamlF>,
        pub digest_before_evaluations: CamlF,
    }

    pub fn create_caml_oracles<
        const FULL_ROUNDS: usize,
        G,
        CamlF,
        EFqSponge,
        EFrSponge,
        CurveParams,
    >(
        lgr_comm: Vec<PolyComm<G>>,
        index: VerifierIndex<FULL_ROUNDS, G, CurveParams>,
        proof: ProverProof<G, OpeningProof<G, FULL_ROUNDS>, FULL_ROUNDS>,
        public_input: &[G::ScalarField],
    ) -> Result<CamlOracles<CamlF>, VerifyError>
    where
        G: KimchiCurve<FULL_ROUNDS>,
        G::BaseField: PrimeField,
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField, FULL_ROUNDS>,
        EFrSponge: FrSponge<G::ScalarField>,
        EFrSponge: From<&'static ArithmeticSpongeParams<G::ScalarField, FULL_ROUNDS>>,
        CamlF: From<G::ScalarField>,
        CurveParams: poly_commitment::OpenProof<G, FULL_ROUNDS>,
    {
        let lgr_comm: Vec<PolyComm<G>> = lgr_comm.into_iter().take(public_input.len()).collect();

        let negated_public: Vec<_> = public_input.iter().map(|s| -*s).collect();

        let p_comm = PolyComm::<G>::multi_scalar_mul(&lgr_comm, &negated_public);

        let oracles_result = proof.oracles::<EFqSponge, EFrSponge, CurveParams>(
            &index,
            &p_comm,
            Some(public_input),
        )?;

        let (mut sponge, combined_inner_product, public_evals, digest, oracles) = (
            oracles_result.fq_sponge,
            oracles_result.combined_inner_product,
            oracles_result.public_evals,
            oracles_result.digest,
            oracles_result.oracles,
        );

        sponge.absorb_fr(&[shift_scalar::<G>(combined_inner_product)]);

        let opening_prechallenges = proof
            .proof
            .prechallenges(&mut sponge)
            .into_iter()
            .map(|x| x.inner().into())
            .collect();

        Ok(CamlOracles {
            o: oracles.into(),
            public_evals: (public_evals[0][0].into(), public_evals[1][0].into()),
            opening_prechallenges,
            digest_before_evaluations: digest.into(),
        })
    }
}
