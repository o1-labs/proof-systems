//! This module implements the data structures of a proof.

use crate::circuits::wires::{COLUMNS, PERMUTS};
use ark_ec::AffineCurve;
use ark_ff::{Field, Zero};
use array_init::array_init;
use commitment_dlog::{commitment::PolyComm, evaluation_proof::OpeningProof};
use itertools::chain;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;

//~ spec:startcode
/// Evaluations of lookup polynomials
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct LookupEvaluations<F>
where
    F: Field,
{
    /// sorted lookup table polynomial
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub sorted: Vec<F>,

    /// lookup aggregation polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub aggreg: F,

    // TODO: May be possible to optimize this away?
    /// lookup table polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub table: F,

    /// Optionally, a runtime table polynomial.
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub runtime: Option<F>,
}

/// Polynomial evaluations contained in a `ProverProof`.
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct ProofEvaluations<F>
where
    F: Field,
{
    /// witness polynomials
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; COLUMNS]")]
    pub w: [F; COLUMNS],

    /// permutation polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub z: F,

    /// permutation polynomials
    /// (PERMUTS-1 evaluations because the last permutation is only used in commitment form)
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS - 1]")]
    pub s: [F; PERMUTS - 1],

    /// lookup-related evaluations
    #[serde(bound = "LookupEvaluations<F>: Serialize + DeserializeOwned")]
    pub lookup: Option<LookupEvaluations<F>>,

    /// evaluation of the generic selector polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub generic_selector: F,

    /// evaluation of the poseidon selector polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub poseidon_selector: F,
}

/// Commitments linked to the lookup feature
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "G: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize")]
pub struct LookupCommitments<G: AffineCurve> {
    /// Commitments to the sorted lookup table polynomial (may have chunks)
    pub sorted: Vec<PolyComm<G>>,
    /// Commitment to the lookup aggregation polynomial
    pub aggreg: PolyComm<G>,
    /// Optional commitment to concatenated runtime tables
    pub runtime: Option<PolyComm<G>>,
}

/// All the commitments that the prover creates as part of the proof.
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "G: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize")]
pub struct ProverCommitments<G: AffineCurve> {
    /// The commitments to the witness (execution trace)
    pub w_comm: [PolyComm<G>; COLUMNS],
    /// The commitment to the permutation polynomial
    pub z_comm: PolyComm<G>,
    /// The commitment to the quotient polynomial
    pub t_comm: PolyComm<G>,
    /// Commitments related to the lookup argument
    pub lookup: Option<LookupCommitments<G>>,
}

/// The proof that the prover creates from a [ProverIndex](super::prover_index::ProverIndex) and a `witness`.
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
#[serde(
    bound = "G: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize, G::ScalarField: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize"
)]
pub struct ProverProof<G: AffineCurve> {
    /// All the polynomial commitments required in the proof
    pub commitments: ProverCommitments<G>,

    /// batched commitment opening proof
    pub proof: OpeningProof<G>,

    /// Two evaluations over a number of committed polynomials
    // TODO(mimoo): that really should be a type Evals { z: PE, zw: PE }
    pub evals: [ProofEvaluations<G::ScalarField>; 2],

    /// Required evaluation for [Maller's optimization](https://o1-labs.github.io/mina-book/crypto/plonk/maller_15.html#the-evaluation-of-l)
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub ft_eval1: G::ScalarField,

    /// The public input
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub public: Vec<G::ScalarField>,

    /// The challenges underlying the optional polynomials folded into the proof
    pub prev_challenges: Vec<RecursionChallenge<G>>,
}

/// A struct to store the challenges inside a `ProverProof`
#[serde_as]
#[derive(Clone, Deserialize, Serialize)]
#[serde(bound = "G: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize")]
pub struct RecursionChallenge<G>
where
    G: AffineCurve,
{
    /// Vector of scalar field elements
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub chals: Vec<G::ScalarField>,
    /// Polynomial commitment
    pub comm: PolyComm<G>,
}

//~ spec:endcode

impl<G: AffineCurve> RecursionChallenge<G> {
    pub fn new(chals: Vec<G::ScalarField>, comm: PolyComm<G>) -> RecursionChallenge<G> {
        RecursionChallenge { chals, comm }
    }

    pub fn evals(
        &self,
        max_poly_size: usize,
        evaluation_points: &[G::ScalarField],
        powers_of_eval_points_for_chunks: &[G::ScalarField],
    ) -> Vec<Vec<G::ScalarField>> {
        let RecursionChallenge { chals, comm: _ } = self;
        // No need to check the correctness of poly explicitly. Its correctness is assured by the
        // checking of the inner product argument.
        let b_len = 1 << chals.len();
        let mut b: Option<Vec<G::ScalarField>> = None;

        (0..2)
            .map(|i| {
                let full = b_poly(chals, evaluation_points[i]);
                if max_poly_size == b_len {
                    return vec![full];
                }
                let mut betaacc = G::ScalarField::one();
                let diff = (max_poly_size..b_len)
                    .map(|j| {
                        let b_j = match &b {
                            None => {
                                let t = b_poly_coefficients(chals);
                                let res = t[j];
                                b = Some(t);
                                res
                            }
                            Some(b) => b[j],
                        };

                        let ret = betaacc * b_j;
                        betaacc *= &evaluation_points[i];
                        ret
                    })
                    .fold(G::ScalarField::zero(), |x, y| x + y);
                vec![full - (diff * powers_of_eval_points_for_chunks[i]), diff]
            })
            .collect()
    }
}

impl<F: Field> ProofEvaluations<F> {
    pub fn iter(&self) -> impl Iterator<Item = F> {
        chain![
            std::iter::once(self.z),
            std::iter::once(self.generic_selector),
            std::iter::once(self.poseidon_selector),
            self.w,
            self.s
        ]
    }

    pub fn dummy_with_witness_evaluations(w: [F; COLUMNS]) -> ProofEvaluations<F> {
        ProofEvaluations {
            w,
            z: F::zero(),
            s: array_init(|_| F::zero()),
            lookup: None,
            generic_selector: F::zero(),
            poseidon_selector: F::zero(),
        }
    }
}

//
// OCaml types
//

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use commitment_dlog::commitment::caml::CamlPolyComm;

    //
    // CamlRecursionChallenge<CamlG, CamlF>
    //

    #[derive(Clone, ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlRecursionChallenge<CamlG, CamlF> {
        pub chals: Vec<CamlF>,
        pub comm: CamlPolyComm<CamlG>,
    }

    //
    // CamlRecursionChallenge<CamlG, CamlF> <-> RecursionChallenge<G>
    //

    impl<G, CamlG, CamlF> From<RecursionChallenge<G>> for CamlRecursionChallenge<CamlG, CamlF>
    where
        G: AffineCurve,
        CamlG: From<G>,
        CamlF: From<G::ScalarField>,
    {
        fn from(ch: RecursionChallenge<G>) -> Self {
            Self {
                chals: ch.chals.into_iter().map(Into::into).collect(),
                comm: ch.comm.into(),
            }
        }
    }

    impl<G, CamlG, CamlF> From<CamlRecursionChallenge<CamlG, CamlF>> for RecursionChallenge<G>
    where
        G: AffineCurve + From<CamlG>,
        G::ScalarField: From<CamlF>,
    {
        fn from(caml_ch: CamlRecursionChallenge<CamlG, CamlF>) -> RecursionChallenge<G> {
            RecursionChallenge {
                chals: caml_ch.chals.into_iter().map(Into::into).collect(),
                comm: caml_ch.comm.into(),
            }
        }
    }

    //
    // CamlLookupEvaluations<CamlF>
    //

    #[derive(Clone, ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlLookupEvaluations<CamlF> {
        pub sorted: Vec<CamlF>,
        pub aggreg: CamlF,
        pub table: CamlF,
        pub runtime: Option<CamlF>,
    }

    impl<F, CamlF> From<LookupEvaluations<F>> for CamlLookupEvaluations<CamlF>
    where
        F: Field,
        CamlF: From<F>,
    {
        fn from(le: LookupEvaluations<F>) -> Self {
            Self {
                sorted: le.sorted.into_iter().map(Into::into).collect(),
                aggreg: le.aggreg.into(),
                table: le.table.into(),
                runtime: le.runtime.map(Into::into),
            }
        }
    }

    impl<F, CamlF> From<CamlLookupEvaluations<CamlF>> for LookupEvaluations<F>
    where
        F: From<CamlF> + Field,
    {
        fn from(pe: CamlLookupEvaluations<CamlF>) -> Self {
            Self {
                sorted: pe.sorted.into_iter().map(Into::into).collect(),
                aggreg: pe.aggreg.into(),
                table: pe.table.into(),
                runtime: pe.runtime.map(Into::into),
            }
        }
    }

    //
    // CamlProofEvaluations<CamlF>
    //

    #[allow(clippy::type_complexity)]
    #[derive(Clone, ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlProofEvaluations<CamlF> {
        pub w: (
            CamlF,
            CamlF,
            CamlF,
            CamlF,
            CamlF,
            CamlF,
            CamlF,
            CamlF,
            CamlF,
            CamlF,
            CamlF,
            CamlF,
            CamlF,
            CamlF,
            CamlF,
        ),
        pub z: CamlF,
        pub s: (CamlF, CamlF, CamlF, CamlF, CamlF, CamlF),
        pub generic_selector: CamlF,
        pub poseidon_selector: CamlF,

        pub lookup: Option<CamlLookupEvaluations<CamlF>>,
    }

    //
    // ProofEvaluations<F> <-> CamlProofEvaluations<CamlF>
    //

    impl<F, CamlF> From<ProofEvaluations<F>> for CamlProofEvaluations<CamlF>
    where
        F: Field,
        CamlF: From<F>,
    {
        fn from(pe: ProofEvaluations<F>) -> Self {
            let w = (
                pe.w[0].into(),
                pe.w[1].into(),
                pe.w[2].into(),
                pe.w[3].into(),
                pe.w[4].into(),
                pe.w[5].into(),
                pe.w[6].into(),
                pe.w[7].into(),
                pe.w[8].into(),
                pe.w[9].into(),
                pe.w[10].into(),
                pe.w[11].into(),
                pe.w[12].into(),
                pe.w[13].into(),
                pe.w[14].into(),
            );
            let s = (
                pe.s[0].into(),
                pe.s[1].into(),
                pe.s[2].into(),
                pe.s[3].into(),
                pe.s[4].into(),
                pe.s[5].into(),
            );

            Self {
                w,
                z: pe.z.into(),
                s,
                generic_selector: pe.generic_selector.into(),
                poseidon_selector: pe.poseidon_selector.into(),
                lookup: pe.lookup.map(Into::into),
            }
        }
    }

    impl<F, CamlF> From<CamlProofEvaluations<CamlF>> for ProofEvaluations<F>
    where
        F: Field + From<CamlF>,
    {
        fn from(cpe: CamlProofEvaluations<CamlF>) -> Self {
            let w = [
                cpe.w.0.into(),
                cpe.w.1.into(),
                cpe.w.2.into(),
                cpe.w.3.into(),
                cpe.w.4.into(),
                cpe.w.5.into(),
                cpe.w.6.into(),
                cpe.w.7.into(),
                cpe.w.8.into(),
                cpe.w.9.into(),
                cpe.w.10.into(),
                cpe.w.11.into(),
                cpe.w.12.into(),
                cpe.w.13.into(),
                cpe.w.14.into(),
            ];
            let s = [
                cpe.s.0.into(),
                cpe.s.1.into(),
                cpe.s.2.into(),
                cpe.s.3.into(),
                cpe.s.4.into(),
                cpe.s.5.into(),
            ];

            Self {
                w,
                z: cpe.z.into(),
                s,
                generic_selector: cpe.generic_selector.into(),
                poseidon_selector: cpe.poseidon_selector.into(),
                lookup: cpe.lookup.map(Into::into),
            }
        }
    }
}
