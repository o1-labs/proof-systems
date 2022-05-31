//! This module implements the data structures of a proof.

use crate::circuits::wires::{COLUMNS, PERMUTS};
use ark_ec::AffineCurve;
use ark_ff::{FftField, Field, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use array_init::array_init;
use commitment_dlog::{commitment::PolyComm, evaluation_proof::OpeningProof};
use o1_utils::{types::fields::*, ExtendedDensePolynomial};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;

//~ spec:startcode

/// Evaluations of lookup polynomials
#[serde_as]
#[derive(Clone, Deserialize, Serialize)]
pub struct LookupEvaluations<F: CanonicalSerialize + CanonicalDeserialize> {
    /// sorted lookup table polynomial
    #[serde_as(as = "Vec<Vec<o1_utils::serialization::SerdeAs>>")]
    pub sorted: Vec<Vec<F>>,
    /// lookup aggregation polynomial
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub aggreg: Vec<F>,
    // TODO: May be possible to optimize this away?
    /// lookup table polynomial
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub table: Vec<F>,
    /// Optionally, a runtime table polynomial.
    #[serde_as(as = "Option<Vec<o1_utils::serialization::SerdeAs>>")]
    pub runtime: Option<Vec<F>>,
}

/// Polynomial evaluations contained in a `ProverProof`.
/// - **Chunked evaluations** use vectors with a length that equals the length of the chunk
/// - **Non chunked evaluations** use single-sized vectors, so the single evaluation appears in the first position of each field of the struct
#[serde_as]
#[derive(Clone, Deserialize, Serialize)]
pub struct ProofEvaluations<F: CanonicalSerialize + CanonicalDeserialize> {
    /// witness polynomials
    #[serde_as(as = "[Vec<o1_utils::serialization::SerdeAs>; COLUMNS]")]
    pub w: [Vec<F>; COLUMNS],
    /// permutation polynomial evaluation (one per chunk)
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub z: Vec<F>,
    /// permutation polynomials
    /// (PERMUTS-1 evaluations because the last permutation is only used in commitment form)
    #[serde_as(as = "[Vec<o1_utils::serialization::SerdeAs>; PERMUTS - 1]")]
    pub s: [Vec<F>; PERMUTS - 1],
    /// lookup-related evaluations
    #[serde(bound = "LookupEvaluations<F>: Serialize")]
    pub lookup: Option<LookupEvaluations<F>>,
    /// evaluation of the generic selector polynomial
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub generic_selector: Vec<F>,
    /// evaluation of the poseidon selector polynomial
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub poseidon_selector: Vec<F>,
}

/// Commitments linked to the lookup feature
#[serde_as]
#[derive(Clone, Deserialize, Serialize)]
pub struct LookupCommitments<G: AffineCurve> {
    /// Commitments to the sorted lookup table polynomial (may have chunks)
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub sorted: Vec<PolyComm<G>>,
    /// Commitment to the lookup aggregation polynomial
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub aggreg: PolyComm<G>,
    /// Optional commitment to concatenated runtime tables
    #[serde(bound = "Option<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub runtime: Option<PolyComm<G>>,
}

/// All the commitments that the prover creates as part of the proof.
#[serde_as]
#[derive(Clone, Deserialize, Serialize)]
pub struct ProverCommitments<G: AffineCurve> {
    /// The commitments to the witness (execution trace)
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub w_comm: [PolyComm<G>; COLUMNS],
    /// The commitment to the permutation polynomial
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub z_comm: PolyComm<G>,
    /// The commitment to the quotient polynomial
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub t_comm: PolyComm<G>,
    /// Commitments related to the lookup argument
    #[serde(bound = "LookupCommitments<G>: Serialize + DeserializeOwned")]
    pub lookup: Option<LookupCommitments<G>>,
}

/// The proof that the prover creates from a [ProverIndex](super::prover_index::ProverIndex) and a `witness`.
#[serde_as]
#[derive(Clone, Deserialize, Serialize)]
pub struct ProverProof<G>
where
    G: AffineCurve,
{
    /// All the polynomial commitments required in the proof
    #[serde(bound = "ProverCommitments<G>: Serialize + DeserializeOwned")]
    pub commitments: ProverCommitments<G>,

    /// batched commitment opening proof
    #[serde(bound = "OpeningProof<G>: Serialize + DeserializeOwned")]
    pub proof: OpeningProof<G>,

    /// Two evaluations over a number of committed polynomials
    // TODO(mimoo): that really should be a type Evals { z: PE, zw: PE }
    #[serde(bound = "ProofEvaluations<ScalarField<G>>: Serialize + DeserializeOwned")]
    pub evals: [ProofEvaluations<ScalarField<G>>; 2],

    /// Required evaluation for [Maller's optimization](https://o1-labs.github.io/mina-book/crypto/plonk/maller_15.html#the-evaluation-of-l)
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub ft_eval1: ScalarField<G>,

    /// The public input
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub public: Vec<ScalarField<G>>,

    /// The challenges underlying the optional polynomials folded into the proof
    #[serde(bound = "RecursionChallenge<G>: Serialize + DeserializeOwned")]
    pub prev_challenges: Vec<RecursionChallenge<G>>,
}

/// A struct to store the challenges inside a `ProverProof`
#[serde_as]
#[derive(Clone, Deserialize, Serialize)]
pub struct RecursionChallenge<G>
where
    G: AffineCurve,
{
    /// Vector of scalar field elements
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub chals: Vec<ScalarField<G>>,
    /// Polynomial commitment
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub comm: PolyComm<G>,
}

//~ spec:endcode

impl<G: AffineCurve> RecursionChallenge<G> {
    pub fn new(chals: Vec<ScalarField<G>>, comm: PolyComm<G>) -> RecursionChallenge<G> {
        RecursionChallenge { chals, comm }
    }
}

impl<F: Field> LookupEvaluations<F> {
    pub fn new(sorted: Vec<F>, aggreg: F, table: F, runtime: Option<F>) -> LookupEvaluations<F> {
        LookupEvaluations {
            sorted: sorted.iter().map(|&s| vec![s]).collect::<Vec<_>>(),
            aggreg: vec![aggreg],
            table: vec![table],
            runtime: runtime.map(|r| vec![r]),
        }
    }

    pub fn get_runtime(&self) -> Option<F> {
        self.runtime.clone().map(|r| r[0])
    }
}

impl<F: Zero + CanonicalDeserialize + CanonicalSerialize> ProofEvaluations<F> {
    pub fn dummy_with_witness_evaluations(w: [F; COLUMNS]) -> ProofEvaluations<F>
    where
        F: Clone,
    {
        ProofEvaluations {
            w: array_init(|i| vec![w[i].clone()]),
            z: vec![F::zero()],
            s: array_init(|_| vec![F::zero()]),
            lookup: None,
            generic_selector: vec![F::zero()],
            poseidon_selector: vec![F::zero()],
        }
    }

    pub fn get_w(&self) -> [F; COLUMNS]
    where
        F: Clone,
    {
        array_init(|i| self.w[i][0].clone())
    }

    pub fn new(
        w: [F; COLUMNS],
        z: F,
        s: [F; PERMUTS - 1],
        lookup: Option<LookupEvaluations<F>>,
        generic_selector: F,
        poseidon_selector: F,
    ) -> ProofEvaluations<F>
    where
        F: Clone,
    {
        ProofEvaluations {
            w: array_init(|i| vec![w[i].clone()]),
            z: vec![z],
            s: array_init(|i| vec![s[i].clone()]),
            lookup,
            generic_selector: vec![generic_selector],
            poseidon_selector: vec![poseidon_selector],
        }
    }
}

impl<F: FftField> ProofEvaluations<F> {
    /// Combines the chunked proof evaluations into single evaluations
    /// at an evaluation point `pt` as vectors of length 1
    pub fn combine(&self, pt: F) -> ProofEvaluations<F> {
        ProofEvaluations {
            w: array_init(|i| vec![DensePolynomial::eval_polynomial(&self.w[i], pt)]),
            s: array_init(|i| vec![DensePolynomial::eval_polynomial(&self.s[i], pt)]),
            z: vec![DensePolynomial::eval_polynomial(&self.z, pt)],
            lookup: self.lookup.as_ref().map(|l| LookupEvaluations {
                table: vec![DensePolynomial::eval_polynomial(&l.table, pt)],
                aggreg: vec![DensePolynomial::eval_polynomial(&l.aggreg, pt)],
                sorted: l
                    .sorted
                    .iter()
                    .map(|x| vec![DensePolynomial::eval_polynomial(x, pt)])
                    .collect(),
                runtime: l
                    .runtime
                    .as_ref()
                    .map(|rt| vec![DensePolynomial::eval_polynomial(rt, pt)]),
            }),
            generic_selector: vec![DensePolynomial::eval_polynomial(&self.generic_selector, pt)],
            poseidon_selector: vec![DensePolynomial::eval_polynomial(
                &self.poseidon_selector,
                pt,
            )],
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
        pub sorted: Vec<Vec<CamlF>>,
        pub aggreg: Vec<CamlF>,
        pub table: Vec<CamlF>,
        pub runtime: Option<Vec<CamlF>>,
    }

    impl<F, CamlF> From<LookupEvaluations<F>> for CamlLookupEvaluations<CamlF>
    where
        F: Clone + CanonicalSerialize + CanonicalDeserialize,
        CamlF: From<F>,
    {
        fn from(le: LookupEvaluations<F>) -> Self {
            Self {
                sorted: le
                    .sorted
                    .into_iter()
                    .map(|x| x.into_iter().map(Into::into).collect())
                    .collect(),
                aggreg: le.aggreg.into_iter().map(Into::into).collect(),
                table: le.table.into_iter().map(Into::into).collect(),
                runtime: le.runtime.map(|r| r.into_iter().map(Into::into).collect()),
            }
        }
    }

    impl<F, CamlF> From<CamlLookupEvaluations<CamlF>> for LookupEvaluations<F>
    where
        F: From<CamlF> + Clone + CanonicalSerialize + CanonicalDeserialize,
    {
        fn from(pe: CamlLookupEvaluations<CamlF>) -> Self {
            Self {
                sorted: pe
                    .sorted
                    .into_iter()
                    .map(|x| x.into_iter().map(Into::into).collect())
                    .collect(),
                aggreg: pe.aggreg.into_iter().map(Into::into).collect(),
                table: pe.table.into_iter().map(Into::into).collect(),
                runtime: pe.runtime.map(|r| r.into_iter().map(Into::into).collect()),
            }
        }
    }

    //
    // CamlProofEvaluations<CamlF>
    //

    #[derive(Clone, ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlProofEvaluations<CamlF> {
        pub w: (
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
        ),
        pub z: Vec<CamlF>,
        pub s: (
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
        ),
        pub generic_selector: Vec<CamlF>,
        pub poseidon_selector: Vec<CamlF>,
    }

    //
    // ProofEvaluations<Vec<F>> <-> CamlProofEvaluations<CamlF>
    //

    impl<F, CamlF> From<ProofEvaluations<F>> for CamlProofEvaluations<CamlF>
    where
        F: Clone + CanonicalSerialize + CanonicalDeserialize,
        CamlF: From<F>,
    {
        fn from(pe: ProofEvaluations<F>) -> Self {
            let w = (
                pe.w[0].iter().cloned().map(Into::into).collect(),
                pe.w[1].iter().cloned().map(Into::into).collect(),
                pe.w[2].iter().cloned().map(Into::into).collect(),
                pe.w[3].iter().cloned().map(Into::into).collect(),
                pe.w[4].iter().cloned().map(Into::into).collect(),
                pe.w[5].iter().cloned().map(Into::into).collect(),
                pe.w[6].iter().cloned().map(Into::into).collect(),
                pe.w[7].iter().cloned().map(Into::into).collect(),
                pe.w[8].iter().cloned().map(Into::into).collect(),
                pe.w[9].iter().cloned().map(Into::into).collect(),
                pe.w[10].iter().cloned().map(Into::into).collect(),
                pe.w[11].iter().cloned().map(Into::into).collect(),
                pe.w[12].iter().cloned().map(Into::into).collect(),
                pe.w[13].iter().cloned().map(Into::into).collect(),
                pe.w[14].iter().cloned().map(Into::into).collect(),
            );
            let s = (
                pe.s[0].iter().cloned().map(Into::into).collect(),
                pe.s[1].iter().cloned().map(Into::into).collect(),
                pe.s[2].iter().cloned().map(Into::into).collect(),
                pe.s[3].iter().cloned().map(Into::into).collect(),
                pe.s[4].iter().cloned().map(Into::into).collect(),
                pe.s[5].iter().cloned().map(Into::into).collect(),
            );

            Self {
                w,
                z: pe.z.into_iter().map(Into::into).collect(),
                s,
                generic_selector: pe.generic_selector.into_iter().map(Into::into).collect(),
                poseidon_selector: pe.poseidon_selector.into_iter().map(Into::into).collect(),
            }
        }
    }

    impl<F, CamlF> From<CamlProofEvaluations<CamlF>> for ProofEvaluations<F>
    where
        F: Clone + CanonicalSerialize + CanonicalDeserialize,
        F: From<CamlF>,
    {
        fn from(cpe: CamlProofEvaluations<CamlF>) -> Self {
            let w = [
                cpe.w.0.into_iter().map(Into::into).collect(),
                cpe.w.1.into_iter().map(Into::into).collect(),
                cpe.w.2.into_iter().map(Into::into).collect(),
                cpe.w.3.into_iter().map(Into::into).collect(),
                cpe.w.4.into_iter().map(Into::into).collect(),
                cpe.w.5.into_iter().map(Into::into).collect(),
                cpe.w.6.into_iter().map(Into::into).collect(),
                cpe.w.7.into_iter().map(Into::into).collect(),
                cpe.w.8.into_iter().map(Into::into).collect(),
                cpe.w.9.into_iter().map(Into::into).collect(),
                cpe.w.10.into_iter().map(Into::into).collect(),
                cpe.w.11.into_iter().map(Into::into).collect(),
                cpe.w.12.into_iter().map(Into::into).collect(),
                cpe.w.13.into_iter().map(Into::into).collect(),
                cpe.w.14.into_iter().map(Into::into).collect(),
            ];
            let s = [
                cpe.s.0.into_iter().map(Into::into).collect(),
                cpe.s.1.into_iter().map(Into::into).collect(),
                cpe.s.2.into_iter().map(Into::into).collect(),
                cpe.s.3.into_iter().map(Into::into).collect(),
                cpe.s.4.into_iter().map(Into::into).collect(),
                cpe.s.5.into_iter().map(Into::into).collect(),
            ];

            Self {
                w,
                z: cpe.z.into_iter().map(Into::into).collect(),
                s,
                lookup: None,
                generic_selector: cpe.generic_selector.into_iter().map(Into::into).collect(),
                poseidon_selector: cpe.poseidon_selector.into_iter().map(Into::into).collect(),
            }
        }
    }
}
