//! This module implements the data structures of a proof.

use crate::circuits::wires::{COLUMNS, PERMUTS};
use ark_ec::AffineCurve;
use ark_ff::{FftField, Zero};
use ark_poly::univariate::DensePolynomial;
use array_init::array_init;
use commitment_dlog::{commitment::PolyComm, evaluation_proof::OpeningProof};
use o1_utils::ExtendedDensePolynomial;
use oracle::poseidon::{ArithmeticSpongeParamsTrait, DefaultSpongeParams};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::marker::PhantomData;

//~ spec:startcode
/// Evaluations of lookup polynomials
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Vec<o1_utils::serialization::SerdeAs>: serde_with::SerializeAs<Field>",
    deserialize = "Vec<o1_utils::serialization::SerdeAs>: serde_with::DeserializeAs<'de, Field>"
))]
pub struct LookupEvaluations<Field> {
    /// sorted lookup table polynomial
    #[serde_as(as = "Vec<Vec<o1_utils::serialization::SerdeAs>>")]
    pub sorted: Vec<Field>,
    /// lookup aggregation polynomial
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub aggreg: Field,
    // TODO: May be possible to optimize this away?
    /// lookup table polynomial
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub table: Field,

    /// Optionally, a runtime table polynomial.
    #[serde_as(as = "Option<Vec<o1_utils::serialization::SerdeAs>>")]
    pub runtime: Option<Field>,
}

// TODO: this should really be vectors here, perhaps create another type for chunked evaluations?
/// Polynomial evaluations contained in a `ProverProof`.
/// - **Chunked evaluations** `Field` is instantiated with vectors with a length that equals the length of the chunk
/// - **Non chunked evaluations** `Field` is instantiated with a field, so they are single-sized#[serde_as]
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Vec<o1_utils::serialization::SerdeAs>: serde_with::SerializeAs<Field>",
    deserialize = "Vec<o1_utils::serialization::SerdeAs>: serde_with::DeserializeAs<'de, Field>"
))]
pub struct ProofEvaluations<Field> {
    /// witness polynomials
    #[serde_as(as = "[Vec<o1_utils::serialization::SerdeAs>; COLUMNS]")]
    pub w: [Field; COLUMNS],
    /// permutation polynomial
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub z: Field,
    /// permutation polynomials
    /// (PERMUTS-1 evaluations because the last permutation is only used in commitment form)
    #[serde_as(as = "[Vec<o1_utils::serialization::SerdeAs>; PERMUTS - 1]")]
    pub s: [Field; PERMUTS - 1],
    /// lookup-related evaluations
    pub lookup: Option<LookupEvaluations<Field>>,
    /// evaluation of the generic selector polynomial
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub generic_selector: Field,
    /// evaluation of the poseidon selector polynomial
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub poseidon_selector: Field,
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
#[serde(bound = "G: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize")]
pub struct ProverProof<G, S = DefaultSpongeParams<<G as AffineCurve>::ScalarField>>
where
    G: AffineCurve,
    S: ArithmeticSpongeParamsTrait<G::ScalarField>,
{
    /// All the polynomial commitments required in the proof
    pub commitments: ProverCommitments<G>,

    /// batched commitment opening proof
    pub proof: OpeningProof<G>,

    /// Two evaluations over a number of committed polynomials
    // TODO(mimoo): that really should be a type Evals { z: PE, zw: PE }
    pub evals: [ProofEvaluations<Vec<G::ScalarField>>; 2],

    /// Required evaluation for [Maller's optimization](https://o1-labs.github.io/mina-book/crypto/plonk/maller_15.html#the-evaluation-of-l)
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub ft_eval1: G::ScalarField,

    /// The public input
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub public: Vec<G::ScalarField>,

    /// The challenges underlying the optional polynomials folded into the proof
    pub prev_challenges: Vec<RecursionChallenge<G>>,
    pub _sponge: PhantomData<S>,
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
}

impl<F: Zero> ProofEvaluations<F> {
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

impl<F: FftField> ProofEvaluations<Vec<F>> {
    pub fn combine(&self, pt: F) -> ProofEvaluations<F> {
        ProofEvaluations::<F> {
            s: array_init(|i| DensePolynomial::eval_polynomial(&self.s[i], pt)),
            w: array_init(|i| DensePolynomial::eval_polynomial(&self.w[i], pt)),
            z: DensePolynomial::eval_polynomial(&self.z, pt),
            lookup: self.lookup.as_ref().map(|l| LookupEvaluations {
                table: DensePolynomial::eval_polynomial(&l.table, pt),
                aggreg: DensePolynomial::eval_polynomial(&l.aggreg, pt),
                sorted: l
                    .sorted
                    .iter()
                    .map(|x| DensePolynomial::eval_polynomial(x, pt))
                    .collect(),
                runtime: l
                    .runtime
                    .as_ref()
                    .map(|rt| DensePolynomial::eval_polynomial(rt, pt)),
            }),
            generic_selector: DensePolynomial::eval_polynomial(&self.generic_selector, pt),
            poseidon_selector: DensePolynomial::eval_polynomial(&self.poseidon_selector, pt),
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

    impl<F, CamlF> From<LookupEvaluations<Vec<F>>> for CamlLookupEvaluations<CamlF>
    where
        F: Clone,
        CamlF: From<F>,
    {
        fn from(le: LookupEvaluations<Vec<F>>) -> Self {
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

    impl<F, CamlF> From<CamlLookupEvaluations<CamlF>> for LookupEvaluations<Vec<F>>
    where
        F: From<CamlF> + Clone,
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

        pub lookup: Option<CamlLookupEvaluations<CamlF>>,
    }

    //
    // ProofEvaluations<Vec<F>> <-> CamlProofEvaluations<CamlF>
    //

    impl<F, CamlF> From<ProofEvaluations<Vec<F>>> for CamlProofEvaluations<CamlF>
    where
        F: Clone,
        CamlF: From<F>,
    {
        fn from(pe: ProofEvaluations<Vec<F>>) -> Self {
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
                lookup: pe.lookup.map(Into::into),
            }
        }
    }

    impl<F, CamlF> From<CamlProofEvaluations<CamlF>> for ProofEvaluations<Vec<F>>
    where
        F: Clone,
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
                generic_selector: cpe.generic_selector.into_iter().map(Into::into).collect(),
                poseidon_selector: cpe.poseidon_selector.into_iter().map(Into::into).collect(),
                lookup: cpe.lookup.map(Into::into),
            }
        }
    }
}
