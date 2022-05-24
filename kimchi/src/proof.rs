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

#[serde_as]
#[derive(Clone, Deserialize, Serialize)]
pub enum EvalEnum<F: CanonicalSerialize + CanonicalDeserialize> {
    #[serde(bound = "ChunkEvals<F>: Serialize")]
    Chunk(ChunkEvals<F>),
    #[serde(bound = "OneEval<F>: Serialize")]
    One(OneEval<F>),
}

#[serde_as]
#[derive(Clone, Deserialize, Serialize)]
pub struct ChunkEvals<F: CanonicalSerialize + CanonicalDeserialize> {
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    chunk: Vec<F>,
}

#[serde_as]
#[derive(Clone, Deserialize, Serialize)]
pub struct OneEval<F: CanonicalSerialize + CanonicalDeserialize> {
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    chunk: F,
}

impl<F: Field> EvalEnum<F> {}

#[test]
fn my_test() {
    use ark_ff::One;
    use mina_curves::pasta::fp::Fp as F;

    let chunk = ChunkEvals {
        chunk: vec![-F::one(), F::zero(), F::one(), F::one().double()],
    };
    let eval = EvalEnum::Chunk(chunk);

    let ser_eval = rmp_serde::to_vec(&eval).unwrap();
    println!("eval size: {}", ser_eval.len());
    println!("eval: {:?}", ser_eval);

    //let elem: ark_ff::Fp256<mina_curves::pasta::fp::FpParameters>;
    //let ser_eval = rmp_serde::to_vec(&elem).unwrap();
    //println!("eval: {:?}", ser_eval);
}

//#[derive(Serialize, Deserialize)]
//#[serde(remote="AffineCurve")]
/*struct SF(ScalarField);

impl Serialize for SF {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
    }
}*/

//~ spec:startcode
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
}

// TODO: this should really be vectors here, perhaps create another type for chunked evaluations?
#[serde_as]
#[derive(Clone, Deserialize, Serialize)]
pub struct ProofEvaluations<F: CanonicalSerialize + CanonicalDeserialize> {
    /// witness polynomials
    #[serde_as(as = "[Vec<o1_utils::serialization::SerdeAs>; COLUMNS]")]
    pub w: [Vec<F>; COLUMNS],
    /// permutation polynomial
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
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub sorted: Vec<PolyComm<G>>,
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub aggreg: PolyComm<G>,
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
    //#[serde_as(as = "o1_utils::serialization::SerdeAs")]
    //#[serde(serialize_with = "o1_utils::serialization::ser::serialize")]
    //#[serde(with = "o1_utils::serialization::ser")]
    //#[serde(bound = "ScalarField<G>: CanonicalSerialize")]
    #[serde(bound = "ScalarField<G>: Serialize + DeserializeOwned")]
    pub ft_eval1: ScalarField<G>,

    /// The public input
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub public: Vec<ScalarField<G>>,

    /// The challenges underlying the optional polynomials folded into the proof
    #[serde(bound = "Vec<(Vec<ScalarField<G>>, PolyComm<G>)>: Serialize + DeserializeOwned")]
    pub prev_challenges: Vec<(Vec<ScalarField<G>>, PolyComm<G>)>,
}
//~ spec:endcode

impl<F: Field> LookupEvaluations<F> {
    pub fn new(sorted: Vec<F>, aggreg: F, table: F) -> LookupEvaluations<F> {
        LookupEvaluations {
            sorted: sorted.iter().map(|&s| vec![s]).collect::<Vec<_>>(),
            aggreg: vec![aggreg],
            table: vec![table],
        }
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
    //pub fn is_chunk(&self) -> bool {
    //    if
    //}

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

    //
    // CamlLookupEvaluations<CamlF>
    //

    #[derive(Clone, ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlLookupEvaluations<CamlF> {
        pub sorted: Vec<Vec<CamlF>>,
        pub aggreg: Vec<CamlF>,
        pub table: Vec<CamlF>,
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
                lookup: None,
                generic_selector: cpe.generic_selector.into_iter().map(Into::into).collect(),
                poseidon_selector: cpe.poseidon_selector.into_iter().map(Into::into).collect(),
            }
        }
    }
}
