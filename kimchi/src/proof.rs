//! This module implements the data structures of a proof.

use crate::circuits::{
    expr::Column,
    gate::GateType,
    wires::{COLUMNS, PERMUTS},
};
use ark_ec::AffineCurve;
use ark_ff::{FftField, One, Zero};
use ark_poly::univariate::DensePolynomial;
use commitment_dlog::{
    commitment::{b_poly, b_poly_coefficients, PolyComm},
    evaluation_proof::OpeningProof,
};
use o1_utils::ExtendedDensePolynomial;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::array;

//~ spec:startcode
/// Evaluations of a polynomial at 2 points
#[serde_as]
#[derive(Copy, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)
)]
#[serde(bound(
    serialize = "Vec<o1_utils::serialization::SerdeAs>: serde_with::SerializeAs<Evals>",
    deserialize = "Vec<o1_utils::serialization::SerdeAs>: serde_with::DeserializeAs<'de, Evals>"
))]
pub struct PointEvaluations<Evals> {
    /// Evaluation at the challenge point zeta.
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub zeta: Evals,
    /// Evaluation at `zeta . omega`, the product of the challenge point and the group generator.
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub zeta_omega: Evals,
}

/// Evaluations of lookup polynomials
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct LookupEvaluations<Eval> {
    /// sorted lookup table polynomial
    pub sorted: Vec<Eval>,
    /// lookup aggregation polynomial
    pub aggreg: Eval,
    // TODO: May be possible to optimize this away?
    /// lookup table polynomial
    pub table: Eval,

    /// Optionally, a runtime table polynomial.
    pub runtime: Option<Eval>,
}

// TODO: this should really be vectors here, perhaps create another type for chunked evaluations?
/// Polynomial evaluations contained in a `ProverProof`.
/// - **Chunked evaluations** `Field` is instantiated with vectors with a length that equals the length of the chunk
/// - **Non chunked evaluations** `Field` is instantiated with a field, so they are single-sized#[serde_as]
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct ProofEvaluations<Eval> {
    /// witness polynomials
    pub w: [Eval; COLUMNS],
    /// permutation polynomial
    pub z: Eval,
    /// permutation polynomials
    /// (PERMUTS-1 evaluations because the last permutation is only used in commitment form)
    pub s: [Eval; PERMUTS - 1],
    /// lookup-related evaluations
    pub lookup: Option<LookupEvaluations<Eval>>,
    /// evaluation of the generic selector polynomial
    pub generic_selector: Eval,
    /// evaluation of the poseidon selector polynomial
    pub poseidon_selector: Eval,
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
pub struct ProverProof<G: AffineCurve> {
    /// All the polynomial commitments required in the proof
    pub commitments: ProverCommitments<G>,

    /// batched commitment opening proof
    pub proof: OpeningProof<G>,

    /// Two evaluations over a number of committed polynomials
    pub evals: ProofEvaluations<PointEvaluations<Vec<G::ScalarField>>>,

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

impl<Evals> PointEvaluations<Evals> {
    pub fn map<Evals2, FN: Fn(Evals) -> Evals2>(self, f: &FN) -> PointEvaluations<Evals2> {
        let PointEvaluations { zeta, zeta_omega } = self;
        PointEvaluations {
            zeta: f(zeta),
            zeta_omega: f(zeta_omega),
        }
    }

    pub fn map_ref<Evals2, FN: Fn(&Evals) -> Evals2>(&self, f: &FN) -> PointEvaluations<Evals2> {
        let PointEvaluations { zeta, zeta_omega } = self;
        PointEvaluations {
            zeta: f(zeta),
            zeta_omega: f(zeta_omega),
        }
    }
}

impl<Eval> LookupEvaluations<Eval> {
    pub fn map<Eval2, FN: Fn(Eval) -> Eval2>(self, f: &FN) -> LookupEvaluations<Eval2> {
        let LookupEvaluations {
            sorted,
            aggreg,
            table,
            runtime,
        } = self;
        LookupEvaluations {
            sorted: sorted.into_iter().map(f).collect(),
            aggreg: f(aggreg),
            table: f(table),
            runtime: runtime.map(f),
        }
    }

    pub fn map_ref<Eval2, FN: Fn(&Eval) -> Eval2>(&self, f: &FN) -> LookupEvaluations<Eval2> {
        let LookupEvaluations {
            sorted,
            aggreg,
            table,
            runtime,
        } = self;
        LookupEvaluations {
            sorted: sorted.iter().map(f).collect(),
            aggreg: f(aggreg),
            table: f(table),
            runtime: runtime.as_ref().map(f),
        }
    }
}

impl<Eval> ProofEvaluations<Eval> {
    pub fn map<Eval2, FN: Fn(Eval) -> Eval2>(self, f: &FN) -> ProofEvaluations<Eval2> {
        let ProofEvaluations {
            w,
            z,
            s,
            lookup,
            generic_selector,
            poseidon_selector,
        } = self;
        ProofEvaluations {
            w: w.map(f),
            z: f(z),
            s: s.map(f),
            lookup: lookup.map(|x| LookupEvaluations::map(x, f)),
            generic_selector: f(generic_selector),
            poseidon_selector: f(poseidon_selector),
        }
    }

    pub fn map_ref<Eval2, FN: Fn(&Eval) -> Eval2>(&self, f: &FN) -> ProofEvaluations<Eval2> {
        let ProofEvaluations {
            w: [w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14],
            z,
            s: [s0, s1, s2, s3, s4, s5],
            lookup,
            generic_selector,
            poseidon_selector,
        } = self;
        ProofEvaluations {
            w: [
                f(w0),
                f(w1),
                f(w2),
                f(w3),
                f(w4),
                f(w5),
                f(w6),
                f(w7),
                f(w8),
                f(w9),
                f(w10),
                f(w11),
                f(w12),
                f(w13),
                f(w14),
            ],
            z: f(z),
            s: [f(s0), f(s1), f(s2), f(s3), f(s4), f(s5)],
            lookup: lookup.as_ref().map(|l| l.map_ref(f)),
            generic_selector: f(generic_selector),
            poseidon_selector: f(poseidon_selector),
        }
    }
}

impl<F> ProofEvaluations<F> {
    /// Transpose the `ProofEvaluations`.
    ///
    /// # Panics
    ///
    /// Will panic if `ProofEvaluation` is None.
    pub fn transpose<const N: usize>(
        evals: [&ProofEvaluations<F>; N],
    ) -> ProofEvaluations<[&F; N]> {
        let has_lookup = evals.iter().all(|e| e.lookup.is_some());
        let has_runtime = has_lookup
            && evals
                .iter()
                .all(|e| e.lookup.as_ref().unwrap().runtime.is_some());

        ProofEvaluations {
            generic_selector: array::from_fn(|i| &evals[i].generic_selector),
            poseidon_selector: array::from_fn(|i| &evals[i].poseidon_selector),
            z: array::from_fn(|i| &evals[i].z),
            w: array::from_fn(|j| array::from_fn(|i| &evals[i].w[j])),
            s: array::from_fn(|j| array::from_fn(|i| &evals[i].s[j])),
            lookup: if has_lookup {
                let sorted_length = evals[0].lookup.as_ref().unwrap().sorted.len();
                Some(LookupEvaluations {
                    aggreg: array::from_fn(|i| &evals[i].lookup.as_ref().unwrap().aggreg),
                    table: array::from_fn(|i| &evals[i].lookup.as_ref().unwrap().table),
                    sorted: (0..sorted_length)
                        .map(|j| array::from_fn(|i| &evals[i].lookup.as_ref().unwrap().sorted[j]))
                        .collect(),
                    runtime: if has_runtime {
                        Some(array::from_fn(|i| {
                            evals[i].lookup.as_ref().unwrap().runtime.as_ref().unwrap()
                        }))
                    } else {
                        None
                    },
                })
            } else {
                None
            },
        }
    }
}

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

impl<F: Zero + Copy> ProofEvaluations<PointEvaluations<F>> {
    pub fn dummy_with_witness_evaluations(
        curr: [F; COLUMNS],
        next: [F; COLUMNS],
    ) -> ProofEvaluations<PointEvaluations<F>> {
        let pt = |curr, next| PointEvaluations {
            zeta: curr,
            zeta_omega: next,
        };
        ProofEvaluations {
            w: array::from_fn(|i| pt(curr[i], next[i])),
            z: pt(F::zero(), F::zero()),
            s: array::from_fn(|_| pt(F::zero(), F::zero())),
            lookup: None,
            generic_selector: pt(F::zero(), F::zero()),
            poseidon_selector: pt(F::zero(), F::zero()),
        }
    }
}

impl<F: FftField> ProofEvaluations<PointEvaluations<Vec<F>>> {
    pub fn combine(&self, pt: &PointEvaluations<F>) -> ProofEvaluations<PointEvaluations<F>> {
        self.map_ref(&|evals| PointEvaluations {
            zeta: DensePolynomial::eval_polynomial(&evals.zeta, pt.zeta),
            zeta_omega: DensePolynomial::eval_polynomial(&evals.zeta_omega, pt.zeta_omega),
        })
    }
}

impl<F> ProofEvaluations<F> {
    pub fn get_column<'a>(&'a self, col: Column) -> Option<&'a F> {
        match col {
            Column::Witness(i) => Some(&self.w[i]),
            Column::Z => Some(&self.z),
            Column::LookupSorted(i) => Some(&self.lookup.as_ref()?.sorted[i]),
            Column::LookupAggreg => Some(&self.lookup.as_ref()?.aggreg),
            Column::LookupTable => Some(&self.lookup.as_ref()?.table),
            Column::LookupKindIndex(_) => None,
            Column::LookupRuntimeSelector => None,
            Column::LookupRuntimeTable => Some(self.lookup.as_ref()?.runtime.as_ref()?),
            Column::Index(GateType::Generic) => Some(&self.generic_selector),
            Column::Index(GateType::Poseidon) => Some(&self.poseidon_selector),
            Column::Index(_) => None,
            Column::Coefficient(_) => None,
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
        pub sorted: Vec<PointEvaluations<Vec<CamlF>>>,
        pub aggreg: PointEvaluations<Vec<CamlF>>,
        pub table: PointEvaluations<Vec<CamlF>>,
        pub runtime: Option<PointEvaluations<Vec<CamlF>>>,
    }

    impl<F, CamlF> From<LookupEvaluations<PointEvaluations<Vec<F>>>> for CamlLookupEvaluations<CamlF>
    where
        F: Clone,
        CamlF: From<F>,
    {
        fn from(le: LookupEvaluations<PointEvaluations<Vec<F>>>) -> Self {
            Self {
                sorted: le
                    .sorted
                    .into_iter()
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect()))
                    .collect(),
                aggreg: le.aggreg.map(&|x| x.into_iter().map(Into::into).collect()),
                table: le.table.map(&|x| x.into_iter().map(Into::into).collect()),
                runtime: le
                    .runtime
                    .map(|r| r.map(&|r| r.into_iter().map(Into::into).collect())),
            }
        }
    }

    impl<F, CamlF> From<CamlLookupEvaluations<CamlF>> for LookupEvaluations<PointEvaluations<Vec<F>>>
    where
        F: From<CamlF> + Clone,
    {
        fn from(pe: CamlLookupEvaluations<CamlF>) -> Self {
            Self {
                sorted: pe
                    .sorted
                    .into_iter()
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect()))
                    .collect(),
                aggreg: pe.aggreg.map(&|x| x.into_iter().map(Into::into).collect()),
                table: pe.table.map(&|x| x.into_iter().map(Into::into).collect()),
                runtime: pe
                    .runtime
                    .map(|r| r.map(&|r| r.into_iter().map(Into::into).collect())),
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
            PointEvaluations<Vec<CamlF>>,
            PointEvaluations<Vec<CamlF>>,
            PointEvaluations<Vec<CamlF>>,
            PointEvaluations<Vec<CamlF>>,
            PointEvaluations<Vec<CamlF>>,
            PointEvaluations<Vec<CamlF>>,
            PointEvaluations<Vec<CamlF>>,
            PointEvaluations<Vec<CamlF>>,
            PointEvaluations<Vec<CamlF>>,
            PointEvaluations<Vec<CamlF>>,
            PointEvaluations<Vec<CamlF>>,
            PointEvaluations<Vec<CamlF>>,
            PointEvaluations<Vec<CamlF>>,
            PointEvaluations<Vec<CamlF>>,
            PointEvaluations<Vec<CamlF>>,
        ),
        pub z: PointEvaluations<Vec<CamlF>>,
        pub s: (
            PointEvaluations<Vec<CamlF>>,
            PointEvaluations<Vec<CamlF>>,
            PointEvaluations<Vec<CamlF>>,
            PointEvaluations<Vec<CamlF>>,
            PointEvaluations<Vec<CamlF>>,
            PointEvaluations<Vec<CamlF>>,
        ),
        pub generic_selector: PointEvaluations<Vec<CamlF>>,
        pub poseidon_selector: PointEvaluations<Vec<CamlF>>,

        pub lookup: Option<CamlLookupEvaluations<CamlF>>,
    }

    //
    // ProofEvaluations<Vec<F>> <-> CamlProofEvaluations<CamlF>
    //

    impl<F, CamlF> From<ProofEvaluations<PointEvaluations<Vec<F>>>> for CamlProofEvaluations<CamlF>
    where
        F: Clone,
        CamlF: From<F>,
    {
        fn from(pe: ProofEvaluations<PointEvaluations<Vec<F>>>) -> Self {
            let w = (
                pe.w[0]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.w[1]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.w[2]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.w[3]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.w[4]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.w[5]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.w[6]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.w[7]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.w[8]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.w[9]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.w[10]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.w[11]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.w[12]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.w[13]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.w[14]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
            );
            let s = (
                pe.s[0]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.s[1]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.s[2]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.s[3]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.s[4]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.s[5]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
            );

            Self {
                w,
                z: pe.z.map(&|x| x.into_iter().map(Into::into).collect()),
                s,
                generic_selector: pe
                    .generic_selector
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                poseidon_selector: pe
                    .poseidon_selector
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                lookup: pe.lookup.map(Into::into),
            }
        }
    }

    impl<F, CamlF> From<CamlProofEvaluations<CamlF>> for ProofEvaluations<PointEvaluations<Vec<F>>>
    where
        F: Clone,
        F: From<CamlF>,
    {
        fn from(cpe: CamlProofEvaluations<CamlF>) -> Self {
            let w = [
                cpe.w.0.map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.w.1.map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.w.2.map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.w.3.map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.w.4.map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.w.5.map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.w.6.map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.w.7.map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.w.8.map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.w.9.map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.w.10.map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.w.11.map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.w.12.map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.w.13.map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.w.14.map(&|x| x.into_iter().map(Into::into).collect()),
            ];
            let s = [
                cpe.s.0.map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.s.1.map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.s.2.map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.s.3.map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.s.4.map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.s.5.map(&|x| x.into_iter().map(Into::into).collect()),
            ];

            Self {
                w,
                z: cpe.z.map(&|x| x.into_iter().map(Into::into).collect()),
                s,
                generic_selector: cpe
                    .generic_selector
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                poseidon_selector: cpe
                    .poseidon_selector
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                lookup: cpe.lookup.map(Into::into),
            }
        }
    }
}
