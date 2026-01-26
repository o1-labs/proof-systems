//! This module implements the data structures of a proof.

use crate::circuits::{
    berkeley_columns::Column,
    gate::GateType,
    lookup::lookups::LookupPattern,
    wires::{COLUMNS, PERMUTS},
};
use ark_ec::AffineRepr;
use ark_ff::{FftField, One, Zero};
use ark_poly::univariate::DensePolynomial;
use core::array;
use o1_utils::ExtendedDensePolynomial;
use poly_commitment::{
    commitment::{b_poly, b_poly_coefficients, CommitmentCurve, PolyComm},
    OpenProof,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

//~ spec:startcode
/// Evaluations of a polynomial at 2 points
#[serde_as]
#[derive(Copy, Clone, Serialize, Deserialize, Default, Debug, PartialEq)]
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

// TODO: this should really be vectors here, perhaps create another type for chunked evaluations?
/// Polynomial evaluations contained in a `ProverProof`.
/// - **Chunked evaluations** `Field` is instantiated with vectors with a length
/// that equals the length of the chunk
/// - **Non chunked evaluations** `Field` is instantiated with a field, so they
/// are single-sized#[serde_as]
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProofEvaluations<Evals> {
    /// public input polynomials
    pub public: Option<Evals>,
    /// witness polynomials
    pub w: [Evals; COLUMNS],
    /// permutation polynomial
    pub z: Evals,
    /// permutation polynomials
    /// (PERMUTS-1 evaluations because the last permutation is only used in
    /// commitment form)
    pub s: [Evals; PERMUTS - 1],
    /// coefficient polynomials
    pub coefficients: [Evals; COLUMNS],
    /// evaluation of the generic selector polynomial
    pub generic_selector: Evals,
    /// evaluation of the poseidon selector polynomial
    pub poseidon_selector: Evals,
    /// evaluation of the elliptic curve addition selector polynomial
    pub complete_add_selector: Evals,
    /// evaluation of the elliptic curve variable base scalar multiplication
    /// selector polynomial
    pub mul_selector: Evals,
    /// evaluation of the endoscalar multiplication selector polynomial
    pub emul_selector: Evals,
    /// evaluation of the endoscalar multiplication scalar computation selector
    /// polynomial
    pub endomul_scalar_selector: Evals,

    // Optional gates
    /// evaluation of the RangeCheck0 selector polynomial
    pub range_check0_selector: Option<Evals>,
    /// evaluation of the RangeCheck1 selector polynomial
    pub range_check1_selector: Option<Evals>,
    /// evaluation of the ForeignFieldAdd selector polynomial
    pub foreign_field_add_selector: Option<Evals>,
    /// evaluation of the ForeignFieldMul selector polynomial
    pub foreign_field_mul_selector: Option<Evals>,
    /// evaluation of the Xor selector polynomial
    pub xor_selector: Option<Evals>,
    /// evaluation of the Rot selector polynomial
    pub rot_selector: Option<Evals>,

    // lookup-related evaluations
    /// evaluation of lookup aggregation polynomial
    pub lookup_aggregation: Option<Evals>,
    /// evaluation of lookup table polynomial
    pub lookup_table: Option<Evals>,
    /// evaluation of lookup sorted polynomials
    pub lookup_sorted: [Option<Evals>; 5],
    /// evaluation of runtime lookup table polynomial
    pub runtime_lookup_table: Option<Evals>,

    // lookup selectors
    /// evaluation of the runtime lookup table selector polynomial
    pub runtime_lookup_table_selector: Option<Evals>,
    /// evaluation of the Xor range check pattern selector polynomial
    pub xor_lookup_selector: Option<Evals>,
    /// evaluation of the Lookup range check pattern selector polynomial
    pub lookup_gate_lookup_selector: Option<Evals>,
    /// evaluation of the RangeCheck range check pattern selector polynomial
    pub range_check_lookup_selector: Option<Evals>,
    /// evaluation of the ForeignFieldMul range check pattern selector
    /// polynomial
    pub foreign_field_mul_lookup_selector: Option<Evals>,
}

/// Commitments linked to the lookup feature
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(bound = "G: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize")]
pub struct LookupCommitments<G: AffineRepr> {
    /// Commitments to the sorted lookup table polynomial (may have chunks)
    pub sorted: Vec<PolyComm<G>>,
    /// Commitment to the lookup aggregation polynomial
    pub aggreg: PolyComm<G>,
    /// Optional commitment to concatenated runtime tables
    pub runtime: Option<PolyComm<G>>,
}

/// All the commitments that the prover creates as part of the proof.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(bound = "G: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize")]
pub struct ProverCommitments<G: AffineRepr> {
    /// The commitments to the witness (execution trace)
    pub w_comm: [PolyComm<G>; COLUMNS],
    /// The commitment to the permutation polynomial
    pub z_comm: PolyComm<G>,
    /// The commitment to the quotient polynomial
    pub t_comm: PolyComm<G>,
    /// Commitments related to the lookup argument
    pub lookup: Option<LookupCommitments<G>>,
}

/// The proof that the prover creates from a
/// [ProverIndex](super::prover_index::ProverIndex) and a `witness`.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(bound = "G: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize")]
pub struct ProverProof<G, OpeningProof, const FULL_ROUNDS: usize>
where
    G: CommitmentCurve,
    OpeningProof: OpenProof<G, FULL_ROUNDS>,
{
    /// All the polynomial commitments required in the proof
    pub commitments: ProverCommitments<G>,

    /// batched commitment opening proof
    #[serde(bound(
        serialize = "OpeningProof: Serialize",
        deserialize = "OpeningProof: Deserialize<'de>"
    ))]
    pub proof: OpeningProof,

    /// Two evaluations over a number of committed polynomials
    pub evals: ProofEvaluations<PointEvaluations<Vec<G::ScalarField>>>,

    /// Required evaluation for [Maller's
    /// optimization](https://o1-labs.github.io/proof-systems/kimchi/maller_15.html#the-evaluation-of-l)
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub ft_eval1: G::ScalarField,

    /// Accumulators from previously verified proofs in the recursion chain.
    ///
    /// Each [`RecursionChallenge`] stores the IPA folding challenges and accumulated
    /// commitment from verifying a previous proof. Instead of checking the IPA
    /// immediately (which requires an expensive MSM `<s, G>` where `s` has `2^k`
    /// elements), we defer this check by storing the accumulator.
    ///
    /// During verification, these accumulators are processed as follows:
    /// 1. The commitments are absorbed into the Fiat-Shamir sponge
    /// 2. The challenges are used to compute evaluations of `b(X)` at `zeta` and
    ///    `zeta * omega` (see [`RecursionChallenge::evals`])
    /// 3. These evaluations are paired with the commitments and included in the
    ///    batched polynomial commitment check
    ///
    /// The actual MSM verification happens in [`SRS::verify`](poly_commitment::ipa::SRS::verify)
    /// (see `poly-commitment/src/ipa.rs`), where `b_poly_coefficients` computes
    /// the `2^k` coefficients and they are batched into a single large MSM with
    /// all other verification checks.
    ///
    /// This design enables efficient recursive proof composition as described in
    /// Section 3.2 of the [Halo paper](https://eprint.iacr.org/2019/1021.pdf).
    pub prev_challenges: Vec<RecursionChallenge<G>>,
}

/// Stores the accumulator from a previously verified IPA (Inner Product Argument).
///
/// In recursive proof composition, when we verify a proof, the IPA verification
/// produces an accumulator that can be "deferred" rather than checked immediately.
/// This accumulator consists of:
///
/// - **`chals`**: The folding challenges `u_1, ..., u_k` sampled during the
///   `k = log_2(n)` rounds of the IPA. These challenges define the
///   **challenge polynomial** (also called `b(X)` or `h(X)`):
///   ```text
///   b(X) = prod_{i=0}^{k-1} (1 + u_{k-i} * X^{2^i})
///   ```
///   This polynomial was introduced in Section 3.2 of the
///   [Halo paper](https://eprint.iacr.org/2019/1021.pdf) as a way to efficiently
///   represent the folded evaluation point.
///
/// - **`comm`**: The accumulated commitment `U = <h, G>` where `h` is the vector
///   of coefficients of `b(X)` and `G` is the commitment basis. This is the
///   "deferred" part of IPA verification.
///
/// The accumulator satisfies the relation `R_Acc`: anyone can verify it in `O(n)`
/// time by recomputing `<h, G>`.
///
/// See the [accumulation documentation](https://o1-labs.github.io/proof-systems/pickles/accumulation.html)
/// for a complete description of how these accumulators are used in Pickles.
#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(bound = "G: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize")]
pub struct RecursionChallenge<G>
where
    G: AffineRepr,
{
    /// The IPA folding challenges `[u_1, ..., u_k]` that define the challenge
    /// polynomial `b(X)`. See [`b_poly`](poly_commitment::commitment::b_poly).
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub chals: Vec<G::ScalarField>,
    /// The accumulated commitment from IPA verification.
    ///
    /// This commitment is used in two places:
    /// 1. Absorbed into the Fq-sponge for Fiat-Shamir (see `prover.rs` and
    ///    `verifier.rs` where commitments of previous challenges are absorbed).
    /// 2. Included in the batched polynomial commitment verification, paired
    ///    with evaluations of `b(X)` at `zeta` and `zeta * omega` (see
    ///    `verifier.rs` where `polys` is constructed from `prev_challenges`).
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

impl<Eval> ProofEvaluations<Eval> {
    pub fn map<Eval2, FN: Fn(Eval) -> Eval2>(self, f: &FN) -> ProofEvaluations<Eval2> {
        let ProofEvaluations {
            public,
            w,
            z,
            s,
            coefficients,
            generic_selector,
            poseidon_selector,
            complete_add_selector,
            mul_selector,
            emul_selector,
            endomul_scalar_selector,
            range_check0_selector,
            range_check1_selector,
            foreign_field_add_selector,
            foreign_field_mul_selector,
            xor_selector,
            rot_selector,
            lookup_aggregation,
            lookup_table,
            lookup_sorted,
            runtime_lookup_table,
            runtime_lookup_table_selector,
            xor_lookup_selector,
            lookup_gate_lookup_selector,
            range_check_lookup_selector,
            foreign_field_mul_lookup_selector,
        } = self;
        ProofEvaluations {
            public: public.map(f),
            w: w.map(f),
            z: f(z),
            s: s.map(f),
            coefficients: coefficients.map(f),
            generic_selector: f(generic_selector),
            poseidon_selector: f(poseidon_selector),
            complete_add_selector: f(complete_add_selector),
            mul_selector: f(mul_selector),
            emul_selector: f(emul_selector),
            endomul_scalar_selector: f(endomul_scalar_selector),
            range_check0_selector: range_check0_selector.map(f),
            range_check1_selector: range_check1_selector.map(f),
            foreign_field_add_selector: foreign_field_add_selector.map(f),
            foreign_field_mul_selector: foreign_field_mul_selector.map(f),
            xor_selector: xor_selector.map(f),
            rot_selector: rot_selector.map(f),
            lookup_aggregation: lookup_aggregation.map(f),
            lookup_table: lookup_table.map(f),
            lookup_sorted: lookup_sorted.map(|x| x.map(f)),
            runtime_lookup_table: runtime_lookup_table.map(f),
            runtime_lookup_table_selector: runtime_lookup_table_selector.map(f),
            xor_lookup_selector: xor_lookup_selector.map(f),
            lookup_gate_lookup_selector: lookup_gate_lookup_selector.map(f),
            range_check_lookup_selector: range_check_lookup_selector.map(f),
            foreign_field_mul_lookup_selector: foreign_field_mul_lookup_selector.map(f),
        }
    }

    pub fn map_ref<Eval2, FN: Fn(&Eval) -> Eval2>(&self, f: &FN) -> ProofEvaluations<Eval2> {
        let ProofEvaluations {
            public,
            w: [w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14],
            z,
            s: [s0, s1, s2, s3, s4, s5],
            coefficients: [c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14],
            generic_selector,
            poseidon_selector,
            complete_add_selector,
            mul_selector,
            emul_selector,
            endomul_scalar_selector,
            range_check0_selector,
            range_check1_selector,
            foreign_field_add_selector,
            foreign_field_mul_selector,
            xor_selector,
            rot_selector,
            lookup_aggregation,
            lookup_table,
            lookup_sorted,
            runtime_lookup_table,
            runtime_lookup_table_selector,
            xor_lookup_selector,
            lookup_gate_lookup_selector,
            range_check_lookup_selector,
            foreign_field_mul_lookup_selector,
        } = self;
        ProofEvaluations {
            public: public.as_ref().map(f),
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
            coefficients: [
                f(c0),
                f(c1),
                f(c2),
                f(c3),
                f(c4),
                f(c5),
                f(c6),
                f(c7),
                f(c8),
                f(c9),
                f(c10),
                f(c11),
                f(c12),
                f(c13),
                f(c14),
            ],
            generic_selector: f(generic_selector),
            poseidon_selector: f(poseidon_selector),
            complete_add_selector: f(complete_add_selector),
            mul_selector: f(mul_selector),
            emul_selector: f(emul_selector),
            endomul_scalar_selector: f(endomul_scalar_selector),
            range_check0_selector: range_check0_selector.as_ref().map(f),
            range_check1_selector: range_check1_selector.as_ref().map(f),
            foreign_field_add_selector: foreign_field_add_selector.as_ref().map(f),
            foreign_field_mul_selector: foreign_field_mul_selector.as_ref().map(f),
            xor_selector: xor_selector.as_ref().map(f),
            rot_selector: rot_selector.as_ref().map(f),
            lookup_aggregation: lookup_aggregation.as_ref().map(f),
            lookup_table: lookup_table.as_ref().map(f),
            lookup_sorted: array::from_fn(|i| lookup_sorted[i].as_ref().map(f)),
            runtime_lookup_table: runtime_lookup_table.as_ref().map(f),
            runtime_lookup_table_selector: runtime_lookup_table_selector.as_ref().map(f),
            xor_lookup_selector: xor_lookup_selector.as_ref().map(f),
            lookup_gate_lookup_selector: lookup_gate_lookup_selector.as_ref().map(f),
            range_check_lookup_selector: range_check_lookup_selector.as_ref().map(f),
            foreign_field_mul_lookup_selector: foreign_field_mul_lookup_selector.as_ref().map(f),
        }
    }
}

impl<G: AffineRepr> RecursionChallenge<G> {
    pub fn new(chals: Vec<G::ScalarField>, comm: PolyComm<G>) -> RecursionChallenge<G> {
        RecursionChallenge { chals, comm }
    }

    /// Computes evaluations of the challenge polynomial `b(X)` at the given points.
    ///
    /// The challenge polynomial is defined by the IPA challenges as:
    /// ```text
    /// b(X) = prod_{i=0}^{k-1} (1 + u_{k-i} * X^{2^i})
    /// ```
    /// where `u_1, ..., u_k` are the challenges sampled during the `k` rounds of
    /// the IPA protocol (stored in `self.chals`).
    ///
    /// This method evaluates `b(X)` at `evaluation_points` (typically `zeta` and
    /// `zeta * omega`). If the polynomial degree exceeds `max_poly_size`, the
    /// evaluations are "chunked" to handle polynomial splitting.
    ///
    /// These evaluations are paired with [`Self::comm`] and included in the
    /// batched polynomial commitment verification (see `verifier.rs`).
    ///
    /// The MSM has size `2^k` where `k` is the number of IPA rounds (e.g., `k = 15` for
    /// a domain of size `2^15`, giving an MSM of 32768 points). Computing this in-circuit
    /// would require EC scalar multiplication: using [`VarBaseMul`](crate::circuits::polynomials::varbasemul)
    /// costs 2 rows per 5 bits (~104 rows for a 256-bit scalar). For an MSM of 32768 points,
    /// the constraint count would be higher than the accepted circuit size. By deferring to
    /// the out-of-circuit verifier, we avoid this cost entirely.
    ///
    /// # Arguments
    /// * `max_poly_size` - Maximum polynomial size for chunking
    /// * `evaluation_points` - Points at which to evaluate (typically `[zeta, zeta * omega]`)
    /// * `powers_of_eval_points_for_chunks` - Powers used for recombining chunks
    ///
    /// # Returns
    /// A vector of evaluation vectors, one per evaluation point. Each inner vector
    /// contains the chunked evaluations (or a single evaluation if no chunking needed).
    ///
    /// # References
    /// - [Halo paper, Section 3.2](https://eprint.iacr.org/2019/1021.pdf)
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
            public: Some(pt(F::zero(), F::zero())),
            w: array::from_fn(|i| pt(curr[i], next[i])),
            z: pt(F::zero(), F::zero()),
            s: array::from_fn(|_| pt(F::zero(), F::zero())),
            coefficients: array::from_fn(|_| pt(F::zero(), F::zero())),
            generic_selector: pt(F::zero(), F::zero()),
            poseidon_selector: pt(F::zero(), F::zero()),
            complete_add_selector: pt(F::zero(), F::zero()),
            mul_selector: pt(F::zero(), F::zero()),
            emul_selector: pt(F::zero(), F::zero()),
            endomul_scalar_selector: pt(F::zero(), F::zero()),
            range_check0_selector: None,
            range_check1_selector: None,
            foreign_field_add_selector: None,
            foreign_field_mul_selector: None,
            xor_selector: None,
            rot_selector: None,
            lookup_aggregation: None,
            lookup_table: None,
            lookup_sorted: array::from_fn(|_| None),
            runtime_lookup_table: None,
            runtime_lookup_table_selector: None,
            xor_lookup_selector: None,
            lookup_gate_lookup_selector: None,
            range_check_lookup_selector: None,
            foreign_field_mul_lookup_selector: None,
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
    pub fn get_column(&self, col: Column) -> Option<&F> {
        match col {
            Column::Witness(i) => Some(&self.w[i]),
            Column::Z => Some(&self.z),
            Column::LookupSorted(i) => self.lookup_sorted[i].as_ref(),
            Column::LookupAggreg => self.lookup_aggregation.as_ref(),
            Column::LookupTable => self.lookup_table.as_ref(),
            Column::LookupKindIndex(LookupPattern::Xor) => self.xor_lookup_selector.as_ref(),
            Column::LookupKindIndex(LookupPattern::Lookup) => {
                self.lookup_gate_lookup_selector.as_ref()
            }
            Column::LookupKindIndex(LookupPattern::RangeCheck) => {
                self.range_check_lookup_selector.as_ref()
            }
            Column::LookupKindIndex(LookupPattern::ForeignFieldMul) => {
                self.foreign_field_mul_lookup_selector.as_ref()
            }
            Column::LookupRuntimeSelector => self.runtime_lookup_table_selector.as_ref(),
            Column::LookupRuntimeTable => self.runtime_lookup_table.as_ref(),
            Column::Index(GateType::Generic) => Some(&self.generic_selector),
            Column::Index(GateType::Poseidon) => Some(&self.poseidon_selector),
            Column::Index(GateType::CompleteAdd) => Some(&self.complete_add_selector),
            Column::Index(GateType::VarBaseMul) => Some(&self.mul_selector),
            Column::Index(GateType::EndoMul) => Some(&self.emul_selector),
            Column::Index(GateType::EndoMulScalar) => Some(&self.endomul_scalar_selector),
            Column::Index(GateType::RangeCheck0) => self.range_check0_selector.as_ref(),
            Column::Index(GateType::RangeCheck1) => self.range_check1_selector.as_ref(),
            Column::Index(GateType::ForeignFieldAdd) => self.foreign_field_add_selector.as_ref(),
            Column::Index(GateType::ForeignFieldMul) => self.foreign_field_mul_selector.as_ref(),
            Column::Index(GateType::Xor16) => self.xor_selector.as_ref(),
            Column::Index(GateType::Rot64) => self.rot_selector.as_ref(),
            Column::Index(_) => None,
            Column::Coefficient(i) => Some(&self.coefficients[i]),
            Column::Permutation(i) => Some(&self.s[i]),
        }
    }
}

//
// OCaml types
//

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use poly_commitment::commitment::caml::CamlPolyComm;

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
        G: AffineRepr,
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
        G: AffineRepr + From<CamlG>,
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
        pub coefficients: (
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

        pub generic_selector: PointEvaluations<Vec<CamlF>>,
        pub poseidon_selector: PointEvaluations<Vec<CamlF>>,
        pub complete_add_selector: PointEvaluations<Vec<CamlF>>,
        pub mul_selector: PointEvaluations<Vec<CamlF>>,
        pub emul_selector: PointEvaluations<Vec<CamlF>>,
        pub endomul_scalar_selector: PointEvaluations<Vec<CamlF>>,

        pub range_check0_selector: Option<PointEvaluations<Vec<CamlF>>>,
        pub range_check1_selector: Option<PointEvaluations<Vec<CamlF>>>,
        pub foreign_field_add_selector: Option<PointEvaluations<Vec<CamlF>>>,
        pub foreign_field_mul_selector: Option<PointEvaluations<Vec<CamlF>>>,
        pub xor_selector: Option<PointEvaluations<Vec<CamlF>>>,
        pub rot_selector: Option<PointEvaluations<Vec<CamlF>>>,
        pub lookup_aggregation: Option<PointEvaluations<Vec<CamlF>>>,
        pub lookup_table: Option<PointEvaluations<Vec<CamlF>>>,
        pub lookup_sorted: Vec<Option<PointEvaluations<Vec<CamlF>>>>,
        pub runtime_lookup_table: Option<PointEvaluations<Vec<CamlF>>>,

        pub runtime_lookup_table_selector: Option<PointEvaluations<Vec<CamlF>>>,
        pub xor_lookup_selector: Option<PointEvaluations<Vec<CamlF>>>,
        pub lookup_gate_lookup_selector: Option<PointEvaluations<Vec<CamlF>>>,
        pub range_check_lookup_selector: Option<PointEvaluations<Vec<CamlF>>>,
        pub foreign_field_mul_lookup_selector: Option<PointEvaluations<Vec<CamlF>>>,
    }

    //
    // ProofEvaluations<Vec<F>> <-> CamlProofEvaluations<CamlF>
    //

    impl<F, CamlF> From<ProofEvaluations<PointEvaluations<Vec<F>>>>
        for (
            Option<PointEvaluations<Vec<CamlF>>>,
            CamlProofEvaluations<CamlF>,
        )
    where
        F: Clone,
        CamlF: From<F>,
    {
        fn from(pe: ProofEvaluations<PointEvaluations<Vec<F>>>) -> Self {
            let first = pe.public.map(|x: PointEvaluations<Vec<F>>| {
                // map both fields of each evaluation.
                x.map(&|x: Vec<F>| {
                    let y: Vec<CamlF> = x.into_iter().map(Into::into).collect();
                    y
                })
            });
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
            let coefficients = (
                pe.coefficients[0]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.coefficients[1]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.coefficients[2]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.coefficients[3]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.coefficients[4]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.coefficients[5]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.coefficients[6]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.coefficients[7]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.coefficients[8]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.coefficients[9]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.coefficients[10]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.coefficients[11]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.coefficients[12]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.coefficients[13]
                    .clone()
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                pe.coefficients[14]
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

            let second = CamlProofEvaluations {
                w,
                coefficients,
                z: pe.z.map(&|x| x.into_iter().map(Into::into).collect()),
                s,
                generic_selector: pe
                    .generic_selector
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                poseidon_selector: pe
                    .poseidon_selector
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                complete_add_selector: pe
                    .complete_add_selector
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                mul_selector: pe
                    .mul_selector
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                emul_selector: pe
                    .emul_selector
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                endomul_scalar_selector: pe
                    .endomul_scalar_selector
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                range_check0_selector: pe
                    .range_check0_selector
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                range_check1_selector: pe
                    .range_check1_selector
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                foreign_field_add_selector: pe
                    .foreign_field_add_selector
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                foreign_field_mul_selector: pe
                    .foreign_field_mul_selector
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                xor_selector: pe
                    .xor_selector
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                rot_selector: pe
                    .rot_selector
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                lookup_aggregation: pe
                    .lookup_aggregation
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                lookup_table: pe
                    .lookup_table
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                lookup_sorted: pe
                    .lookup_sorted
                    .iter()
                    .map(|x| {
                        x.as_ref().map(|x| {
                            x.map_ref(&|x| x.clone().into_iter().map(Into::into).collect())
                        })
                    })
                    .collect::<Vec<_>>(),
                runtime_lookup_table: pe
                    .runtime_lookup_table
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                runtime_lookup_table_selector: pe
                    .runtime_lookup_table_selector
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                xor_lookup_selector: pe
                    .xor_lookup_selector
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                lookup_gate_lookup_selector: pe
                    .lookup_gate_lookup_selector
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                range_check_lookup_selector: pe
                    .range_check_lookup_selector
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                foreign_field_mul_lookup_selector: pe
                    .foreign_field_mul_lookup_selector
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
            };

            (first, second)
        }
    }

    impl<F, CamlF>
        From<(
            Option<PointEvaluations<Vec<CamlF>>>,
            CamlProofEvaluations<CamlF>,
        )> for ProofEvaluations<PointEvaluations<Vec<F>>>
    where
        F: Clone,
        CamlF: Clone,
        F: From<CamlF>,
    {
        fn from(
            (public, cpe): (
                Option<PointEvaluations<Vec<CamlF>>>,
                CamlProofEvaluations<CamlF>,
            ),
        ) -> Self {
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
            let coefficients = [
                cpe.coefficients
                    .0
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.coefficients
                    .1
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.coefficients
                    .2
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.coefficients
                    .3
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.coefficients
                    .4
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.coefficients
                    .5
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.coefficients
                    .6
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.coefficients
                    .7
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.coefficients
                    .8
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.coefficients
                    .9
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.coefficients
                    .10
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.coefficients
                    .11
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.coefficients
                    .12
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.coefficients
                    .13
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                cpe.coefficients
                    .14
                    .map(&|x| x.into_iter().map(Into::into).collect()),
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
                public: public.map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                w,
                coefficients,
                z: cpe.z.map(&|x| x.into_iter().map(Into::into).collect()),
                s,
                generic_selector: cpe
                    .generic_selector
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                poseidon_selector: cpe
                    .poseidon_selector
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                complete_add_selector: cpe
                    .complete_add_selector
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                mul_selector: cpe
                    .mul_selector
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                emul_selector: cpe
                    .emul_selector
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                endomul_scalar_selector: cpe
                    .endomul_scalar_selector
                    .map(&|x| x.into_iter().map(Into::into).collect()),
                range_check0_selector: cpe
                    .range_check0_selector
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                range_check1_selector: cpe
                    .range_check1_selector
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                foreign_field_add_selector: cpe
                    .foreign_field_add_selector
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                foreign_field_mul_selector: cpe
                    .foreign_field_mul_selector
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                xor_selector: cpe
                    .xor_selector
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                rot_selector: cpe
                    .rot_selector
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                lookup_aggregation: cpe
                    .lookup_aggregation
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                lookup_table: cpe
                    .lookup_table
                    .map(|x| x.map(&|x| x.into_iter().map(Into::into).collect())),
                lookup_sorted: {
                    assert_eq!(cpe.lookup_sorted.len(), 5); // Invalid proof
                    array::from_fn(|i| {
                        cpe.lookup_sorted[i]
                            .as_ref()
                            .map(|x| x.clone().map(&|x| x.into_iter().map(Into::into).collect()))
                    })
                },
                runtime_lookup_table: cpe
                    .runtime_lookup_table
                    .map(|x| x.map(&|x| x.iter().map(|x| x.clone().into()).collect())),
                runtime_lookup_table_selector: cpe
                    .runtime_lookup_table_selector
                    .map(|x| x.map(&|x| x.iter().map(|x| x.clone().into()).collect())),
                xor_lookup_selector: cpe
                    .xor_lookup_selector
                    .map(|x| x.map(&|x| x.iter().map(|x| x.clone().into()).collect())),
                lookup_gate_lookup_selector: cpe
                    .lookup_gate_lookup_selector
                    .map(|x| x.map(&|x| x.iter().map(|x| x.clone().into()).collect())),
                range_check_lookup_selector: cpe
                    .range_check_lookup_selector
                    .map(|x| x.map(&|x| x.iter().map(|x| x.clone().into()).collect())),
                foreign_field_mul_lookup_selector: cpe
                    .foreign_field_mul_lookup_selector
                    .map(|x| x.map(&|x| x.iter().map(|x| x.clone().into()).collect())),
            }
        }
    }
}
