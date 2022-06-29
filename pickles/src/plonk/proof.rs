use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

use std::iter;

use circuit_construction::{Cs, Var};

use super::{COLUMNS, PERMUTS};

use crate::plonk::types::{VarOpen, VarPolyComm};
use crate::transcript::{Absorb, Msg, VarSponge};

use kimchi::proof::ProverProof;

pub struct VarAccumulatorChallenges<F: FftField + PrimeField, const N: usize>(Vec<Var<F>>);

impl<F, const N: usize> Absorb<F> for VarAccumulatorChallenges<F, N>
where
    F: FftField + PrimeField,
{
    fn absorb<C: Cs<F>>(&self, cs: &mut C, sponge: &mut VarSponge<F>) {
        self.0.iter().map(|chal| sponge.absorb(cs, chal));
    }
}

impl<F, const N: usize> VarAccumulatorChallenges<F, N>
where
    F: FftField + PrimeField,
{
    /// PC_DL.SuccinctCheck, Step 8
    /// Evaluate the h(X) polynomial (defined by the challenges )
    ///
    /// h(X) = \prod_{i = 0}^{n} (1 + c_{n-i} X^{2^i})
    ///
    /// Evalute h(X) at x.
    pub fn eval_h<C: Cs<F>>(&self, cs: &mut C, x: Var<F>) -> VarOpen<F, 1> {
        assert_ne!(
            self.0.len(),
            0,
            "h is undefined for the empty challenge list"
        );

        let one = cs.constant(F::one());

        let mut xpow = one; // junk (value does not matter)
        let mut prod = one; // junk (value does not matter)

        // enumrate the challenges c in reverse order: c_{n - i}
        for (i, ci) in self.0.iter().rev().cloned().enumerate() {
            // compute X^{2^i}
            xpow = if i == 0 { x } else { cs.mul(xpow, xpow) };

            // compute 1 + ci * X^{2^i}
            let term = if i == 0 { ci } else { cs.mul(ci, xpow) };
            let term = cs.add(one, term);

            // multiply into running product
            prod = cs.mul(prod, term);
        }

        VarOpen { chunks: [prod] }
    }
}



/// Add constraints for evaluating a polynomial
///
/// coeffs are the coefficients from least significant to most significant
/// (e.g. starting with the constant term)
pub fn eval_polynomial<F: FftField + PrimeField, C: Cs<F>>(
    cs: &mut C,
    coeffs: &[Var<F>],
    x: Var<F>,
) -> Var<F> {
    // iterate over coefficients:
    // most-to-least significant
    let mut chk = coeffs.iter().rev().cloned();

    // the initial sum is the most significant term
    let mut sum = chk.next().expect("zero chunks in poly.");

    // shift by pt and add next chunk
    for c in chk {
        sum = cs.mul(sum, x.clone());
        sum = cs.add(sum, c);
    }

    sum
}

//~ spec:startcode
#[derive(Clone)]
pub struct LookupEvaluations<Field> {
    /// sorted lookup table polynomial
    pub sorted: Vec<Field>,
    /// lookup aggregation polynomial
    pub aggreg: Field,
    // TODO: May be possible to optimize this away?
    /// lookup table polynomial
    pub table: Field,
}

/// Note: the number of chunks is always 1 for the polynomials covered below.
pub struct VarEvaluation<F: FftField + PrimeField> {
    /// witness polynomials
    pub w: [VarOpen<F, 1>; COLUMNS],

    /// permutation polynomial
    pub z: VarOpen<F, 1>,

    /// permutation polynomials
    /// (PERMUTS-1 evaluations because the last permutation is only used in commitment form)
    pub s: [VarOpen<F, 1>; PERMUTS - 1],

    /// lookup-related evaluations
    // pub lookup: Option<LookupEvaluations<F>>,

    /// evaluation of the generic selector polynomial
    pub generic_selector: VarOpen<F, 1>,

    /// evaluation of the poseidon selector polynomial
    pub poseidon_selector: VarOpen<F, 1>,
}

impl<F: FftField + PrimeField> VarEvaluation<F> {
    /// Iterate over the evaluations in the order used by both:
    /// - The combined inner product
    /// - When absorbing the evaluations in the transcript.
    pub fn iter(&self) -> impl Iterator<Item = &VarOpen<F, 1>> {
        iter::empty()
            .chain(iter::once(&self.z))
            .chain(iter::once(&self.generic_selector))
            .chain(iter::once(&self.poseidon_selector))
            .chain(self.w.iter())
            .chain(self.s.iter())
    }
}

impl<F: FftField + PrimeField> Absorb<F> for VarEvaluation<F> {
    fn absorb<C: Cs<F>>(&self, cs: &mut C, sponge: &mut VarSponge<F>) {
        self.iter().for_each(|p| sponge.absorb(cs, p));
    }
}

pub struct VarEvaluations<F: FftField + PrimeField> {
    pub zeta: VarEvaluation<F>,
    pub zetaw: VarEvaluation<F>,
}

/// All the commitments included in a PlonK/Kimchi proof.
///
/// D: the max degree of any row constraint.
pub struct VarCommitments<A>
where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
    /// The commitments to the witness (execution trace)
    /// (always 1 chunk)
    pub w_comm: Msg<[VarPolyComm<A, 1>; COLUMNS]>,

    /// The commitment to the permutation polynomial
    /// (always 1 chunk)
    pub z_comm: Msg<VarPolyComm<A, 1>>,

    /// The commitment to the quotient polynomial
    /// (is the max degree of any row constraint; 3 for vanilla PlonK)
    pub t_comm: Msg<VarPolyComm<A, PERMUTS>>,
}

pub struct VarAccumulators<G, const B: usize, const N: usize>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    // all the challenges
    pub chal: Msg<[VarAccumulatorChallenges<G::ScalarField, N>; B]>,

    // all the commitments (1 chunk each)
    pub comm: Msg<[VarPolyComm<G, 1>; N]>,
}

pub struct ProofEvaluations<F: FftField + PrimeField> {
    pub zeta: Msg<VarEvaluation<F>>,  // evaluation at \zeta
    pub zetaw: Msg<VarEvaluation<F>>, // evaluation at \zeta * \omega (2^k root of unity, next step)
}


/// WARNING: Make sure this only contains Msg types
/// (or structs of Msg types)
pub struct VarProof<G, const B: usize>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    pub commitments: VarCommitments<G>,
    pub ft_eval1: Msg<VarOpen<G::ScalarField, 1>>, // THIS MUST BE INCLUDED IN PUBLIC INPUT!
    pub evals: ProofEvaluations<G::ScalarField>,
    pub prev_challenges: VarAccumulators<G, B, 16>, // maybe change the name of this field?
}

impl<G, const B: usize> VarProof<G, B>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    pub fn new(witness: Option<ProverProof<G>>) -> Self {
        unimplemented!()
    }
}
