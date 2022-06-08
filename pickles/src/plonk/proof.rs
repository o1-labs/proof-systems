use ark_ec::AffineCurve;
use ark_ff::{FftField, FpParameters, PrimeField};

use std::iter;

use std::marker::PhantomData;

use circuit_construction::{Cs, Var};

use super::{Proof, CHALLENGE_LEN, COLUMNS, PERMUTS, SELECTORS};

use crate::context::{Bounded, Context};
use crate::transcript::{Absorb, Challenge, Msg, VarSponge};

pub struct VarIPAChallenges<F: FftField + PrimeField> {
    c: Vec<Var<F>>
}

impl <F> VarIPAChallenges<F> where F: FftField + PrimeField {
    /// PC_DL.SuccinctCheck, Step 8
    /// Evaluate the h(X) polynomial (defined by the challenges )
    /// 
    /// h(X) = \prod_{i = 0}^{n} (1 + c_{n-i} X^{2^i})
    /// 
    /// Evalute h(X) at x.
    pub fn eval_h<C: Cs<F>>(&self, cs: &mut C, x: Var<F>) -> VarOpen<F, 1> {    
        assert_ne!(self.c.len(), 0, "h is undefined for the empty challenge list");

        let one = cs.constant(F::one());

        let mut xpow = one; // junk (value does not matter)
        let mut prod = one; // junk (value does not matter)

        // enumrate the challenges c in reverse order: c_{n - i}
        for (i, ci) in self.c.iter().rev().cloned().enumerate() {

            // compute X^{2^i}
            xpow = if i == 0 { x } else { cs.mul(xpow, xpow)};

            // compute 1 + ci * X^{2^i} 
            let term = cs.add(one, if i == 0 { ci } else { cs.mul(ci, xpow) });

            // multiply into running product
            prod = cs.mul(prod, term);
        }

        VarOpen{ chunks: [prod] }
    }
}

pub struct VarPoint<A>
where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
    _ph: PhantomData<A>,
    x: Var<A::BaseField>,
    y: Var<A::BaseField>,
}

impl<A> Absorb<A::BaseField> for VarPoint<A>
where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
    fn absorb<C: Cs<A::BaseField>>(&self, cs: &mut C, sponge: &mut VarSponge<A::BaseField>) {
        sponge.absorb(cs, &self.x);
        sponge.absorb(cs, &self.y);
    }
}

/// A commitment to a polynomial
/// with a given number of chunks
pub struct VarPolyComm<A, const N: usize>
where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
    chunks: [VarPoint<A>; N],
}

pub struct Domain<A>
where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
    pub group_gen: Var<A::ScalarField>, // change
}

pub struct VarIndex<A>
where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
    pub domain: Domain<A>,
    pub max_poly_size: usize,

    _ph: PhantomData<A>,
    pub q: [VarPolyComm<A, 1>; SELECTORS], // commits to selector polynomials
}

impl<A, const N: usize> Absorb<A::BaseField> for VarPolyComm<A, N>
where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
    fn absorb<C: Cs<A::BaseField>>(&self, cs: &mut C, sponge: &mut VarSponge<A::BaseField>) {
        sponge.absorb(cs, &self.chunks);
    }
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

/// The evaluation of a (possibly chunked) polynomial.
/// The least significant chunk is first.
#[derive(Clone)]
pub struct VarOpen<F: FftField + PrimeField, const C: usize> {
    pub(super) chunks: [Var<F>; C],
}

// For exactly one chunk, we can use a polynomial opening as a variable
impl <F> AsRef<Var<F>> for VarOpen<F, 1> where F: FftField + PrimeField {
    fn as_ref(&self) -> &Var<F> {
        &self.chunks[1]
    }
}

// In general a polynomial opening is a slice of variables
impl<F: FftField + PrimeField, const C: usize> AsRef<[Var<F>]> for VarOpen<F, C> {
    fn as_ref(&self) -> &[Var<F>] {
        &self.chunks
    }
}

impl <F> Into<VarOpen<F, 1>> for Var<F> where F: FftField + PrimeField {
    fn into(self) -> VarOpen<F, 1> {
        VarOpen {
            chunks: [self]
        }
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

impl<F: FftField + PrimeField, const N: usize> VarOpen<F, N> {
    /// Combines the evaluation chunks f_0(x), f_1(m), ..., f_m(x) to a single evaluation
    /// f(x) = f_0(x) + x^N f_1(x) + ... + x^{m N} f_m(x)
    ///
    /// pt is zeta^max_degree
    fn combine<C: Cs<F>>(&self, cs: &mut C, pt: Var<F>) -> Var<F> {
        // iterate over coefficients:
        // most-to-least significant
        let mut chk = self.chunks[..].iter().rev().cloned();

        // the initial sum is the most significant term
        let mut sum = chk.next().expect("zero chunks in poly.");

        // shift by pt and add next chunk
        for c in chk {
            sum = cs.mul(sum, pt.clone());
            sum = cs.add(sum, c);
        }

        sum
    }
}

impl<F: FftField + PrimeField, const N: usize> Absorb<F> for VarOpen<F, N> {
    fn absorb<C: Cs<F>>(&self, cs: &mut C, sponge: &mut VarSponge<F>) {
        sponge.absorb(cs, &self.chunks);
    }
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

///
///
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
    pub z: VarEvaluation<F>,  // evaluation at z
    pub zw: VarEvaluation<F>, // evaluation at z * \omega (2^k root of unity, next step)
}

impl<F: FftField + PrimeField> Absorb<F> for VarEvaluations<F> {
    fn absorb<C: Cs<F>>(&self, cs: &mut C, sponge: &mut VarSponge<F>) {
        sponge.absorb(cs, &self.z);
        sponge.absorb(cs, &self.zw);
    }
}

///
///
/// WARNING: Make sure this only contains Msg types
/// (or structs of Msg types)
pub struct VarProof<A>
where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
    _ph: PhantomData<A>,
    pub commitments: VarCommitments<A>,
    pub ft_eval1: Msg<VarOpen<A::ScalarField, 1>>, // THIS MUST BE INCLUDED IN PUBLIC INPUT!
    pub evals: Msg<VarEvaluations<A::ScalarField>>,
    pub prev_challenges: VarIPAChallenges<A::ScalarField>,
    
}

impl<A> VarProof<A>
where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
    pub fn new(witness: Option<Proof<A>>) -> Self {
        unimplemented!()
    }
}

/// A collection of CHALLENGE_LEN bits
/// (represented over the given field)
pub struct ScalarChallenge<F: FftField + PrimeField> {
    challenge: Var<F>,
}

impl<F: FftField + PrimeField> From<Var<F>> for ScalarChallenge<F> {
    fn from(v: Var<F>) -> Self {
        Self { challenge: v }
    }
}

impl<F: FftField + PrimeField> Bounded<F> for ScalarChallenge<F> {
    const SIZE: usize = CHALLENGE_LEN;
}

impl<F: FftField + PrimeField> From<(Var<F>, Option<Var<F>>)> for ScalarChallenge<F> {
    fn from(t: (Var<F>, Option<Var<F>>)) -> Self {
        assert!(t.1.is_none());
        Self { challenge: t.0 }
    }
}

impl<F: FftField + PrimeField> Into<Var<F>> for ScalarChallenge<F> {
    fn into(self) -> Var<F> {
        self.challenge
    }
}

impl<F: FftField + PrimeField> Challenge<F> for ScalarChallenge<F> {
    fn generate<C: Cs<F>>(cs: &mut C, sponge: &mut VarSponge<F>) -> Self {
        // generate challenge using sponge
        let scalar: Var<F> = Var::generate(cs, sponge);

        // create endoscalar (bit decompose)
        let challenge = cs.endo_scalar(CHALLENGE_LEN, || {
            let s: F = scalar.val();
            s.into_repr()
        });

        // enforce equality
        cs.assert_eq(challenge, scalar);

        // bit decompose challenge
        ScalarChallenge { challenge }
    }
}

impl<Fp: FftField + PrimeField> ScalarChallenge<Fp> {
    pub fn to_field<Fr, CsFp, CsFr>(&self, ctx: &mut Context<Fp, Fr, CsFp, CsFr>) -> Var<Fp>
    where
        Fp: FftField + PrimeField,
        Fr: FftField + PrimeField,
        CsFp: Cs<Fp>,
        CsFr: Cs<Fr>,
    {
        unimplemented!()
    }
}
