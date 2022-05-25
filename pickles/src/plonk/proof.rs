use ark_ec::AffineCurve;
use ark_ff::{FftField, FpParameters, PrimeField};

use std::iter;

use std::marker::PhantomData;

use circuit_construction::{Cs, Var};

use super::{Proof, CHALLENGE_LEN, COLUMNS, PERMUTS, SELECTORS};

use crate::context::{Context, Passable};
use crate::transcript::{Absorb, Challenge, Msg, VarSponge};

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


pub struct VarIndex<A>
where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
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

pub struct VarCommitments<A>
where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
    /// The commitments to the witness (execution trace)
    /// (1 chunk)
    pub w_comm: Msg<[VarPolyComm<A, 1>; COLUMNS]>,

    /// The commitment to the permutation polynomial
    /// (1 chunk)
    pub z_comm: Msg<VarPolyComm<A, 1>>,

    /// The commitment to the quotient polynomial
    /// (3 chunks; see PlonK paper for details)
    pub t_comm: Msg<VarPolyComm<A, 3>>,
}

/// A opening of a chunked polynomial
///
/// The least significant chunk is first.
pub struct VarOpen<F: FftField + PrimeField, const C: usize> {
    chunks: [Var<F>; C],
}

impl<F: FftField + PrimeField, const N: usize> VarOpen<F, N> {
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
struct VarEvaluation<F: FftField + PrimeField> {
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

// DISCUSS: I would really like to #[derieve(Absorb)] this,
// but it means settling on an order which is the same as in the struct!
impl<F: FftField + PrimeField> Absorb<F> for VarEvaluation<F> {
    fn absorb<C: Cs<F>>(&self, cs: &mut C, sponge: &mut VarSponge<F>) {
        // concatenate
        let points = iter::empty()
            .chain(iter::once(&self.z))
            .chain(iter::once(&self.generic_selector))
            .chain(iter::once(&self.poseidon_selector))
            .chain(self.w.iter())
            .chain(self.s.iter());

        // absorb in order
        points.for_each(|p| sponge.absorb(cs, p));
    }
}

struct VarEvaluations<F: FftField + PrimeField> {
    z: VarEvaluation<F>,  // evaluation at z
    zw: VarEvaluation<F>, // evaluation at z * \omega (2^k root of unity, next step)
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
    pub ft_eval1: Msg<Var<A::ScalarField>>,
    pub evals: Msg<VarEvaluations<A::ScalarField>>,
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

pub struct ScalarChallenge<F: FftField + PrimeField> {
    challenge: Var<F>,
}

impl<F: FftField + PrimeField> Passable<F> for ScalarChallenge<F> {
    const SIZE: usize = CHALLENGE_LEN;
}

impl<F: FftField + PrimeField> Passable<F> for Var<F> {
    const SIZE: usize = F::Params::MODULUS_BITS as usize;
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
