use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

use ark_poly::Radix2EvaluationDomain as Domain;
use ark_poly::EvaluationDomain;

use circuit_construction::{Cs, Var, generic};

use std::marker::PhantomData;

use crate::context::{AsPublic, PassTo, Public};
use crate::transcript::{Absorb, Challenge, VarSponge};

use crate::plonk::CHALLENGE_LEN;
use crate::plonk::misc::var_sum;

pub struct VarPoint<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    _ph: PhantomData<G>,
    x: Var<G::BaseField>,
    y: Var<G::BaseField>,
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

impl<A, const N: usize> Absorb<A::BaseField> for VarPolyComm<A, N>
where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
    fn absorb<C: Cs<A::BaseField>>(&self, cs: &mut C, sponge: &mut VarSponge<A::BaseField>) {
        sponge.absorb(cs, &self.chunks);
    }
}

/// The evaluation of a (possibly chunked) polynomial.
/// The least significant chunk is first.
#[derive(Clone)]
pub struct VarOpen<F: FftField + PrimeField, const C: usize> {
    pub(super) chunks: [Var<F>; C],
}

// For exactly one chunk, we can use a polynomial opening as a variable
impl<F> AsRef<Var<F>> for VarOpen<F, 1>
where
    F: FftField + PrimeField,
{
    fn as_ref(&self) -> &Var<F> {
        &self.chunks[0]
    }
}

// In general a polynomial opening is a slice of variables
impl<F: FftField + PrimeField, const C: usize> AsRef<[Var<F>]> for VarOpen<F, C> {
    fn as_ref(&self) -> &[Var<F>] {
        &self.chunks
    }
}

impl<F> Into<VarOpen<F, 1>> for Var<F>
where
    F: FftField + PrimeField,
{
    fn into(self) -> VarOpen<F, 1> {
        VarOpen { chunks: [self] }
    }
}

impl<F> From<VarOpen<F, 1>> for Var<F>
where
    F: FftField + PrimeField,
{
    fn from(open: VarOpen<F, 1>) -> Var<F> {
        open.chunks[0]
    }
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

/// A collection of CHALLENGE_LEN bits
/// (represented over the given field)
pub struct ScalarChallenge<F: FftField + PrimeField> {
    challenge: Var<F>,
}

impl <F: FftField + PrimeField> AsPublic<F> for ScalarChallenge<F> where {
    fn public(&self) -> Vec<Public<F>> {
        unimplemented!()
    }
}

impl <Fp, Fr> PassTo<ScalarChallenge<Fr>, Fp, Fr> for ScalarChallenge<Fp>
    where 
          Fp: FftField + PrimeField,
          Fr: FftField + PrimeField

{
    fn convert<CsFp: Cs<Fp>, CsFr: Cs<Fr>>(self, csfp: &mut CsFp, csfr: &mut CsFr) -> ScalarChallenge<Fr> {
        unimplemented!()
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

impl<F: FftField + PrimeField> ScalarChallenge<F> {
    pub fn to_field<C: Cs<F>>(&self, cs: &mut C) -> Var<F> {
        unimplemented!()
    }
}

pub struct LagrangePoly<F: FftField + PrimeField> {
    evals: Vec<Var<F>>,
}

/// A saved evaluation of the vanishing polynomial Z_H of H
/// at the point x. In Kimchi this is refered to as zeta1m1 
///
/// Note that this polynomial evaluates to the same on any element of the same H coset:
/// i.e. $Z_H(\omega^i * \zeta) = Z_H(\zeta)$ for any $\zeta, i$.
pub struct VanishEval<F: FftField + PrimeField> {
    xn: Var<F>,
    zhx: Var<F>,
    domain: Domain<F>
}

impl <F: FftField + PrimeField> VanishEval<F> {
   
    // compute Z_H(x)
    pub fn new<C: Cs<F>>(cs: &mut C, domain: &Domain<F>, x: Var<F>) -> Self {
        let one: F = F::one();
        let xn: Var<F> = cs.pow(x, domain.size);

        VanishEval{
            xn,
            domain: domain.clone(),
            zhx: generic!(cs, (xn) : { xn - one = ?}),
        }
    }
}

impl <F: FftField + PrimeField> AsRef<Var<F>> for VanishEval<F> {
    fn as_ref(&self) -> &Var<F> {
        &self.zhx
    }
}

impl <F: FftField + PrimeField> LagrangePoly<F> {
    pub fn len(&self) -> usize {
        self.evals.len()
    }

    // evaluates a lagrange polynomial at 
    //
    // see: https://o1-labs.github.io/proof-systems/plonk/lagrange.html
    pub fn eval<C: Cs<F>>(
        &self, 
        cs: &mut C, 
        x: Var<F>,
        pnt: &VanishEval<F>,
    ) -> VarOpen<F,1> {

        assert!(self.evals.len() > 0);
        assert!(self.evals.len() as u64 <= pnt.domain.size);

        // L_i(X) = Z_H(X) / (m * (X - g^i))
   
        // iterate over evaluation pairs (xi, yi)
        let mut terms = vec![];
        for (gi, yi) in pnt.domain.elements().zip(self.evals.iter().cloned()) {
            // compute g^i
            let m = pnt.domain.size_as_field_element;

            // The lagrange polynomial time yi can be evaluated using a single generic gate.
            // (since only x and yi are variable).
            //
            // Define:
            //
            // liyi = yi * L_i(x) / Z_H(x)
            // yi times the i'th lagrange poly L_i evaluated at x, except the multiplication by Z_H(x).
            // 
            // Rewrite:
            //
            // 1. [liyi] = ([yi] * gi) / (m * [x] - m gi)
            // 2. [liyi] * (m * [x] - m g^i) = [yi] * gi 
            // 3. [liyi] * (m * [x] - m g^i) = [yi] * gi
            terms.push(
                generic!(
                    cs,
                    (x, yi) : { ? * (m*x - m*gi) = yi*gi }
                )
            );
        }

        // compute sum and muliply bu Z_H(x)
        let sum = var_sum(cs, terms.into_iter());
        cs.mul(
            sum,
            pnt.zhx
        ).into()
    }

    pub fn size(&self) -> usize {
        self.evals.len()
    }
}
