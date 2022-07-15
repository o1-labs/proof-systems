use ark_ec::AffineCurve;
use ark_ff::{PrimeField, FftField};

use circuit_construction::{Var, Cs};

use crate::types::{VarPoint, VarPolyComm, VarEval, GLVChallenge};

/// Polynomial commitments from Pedersen commitments
/// 
/// Let [f(X)] denote a commitment to f(X).
/// 
/// # Openings
/// 
/// The opening protocol below appears redundant (in particular it uses another protocol for opening),
/// however it enables batching. Suppose the prover wants to open [f(X)] at x to y: f(x) = y.
/// This is done as follow:
/// 
/// P:
///   1. Computes w(X) = (f(X) - y) / (X - x)
///   2. Sends [w(X)] to V.
/// 
/// V: 
///   3. Sends u to P.
/// 
/// P:
///   4. Opens f(u) and w(u) using another opening protocol
///      (i.e. the folding argument)
/// 
/// V:
///   5. Checks f(u) = w(u) * (u - x)
/// 
/// # Multiple openings at the same point.
/// 
/// The first observation is that if we are opening multiple polynomials 
/// at the same point we can exploit the linear homomorphism using a random linear combination. i.e.
/// 
/// Rather than opening f1(u) = z1, f2(u) = z2, ...
/// We do:
/// 
/// P:
///     1. Sends f0(u), ..., fn(u) to V
///  
/// V:
///     2. Picks random v
/// 
/// P: 
///     3. Opens v * [f1(u)] + 
/// 
/// 
/// 
/// 
/// # Multiple openings at different points.
/// 
/// 
/// 
/// 
pub struct Challenge<F: FftField + PrimeField>(Var<F>);

/*
fn combine_commitments<G, I, C, const M: usize, const N: usize>(
    cs: &mut C,
    evaluations: I,
    v_chal: GLVChallenge<G::BaseField>, // a GLV challenge
) -> VarPolyComm<G, N> where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
    I: DoubleEndedIterator<Item = (VarPolyComm<G, N>, [VarEval<G::ScalarField, N>; M])>, // iterator over evaluation point
    C: Cs<G::ScalarField>
{

}

fn combine<G, C, const N: usize>(
    cs: &mut C,
    comms: 
    eval_z: Vec<VarEval<G::ScalarField, N>>,
    eval_zw: Vec<VarEval<G::ScalarField, N>>,
    

    v_chal: GLVChallenge<G::BaseField>, // a GLV challenge
    v: Var<G::ScalarField>, // combines polynomials/evaluations (f(x)'s)
    u: Var<G::ScalarField>, // combines evaluation points (x's)
) -> (VarPolyComm<G, N>, VarEval<G::ScalarField, N>) where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
    I: Iterator<
        Item = (VarPolyComm<G, N>, (VarEval<G::ScalarField, N>, VarEval<G::ScalarField, N>))
    >, // iterator over evaluation point
    C: Cs<G::ScalarField>
{
    let openings: Vec<_> = openings.collect();

    let gz = VarEval::combine(cs, openings, v);

    for (comm, evals) in ) {
        // combine commitment and evaluations using v

    }

    // combine all polynomials at the same evaluation using v-power combination
    let gs = evaluations.map(|fs| VarEval::combine(cs, fs.into_iter(), v));

    // combine across all evaluation points using u-power combination
    VarEval::combine(cs, gs, u)
}

/// An aggregated opening proof for 
pub struct OpeningProof<G> 
where
    G: AffineCurve,
    G::BaseField : PrimeField + FftField
{
    /// vector of rounds of L & R commitments
    /// Transcript of the folding argument
    pub lr: Vec<(VarPoint<G>, VarPoint<G>)>,

    /// ???
    pub delta: VarPoint<G>,

    /// claimed opening of aggregated polynomial at $\zeta$
    pub z1: VarEval<G::ScalarField, 1>,
    
    /// claimed opening of aggregated polynomial at $\zeta\omega$
    pub z2: VarEval<G::ScalarField, 1>,

    /// The final folding
    pub sg: VarPoint<G>
}
*/