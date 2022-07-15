use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

use circuit_construction::{Cs, Var};

use std::marker::PhantomData;

use crate::types::VarEval;
use crate::util::eval_polynomial;

struct BatchedEvaluation<G>
where G: AffineCurve 
{
    _ph: PhantomData<G>,
    zeta: G::ScalarField,
    zetaw: G::ScalarField
}

fn combined_opening() {

}

/// Combine multiple openings using a linear combination
///
/// QUESTION: why can this not just be one large linear combination,
/// why do we need both xi and r?
pub fn combine_inner_product<'a, F, C: Cs<F>, const N: usize>(
    cs: &mut C,
    evaluations: &[(Var<F>, Vec<VarEval<F, N>>)], // evaluation point and openings
    xi: Var<F>,                                   // combinations at powers of x
    r: Var<F>,                                    // new evaluation point
) -> VarEval<F, 1>
where
    F: FftField + PrimeField,
{
    // accumulated sum: \sum_{j=0} xi^j * term_j
    let mut res = cs.constant(F::zero());

    // xi^i
    let mut xi_i = cs.constant(F::one());

    //
    for (_eval_point, polys) in evaluations {
        for i in 0..N {
            // take the i'th chunk from each polynomial
            let chunks: Vec<Var<F>> = polys.iter().map(|p| p.chunks[i]).collect();

            // evaluate the polynomial with the chunks as coefficients
            let term: Var<F> = eval_polynomial(cs, &chunks, r);

            // res += xi_i * term
            let xi_i_term = cs.mul(xi_i, term);
            res = cs.add(res, xi_i_term);

            // xi_i *= xi
            xi_i = cs.mul(xi_i, xi);

            // QUESTION: the shifting does not seem to be used
            // do we need it? It adds complexity and constraints particularly
            // in the circuit where we need to add a circuit for computing the shift
        }
    }

    res.into()
}