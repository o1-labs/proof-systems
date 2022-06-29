
use ark_poly::univariate::DensePolynomial;
use ark_ff::{FftField, PrimeField};

use circuit_construction::{Cs, Var};

// evaluate constant polynomial at variable point
//
// TODO: optimize significantly using GenericGates
pub fn eval_const_poly<F: FftField + PrimeField, C: Cs<F>>(
    cs: &mut C,
    f: &DensePolynomial<F>,
    x: Var<F>,
) -> Var<F> {
    // iterate over coefficients:
    // most-to-least significant   
    let mut coeff = f.coeffs.iter().rev();

    // the initial sum is the most significant term
    let mut sum = cs.constant(
        coeff.next().expect("zero chunks in poly.").clone()
    );

    // shift by pt and add next chunk
    for c in coeff {
        // this can be reduced to a single generic gate!
        let c = cs.constant(c.clone());
        sum = cs.mul(sum, x.clone());
        sum = cs.add(sum, c);
    }

    sum
}

// Computes a summation of variables
//
// Panics if there are zero terms in the summation.
pub fn var_sum<F: FftField + PrimeField, I: Iterator<Item = Var<F>>, C: Cs<F>>(
    cs: &mut C, 
    mut terms: I
) -> Var<F> {

    let mut sum = terms.next().unwrap();
    
    for term in terms {
        sum = cs.add(sum, term);
    }
    sum
}