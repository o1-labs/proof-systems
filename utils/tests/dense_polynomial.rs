use ark_ff::One;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use mina_curves::pasta::Fp;
use o1_utils::ExtendedDensePolynomial;

#[test]
fn test_chunk() {
    let one = Fp::one();
    let two = one + one;
    let three = two + one;
    let num_chunks = 4;

    // 1 + x + x^2 + x^3 + x^4 + x^5 + x^6 + x^7
    let coeffs = [one, one, one, one, one, one, one, one];
    let f = DensePolynomial::from_coefficients_slice(&coeffs);
    let evals = f.to_chunked_polynomial(num_chunks, 2).evaluate_chunks(two);
    assert_eq!(evals.len(), num_chunks);
    for eval in evals.into_iter().take(num_chunks) {
        assert!(eval == three);
    }
}
