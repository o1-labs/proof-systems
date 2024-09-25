use ark_ff::{Field, One};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use mina_curves::pasta::Fp;
use o1_utils::ExtendedDensePolynomial;

#[test]

fn test_chunk_poly() {
    let one = Fp::one();
    let zeta = one + one;
    let zeta_n = zeta.square();
    let num_chunks = 4;
    let res = (one + zeta)
        * (one + zeta_n + zeta_n * zeta.square() + zeta_n * zeta.square() * zeta.square());

    // 1 + x + x^2 + x^3 + x^4 + x^5 + x^6 + x^7 = (1+x) + x^2 (1+x) + x^4 (1+x) + x^6 (1+x)
    let coeffs = [one, one, one, one, one, one, one, one];
    let f = DensePolynomial::from_coefficients_slice(&coeffs);

    let eval = f
        .to_chunked_polynomial(num_chunks, 2)
        .linearize(zeta_n)
        .evaluate(&zeta);

    assert!(eval == res);
}
