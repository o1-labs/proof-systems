//! This module defines Property-based tests for the SRS trait.
//! It includes tests regarding methods the SRS trait should implement.
//! It aims to verify the implementation respects the properties described in
//! the documentation of the methods.

use ark_ff::Zero;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use rand::Rng;

use crate::{commitment::CommitmentCurve, SRS};

// Testing how many chunks are generated with different polynomial sizes and
// different number of chunks requested.
pub fn test_regression_commit_non_hiding_expected_number_of_chunks<
    G: CommitmentCurve,
    Srs: SRS<G>,
>() {
    let mut rng = &mut o1_utils::tests::make_test_rng(None);
    // maximum random srs size is 64
    let log2_srs_size = rng.gen_range(1..6);
    let srs_size = 1 << log2_srs_size;
    let srs = Srs::create(srs_size);

    // If we have a polynomial of the size of the SRS (i.e. of degree `srs_size
    // - 1`), and we request 1 chunk, we should get 1 chunk.
    {
        // srs_size is the number of evaluation degree
        let poly_degree = srs_size - 1;
        let poly = DensePolynomial::<G::ScalarField>::rand(poly_degree, &mut rng);
        let commitment = srs.commit_non_hiding(&poly, 1);
        assert_eq!(commitment.len(), 1);
    }

    // If we have a polynomial of the size of the SRS (i.e. of degree `srs_size
    // - 1`), and we request k chunks (k > 1), we should get k chunk.
    {
        // srs_size is the number of evaluation degree
        let poly_degree = srs_size - 1;
        // maximum 10 chunks for the test
        let k = rng.gen_range(2..10);
        let poly = DensePolynomial::<G::ScalarField>::rand(poly_degree, &mut rng);
        let commitment = srs.commit_non_hiding(&poly, k);
        assert_eq!(commitment.len(), k);
    }

    // Same than the two previous cases, but with the special polynomial equals
    // to zero.
    {
        let k = rng.gen_range(1..10);
        let poly = DensePolynomial::<G::ScalarField>::zero();
        let commitment = srs.commit_non_hiding(&poly, k);
        assert_eq!(commitment.len(), k);
    }

    // Polynomial of exactly a multiple of the SRS size, i.e degree is k *
    // srs_size - 1.
    {
        let k = rng.gen_range(2..5);
        let poly_degree = k * srs_size - 1;
        let poly = DensePolynomial::<G::ScalarField>::rand(poly_degree, &mut rng);
        // if we request a number of chunks smaller than the multiple, we will
        // still get a number of chunks equals to the multiple.
        let requested_num_chunks = rng.gen_range(1..k);
        let commitment = srs.commit_non_hiding(&poly, requested_num_chunks);
        assert_eq!(commitment.len(), k);

        // if we request a number of chunks equals to the multiple, we will get
        // the exact number of chunks.
        let commitment = srs.commit_non_hiding(&poly, k);
        assert_eq!(commitment.len(), k);

        // if we request a number of chunks greater than the multiple, we will
        // get the exact number of chunks requested.
        let requested_num_chunks = rng.gen_range(k + 1..10);
        let commitment = srs.commit_non_hiding(&poly, requested_num_chunks);
        assert_eq!(commitment.len(), requested_num_chunks);
    }
}
