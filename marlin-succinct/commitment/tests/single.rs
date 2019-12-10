/*****************************************************************************************************************

This source file implements the polynomial commitment unit test suite driver.
The following tests are implemented:

1. Polynomial commiment test
    1. Generate URS instance of sufficient depth
    2. Generate a random polynomials vector over the base field that fits into the URS depth.
       The polynomial coefficients are random base field elements.
    3. Commit to the polynomials against the URS instance
    4. Evaluate the polynomials at a given randomly generated base field elements
    5. Open the polynomials commitment at the given random base field element producing the opening proof
    6. Verify the commitment opening proofs against the:
        a. the URS instance
        b. Polynomial evaluations at the given base field element
        c. The given base field elements
        d. Commitment opening proofs

*****************************************************************************************************************/

use algebra::{curves::bls12_381::Bls12_381, Field, PairingEngine, UniformRand};
use commitment::urs::URS;
use ff_fft::DensePolynomial;
use rand_core::OsRng;

#[test]
fn single_commitment_test()
{
    test::<Bls12_381>();
}

fn test<E: PairingEngine>()
{
    let rng = &mut OsRng;
    let depth = 500;

    // generate sample URS
    let urs = URS::<E>::create(depth, rng);

    // generate sample random vector of polynomials over the base field, commit and evaluate them
    let mut plnms: Vec<(E::Fr, E::Fr, Vec<(E::G1Affine, E::Fr, usize)>, E::G1Affine)> = Vec::new();
    for _ in 0..10
    {
        let plnm = DensePolynomial::<E::Fr>::rand(depth-1, rng);
        let y = E::Fr::rand(rng);
        // Commit/Open and verify the polynomial commitments
        match (urs.commit(&plnm, plnm.coeffs.len()), urs.open(&plnm, y))
        {
            (Some(comm), Some(prf)) => {plnms.push((y, E::Fr::one(), vec![(comm, plnm.evaluate(y), plnm.coeffs.len())], prf));}
            (_,_) => {panic!("This error should not happen")}
        }
    }
    assert_eq!(true, urs.verify(&vec![plnms; 1], rng));
}
