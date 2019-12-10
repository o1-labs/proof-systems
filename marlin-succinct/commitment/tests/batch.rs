/*****************************************************************************************************************

This source file implements the batched polynomial commitment unit test suite driver.
The following tests are implemented:

1. Batched polynomial commiment test
    1. Generate URS instance of sufficient depth
    2. Generate vector of vectors of random polynomials over the base field that fits into the URS depth.
       The polynomial coefficients are random base filed elements
    3. Commit to the polynomial vectors against the URS instance with masking/scaling value
    4. Evaluate the polynomials at a given randomly generated base field element
    5. Open the polynomial commitment vectors at the given random base field element producing the opening proof
    6. Verify the commitment vector opening proof against the:
        a. the URS instance
        b. Polynomial evaluations at the given base field element
        c. The given base field element
        d. Commitment opening proof

*****************************************************************************************************************/

use commitment::urs::URS;
use algebra::{PairingEngine, curves::bls12_381::Bls12_381, UniformRand};
use ff_fft::DensePolynomial;
use rand_core::OsRng;

#[test]
fn batch_commitment_test()
{
    test::<Bls12_381>();
}

fn test<E: PairingEngine>()
{
    let rng = &mut OsRng;
    let depth = 500;

    // generate sample URS
    let urs = URS::<E>::create
    (
        depth,
        rng
    );

    // generate random polynomials over the base field
    let mut block: Vec
    <(
        E::Fr,
        E::Fr,
        Vec<(E::G1Affine, E::Fr, usize)>,
        E::G1Affine
    )> = Vec::new();

    for _ in 0..7
    {
        let elm = E::Fr::rand(rng);
        let mask = E::Fr::rand(rng);
        let mut plnms: Vec<DensePolynomial<E::Fr>> = Vec::new();
        let mut max: Vec<usize> = Vec::new();
        let mut eval: Vec<E::Fr> = Vec::new();

        let mut plnm = DensePolynomial::<E::Fr>::rand(depth-1, rng);

        max.push(plnm.coeffs.len());
        eval.push(plnm.evaluate(elm));
        plnms.push(plnm);

        plnm = DensePolynomial::<E::Fr>::rand(depth-2, rng);
        
        max.push(plnm.coeffs.len());
        eval.push(plnm.evaluate(elm));
        plnms.push(plnm);

        plnm = DensePolynomial::<E::Fr>::rand(depth-3, rng);
        
        max.push(plnm.coeffs.len());
        eval.push(plnm.evaluate(elm));
        plnms.push(plnm);

        // Commit, open and verify the polynomial commitments
        let comm: Vec<E::G1Affine> = (plnms.iter().zip(max.iter())).map(|(p, m)| urs.commit(p, *m).unwrap()).collect();
        match urs.open_batch(&plnms, mask, elm)
        {
            None => {panic!("This error should not happen");}
            Some (prf) =>
            {
                block.push((elm, mask, comm.into_iter().zip(eval.into_iter()).zip(max.into_iter()).map(|((x,y),z)| (x,y,z)).collect(), prf))
            }
        }
    }
    assert_eq!(true, urs.verify(&vec![block; 1], rng));
}
