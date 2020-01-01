/*****************************************************************************************************************

This source file implements the Marlin structured reference string primitive

NOTE: the current implementation profides faster SRS generation only for
testing efficiency purpose. In production, the use of E::G1Projective::rand()
or sequential hashing into the group has to be utilized. 

*****************************************************************************************************************/

use algebra::{ProjectiveCurve, PrimeField, PairingEngine, FixedBaseMSM, UniformRand};
use rand_core::RngCore;

pub struct SRS<E: PairingEngine>
{
    pub g: Vec<E::G1Affine>,    // for committing polynomials
    pub s: E::G1Affine,         // for committing scalars, inner product
}

impl<E: PairingEngine> SRS<E>
{
    // This function creates SRS instance for circuits up to depth d
    //     depth: maximal depth of the circuits
    //     rng: randomness source context
    pub fn create
    (
        depth: usize,
        rng: &mut dyn RngCore
    ) -> Self
    {
        let size_in_bits = E::Fr::size_in_bits();
        let window_size = FixedBaseMSM::get_mul_window_size(depth+1);
        let mut v = FixedBaseMSM::multi_scalar_mul::<E::G1Projective>
        (
            size_in_bits,
            window_size,
            &FixedBaseMSM::get_window_table
            (
                size_in_bits,
                window_size,
                E::G1Projective::prime_subgroup_generator()
            ),
            &(0..depth+1).map(|_| E::Fr::rand(rng)).collect::<Vec<E::Fr>>(),
        );
        ProjectiveCurve::batch_normalization(&mut v);

        SRS
        {
            g: v[0..depth].iter().map(|e| e.into_affine()).collect(),
            s: v[depth].into_affine()
        }
    }
}