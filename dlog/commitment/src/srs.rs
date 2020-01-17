/*****************************************************************************************************************

This source file implements the Marlin structured reference string primitive

NOTE: the current implementation profides faster SRS generation only for
testing efficiency purpose. In production, the use of E::G1Projective::rand()
or sequential hashing into the group has to be utilized. 

*****************************************************************************************************************/

use algebra::{ProjectiveCurve, PrimeField, AffineCurve, FixedBaseMSM, UniformRand};
use rand_core::RngCore;

#[derive(Debug, Clone)]
pub struct SRS<G: AffineCurve>
{
    pub g: Vec<G>,    // for committing polynomials
    pub s: G,         // for committing scalars, inner product
}

impl<G: AffineCurve> SRS<G>
{
    pub fn max_degree(&self) -> usize {
        self.g.len()
    }

    // This function creates SRS instance for circuits up to depth d
    //     depth: maximal depth of the circuits
    //     rng: randomness source context
    pub fn create
    (
        depth: usize,
        rng: &mut dyn RngCore
    ) -> Self
    {
        let size_in_bits = G::ScalarField::size_in_bits();
        let window_size = FixedBaseMSM::get_mul_window_size(depth+1);
        let mut v = FixedBaseMSM::multi_scalar_mul::<G::Projective>
        (
            size_in_bits,
            window_size,
            &FixedBaseMSM::get_window_table
            (
                size_in_bits,
                window_size,
                G::Projective::prime_subgroup_generator()
            ),
            &(0..depth+1).map(|_| G::ScalarField::rand(rng)).collect::<Vec<G::ScalarField>>(),
        );
        ProjectiveCurve::batch_normalization(&mut v);

        SRS
        {
            g: v[0..depth].iter().map(|e| e.into_affine()).collect(),
            s: v[depth].into_affine()
        }
    }
}
