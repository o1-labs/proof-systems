/*****************************************************************************************************************

This source file implements the Marlin structured reference string primitive

NOTE: the current implementation profides faster SRS generation only for
testing efficiency purpose. In production, the use of E::G1Projective::rand()
or sequential hashing into the group has to be utilized.

*****************************************************************************************************************/

use algebra::curves::short_weierstrass_jacobian::GroupAffine as SWAffine;
use algebra::SWModelParameters;
use algebra::{
    AffineCurve, Field, FixedBaseMSM, FromBytes, PrimeField, ProjectiveCurve, SquareRootField,
    ToBytes, UniformRand,
};
use blake2::{Blake2b, Digest};
use rand_core::RngCore;
use rayon::prelude::*;
use std::io::{Read, Result as IoResult, Write};
use crate::commitment::CommitmentCurve;
use groupmap::GroupMap;

#[derive(Debug, Clone)]
pub struct SRS<G: AffineCurve>
{
    pub g: Vec<G>,    // for committing polynomials
    pub h: G,         // blinding
}

impl<G: AffineCurve> SRS<G>
{
    pub fn max_degree(&self) -> usize {
        self.g.len()
    }

    // This function creates SRS instance for circuits up to depth d
    //     depth: maximal depth of the circuits
    //     rng: randomness source context
    pub fn create(depth: usize, rng: &mut dyn RngCore) -> Self {
        let size_in_bits = G::ScalarField::size_in_bits();
        let window_size = FixedBaseMSM::get_mul_window_size(depth + 1);
        let mut v = FixedBaseMSM::multi_scalar_mul::<G::Projective>(
            size_in_bits,
            window_size,
            &FixedBaseMSM::get_window_table(
                size_in_bits,
                window_size,
                G::Projective::prime_subgroup_generator(),
            ),
            &(0..depth + 1)
                .map(|_| G::ScalarField::rand(rng))
                .collect::<Vec<G::ScalarField>>(),
        );
        ProjectiveCurve::batch_normalization(&mut v);

        SRS {
            g: v[0..depth].iter().map(|e| e.into_affine()).collect(),
            h: v[depth].into_affine(),
        }
    }

    pub fn batch_create(depth: usize, x_trits: Vec<usize>) -> Self {
        let m = G::Map::setup();

        let ts : Vec<_> = (0..depth + 1).map(|i| {
            let mut h = Blake2b::new();
            h.input(&(i as u32).to_be_bytes());
            let random_bytes = &h.result()[..32];
            G::BaseField::from_random_bytes(&random_bytes).unwrap()
        }).collect();

        let potential_xs = m.batch_to_group_x(ts);
        let v : Vec<_>;
        for (i, &j) in x_trits.iter().enumerate() {
            let x = potential_xs[i][j];

            // x(x^2 + a) + b
            // x^3 + ax + b
            let mut y2 = x;
            y2.square_in_place();
            y2 += &P::COEFF_A;
            y2 *= &x;
            y2 += &P::COEFF_B;

            let y = y2.sqrt().unwrap();
            let greatest = true;
            let negy = -y;
            let y = if (y < negy) ^ greatest { y } else { negy };
            v.push(G::of_coordinates(x, y));
        };

        SRS {
            g: v[0..depth].iter().map(|e| *e).collect(),
            h: v[depth],
        }
    }

    pub fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        u64::write(&(self.g.len() as u64), &mut writer)?;
        for x in &self.g {
            G::write(x, &mut writer)?;
        }
        G::write(&self.h, &mut writer)?;
        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let n = u64::read(&mut reader)? as usize;
        let mut g = vec![];
        for _ in 0..n {
            g.push(G::read(&mut reader)?);
        }
        let h = G::read(&mut reader)?;
        Ok(SRS { g, h })
    }
}


fn random_point<P: SWModelParameters>(i: usize) -> SWAffine<P>
where
    P::BaseField: PrimeField,
{
    let mut res = SWAffine::<P>::zero();

    for j in 0.. {
        let mut h = Blake2b::new();

        h.input(&(i as u32).to_be_bytes());
        h.input(&(j as u32).to_be_bytes());
        let random_bytes = &h.result()[..32];

        let x = P::BaseField::from_random_bytes(&random_bytes).unwrap();

        // x(x^2 + a) + b
        // x^3 + ax + b
        let mut y2 = x;
        y2.square_in_place();
        y2 += &P::COEFF_A;
        y2 *= &x;
        y2 += &P::COEFF_B;

        match y2.sqrt() {
            None => continue,
            Some(y) => {
                let greatest = true;
                let negy = -y;
                let y = if (y < negy) ^ greatest { y } else { negy };
                res = SWAffine::<P>::new(x, y, false);
                break;
            }
        };
    }

    res
}

impl<P: SWModelParameters> SRS<SWAffine<P>> {
    pub fn create_sw(depth: usize) -> SRS<SWAffine<P>>
    where
        P::BaseField: PrimeField,
    {
        /*
        let ts = (0..(depth + 1)).into_par_iter().map(|i|  {
            let mut h = Blake2b::new();

            h.input(& (i as u32).to_be_bytes());
            let random_bytes = &h.result()[..32];
            P::BaseField::from_random_bytes(& random_bytes).unwrap()
        }); */

        SRS {
            g: (0..depth).into_par_iter().map(random_point).collect(),
            h: random_point(depth),
        }
    }
}
