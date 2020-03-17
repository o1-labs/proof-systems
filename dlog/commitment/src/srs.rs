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
pub struct SRS<G: CommitmentCurve>
{
    pub g: Vec<G>,    // for committing polynomials
    pub h: G,         // blinding
}

impl<G: CommitmentCurve> SRS<G> where G::BaseField : PrimeField {
    pub fn max_degree(&self) -> usize {
        self.g.len()
    }

    // This function creates SRS instance for circuits up to depth d
    //     depth: maximal depth of the circuits
    pub fn create(depth: usize) -> Self {
        let m = G::Map::setup();

        let v : Vec<_> = (0..depth + 1).map(|i| {
            let mut h = Blake2b::new();
            h.input(&(i as u32).to_be_bytes());
            let random_bytes = &h.result()[..32];
            let t = G::BaseField::from_random_bytes(&random_bytes).unwrap();
            let (x, y) = m.to_group(t);
            G::of_coordinates(x, y)
        }).collect();

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
