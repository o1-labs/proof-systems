/*****************************************************************************************************************

This source file implements the Marlin structured reference string primitive

NOTE: the current implementation profides faster SRS generation only for
testing efficiency purpose. In production, the use of E::G1Projective::rand()
or sequential hashing into the group has to be utilized.

*****************************************************************************************************************/

use algebra::{
    FromBytes, PrimeField, ToBytes,
};
use blake2::{Blake2b, Digest};
use std::io::{Read, Result as IoResult, Write};
use crate::commitment::CommitmentCurve;
use groupmap::GroupMap;

#[derive(Debug, Clone)]
pub struct SRS<G: CommitmentCurve>
{
    pub g: Vec<G>,    // for committing polynomials
    pub h: G,         // blinding

    // Coefficients for the curve endomorphism
    pub endo_r: G::ScalarField,
    pub endo_q: G::BaseField,
}

fn endos<G: CommitmentCurve>() -> (G::ScalarField, G::BaseField)
where G::BaseField : PrimeField {
    let endo_q : G::BaseField = oracle::marlin_sponge::endo_coefficient();
    let endo_r = {
        let potential_endo_r : G::ScalarField = oracle::marlin_sponge::endo_coefficient();
        let t = G::prime_subgroup_generator();
        let (x, y) = t.to_coordinates().unwrap();
        let phi_t = G::of_coordinates(x * &endo_q, y);
        if t.mul(potential_endo_r) == phi_t.into_projective() {
            potential_endo_r
        } else {
            potential_endo_r * &potential_endo_r
        }
    };
    (endo_r, endo_q)
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

        let (endo_r, endo_q) = endos::<G>();

        SRS {
            g: v[0..depth].iter().map(|e| *e).collect(),
            h: v[depth],
            endo_r, endo_q
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
        let (endo_r, endo_q) = endos::<G>();
        Ok(SRS { g, h, endo_r, endo_q })
    }
}

