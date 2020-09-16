/*****************************************************************************************************************

This source file implements the Marlin structured reference string primitive

*****************************************************************************************************************/

pub use crate::{QnrField, CommitmentField};
use blake2::{Blake2b, Digest};
use std::io::{Read, Result as IoResult, Write};
use algebra::{FromBytes, PrimeField, ToBytes, BigInteger, Zero, One};
use ff_fft::{Radix2EvaluationDomain as D, Evaluations, EvaluationDomain};
use crate::commitment::{CommitmentCurve, PolyComm};
use groupmap::GroupMap;

#[derive(Debug, Clone)]
pub struct SRS<G: CommitmentCurve>
{
    pub g: Vec<G>,    // for committing polynomials
    pub h: G,         // blinding

    // Lagrange polynomial commitments
    pub lgr_comm: Vec<PolyComm<G>>,

    // Coefficients for the curve endomorphism
    pub endo_r: G::ScalarField,
    pub endo_q: G::BaseField,
}

pub fn endos<G: CommitmentCurve>() -> (G::BaseField, G::ScalarField)
where G::BaseField : PrimeField {
    let endo_q : G::BaseField = oracle::sponge::endo_coefficient();
    let endo_r = {
        let potential_endo_r : G::ScalarField = oracle::sponge::endo_coefficient();
        let t = G::prime_subgroup_generator();
        let (x, y) = t.to_coordinates().unwrap();
        let phi_t = G::of_coordinates(x * &endo_q, y);
        if t.mul(potential_endo_r) == phi_t.into_projective() {
            potential_endo_r
        } else {
            potential_endo_r * &potential_endo_r
        }
    };
    (endo_q, endo_r)
}

impl<G: CommitmentCurve> SRS<G> where G::BaseField : PrimeField, G::ScalarField : CommitmentField {
    pub fn max_degree(&self) -> usize {
        self.g.len()
    }

    // This function creates SRS instance for circuits up to depth d
    //      depth: maximal depth of SRS string
    //      public: maximal number of public inputs
    //      size: circuit size
    pub fn create(depth: usize, public: usize, size: usize) -> Self {
        let m = G::Map::setup();

        const N : usize = 31;
        let v : Vec<_> = (0..depth + 1).map(|i| {
            let mut h = Blake2b::new();
            h.input(&(i as u32).to_be_bytes());

            let random_bytes = &h.result()[..N];
            let mut bits = [false;8*N];
            for i in 0..N {
                for j in 0..8 {
                    bits[8*i + j] = (random_bytes[i] >> j) & 1 == 1;
                }
            }

            let n = <G::BaseField as PrimeField>::BigInt::from_bits(&bits);
            let t = G::BaseField::from_repr(n);
            let (x, y) = m.to_group(t);
            G::of_coordinates(x, y)
        }).collect();

        let (endo_q, endo_r) = endos::<G>();

        let mut srs = SRS
        {
            g: v[0..depth].iter().map(|e| *e).collect(),
            h: v[depth],
            lgr_comm: Vec::new(),
            endo_r, endo_q
        };

        srs.lgr_comm = (0..public).map
        (
            |i|
            {
                let mut lagr = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain
                    (vec![G::ScalarField::zero(); size], D::<G::ScalarField>::new(size).unwrap());
                lagr.evals[i] = G::ScalarField::one();
                srs.commit(&lagr.interpolate(), None)
            }
        ).collect::<Vec<_>>();

        srs
    }

    pub fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        u64::write(&(self.g.len() as u64), &mut writer)?;
        for x in &self.g {
            G::write(x, &mut writer)?;
        }
        u64::write(&(self.lgr_comm.len() as u64), &mut writer)?;
        for x in &self.lgr_comm {
            G::write(&x.unshifted[0], &mut writer)?;
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
        let n = u64::read(&mut reader)? as usize;
        let mut lgr_comm = Vec::with_capacity(n);
        for _ in 0..n {
            lgr_comm.push(PolyComm::<G>{shifted: None, unshifted: vec![G::read(&mut reader)?]});
        }

        let h = G::read(&mut reader)?;
        let (endo_q, endo_r) = endos::<G>();
        Ok(SRS { g, lgr_comm, h, endo_r, endo_q })
    }
}
