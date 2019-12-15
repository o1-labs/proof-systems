/*****************************************************************************************************************

This source file implements the polynomial commitment batch primitive. The primitive provides the following zero-
knowledge protocol:

1. Commit to the batch of vectors of polynomials against the URS instance
2. Evaluate the vector of polynomials at the given base field element
3. Open the polynomial commitment batch at the given random base field element producing the opening proof
   with the masking base field element
4. Verify the commitment opening proof against the following;
     a. the URS instance
     b. Polynomial evaluations at the given base field element
     c. The given base field element
     d. The given masking base field element
     e. Commitment opening proof

*****************************************************************************************************************/

use oracle::rndoracle::ProofError;
use algebra::{AffineCurve, ProjectiveCurve, Field, PairingEngine, PairingCurve, UniformRand};
use ff_fft::DensePolynomial;
pub use super::urs::URS;
use rand_core::RngCore;

impl<E: PairingEngine> URS<E>
{
    // This function commits the polynomial against URS instance
    //     plnm: polynomial to commit
    //     max: maximal degree of the polynomial
    //     RETURN: commitment group element
    pub fn commit
    (
        &self,
        plnm: &DensePolynomial<E::Fr>,
        max: usize,
    ) -> Result<E::G1Affine, ProofError>
    {
        let d = self.gp.len();
        if d < max || plnm.coeffs.len() > max {return Err(ProofError::PolyCommit)}

        let mut exp: Vec<(E::G1Affine, E::Fr)> = vec![];
        for i in 0..max
        {
            if plnm.coeffs[i].is_zero() {continue;}
            exp.push((self.gp[i + d - max], plnm.coeffs[i]));
        }
        Ok(Self::multiexp(&exp))
    }

    // This function exponentiates a polynomial against URS instance
    //     plnm: polynomial to exponentiate
    //     RETURN: commitment group element
    pub fn exponentiate
    (
        &self,
        plnm: &DensePolynomial<E::Fr>
    ) -> Result<E::G1Affine, ProofError>
    {
        if plnm.coeffs.len() > self.gp.len() {return Err(ProofError::PolyExponentiate)}
        let mut exp: Vec<(E::G1Affine, E::Fr)> = vec![];

        for (x, y) in plnm.coeffs.iter().zip(self.gp.iter())
        {
            if x.is_zero() {continue;}
            exp.push((*y, *x));
        }
        Ok(Self::multiexp(&exp))
    }

    // This function opens the polynomial commitment
    //     elm: base field element to open the commitment at
    //     plnm: commited polynomial
    //     RETURN: commitment opening proof
    pub fn open
    (
        &self,
        plnm: &DensePolynomial<E::Fr>,
        elm: E::Fr
    ) -> Result<E::G1Affine, ProofError>
    {
        // do polynomial division (F(x)-F(elm))/(x-elm)
        self.exponentiate(&plnm.divide(elm))
    }

    // This function opens the polynomial commitment batch
    //     plnms: batch of commited polynomials
    //     mask: base field element masking value
    //     elm: base field element to open the commitment at
    //     RETURN: commitment opening proof
    pub fn open_batch
    (
        &self,
        plnms: &Vec<DensePolynomial<E::Fr>>,
        mask: E::Fr,
        elm: E::Fr
    ) -> Result<E::G1Affine, ProofError>
    {
        let mut acc = DensePolynomial::<E::Fr>::zero();
        let mut scale = mask;
        
        for x in plnms.iter()
        {
            acc += &(x * &DensePolynomial::<E::Fr>::from_coefficients_slice(&[scale]));
            scale *= &mask;
        }
        self.exponentiate(&acc.divide(elm))
    }

    // This function update the polynomial commitment opening batch with another opening proof
    //     batch: polynomial commitment opening batch to update
    //     proof: polynomial commitment opening proof to update with
    //     mask: base field element masking value
    //     index: update index
    //     RETURN: updated commitment opening batch proof
    pub fn update_batch
    (
        batch: E::G1Affine,
        proof: E::G1Affine,
        mask: E::Fr,
        index: usize
    ) -> E::G1Affine
    {
        (batch.into_projective() + &proof.mul(mask.pow(&[index as u64]))).into_affine()
    }

    // This function verifies the batch polynomial commitment proofs of vectors of polynomials
    //     base field element to open the commitment at
    //     base field element masking value
    //     polynomial commitment batch of
    //         commitment value
    //         polynomial evaluation
    //         max positive powers size of the polynomial
    //     polynomial commitment opening proof
    //     randomness source context
    //     RETURN: verification status
    pub fn verify
    (
        &self,
        batch: &Vec<Vec
        <(
            E::Fr,
            E::Fr,
            Vec<(E::G1Affine, E::Fr, usize)>,
            E::G1Affine,
        )>>,
        rng: &mut dyn RngCore
    ) -> bool
    {
        let d = self.gp.len();
        let mut table = vec![];
        let mut open: Vec<(E::G1Affine, E::Fr)> = vec![];
        let mut openy: Vec<(E::G1Affine, E::Fr)> = vec![];

        for prf in batch.iter()
        {
            let mut pcomm: Vec<Vec<(E::G1Affine, E::Fr)>> = vec![vec![]; prf[0].2.len()];
            let mut eval = E::Fr::zero();

            for x in prf.iter()
            {
                let rnd = E::Fr::rand(rng);
                open.push((x.3, rnd));
                openy.push((x.3, -(rnd * &x.0)));
                let mut scale = x.1;
                let mut v = E::Fr::zero();
                
                for (z, y) in x.2.iter().zip(pcomm.iter_mut())
                {
                    v += &(z.1 * &scale);
                    y.push((z.0, rnd * &scale));
                    scale *= &x.1;
                }
                v *= &rnd;
                eval += &v;
            };
            openy.push((self.gp[0], eval));

            for (z, y) in prf[0].2.iter().zip(pcomm.iter_mut())
            {
                table.push
                ((
                    Self::multiexp(&y).prepare(),
                    (-self.hn[d-z.2]).prepare()
                ));
            }
        }
        table.push((Self::multiexp(&open).prepare(), self.hx.prepare()));
        table.push((Self::multiexp(&openy).prepare(), self.hn[0].prepare()));
    
        let x: Vec<(&<E::G1Affine as PairingCurve>::Prepared, &<E::G2Affine as PairingCurve>::Prepared)> = table.iter().map(|x| (&x.0, &x.1)).collect();
        E::final_exponentiation(&E::miller_loop(&x)).unwrap() == E::Fqk::one()
    }
}

pub trait KateDivision<F: Field>
{
    fn divide(&self, elm: F) -> Self;
}

impl<F: Field> KateDivision<F> for DensePolynomial<F>
{
    // This function divides this polynomial difference: (F(x)-F(elm))/(x-elm)
    //    elm: base field element
    //    RETURN: resulting polynomial
    fn divide
    (
        &self,
        mut elm: F
    ) -> Self
    {
        // do polynomial division (F(x)-F(elm))/(x-elm)
        elm = -elm;
        let mut pos = vec![F::zero(); self.coeffs.len() - 1];
        let mut rcff = F::zero();
        for (x, y) in self.coeffs.iter().rev().zip(pos.iter_mut().rev())
        {
            *y = *x - &rcff;
            rcff = *y * &elm;
        }
        Self::from_coefficients_vec(pos)
    }
}
