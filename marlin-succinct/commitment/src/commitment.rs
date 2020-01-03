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
use algebra::{AffineCurve, ProjectiveCurve, Field, PrimeField, PairingEngine, PairingCurve, UniformRand, VariableBaseMSM};
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

        Ok(VariableBaseMSM::multi_scalar_mul
        (
            &(0..plnm.len()).map(|i| self.gp[i + d - max]).collect::<Vec<_>>(),
            &plnm.coeffs.iter().map(|s| s.into_repr()).collect::<Vec<_>>()
        ).into_affine())
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

        Ok(VariableBaseMSM::multi_scalar_mul
        (
            &(0..plnm.len()).map(|i| self.gp[i]).collect::<Vec<_>>(),
            &plnm.coeffs.iter().map(|s| s.into_repr()).collect::<Vec<_>>()
        ).into_affine())
    }

    pub fn exponentiate_sub_domain
    (
        &self,
        plnm: &DensePolynomial<E::Fr>,
        ratio : usize,
    ) -> Result<E::G1Affine, ProofError>
    {
        if plnm.coeffs.len() > self.gp.len() {return Err(ProofError::PolyExponentiate)}

        Ok(VariableBaseMSM::multi_scalar_mul
        (
            &(0..plnm.len()).map(|i| self.gp[ratio * i]).collect::<Vec<_>>(),
            &plnm.coeffs.iter().map(|s| s.into_repr()).collect::<Vec<_>>()
        ).into_affine())
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
            acc += &(x.scale(scale));
            scale *= &mask;
        }
        self.exponentiate(&acc.divide(elm))
    }

    // This function updates the polynomial commitment opening batch with another opening proof
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
        let mut open_scalar = Vec::new();
        let mut open_point = Vec::new();
        let mut openy_scalar = Vec::new();
        let mut openy_point = Vec::new();

        for prf in batch.iter()
        {
            let mut pcomm: Vec<Vec<(E::G1Affine, E::Fr)>> = vec![vec![]; prf[0].2.len()];
            let mut eval = E::Fr::zero();

            for x in prf.iter()
            {
                let rnd = E::Fr::rand(rng);
                open_scalar.push(rnd.into_repr());
                open_point.push(x.3);
                openy_scalar.push((-rnd * &x.0).into_repr());
                openy_point.push(x.3);
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
            openy_scalar.push(eval.into_repr());
            openy_point.push(self.gp[0]);

            for (z, y) in prf[0].2.iter().zip(pcomm.iter_mut())
            {
                if !self.hn.contains_key(&(d-z.2)) {return false}
                table.push
                ((
                    VariableBaseMSM::multi_scalar_mul
                    (
                        &y.iter().map(|p| p.0).collect::<Vec<_>>(),
                        &y.iter().map(|s| s.1.into_repr()).collect::<Vec<_>>(),
                    ).into_affine().prepare(),
                    (-self.hn[&(d-z.2)]).prepare()
                ));
            }
        }
        table.push((VariableBaseMSM::multi_scalar_mul(&open_point, &open_scalar).into_affine().prepare(), self.hx.prepare()));
        table.push((VariableBaseMSM::multi_scalar_mul(&openy_point, &openy_scalar).into_affine().prepare(), E::G2Affine::prime_subgroup_generator().prepare()));
    
        let x: Vec<(&<E::G1Affine as PairingCurve>::Prepared, &<E::G2Affine as PairingCurve>::Prepared)> = table.iter().map(|x| (&x.0, &x.1)).collect();
        E::final_exponentiation(&E::miller_loop(&x)).unwrap() == E::Fqk::one()
    }
}

pub trait Utils<F: Field>
{
    fn divide(&self, elm: F) -> Self;
    fn scale(&self, elm: F) -> Self;
}

impl<F: Field> Utils<F> for DensePolynomial<F>
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

    // This function "scales" (multiplies) polynomaial with a scalar
    // It is implemented to have the desired functionality for DensePolynomial
    fn scale(&self, elm: F) -> Self
    {
        let mut result = self.clone();
        for coeff in &mut result.coeffs {*coeff *= &elm}
        result
    }
}
