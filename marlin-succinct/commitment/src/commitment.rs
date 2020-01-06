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
use std::collections::HashMap;
use ff_fft::DensePolynomial;
pub use super::urs::URS;
use rand_core::RngCore;

impl<E: PairingEngine> URS<E>
{
    // This function commits a polynomial against URS instance
    //     plnm: polynomial to commit to
    //     RETURN: tuple of: unbounded commitment
    pub fn commit
    (
        &self,
        plnm: &DensePolynomial<E::Fr>,
    ) -> Result<E::G1Affine, ProofError>
    {
        if plnm.coeffs.len() > self.gp.len() {return Err(ProofError::PolyCommit)}
        Ok (
            VariableBaseMSM::multi_scalar_mul
            (
                &self.gp[0..plnm.len()],
                &plnm.coeffs.iter().map(|s| s.into_repr()).collect::<Vec<_>>()
            ).into_affine() )
    }

    // This function commits a polynomial against URS instance
    //     plnm: polynomial to commit to
    //     max: maximal degree of the polynomial, if none , no degree bound
    //     RETURN: tuple of: unbounded commitment, optional bounded commitment
    pub fn commit_with_degree_bound
    (
        &self,
        plnm: &DensePolynomial<E::Fr>,
        max: usize,
    ) -> Result<(E::G1Affine, E::G1Affine), ProofError>
    {
        let unshifted = self.commit(plnm)?;

        let d = self.gp.len();
        if d < max || plnm.coeffs.len() > max {return Err(ProofError::PolyCommitWithBound)}
        let shifted = VariableBaseMSM::multi_scalar_mul
        (
            &self.gp[d - max..plnm.len() + d - max],
            &plnm.coeffs.iter().map(|s| s.into_repr()).collect::<Vec<_>>(),
        ).into_affine();

        Ok((unshifted, shifted))
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

    // This function opens the polynomial commitment batch
    //     polys: commited polynomials with no degree bound
    //     mask: base field element masking value
    //     elm: base field element to open the commitment at
    //     RETURN: commitment opening proof
    pub fn open
    (
        &self,
        polys: &Vec<DensePolynomial<E::Fr>>,
        mask: E::Fr,
        elm: E::Fr
    ) -> Result<E::G1Affine, ProofError>
    {
        let mut acc = DensePolynomial::<E::Fr>::zero();
        let mut scale = E::Fr::one();
        
        for p in polys
        {
            scale *= &mask;
            acc += &(p.scale(scale));
        }
        self.commit(&acc.divide(elm))
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
            Vec<(E::G1Affine, E::Fr, Option<(E::G1Affine, usize)>)>,
            E::G1Affine,
        )>>,
        rng: &mut dyn RngCore
    ) -> bool
    {
        let d = self.gp.len();
        let mut table = vec![];

        // verify commitment opening proofs against unshifted commitments:
        // e(prf, h^x) * e(g^eval * prf^(-chal), h^0)) = e(unshComm, h^0)

        let mut open_scalar = Vec::new();
        let mut open_point = Vec::new();
        let mut openy_scalar = Vec::new();
        let mut openy_point = Vec::new();

        for prf in batch.iter()
        {
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
                
                for z in x.2.iter()
                {
                    v += &(z.1 * &scale);
                    openy_point.push(z.0);
                    openy_scalar.push((-rnd * &scale).into_repr());
                    scale *= &x.1;
                }
                v *= &rnd;
                eval += &v;
            };
            openy_scalar.push(eval.into_repr());
            openy_point.push(self.gp[0]);
        }

        // verify shifted commitments against unshifted commitments:
        // e(ushComm, h^0) = e(shComm, h^x^(max-d))

        let mut shifted: HashMap<usize, Vec<(E::G1Affine, E::Fr)>> = HashMap::new();
        for x1 in batch.iter()
        {
            for x2 in x1.iter()
            {
                for x3 in x2.2.iter()
                {
                    match x3.2
                    {
                        Some((p, m)) =>
                        {
                            let rnd = E::Fr::rand(rng);
                            openy_point.push(x3.0);
                            openy_scalar.push(rnd.into_repr());
                            if !shifted.contains_key(&m) {shifted.insert(m, Vec::new());}
                            shifted.get_mut(&m).unwrap().push((p, rnd))
                        }
                        None => continue
                    }        
                }
            }
        }

        for max in shifted.keys()
        {
            if !self.hn.contains_key(&(d-max)) {return false}
            table.push
            ((
                VariableBaseMSM::multi_scalar_mul
                (
                    &shifted[max].iter().map(|p| p.0).collect::<Vec<_>>(),
                    &shifted[max].iter().map(|s| s.1.into_repr()).collect::<Vec<_>>(),
                ).into_affine().prepare(),
                (-self.hn[&(d-max)]).prepare()
            ));
        }
        table.push
        ((
            VariableBaseMSM::multi_scalar_mul
            (
                &open_point,
                &open_scalar
            ).into_affine().prepare(),
            self.hx.prepare()
        ));
        table.push
        ((
            VariableBaseMSM::multi_scalar_mul
            (
                &openy_point,
                &openy_scalar
            ).into_affine().prepare(),
            E::G2Affine::prime_subgroup_generator().prepare()
        ));
    
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
