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
    //     size: maximal size of the polynomial chunks
    //     RETURN: tuple of: unbounded commitment vector
    pub fn commit
    (
        &self,
        plnm: &DensePolynomial<E::Fr>,
        size: usize
    ) -> Result<Vec<E::G1Affine>, ProofError>
    {
        if plnm.coeffs.len() > self.depth {return Err(ProofError::PolyCommit)}
        Ok
        (
            (0..plnm.len()/size + if plnm.len()%size != 0 {1} else {0}).map
            (
                |i|
                {
                    VariableBaseMSM::multi_scalar_mul
                    (
                        &self.gp[0..if (i+1)*size < plnm.coeffs.len() {size} else {plnm.coeffs.len()-i*size}],
                        &plnm.coeffs[i*size..if (i+1)*size < plnm.coeffs.len() {(i+1)*size} else {plnm.coeffs.len()}]
                            .iter().map(|s| s.into_repr()).collect::<Vec<_>>()
                    ).into_affine()
                }
            ).collect()
        )
    }

    // This function commits a polynomial against URS instance
    //     plnm: polynomial to commit to with max size of sections
    //     max: maximal degree of the polynomial, if none, no degree bound
    //     size: maximal size of the polynomial chunks
    //     RETURN: tuple of: unbounded commitment vector, bounded commitment
    pub fn commit_with_degree_bound
    (
        &self,
        plnm: &DensePolynomial<E::Fr>,
        max: usize,
        size: usize
    ) -> Result<(Vec<E::G1Affine>, E::G1Affine), ProofError>
    {
        if self.depth < max || plnm.coeffs.len() > max {return Err(ProofError::PolyCommitWithBound)}
        Ok
        ((
            self.commit(plnm, size)?,
            VariableBaseMSM::multi_scalar_mul
            (
                &self.gp[self.depth - max..plnm.len() + self.depth - max],
                &plnm.coeffs.iter().map(|s| s.into_repr()).collect::<Vec<_>>(),
            ).into_affine()
        ))
    }

    // This function opens the polynomial commitment batch with optional max size of sections
    //     polys: commited polynomials with no degree bound
    //     mask: base field element masking value
    //     elm: base field element to open the commitment at
    //     size: maximal size of the polynomial chunks
    //     RETURN: commitment opening proof
    pub fn open
    (
        &self,
        polys: Vec<&DensePolynomial<E::Fr>>,
        mask: E::Fr,
        elm: E::Fr,
        size: usize
    ) -> Result<E::G1Affine, ProofError>
    {
        let mut acc = DensePolynomial::<E::Fr>::zero();
        let mut scale = E::Fr::one();

        // iterating over polynomials in the batch        
        for p in polys.iter()
        {
            let mut offset = 0;
            // iterating over chunks of the polynomial
            while offset < p.coeffs.len()
            {
                acc += &(DensePolynomial::<E::Fr>::from_coefficients_slice
                    (&p.coeffs[offset..if offset+size > p.coeffs.len() {p.coeffs.len()} else {offset+size}])
                    .scale(scale));
                scale *= &mask;
                offset += size;
            }
        }

        acc = acc.divide(elm);
        if acc.coeffs.len() > self.depth {return Err(ProofError::PolyCommit)}
        Ok
        (
            VariableBaseMSM::multi_scalar_mul
            (
                &self.gp[0..acc.coeffs.len()],
                &acc.coeffs.iter().map(|s| s.into_repr()).collect::<Vec<_>>()
            ).into_affine()
        )
    }

    // This function verifies the batch polynomial commitment proofs of vectors of polynomials
    //     base field element to open the commitment at
    //     base field element masking value
    //     polynomial commitment batch of
    //         commitment value & polynomial evaluation vector
    //         max positive powers size of the polynomial
    //     polynomial commitment opening proof
    //     randomness source context
    //     RETURN: verification status
    pub fn verify
    (
        &self,
        batch: &Vec
        <(
            E::Fr,
            E::Fr,
            Vec<(Vec<(E::G1Affine, E::Fr)>, Option<(E::G1Affine, usize)>)>,
            E::G1Affine,
        )>,
        rng: &mut dyn RngCore
    ) -> bool
    {
        let mut table = vec![];

        // verify commitment opening proofs against unshifted commitments:
        // e(prf, h^x) * e(g^eval * prf^(-chal), h^0)) = e(unshComm, h^0)

        let mut open_scalar = Vec::new();
        let mut open_point = Vec::new();
        let mut openy_scalar = Vec::new();
        let mut openy_point = Vec::new();
        let mut eval = E::Fr::zero();

        for x in batch.iter()
        {
            let rnd = E::Fr::rand(rng);
            open_scalar.push(rnd.into_repr());
            open_point.push(x.3);
            openy_scalar.push((-rnd * &x.0).into_repr());
            openy_point.push(x.3);
            let mut scale = E::Fr::one();
            let mut v = E::Fr::zero();
            
            // iterating over polynomials in the batch
            for poly in x.2.iter()
            {
                // iterating over chunks of the polynomial
                for chunk in poly.0.iter()
                {
                    v += &(chunk.1 * &scale);
                    openy_point.push(chunk.0);
                    openy_scalar.push((-rnd * &scale).into_repr());
                    scale *= &x.1;
                }
            }
            v *= &rnd;
            eval += &v;
        }
        openy_scalar.push(eval.into_repr());
        openy_point.push(self.gp[0]);

        // verify shifted commitments against unshifted commitments:
        // for all i e(ushComm_chunk, h^x^(size*i)) = e(shComm, h^x^(max-d))

        let mut shifted: HashMap<isize, HashMap<E::G1Affine, E::Fr>> = HashMap::new();
        for x1 in batch.iter()
        {
            for x2 in x1.2.iter()
            {
                match x2.1
                {
                    Some((p, m)) =>
                    {
                        let rnd = E::Fr::rand(rng);

                        for (i, chunk) in x2.0.iter().enumerate()
                        {
                            if !shifted.contains_key(&(i as isize))
                                {shifted.insert(i as isize, HashMap::new());}
                            let map = shifted.get_mut(&(i as isize)).unwrap();
                            if !map.contains_key(&chunk.0)
                                {map.insert(chunk.0, rnd);}
                            else 
                                {*map.get_mut(&chunk.0).unwrap() += &rnd}
                        }
                        
                        if !shifted.contains_key(&(m as isize - self.depth as isize))
                            {shifted.insert(m as isize - self.depth as isize, HashMap::new());}
                        let map = shifted.get_mut(&(m as isize - self.depth as isize)).unwrap();
                        if !map.contains_key(&p)
                            {map.insert(p, -rnd);}
                        else 
                            {*map.get_mut(&p).unwrap() -= &rnd}
                    }
                    None => continue
                }        
            }
        }

        for max in shifted.keys()
        {
            if *max < 0 && !self.hn.contains_key(&((-max) as usize)) {return false}
            let mut scalars = Vec::new();
            let mut points = Vec::new();
            for (point, scalar) in shifted[max].iter()
            {
                points.push(*point);
                scalars.push(scalar.into_repr());
            }
            table.push
            ((
                VariableBaseMSM::multi_scalar_mul
                (
                    &points,
                    &scalars,
                ).into_affine().prepare(),
                (if *max < 0 {self.hn[&((-max) as usize)]} else {self.hp[*max as usize]}).prepare()
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
    fn eval(&self, elm: F, size: usize) -> Vec<F>;
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

    // This function evaluates polynomial in chunks
    fn eval(&self, elm: F, size: usize) -> Vec<F>
    {
        (0..self.coeffs.len()).step_by(size).map
        (
            |i| Self::from_coefficients_slice
                (&self.coeffs[i..if i+size > self.coeffs.len() {self.coeffs.len()} else {i+size}]).evaluate(elm)
        ).collect()
    }
}
