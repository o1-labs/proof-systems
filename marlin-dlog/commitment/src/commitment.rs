/*****************************************************************************************************************

This source file implements Dlog-based polynomial commitment schema.
The folowing functionality is implemented

1. Commit to polynomial with its max degree 
2. Open polynomial commitment batch at the given evaluation point and scaling factor scalar
    producing the batched opening proof
3. Verify batch of batched opening proofs

*****************************************************************************************************************/

use rand_core::RngCore;
use oracle::rndoracle::{ArithmeticSpongeParams, RandomOracleArgument, ProofError};
use algebra::{PairingEngine, UniformRand, Field, PrimeField, AffineCurve, ProjectiveCurve, VariableBaseMSM};
use ff_fft::DensePolynomial;
pub use super::srs::SRS;

#[derive(Clone)]
pub struct OpeningProof<E: PairingEngine>
{
    pub lr: Vec<(E::G1Affine, E::G1Affine)>,    // vector of rounds of L & R commitments
    pub s: E::Fr,                               // folded witness value revealed
}

impl<E: PairingEngine> SRS<E>
{
    // This function commits the polynomial against SRS instance
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
        let d = self.g.len();
        if d < max || plnm.coeffs.len() > max {return Err(ProofError::PolyCommit)}

        Ok(VariableBaseMSM::multi_scalar_mul
        (
            &self.g[d - max..plnm.len() + d - max],
            &plnm.coeffs.iter().map(|s| s.into_repr()).collect::<Vec<_>>()
        ).into_affine())
    }

    // This function opens polynomial commitments in batch
    //     plnms: batch of polynomials to open commitments for with max degrees
    //     mask: scaling factor for opening commitments in batch
    //     elm: base field element to open the commitment at
    //     oracle_params: parameters for the random oracle argument
    //     RETURN: commitment opening proof
    pub fn open
    (
        &self,
        plnms: &Vec<(DensePolynomial<E::Fr>, usize)>,
        mask: E::Fr,
        elm: E::Fr,
        oracle_params: &ArithmeticSpongeParams::<E::Fr>
    ) -> Result<OpeningProof<E>, ProofError>
    {
        fn recursion<E: PairingEngine>
        (
            srs: &SRS<E>,
            a: &DensePolynomial<E::Fr>,
            b: &DensePolynomial<E::Fr>,
            mut argument: &mut RandomOracleArgument<E>,
        ) -> Result<(Vec<(E::G1Affine, E::G1Affine)>, E::Fr), ProofError>
        {
            if a.coeffs.len() == 1
            {
                return Ok((Vec::new(), a.coeffs[0]))
            }

            // find the nearest 2^
            let mut length = 1;
            while length < a.coeffs.len() {length <<= 1}
            length >>= 1;

            // slice the polynomials into chunks
            let a =
            [
                DensePolynomial::<E::Fr>::from_coefficients_vec(a.coeffs[0..length].to_vec()),
                DensePolynomial::<E::Fr>::from_coefficients_vec(a.coeffs[length..].to_vec())
            ];
            let b =
            [
                DensePolynomial::<E::Fr>::from_coefficients_vec(b.coeffs[0..length].to_vec()),
                DensePolynomial::<E::Fr>::from_coefficients_vec(b.coeffs[length..].to_vec())
            ];

            // slice SRS into chunks
            let g = [srs.g[0..length].to_vec(), srs.g[length..].to_vec()];

            // compute L & R points

            let mut points = g[1].clone();
            points.push(srs.s);
            let mut scalars = (0..g[1].len()).map(|i| a[0][i].into_repr()).collect::<Vec<_>>();
            scalars.push(a[0].dot(&b[1]).into_repr());

            let l = VariableBaseMSM::multi_scalar_mul(&points, &scalars).into_affine();

            let mut points = g[0][0..a[1].len()].to_vec();
            points.push(srs.s);
            let mut scalars = a[1].coeffs.iter().map(|s| s.into_repr()).collect::<Vec<_>>();
            scalars.push(a[1].dot(&b[0]).into_repr());

            let r = VariableBaseMSM::multi_scalar_mul(&points, &scalars).into_affine();

            // absorb L & R points into the argument
            argument.commit_points(&[l, r])?;
            // sample challenge oracle
            let xp = argument.challenge();
            let xn = xp.inverse().unwrap();

            // compute folded polynoms
            let a = &a[0].scale(xp) + &a[1].scale(xn);
            let b = &b[0].scale(xn) + &b[1].scale(xp);

            // compute folded srs
            let g: Vec<E::G1Affine> = (0..length).map
            (
                |i| {(g[0][i].mul(xn) + &{if i<g[1].len() {g[1][i].mul(xp)} else {E::G1Projective::zero()}}).into_affine()}
            ).collect();

            match recursion(&SRS::<E>{g, s:srs.s}, &a, &b, &mut argument)
            {
                Ok(c) => {Ok({let mut result: Vec<(E::G1Affine, E::G1Affine)> = vec![(l, r)]; result.extend(c.0); (result, c.1)})}
                Err(err) => {Err(err)}
            }
        }

        let mut p = DensePolynomial::<E::Fr>::zero();
        
        // randomise/scale the polynoms in accumulator shifted to the end of SRS
        let max = plnms.iter().map(|p| p.1).max().map_or(Err(ProofError::RuntimeEnv), |s| Ok(s))?;
        let dim = plnms.iter().map(|p| p.0.coeffs.len()).max().map_or(Err(ProofError::RuntimeEnv), |s| Ok(s))?;
        if dim > max {return Err(ProofError::PolyCommit)}

        let mut scale = E::Fr::one();
        for x in plnms.iter()
        {
            scale *= &mask;
            p += &(x.0.shiftr(max-x.1).scale(scale));
        }

        let mut acc = E::Fr::one();
        let b = DensePolynomial::<E::Fr>::from_coefficients_vec((0..p.coeffs.len()).map(|_| {let r = acc; acc *= &elm; r}).collect::<Vec<_>>());

        let d = self.g.len();
        let mut argument = RandomOracleArgument::<E>::new(oracle_params.clone());
        match recursion (&SRS::<E>{g:self.g[d - max..dim + d - max].to_vec(), s:self.s}, &p, &b, &mut argument)
        {
            Ok(proof) => Ok(OpeningProof::<E>{lr: proof.0, s: proof.1}),
            Err(err) => Err(err)
        }
    }

    // This function verifies batch of batched polynomial commitment opening proofs
    //     batch: batch of batched polynomial commitment opening proofs
    //          evaluation point
    //          scaling factor for this batched openinig proof
    //          batch/vector of polycommitments (opened in this batch), evaluations and max degrees
    //          opening proof for this batched opening
    //     oracle_params: parameters for the random oracle argument
    //     randomness source context
    //     RETURN: verification status
    pub fn verify
    (
        &self,
        batch: &Vec
        <(
            E::Fr,
            E::Fr,
            Vec<(E::G1Affine, E::Fr, usize)>,
            OpeningProof<E>,
        )>,
        oracle_params: &ArithmeticSpongeParams::<E::Fr>,
        rng: &mut dyn RngCore
    ) -> bool
    {
        let mut points = Vec::new();
        let mut scalars = Vec::new();

        for proof in batch.iter()
        {
            // sample randomiser to scale the proofs with
            let rnd = E::Fr::rand(rng);

            // sample random oracles
            let mut argument = RandomOracleArgument::<E>::new(oracle_params.clone());
            let mut xp = (proof.3).lr.iter().map
            (
                |lr|
                {
                    argument.commit_points(&[lr.0, lr.1]).unwrap();
                    argument.challenge()
                }
            ).collect::<Vec<_>>();
            xp.reverse();
            let mut xn = xp.clone();
            algebra::fields::batch_inversion::<E::Fr>(&mut xn);
            
            let length = (2 as usize).pow((proof.3).lr.len() as u32);

            // precompute powers of x
            let mut acc = E::Fr::one();
            let b = (0..length).map(|_| {let r = acc; acc *= &proof.0; r}).collect::<Vec<_>>();

            // compute <x^, s> logarithmically, adjust later for the padding
            let mut bf = (0..xp.len()).map(|i| xp[i] * &b[(2 as usize).pow(i as u32)] + &xn[i])
                .fold(E::Fr::one(), |x, y| x * &y);

            let mut s: Vec<E::Fr> = vec![E::Fr::zero(); length];
            s[0] = xp.iter().map(|s| s).fold(E::Fr::one(), |x, y| x * y).inverse().unwrap();

            let xp = xp.iter().map(|s| s.square()).collect::<Vec<_>>();
            let mut xn = xp.clone();
            algebra::fields::batch_inversion::<E::Fr>(&mut xn);

            // prepare multiexp array for L^x^2*P*R^x^-2
            let max = proof.2.iter().map(|p| p.2).max().unwrap();
            let mut scale = E::Fr::one();
            for i in 0..proof.2.len()
            {
                scale *= &proof.1;
                points.push(-proof.2[i].0);
                scalars.push((scale * &rnd).into_repr());
                points.push(-self.s);
                scalars.push((proof.2[i].1 * &rnd * &scale * &proof.0.pow([(max - proof.2[i].2) as u64])).into_repr());
            }
            for (lr, (p, n)) in (proof.3).lr.iter().zip(xp.iter().rev().zip(xn.iter().rev()))
            {
                points.push(-lr.0);
                scalars.push((*p * &rnd).into_repr());
                points.push(-lr.1);
                scalars.push((*n * &rnd).into_repr());
            }

            // compute s scalars
            let mut k: usize = 0;
            let mut pow: usize = 1;
            for i in 1..length
            {
                k += if i == pow {1} else {0};
                pow <<= if i == pow {1} else {0};
                s[i] = s[i-(pow>>1)] * &xp[k-1];
            }

            // adjust bf for the padding
            bf -= &(max..s.len()).map(|i| s[i] * &b[i]).fold(E::Fr::zero(), |x, y| x + &y);

            // prepare multiexp array for <G, s>
            let d = self.g.len();
            points.push(self.s);
            scalars.push(((proof.3).s * &rnd * &bf).into_repr());
            points.extend(self.g[d - max..].to_vec());
            scalars.extend((0..self.g[d - max..].len()).map(|i| ((proof.3).s * &rnd * &s[i]).into_repr()).collect::<Vec<_>>());
        }
        // verify the equation
        VariableBaseMSM::multi_scalar_mul(&points, &scalars) == E::G1Projective::zero()
    }
}

pub trait Utils<F: Field>
{
    fn scale(&self, elm: F) -> Self;
    fn shiftr(&self, size: usize) -> Self;
    fn dot(&self, other: &Self) -> F;
}

impl<F: Field> Utils<F> for DensePolynomial<F>
{
    // This function "scales" (multiplies) polynomaial with a scalar
    // It is implemented to have the desired functionality for DensePolynomial
    fn scale(&self, elm: F) -> Self
    {
        let mut result = self.clone();
        for coeff in &mut result.coeffs {*coeff *= &elm}
        result
    }

    fn shiftr(&self, size: usize) -> Self
    {
        let mut result = vec![F::zero(); size];
        result.extend(self.coeffs.clone());
        DensePolynomial::<F>::from_coefficients_vec(result)
    }

    fn dot(&self, other: &Self) -> F
    {
        self.coeffs.iter().zip(other.coeffs.iter()).map(|(a, b)| *a * b).fold(F::zero(), |x, y| x + &y)
    }
}

pub trait Multiply<C: AffineCurve>
{
    fn scale(&self, elm: C::ScalarField) -> Self;
}

impl<C: AffineCurve> Multiply<C> for Vec<C>
{
    fn scale(&self, elm: C::ScalarField) -> Self
    {
        self.iter().map(|p| p.mul(elm).into_affine()).collect()
    }
}
