/*****************************************************************************************************************

This source file implements Dlog-based polynomial commitment schema.
The folowing functionality is implemented

1. Commit to polynomial with its max degree 
2. Open polynomial commitment batch at the given evaluation point and scaling factor scalar
    producing the batched opening proof
3. Verify batch of batched opening proofs

*****************************************************************************************************************/

use oracle::FqSponge;
use rand_core::RngCore;
use oracle::rndoracle::{ArithmeticSpongeParams, ProofError};
use algebra::{UniformRand, Field, PrimeField, AffineCurve, ProjectiveCurve, VariableBaseMSM};
use ff_fft::DensePolynomial;
use super::srs::SRS;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

#[derive(Clone)]
pub struct OpeningProof<G: AffineCurve>
{
    pub lr: Vec<(G, G)>,    // vector of rounds of L & R commitments
    pub s: Fr<G>,           // folded witness value revealed
}

impl<G: AffineCurve> SRS<G>
{
    // This function commits the polynomial against SRS instance with degree bound
    //     plnm: polynomial to commit
    //     max: maximal degree of the polynomial
    //     RETURN: commitment group elements: unshifted, shifted
    pub fn commit_with_degree_bound
    (
        &self,
        plnm: &DensePolynomial<Fr<G>>,
        max: usize,
    ) -> Result<(G, G), ProofError>
    {
        let d = self.g.len();
        if d < max || plnm.coeffs.len() > max {return Err(ProofError::PolyCommit)}

        Ok
        ((
            self.commit_no_degree_bound(&plnm)?,
            VariableBaseMSM::multi_scalar_mul
            (
                &self.g[d - max..plnm.len() + d - max],
                &plnm.coeffs.iter().map(|s| s.into_repr()).collect::<Vec<_>>()
            ).into_affine()
        ))
    }

    // This function commits the polynomial against SRS instance without degree bound
    //     plnm: polynomial to commit
    //     RETURN: commitment group element
    pub fn commit_no_degree_bound
    (
        &self,
        plnm: &DensePolynomial<Fr<G>>,
    ) -> Result<G, ProofError>
    {
        if self.g.len() < plnm.coeffs.len() {return Err(ProofError::PolyCommit)}

        Ok(VariableBaseMSM::multi_scalar_mul
        (
            &self.g[0..plnm.coeffs.len()],
            &plnm.coeffs.iter().map(|s| s.into_repr()).collect::<Vec<_>>()
        ).into_affine())
    }

    // This function runs rounds of commitment opening recursion
    fn recursion
        <EFqSponge: FqSponge<Fq<G>, G, Fr<G>>>
    (
        srs: &SRS<G>,
        a: &DensePolynomial<Fr<G>>,
        b: &DensePolynomial<Fr<G>>,
        sponge: &mut EFqSponge,
    ) -> Result<(Vec<(G, G)>, Fr<G>), ProofError>
    {
        if a.coeffs.len() == 1
        {
            return Ok((Vec::new(), a.coeffs[0]))
        }

        // find the nearest 2^
        let mut length = 1;
        while length < srs.g.len() {length <<= 1}
        length >>= 1;

        // slice the polynomials into chunks
        let a = if a.len() > length
        {[
            DensePolynomial::<Fr<G>>::from_coefficients_vec(a.coeffs[0..length].to_vec()),
            DensePolynomial::<Fr<G>>::from_coefficients_vec(a.coeffs[length..].to_vec())
        ]}
        else
        {[
            DensePolynomial::<Fr<G>>::from_coefficients_vec(a.coeffs.clone()),
            DensePolynomial::<Fr<G>>::zero()
        ]};
        let b =
        [
            DensePolynomial::<Fr<G>>::from_coefficients_vec(b.coeffs[0..length].to_vec()),
            DensePolynomial::<Fr<G>>::from_coefficients_vec(b.coeffs[length..].to_vec())
        ];

        // slice SRS into chunks
        let g = [srs.g[0..length].to_vec(), srs.g[length..].to_vec()];

        // compute L & R points

        let min = if g[1].len() < a[0].len() {g[1].len()} else {a[0].len()};
        let mut points = g[1][0..min].to_vec();
        points.push(srs.s);
        let mut scalars = (0..min).map(|i| a[0][i].into_repr()).collect::<Vec<_>>();
        scalars.push(a[0].dot(&b[1]).into_repr());

        let l = VariableBaseMSM::multi_scalar_mul(&points, &scalars).into_affine();

        let mut points = g[0][0..a[1].len()].to_vec();
        points.push(srs.s);
        let mut scalars = a[1].coeffs.iter().map(|s| s.into_repr()).collect::<Vec<_>>();
        scalars.push(a[1].dot(&b[0]).into_repr());

        let r = VariableBaseMSM::multi_scalar_mul(&points, &scalars).into_affine();

        // absorb L & R points into the argument
        sponge.absorb_g(&l);
        sponge.absorb_g(&r);
        // sample challenge oracle
        let xp = sponge.challenge();
        let xn = xp.inverse().unwrap();

        // compute folded polynoms
        let a = &a[0].scale(xp) + &a[1].scale(xn);
        let b = &b[0].scale(xn) + &b[1].scale(xp);

        // compute folded srs
        let g: Vec<G> = (0..length).map
        (
            |i| {(g[0][i].mul(xn) + &{if i<g[1].len() {g[1][i].mul(xp)} else {G::Projective::zero()}}).into_affine()}
        ).collect();

        match Self::recursion(&SRS::<G>{g, s:srs.s}, &a, &b, sponge)
        {
            Ok(c) => {Ok({let mut result: Vec<(G, G)> = vec![(l, r)]; result.extend(c.0); (result, c.1)})}
            Err(err) => {Err(err)}
        }
    }

    // This function opens polynomial commitments in batch
    //     plnms: batch of polynomials to open commitments for with, optionally, max degrees
    //     elm: evaluation point vector to open the commitments at
    //     polyscale: polynomial scaling factor for opening commitments in batch
    //     evalscale: eval scaling factor for opening commitments in batch
    //     oracle_params: parameters for the random oracle argument
    //     RETURN: commitment opening proof
    pub fn open
        <EFqSponge: FqSponge<Fq<G>, G, Fr<G>>>
    (
        &self,
        plnms: &Vec<(DensePolynomial<Fr<G>>, Option<usize>)>,   // vector of polynomial with optional degree bound
        elm: &Vec<Fr<G>>,                                       // vector of evaluation points
        polyscale: Fr<G>,                                       // scaling factor for polynoms
        evalscale: Fr<G>,                                       // scaling factor for evaluation point powers
        oracle_params: &ArithmeticSpongeParams::<Fq<G>>         // parameters for the random oracle argument
    ) -> Result<OpeningProof<G>, ProofError>
    {
        let d = self.g.len();
        let mut p = DensePolynomial::<Fr<G>>::zero();
        
        // randomise/scale the polynoms in accumulator shifted, if bounded, to the end of SRS
        let mut scale = Fr::<G>::one();
        for x in plnms.iter()
        {
            match x.1
            {
                Some(m) =>
                {
                    scale *= &polyscale;
                    // mixing in the shifted polynom since degree is bounded
                    p += &(x.0.shiftr(d-m).scale(scale));
                }
                _ => {}
            }
            scale *= &polyscale;
            // always mixing in the unshifted polynom
            p += &(x.0.scale(scale));
        }

        // randomise/scale the eval powers
        let mut scale = Fr::<G>::one();
        let b = elm.iter().map
        (
            |elm|
            {
                let mut acc = Fr::<G>::one();
                DensePolynomial::<Fr<G>>::from_coefficients_vec((0..d).map(|_| {let r = acc; acc *= &elm; r}).collect::<Vec<_>>())
            }
        ).fold(DensePolynomial::<Fr<G>>::zero(), |x, y| {scale *= &evalscale; &x + &y.scale(scale)});
        

        let mut sponge = EFqSponge::new(oracle_params.clone());
        match Self::recursion (&self, &p, &b, &mut sponge)
        {
            Ok(proof) => Ok(OpeningProof::<G>{lr: proof.0, s: proof.1}),
            Err(err) => Err(err)
        }
    }

    // This function verifies batch of batched polynomial commitment opening proofs
    //     batch: batch of batched polynomial commitment opening proofs
    //          vector of evaluation points
    //          polynomial scaling factor for this batched openinig proof
    //          eval scaling factor for this batched openinig proof
    //          batch/vector of polycommitments (opened in this batch), evaluation vectors and, optionally, max degrees
    //          opening proof for this batched opening
    //     oracle_params: parameters for the random oracle argument
    //     randomness source context
    //     RETURN: verification status
    pub fn verify
        <EFqSponge: FqSponge<Fq<G>, G, Fr<G>>>
    (
        &self,
        batch: &Vec
        <(
            Vec<Fr<G>>,             // vector of evaluation points
            Fr<G>,                  // scaling factor for polynoms
            Fr<G>,                  // scaling factor for evaluation point powers
            Vec
            <(
                G,                  // unshifted polycommitment
                Vec<Fr<G>>,         // vector of evaluations
                Option<(G, usize)>  // shifted polycommitment and degree bound
            )>,
            OpeningProof<G>,        // batched opening proof
        )>,
        oracle_params: &ArithmeticSpongeParams::<Fq<G>>,
        rng: &mut dyn RngCore
    ) -> bool
    {
        let d = self.g.len();
        let mut points = Vec::new();
        let mut scalars = Vec::new();

        for proof in batch.iter()
        {
            // sample randomiser to scale the proofs with
            let rnd = Fr::<G>::rand(rng);

            // sample random oracles
            let mut fq_sponge = EFqSponge::new(oracle_params.clone());
            let mut xp = (proof.4).lr.iter().map
            (
                |(l, r)|
                {
                    fq_sponge.absorb_g(l);
                    fq_sponge.absorb_g(r);
                    fq_sponge.challenge()
                }
            ).collect::<Vec<_>>();
            xp.reverse();
            let mut xn = xp.clone();
            algebra::fields::batch_inversion::<Fr<G>>(&mut xn);
            
            let length = (2 as usize).pow((proof.4).lr.len() as u32);

            // precompute randomised/scaled eval power linear combinations
            let b = proof.0.iter().map
            (
                |elm|
                {
                    let mut acc = Fr::<G>::one();
                    DensePolynomial::<Fr<G>>::from_coefficients_vec((0..length).map(|_| {let r = acc; acc *= &elm; r}).collect::<Vec<_>>())
                }
            ).collect::<Vec<DensePolynomial<Fr<G>>>>();

            // compute <x^, s> logarithmically, adjust later for the padding
            let mut scale = Fr::<G>::one();
            let mut bf = b.iter().map
            (
                |bb| 
                {
                    (0..xp.len())
                        .map(|i| xp[i] * &bb.coeffs[(2 as usize).pow(i as u32)] + &xn[i])
                        .fold(Fr::<G>::one(), |x, y| x * &y)
                }
            ).fold(Fr::<G>::zero(), |x, y| {scale *= &proof.2; x + &(y * &scale)});

            let mut scale = Fr::<G>::one();
            let b = b.iter().fold(DensePolynomial::<Fr<G>>::zero(), |x, y| {scale *= &proof.2; &x + &y.scale(scale)}).coeffs;

            let mut s: Vec<Fr<G>> = vec![Fr::<G>::zero(); length];
            s[0] = xp.iter().fold(Fr::<G>::one(), |x, y| x * y).inverse().unwrap();

            let xp = xp.iter().map(|s| s.square()).collect::<Vec<_>>();
            let mut xn = xp.clone();
            algebra::fields::batch_inversion::<Fr<G>>(&mut xn);

            // prepare multiexp array for L^x^2*P*R^x^-2
            let mut scale1 = Fr::<G>::one();
            for i in 0..proof.3.len()
            {
                match proof.3[i].2
                {
                    Some(c) =>
                    {
                        scale1 *= &proof.1;
                        // mixing in the shifted polynom since degree is bounded
                        points.push(-c.0);
                        scalars.push((scale1 * &rnd).into_repr());
                        points.push(-self.s);
                        let mut scale2 = Fr::<G>::one();
                        scalars.push
                        ((
                            (0..proof.3[i].1.len())
                                .map(|j| proof.3[i].1[j] * &proof.0[j].pow([(d-c.1) as u64]))
                                .fold(Fr::<G>::zero(), |x, y| {scale2 *= &proof.2; x + &(scale2 * &y)})
                            * &rnd * &scale1
                        ).into_repr());
                    }
                    _ => {}
                }
                scale1 *= &proof.1;
                // always mixing in the unshifted polynom
                points.push(-proof.3[i].0);
                scalars.push((scale1 * &rnd).into_repr());
                points.push(-self.s);
                let mut scale2 = Fr::<G>::one();
                scalars.push
                ((
                    proof.3[i].1.iter().fold(Fr::<G>::zero(), |x, y| {scale2 *= &proof.2; x + &(scale2 * y)})
                    * &rnd * &scale1
                ).into_repr());
            }
            for (lr, (p, n)) in (proof.4).lr.iter().zip(xp.iter().rev().zip(xn.iter().rev()))
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
            bf -= &(d..s.len())
                .map(|i| s[i] * &b[i])
                .fold(Fr::<G>::zero(), |x, y| x + &y);

            // prepare multiexp array for <G, s>
            points.push(self.s);
            scalars.push(((proof.4).s * &rnd * &bf).into_repr());
            points.extend(self.g.clone());
            scalars.extend((0..d)
                .map(|i| ((proof.4).s * &rnd * &s[i]).into_repr())
                .collect::<Vec<_>>());
        }
        // verify the equation
        VariableBaseMSM::multi_scalar_mul(&points, &scalars) == G::Projective::zero()
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
