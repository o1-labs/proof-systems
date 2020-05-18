/********************************************************************************************

This source file implements prover's zk-proof primitive.

*********************************************************************************************/

use rand_core::RngCore;
use algebra::{Field, PairingEngine, UniformRand};
use oracle::rndoracle::{ProofError};
use ff_fft::{DensePolynomial, SparsePolynomial, Evaluations};
//use commitment_pairing::commitment::Utils;
pub use super::index::Index;
use oracle::sponge::{FqSponge/*, ScalarChallenge*/};
use crate::plonk_sponge::FrSponge;

#[derive(Clone)]
pub struct ProofEvaluations<Fr> {
    pub _x: Fr,
}

#[derive(Clone)]
pub struct ProverProof<E: PairingEngine>
{
    // polynomial commitments
    pub a: E::G1Affine,
    pub b: E::G1Affine,
    pub c: E::G1Affine,

    // batched commitment opening proofs

    // polynomial evaluations

    // prover's scalars

    // public part of the witness
}

impl<E: PairingEngine> ProverProof<E>
{
    // This function constructs prover's zk-proof from the witness & the Index against URS instance
    //     witness: computation witness
    //     index: Index
    //     RETURN: prover's zk-proof
    pub fn create
        <EFqSponge: FqSponge<E::Fq, E::G1Affine, E::Fr>,
         EFrSponge: FrSponge<E::Fr>,
        >
    (
        witness: &Vec::<E::Fr>,
        index: &Index<E>,
        rng: &mut dyn RngCore
    ) -> Result<Self, ProofError>
    {
        let mut l = Evaluations::<E::Fr>::from_vec_and_domain(index.cs.gates.iter().map(|gate| witness[gate.l]).collect(), index.cs.domain).interpolate();
        let mut r = Evaluations::<E::Fr>::from_vec_and_domain(index.cs.gates.iter().map(|gate| index.cs.r*&witness[gate.r]).collect(), index.cs.domain).interpolate();
        let mut o = Evaluations::<E::Fr>::from_vec_and_domain(index.cs.gates.iter().map(|gate| index.cs.o*&witness[gate.o]).collect(), index.cs.domain).interpolate();

        // query the blinders
        let bl = (0..9).map(|_| E::Fr::rand(rng)).collect::<Vec<_>>();

        l += &SparsePolynomial::from_coefficients_slice(&[(0, bl[1]), (1, bl[0])]).mul(&index.cs.domain.vanishing_polynomial()).into();
        r += &SparsePolynomial::from_coefficients_slice(&[(0, bl[3]), (1, bl[2])]).mul(&index.cs.domain.vanishing_polynomial()).into();
        o += &SparsePolynomial::from_coefficients_slice(&[(0, bl[5]), (1, bl[4])]).mul(&index.cs.domain.vanishing_polynomial()).into();

        // commit to the a, b, c wire values
        let a = index.urs.get_ref().commit(&l)?;
        let b = index.urs.get_ref().commit(&r)?;
        let c = index.urs.get_ref().commit(&o)?;

        // the transcript of the random oracle non-interactive argument
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        // absorb the public input and W, ZA, ZB polycommitments into the argument
        fq_sponge.absorb_g(&[a, b, c]);

        // sample beta, gamma oracles
        let beta = fq_sponge.challenge();
        let gamma = fq_sponge.challenge();

        // compute permutation polynomial

        let mut denominators = (1..index.cs.domain.size()).map
        (
            |j|
                (witness[index.cs.gates[j].l] + &(index.cs.sigma[0][j] * &beta) + &gamma) *&
                (witness[index.cs.gates[j].r] + &(index.cs.sigma[1][j] * &beta) + &gamma) *&
                (witness[index.cs.gates[j].o] + &(index.cs.sigma[2][j] * &beta) + &gamma)
        ).collect::<Vec<_>>();
        algebra::fields::batch_inversion::<E::Fr>(&mut denominators);

        let mut coeffs = (1..index.cs.domain.size()).map
        (
            |j|
                (witness[index.cs.gates[j].l] + &(index.cs.sid[j] * &beta) + &gamma) *&
                (witness[index.cs.gates[j].r] + &(index.cs.sid[j] * &beta * &index.cs.r) + &gamma) *&
                (witness[index.cs.gates[j].o] + &(index.cs.sid[j] * &beta * &index.cs.o) + &gamma)
        ).collect::<Vec<_>>();
        (1..coeffs.len()).for_each(|i| {let x = coeffs[i-1]; coeffs[i] *= &(x * &denominators[i])});
        coeffs.insert(0, E::Fr::one());
        
        let z = &Evaluations::<E::Fr>::from_vec_and_domain(coeffs, index.cs.domain).interpolate() +
            &SparsePolynomial::from_coefficients_slice(&[(0, bl[8]), (1, bl[7]), (2, bl[6])]).mul(&index.cs.domain.vanishing_polynomial()).into();

        // commit to z
        let z = index.urs.get_ref().commit(&z)?;

        // absorb the z commitment into the argument and query alpha
        fq_sponge.absorb_g(&[z]);
        let alpha = fq_sponge.challenge();

        // compute public input polynomial
        let p = Evaluations::<E::Fr>::from_vec_and_domain((0..index.cs.public).map(|i| witness[i]).collect::<Vec<_>>(), index.cs.domain);

        // compute quotient polynomial

        Ok(Self
        {
            a,
            b,
            c,
        })
    }
}

pub struct RandomOracles<F: Field>
{
    pub _x: F,
}

impl<F: Field> RandomOracles<F>
{
    pub fn zero () -> Self
    {
        Self
        {
            _x: F::zero(),
        }
    }
}
