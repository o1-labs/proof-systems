/********************************************************************************************

This source file implements prover's zk-proof primitive.

*********************************************************************************************/

use algebra::{Field, PairingEngine};
use oracle::rndoracle::{ProofError};
//use ff_fft::{DensePolynomial, Evaluations};
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
    pub _x: E::G1Affine,

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
        _witness: &Vec::<E::Fr>,
        _index: &Index<E>
    ) -> Result<Self, ProofError>
    {
        Err(ProofError::ProofCreation)
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
