/********************************************************************************************

This source file implements zk-proof batch verifier functionality.

*********************************************************************************************/

use rand_core::RngCore;
use crate::index::{VerifierIndex as Index};
use oracle::rndoracle::{ProofError};
pub use super::prover::{ProverProof, RandomOracles};
use algebra::{/*Field,*/ PairingEngine};
//use ff_fft::{DensePolynomial, Evaluations};
use oracle::sponge::{FqSponge/*, ScalarChallenge*/};
use crate::plonk_sponge::FrSponge;

impl<E: PairingEngine> ProverProof<E>
{
    // This function verifies the batch of zk-proofs
    //     proofs: vector of Plonk proofs
    //     index: Index
    //     rng: randomness source context
    //     RETURN: verification status
    pub fn verify
        <EFqSponge: FqSponge<E::Fq, E::G1Affine, E::Fr>,
         EFrSponge: FrSponge<E::Fr>,
        >
    (
        _proofs: &Vec<ProverProof<E>>,
        _index: &Index<E>,
        _rng: &mut dyn RngCore
    ) -> Result<bool, ProofError>
    {
        Err(ProofError::ProofCreation)
    }
}
