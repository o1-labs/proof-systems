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

    // This function queries random oracle values from non-interactive
    // argument context by verifier
    pub fn oracles
        <EFqSponge: FqSponge<E::Fq, E::G1Affine, E::Fr>,
         EFrSponge: FrSponge<E::Fr>,
        >
    (
        &self,
        index: &Index<E>
    ) -> Result<RandomOracles<E::Fr>, ProofError>
    {
        let mut oracles = RandomOracles::<E::Fr>::zero();
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        // absorb the public a, b, c polycommitments into the argument
        fq_sponge.absorb_g(&[self.a_comm, self.b_comm, self.c_comm]);
        // sample beta, gamma oracles
        oracles.beta = fq_sponge.challenge();
        oracles.gamma = fq_sponge.challenge();

        // absorb the z commitment into the argument and query alpha
        fq_sponge.absorb_g(&[self.z_comm]);
        oracles.alpha = fq_sponge.challenge();

        // absorb the polycommitments into the argument and sample zeta
        fq_sponge.absorb_g(&[self.tlow_comm, self.tmid_comm, self.thgh_comm]);
        oracles.zeta = fq_sponge.challenge();
        // query opening scaler challenge
        oracles.v = fq_sponge.challenge();

        Ok(oracles)
    }
}
