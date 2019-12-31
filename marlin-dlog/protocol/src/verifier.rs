/********************************************************************************************

This source file implements zk-proof batch verifier functionality.

*********************************************************************************************/

use rand_core::RngCore;
use circuits::index::Index;
use oracle::rndoracle::{ProofError, RandomOracleArgument};
pub use super::prover::{ProverProof, RandomOracles};
use algebra::{Field, PairingEngine};
use ff_fft::Evaluations;

impl<E: PairingEngine> ProverProof<E>
{
    // This function verifies the prover's first sumcheck argument values
    //     index: Index
    //     oracles: random oracles of the argument
    //     RETURN: verification status
    pub fn sumcheck_1_verify
    (
        &self,
        index: &Index<E>,
        oracles: &RandomOracles<E::Fr>,
    ) -> bool
    {
        // compute ra*zm - ram*z ?= h*v + b*g to verify the first sumcheck argument
        (oracles.alpha.pow([index.h_group.size]) - &oracles.beta[0].pow([index.h_group.size])) *
            &(0..3).map
            (
                |i|
                {
                    match i
                    {
                        0 => {self.za_eval * &oracles.eta_a}
                        1 => {self.zb_eval * &oracles.eta_b}
                        2 => {self.za_eval * &self.zb_eval * &oracles.eta_c}
                        _ => {E::Fr::zero()}
                    }
                }
            ).fold(E::Fr::zero(), |x, y| x + &y)
        ==
        (oracles.alpha - &oracles.beta[0]) *
        &(
            self.h1_eval * &index.h_group.evaluate_vanishing_polynomial(oracles.beta[0]) +
            &(oracles.beta[0] * &self.g1_eval) +
            &(self.sigma2 * &index.h_group.size_as_field_element *
            &(self.w_eval * &index.x_group.evaluate_vanishing_polynomial(oracles.beta[0]) +
            // interpolating/evaluating public input over small domain x_group
            // TODO: investigate which of the below is faster
            &Evaluations::<E::Fr>::from_vec_and_domain(self.public.clone(), index.x_group).interpolate().evaluate(oracles.beta[0])))
            /*
            &index.x_group.evaluate_all_lagrange_coefficients(oracles.beta[0])
            .iter()
            .zip(self.public.iter())
            .map(|(l, x)| *l * x)
            .fold(E::Fr::zero(), |x, y| x + &y)))
            */
        )
    }

    // This function verifies the prover's second sumcheck argument values
    //     index: Index
    //     oracles: random oracles of the argument
    //     RETURN: verification status
    pub fn sumcheck_2_verify
    (
        &self,
        index: &Index<E>,
        oracles: &RandomOracles<E::Fr>,
    ) -> bool
    {
        self.sigma3 * &index.k_group.size_as_field_element *
            &((oracles.alpha.pow([index.h_group.size]) - &oracles.beta[1].pow([index.h_group.size])))
        ==
        (oracles.alpha - &oracles.beta[1]) * &(self.h2_eval *
            &index.h_group.evaluate_vanishing_polynomial(oracles.beta[1]) +
            &self.sigma2 + &(self.g2_eval * &oracles.beta[1]))
    }

    // This function verifies the prover's third sumcheck argument values
    //     index: Index
    //     oracles: random oracles of the argument
    //     RETURN: verification status
    pub fn sumcheck_3_verify
    (
        &self,
        index: &Index<E>,
        oracles: &RandomOracles<E::Fr>
    ) -> bool
    {
        let crb: Vec<E::Fr> = (0..3).map
        (
            |i| {(oracles.beta[1] - &self.row_eval[i]) * &(oracles.beta[0] - &self.col_eval[i])}
        ).collect();

        let acc = (0..3).map
        (
            |i|
            {
                let mut x = self.val_eval[i] * &[oracles.eta_a, oracles.eta_b, oracles.eta_c][i];
                for j in 0..3 {if i != j {x *= &crb[j]}}
                x
            }
        ).fold(E::Fr::zero(), |x, y| x + &y);

        index.k_group.evaluate_vanishing_polynomial(oracles.beta[2]) * &self.h3_eval
        ==
        index.h_group.evaluate_vanishing_polynomial(oracles.beta[0]) *
            &(index.h_group.evaluate_vanishing_polynomial(oracles.beta[1])) *
            &acc - &((oracles.beta[2] * &self.g3_eval + &self.sigma3) *
            &crb[0] * &crb[1] * &crb[2])
    }

    // This function verifies the batch of zk-proofs
    //     proofs: vector of Marlin proofs
    //     index: Index
    //     rng: randomness source context
    //     RETURN: verification status
    pub fn verify
    (
        proofs: &Vec<ProverProof<E>>,
        index: &Index<E>,
        rng: &mut dyn RngCore
    ) -> Result<bool, ProofError>
    {
        let mut batch = Vec::with_capacity(proofs.len() * 3);
        for proof in proofs.iter()
        {
            let proof = proof.clone();
            let oracles = proof.oracles(index)?;

            // first, verify the sumcheck argument values
            if 
                !proof.sumcheck_1_verify (index, &oracles) ||
                !proof.sumcheck_2_verify (index, &oracles) ||
                !proof.sumcheck_3_verify (index, &oracles)
            {
                return Err(ProofError::ProofVerification)
            }

            batch.push
            ((
                oracles.beta[0],
                oracles.batch,
                vec!
                [
                    (proof.za_comm, proof.za_eval, index.h_group.size()),
                    (proof.zb_comm, proof.zb_eval, index.h_group.size()),
                    (proof.w_comm,  proof.w_eval,  index.h_group.size() - index.x_group.size()),
                    (proof.h1_comm, proof.h1_eval, index.h_group.size()*2-2),
                    (proof.g1_comm, proof.g1_eval, index.h_group.size()-1),
                ],
                proof.proof1
            ));
            batch.push
            ((
                oracles.beta[1],
                oracles.batch,
                vec!
                [
                    (proof.h2_comm, proof.h2_eval, index.h_group.size()-1),
                    (proof.g2_comm, proof.g2_eval, index.h_group.size()-1),
                ],
                proof.proof2
            ));
            batch.push
            ((
                oracles.beta[2],
                oracles.batch,
                vec!
                [
                    (proof.h3_comm, proof.h3_eval, index.k_group.size()*6-6),
                    (proof.g3_comm, proof.g3_eval, index.k_group.size()-1),
                    (index.compiled[0].row_comm, proof.row_eval[0], index.k_group.size()),
                    (index.compiled[1].row_comm, proof.row_eval[1], index.k_group.size()),
                    (index.compiled[2].row_comm, proof.row_eval[2], index.k_group.size()),
                    (index.compiled[0].col_comm, proof.col_eval[0], index.k_group.size()),
                    (index.compiled[1].col_comm, proof.col_eval[1], index.k_group.size()),
                    (index.compiled[2].col_comm, proof.col_eval[2], index.k_group.size()),
                    (index.compiled[0].val_comm, proof.val_eval[0], index.k_group.size()),
                    (index.compiled[1].val_comm, proof.val_eval[1], index.k_group.size()),
                    (index.compiled[2].val_comm, proof.val_eval[2], index.k_group.size()),
                ],
                proof.proof3
            ));
        }
        // second, verify the commitment opening proofs
        match index.srs.verify(&batch, &index.oracle_params.clone(), rng)
        {
            false => Err(ProofError::OpenProof),
            true => Ok(true)
        }
    }

    // This function queries random oracle values from non-interactive
    // argument context by verifier
    pub fn oracles
    (
        &self,
        index: &Index<E>,
    ) -> Result<RandomOracles<E::Fr>, ProofError>
    {
        let mut oracles = RandomOracles::<E::Fr>::zero();
        let mut argument = RandomOracleArgument::<E>::new(index.oracle_params.clone());

        // absorb previous proof context into the argument
        argument.commit_scalars(&[E::Fr::one()]);
        // absorb the public input into the argument
        argument.commit_scalars(&self.public[..]);
        // absorb W, ZA, ZB polycommitments
        argument.commit_points(&[self.w_comm, self.za_comm, self.zb_comm])?;
        // sample alpha, eta[0..3] oracles
        oracles.alpha = argument.challenge();
        oracles.eta_a = argument.challenge();
        oracles.eta_b = argument.challenge();
        oracles.eta_c = argument.challenge();
        // absorb H1, G1 polycommitments
        argument.commit_points(&[self.h1_comm, self.g1_comm])?;
        // sample beta[0] oracle
        oracles.beta[0] = argument.challenge();
        // absorb sigma2 scalar
        argument.commit_scalars(&[self.sigma2]);
        // sample beta[1] oracle
        oracles.beta[1] = argument.challenge();
        // absorb sigma3 scalar
        argument.commit_scalars(&[self.sigma3]);
        // sample beta[2] & batch oracles
        oracles.beta[2] = argument.challenge();
        oracles.batch = argument.challenge();

        Ok(oracles)
    }
}
