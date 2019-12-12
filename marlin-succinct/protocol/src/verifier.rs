/********************************************************************************************

This source file implements prover's zk-proof primitive.

*********************************************************************************************/

use rand_core::RngCore;
use circuits::index::Index;
use oracle::rndoracle::{ProofError, RandomOracleArgument};
pub use super::prover::{ProverProof, RandomOracles};
use algebra::{Field, PrimeField, PairingEngine};
use ff_fft::Evaluations;

impl<E: PairingEngine> ProverProof<E>
{
    // This function verifies the prover's first sumcheck argument values
    //     index: Index
    //     oracles: random oraclrs of the argument
    //     RETURN: verification status
    pub fn sumcheck_1_verify
    (
        &self,
        index: &Index<E>,
        oracles: &RandomOracles<E::Fr>,
    ) -> bool
    {
        let mut rzrzg = E::Fr::zero();
        // compute values for the first sumcheck argument
        for i in 0..3
        {
            // compute ra*zm - ram*z ?= h*v + b*g, verify the first sumcheck argument
            rzrzg += &((oracles.alpha.pow([index.h_group.size]) -
                &oracles.beta[0].pow([index.h_group.size])) /
                &(oracles.alpha - &oracles.beta[0]) * &[oracles.eta_a, oracles.eta_b, oracles.eta_c][i] *
                &match i
                {
                    0 => {self.za_eval}
                    1 => {self.zb_eval}
                    2 => {self.za_eval * &self.zb_eval}
                    _ => {E::Fr::zero()}
                });
        }

        rzrzg ==
        (
            self.h1_eval * &index.h_group.evaluate_vanishing_polynomial(oracles.beta[0]) +
            &(oracles.beta[0] * &self.g1_eval) +
            &(self.sigma2 * &E::Fr::from_repr(<<E as PairingEngine>::Fr as PrimeField>::BigInt::from(index.h_group.size)) *
            &(self.w_eval + &Evaluations::<E::Fr>::from_vec_and_domain(self.public.0.clone(), index.h_group).interpolate().evaluate(oracles.beta[0])))
        )
    }

    // This function verifies the prover's second sumcheck argument values
    //     index: Index
    //     oracles: random oraclrs of the argument
    //     RETURN: verification status
    pub fn sumcheck_2_verify
    (
        &self,
        index: &Index<E>,
        oracles: &RandomOracles<E::Fr>,
    ) -> bool
    {
        // evaluate ra polynomial succinctly
        // verify the second sumcheck argument
        self.sigma3 *
            &((oracles.alpha.pow([index.h_group.size]) - &oracles.beta[1].pow([index.h_group.size])) / &(oracles.alpha - &oracles.beta[1])) * 
            &E::Fr::from_repr(<<E as PairingEngine>::Fr as PrimeField>::BigInt::from(index.k_group.size))
        ==
        self.h2_eval *
            &index.h_group.evaluate_vanishing_polynomial(oracles.beta[1]) +
            &self.sigma2 + &(self.g2_eval * &oracles.beta[1])
    }

    // This function verifies the prover's third sumcheck argument values
    //     index: Index
    //     oracles: random oraclrs of the argument
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

        let (mut acc1, mut acc2) = (E::Fr::zero(), E::Fr::one());
        for i in 0..3
        {
            acc2 *= &crb[i];
            let mut x = self.val_eval[i] * &[oracles.eta_a, oracles.eta_b, oracles.eta_c][i];
            for j in 0..3 {if i != j {x *= &crb[j]}}
            acc1 += &x;
        }

        index.k_group.evaluate_vanishing_polynomial(oracles.beta[2]) * &self.h3_eval
        ==
        ((oracles.beta[0].pow(&[index.h_group.size]) - &E::Fr::one()) *
            &(oracles.beta[1].pow(&[index.h_group.size]) - &E::Fr::one())) *
            &acc1 - &((oracles.beta[2] * &self.g3_eval + &self.sigma3) * &acc2)
    }

    // This function verifies the prover's zk-proof
    //     index: Index
    //     rng: randomness source context
    //     RETURN: verification status
    pub fn verify
    (
        &self,
        index: &Index<E>,
        rng: &mut dyn RngCore
    ) -> Result<bool, ProofError>
    {
        let oracles = self.oracles(index)?;

        // first, verify sumcheck arguments
        match 
            self.sumcheck_1_verify (index, &oracles) &&
            self.sumcheck_2_verify (index, &oracles) &&
            self.sumcheck_3_verify (index, &oracles) &&

            // second, verify commitment opening proofs
            index.urs.verify
            (
                &vec!
                [
                    vec!
                    [(
                        oracles.beta[0],
                        oracles.batch,
                        vec!
                        [
                            (self.za_comm,  self.za_eval,   index.h_group.size()),
                            (self.zb_comm,  self.zb_eval,   index.h_group.size()),
                            (self.w_comm,   self.w_eval,    index.h_group.size()),
                            (self.h1_comm,  self.h1_eval,   index.h_group.size()*2),
                            (self.g1_comm,  self.g1_eval,   index.h_group.size()-1),
                        ],
                        self.proof1
                    )],
                    vec!
                    [(
                        oracles.beta[1],
                        oracles.batch,
                        vec!
                        [
                            (self.h2_comm, self.h2_eval, index.h_group.size()),
                            (self.g2_comm, self.g2_eval, (index.h_group.size())-1),
                        ],
                        self.proof2
                    )],
                    vec!
                    [(
                        oracles.beta[2],
                        oracles.batch,
                        vec!
                        [
                            (self.h3_comm, self.h3_eval, index.compiled[0].val.coeffs.len()*6),
                            (self.g3_comm, self.g3_eval, index.compiled[0].val.coeffs.len()-1),
                            (index.compiled[0].row_comm, self.row_eval[0], index.k_group.size()),
                            (index.compiled[1].row_comm, self.row_eval[1], index.k_group.size()),
                            (index.compiled[2].row_comm, self.row_eval[2], index.k_group.size()),
                            (index.compiled[0].col_comm, self.col_eval[0], index.k_group.size()),
                            (index.compiled[1].col_comm, self.col_eval[1], index.k_group.size()),
                            (index.compiled[2].col_comm, self.col_eval[2], index.k_group.size()),
                            (index.compiled[0].val_comm, self.val_eval[0], index.k_group.size()),
                            (index.compiled[1].val_comm, self.val_eval[1], index.k_group.size()),
                            (index.compiled[2].val_comm, self.val_eval[2], index.k_group.size()),
                        ],
                        self.proof3
                    )]
                ],
                rng
            )
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
        argument.commit_scalars(&self.public.0[0..self.public.1]);
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
