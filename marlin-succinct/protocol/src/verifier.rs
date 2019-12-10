/********************************************************************************************

This source file implements prover's zk-proof primitive.

*********************************************************************************************/

use rand_core::RngCore;
use circuits::index::Index;
use algebra::{Field, PrimeField, PairingEngine};
pub use super::prover::{ProverProof, RandomOracles};
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
                &oracles.betta[0].pow([index.h_group.size])) /
                &(oracles.alpha - &oracles.betta[0]) * &oracles.gamma[i] *
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
            self.h1_eval * &index.h_group.evaluate_vanishing_polynomial(oracles.betta[0]) +
            &(oracles.betta[0] * &self.g1_eval) +
            &(self.sigma2 * &E::Fr::from_repr(<<E as PairingEngine>::Fr as PrimeField>::BigInt::from(index.h_group.size)) *
            &(self.w_eval + &Evaluations::<E::Fr>::from_vec_and_domain(self.public.0.clone(), index.h_group).interpolate().evaluate(oracles.betta[0])))
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
            &((oracles.alpha.pow([index.h_group.size]) - &oracles.betta[1].pow([index.h_group.size])) / &(oracles.alpha - &oracles.betta[1])) * 
            &E::Fr::from_repr(<<E as PairingEngine>::Fr as PrimeField>::BigInt::from(index.k_group.size))
        ==
        self.h2_eval *
            &index.h_group.evaluate_vanishing_polynomial(oracles.betta[1]) +
            &self.sigma2 + &(self.g2_eval * &oracles.betta[1])
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
            |i| {(oracles.betta[1] - &self.row_eval[i]) * &(oracles.betta[0] - &self.col_eval[i])}
        ).collect();

        let (mut acc1, mut acc2) = (E::Fr::zero(), E::Fr::one());
        for i in 0..3
        {
            acc2 *= &crb[i];
            let mut x = self.val_eval[i] * &oracles.gamma[i];
            for j in 0..3 {if i != j {x *= &crb[j]}}
            acc1 += &x;
        }

        index.k_group.evaluate_vanishing_polynomial(oracles.betta[2]) * &self.h3_eval
        ==
        ((oracles.betta[0].pow(&[index.h_group.size]) - &E::Fr::one()) *
            &(oracles.betta[1].pow(&[index.h_group.size]) - &E::Fr::one())) *
            &acc1 - &((oracles.betta[2] * &self.g3_eval + &self.sigma3) * &acc2)
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
    ) -> bool
    {
        let oracles = self.oracles(index);

        // first, verify sumcheck arguments
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
                    oracles.betta[0],
                    oracles.batch[0],
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
                    oracles.betta[1],
                    oracles.batch[1],
                    vec!
                    [
                        (self.h2_comm, self.h2_eval, index.h_group.size()),
                        (self.g2_comm, self.g2_eval, (index.h_group.size())-1),
                    ],
                    self.proof2
                )],
                vec!
                [(
                    oracles.betta[2],
                    oracles.batch[2],
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
    }
}
