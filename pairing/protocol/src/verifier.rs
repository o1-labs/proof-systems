/********************************************************************************************

This source file implements zk-proof batch verifier functionality.

*********************************************************************************************/

use rand_core::RngCore;
use circuits_pairing::index::{VerifierIndex as Index};
use oracle::rndoracle::{ProofError};
pub use super::prover::{ProverProof, RandomOracles};
use algebra::{Field, PairingEngine};
use ff_fft::{DensePolynomial, Evaluations};
use crate::marlin_sponge::{FqSponge, FrSponge};
use commitment_pairing::commitment::Utils;

pub struct ProofEvals<Fr> {
    pub w: Fr,
    pub za: Fr,
    pub zb: Fr,
    pub h1: Fr,
    pub g1: Fr,
    pub h2: Fr,
    pub g2: Fr,
    pub h3: Fr,
    pub g3: Fr,
    pub row: [Fr; 3],
    pub col: [Fr; 3],
    pub val: [Fr; 3],
    pub rc: [Fr; 3],
    pub x: Fr,
}

impl<E: PairingEngine> ProverProof<E>
{
    // This function verifies the prover's first sumcheck argument values
    //     index: Index
    //     oracles: random oracles of the argument
    //     evals: polynomial evaluations
    //     RETURN: verification status
    pub fn sumcheck_1_verify
    (
        &self,
        index: &Index<E>,
        oracles: &RandomOracles<E::Fr>,
        evals: &ProofEvals<E::Fr>
    ) -> bool
    {
        // compute ra*zm - ram*z ?= h*v + b*g to verify the first sumcheck argument
        (oracles.alpha.pow([index.domains.h.size]) - &oracles.beta[0].pow([index.domains.h.size])) *
            &(0..3).map
            (
                |i|
                {
                    match i
                    {
                        0 => {evals.za * &oracles.eta_a}
                        1 => {evals.zb * &oracles.eta_b}
                        2 => {evals.za * &evals.zb * &oracles.eta_c}
                        _ => {E::Fr::zero()}
                    }
                }
            ).fold(E::Fr::zero(), |x, y| x + &y)
        ==
        (oracles.alpha - &oracles.beta[0]) *
        &(
            evals.h1 * &index.domains.h.evaluate_vanishing_polynomial(oracles.beta[0]) +
            &(oracles.beta[0] * &evals.g1) +
            &(self.sigma2 * &index.domains.h.size_as_field_element *
            &(evals.w * &index.domains.x.evaluate_vanishing_polynomial(oracles.beta[0]) +
            &evals.x))
        )
    }

    // This function verifies the prover's second sumcheck argument values
    //     index: Index
    //     oracles: random oracles of the argument
    //     evals: polynomial evaluations
    //     RETURN: verification status
    pub fn sumcheck_2_verify
    (
        &self,
        index: &Index<E>,
        oracles: &RandomOracles<E::Fr>,
        evals: &ProofEvals<E::Fr>
    ) -> bool
    {
        self.sigma3 * &index.domains.k.size_as_field_element *
            &((oracles.alpha.pow([index.domains.h.size]) - &oracles.beta[1].pow([index.domains.h.size])))
        ==
        (oracles.alpha - &oracles.beta[1]) * &(evals.h2 *
            &index.domains.h.evaluate_vanishing_polynomial(oracles.beta[1]) +
            &self.sigma2 + &(evals.g2 * &oracles.beta[1]))
    }

    // This function verifies the prover's third sumcheck argument values
    //     index: Index
    //     oracles: random oracles of the argument
    //     evals: polynomial evaluations
    //     RETURN: verification status
    pub fn sumcheck_3_verify
    (
        &self,
        index: &Index<E>,
        oracles: &RandomOracles<E::Fr>,
        evals: &ProofEvals<E::Fr>
    ) -> bool
    {
        let crb: Vec<E::Fr> = (0..3).map
        (
            |i|
            {
                oracles.beta[1] * &oracles.beta[0] -
                &(oracles.beta[0] * &evals.row[i]) -
                &(oracles.beta[1] * &evals.col[i]) +
                &evals.rc[i]
            }
        ).collect();

        let acc = (0..3).map
        (
            |i|
            {
                let mut x = evals.val[i] * &[oracles.eta_a, oracles.eta_b, oracles.eta_c][i];
                for j in 0..3 {if i != j {x *= &crb[j]}}
                x
            }
        ).fold(E::Fr::zero(), |x, y| x + &y);

        index.domains.k.evaluate_vanishing_polynomial(oracles.beta[2]) * &evals.h3
        ==
        index.domains.h.evaluate_vanishing_polynomial(oracles.beta[0]) *
            &(index.domains.h.evaluate_vanishing_polynomial(oracles.beta[1])) *
            &acc - &((oracles.beta[2] * &evals.g3 + &self.sigma3) *
            &crb[0] * &crb[1] * &crb[2])
    }

    // This function verifies the batch of zk-proofs
    //     proofs: vector of Marlin proofs
    //     index: Index
    //     rng: randomness source context
    //     RETURN: verification status
    pub fn verify
        <EFqSponge: FqSponge<E::Fq, E::G1Affine, E::Fr>,
         EFrSponge: FrSponge<E::Fr>,
        >
    (
        proofs: &Vec<ProverProof<E>>,
        index: &Index<E>,
        rng: &mut dyn RngCore
    ) -> Result<bool, ProofError>
    {
        let mut batch = Vec::new();
        for proof in proofs.iter()
        {
            // TODO: Cache this interpolated polynomial.
            let x_hat = Evaluations::<E::Fr>::from_vec_and_domain(proof.public.clone(), index.domains.x).interpolate();
            let x_hat_comm = index.urs.commit(&x_hat, index.max_poly_size)?;

            let oracles = proof.oracles::<EFqSponge, EFrSponge>(index, &x_hat_comm, &x_hat)?;
            let beta =
            [
                oracles.beta[0].pow([index.max_poly_size as u64]),
                oracles.beta[1].pow([index.max_poly_size as u64]),
                oracles.beta[2].pow([index.max_poly_size as u64])
            ];

            let evals = ProofEvals::<E::Fr>
            {
                w: DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.w.clone()).evaluate(beta[0]),
                za: DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.za.clone()).evaluate(beta[0]),
                zb: DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.zb.clone()).evaluate(beta[0]),
                h1: DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.h1.clone()).evaluate(beta[0]),
                g1: DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.g1.clone()).evaluate(beta[0]),
                h2: DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.h2.clone()).evaluate(beta[1]),
                g2: DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.g2.clone()).evaluate(beta[1]),
                h3: DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.h3.clone()).evaluate(beta[2]),
                g3: DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.g3.clone()).evaluate(beta[2]),
                row:
                [
                    DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.row[0].clone()).evaluate(beta[2]),
                    DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.row[1].clone()).evaluate(beta[2]),
                    DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.row[2].clone()).evaluate(beta[2]),
                ],
                col:
                [
                    DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.col[0].clone()).evaluate(beta[2]),
                    DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.col[1].clone()).evaluate(beta[2]),
                    DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.col[2].clone()).evaluate(beta[2]),
                ],
                val:
                [
                    DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.val[0].clone()).evaluate(beta[2]),
                    DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.val[1].clone()).evaluate(beta[2]),
                    DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.val[2].clone()).evaluate(beta[2]),
                ],
                rc:
                [
                    DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.rc[0].clone()).evaluate(beta[2]),
                    DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.rc[1].clone()).evaluate(beta[2]),
                    DensePolynomial::<E::Fr>::from_coefficients_vec(proof.evals.rc[2].clone()).evaluate(beta[2]),
                ],
                x: DensePolynomial::<E::Fr>::from_coefficients_vec(oracles.x_hat_beta1.clone()).evaluate(beta[0])
            };

            // first, verify the sumcheck argument values
            if 
                !proof.sumcheck_1_verify (index, &oracles, &evals) ||
                !proof.sumcheck_2_verify (index, &oracles, &evals) ||
                !proof.sumcheck_3_verify (index, &oracles, &evals)
            {
                return Err(ProofError::ProofVerification)
            }

            batch.push
            ((
                oracles.beta[0],
                oracles.batch,
                vec!
                [
                    (x_hat_comm.iter().zip(oracles.x_hat_beta1.iter()).map(|(c, e)| (*c, *e)).collect(), None),
                    (proof.w_comm.iter().zip(proof.evals.w.iter()).map(|(c, e)| (*c, *e)).collect(), None),
                    (proof.za_comm.iter().zip(proof.evals.za.iter()).map(|(c, e)| (*c, *e)).collect(), None),
                    (proof.zb_comm.iter().zip(proof.evals.zb.iter()).map(|(c, e)| (*c, *e)).collect(), None),
                    (proof.g1_comm.0.iter().zip(proof.evals.g1.iter()).map(|(c, e)| (*c, *e)).collect(), Some((proof.g1_comm.1, index.domains.h.size()-1))),
                    (proof.h1_comm.iter().zip(proof.evals.h1.iter()).map(|(c, e)| (*c, *e)).collect(), None),
                ],
                proof.proof1
            ));
            batch.push
            ((
                oracles.beta[1],
                oracles.batch,
                vec!
                [
                    (proof.g2_comm.0.iter().zip(proof.evals.g2.iter()).map(|(c, e)| (*c, *e)).collect(), Some((proof.g2_comm.1, index.domains.h.size()-1))),
                    (proof.h2_comm.iter().zip(proof.evals.h2.iter()).map(|(c, e)| (*c, *e)).collect(), None),
                ],
                proof.proof2
            ));
            batch.push
            ((
                oracles.beta[2],
                oracles.batch,
                vec!
                [
                    (proof.g3_comm.0.iter().zip(proof.evals.g3.iter()).map(|(c, e)| (*c, *e)).collect(), Some((proof.g3_comm.1, index.domains.k.size()-1))),
                    (proof.h3_comm.iter().zip(proof.evals.h3.iter()).map(|(c, e)| (*c, *e)).collect(), None),
                    (index.matrix_commitments[0].row.iter().zip(proof.evals.row[0].iter()).map(|(c, e)| (*c, *e)).collect(), None),
                    (index.matrix_commitments[1].row.iter().zip(proof.evals.row[1].iter()).map(|(c, e)| (*c, *e)).collect(), None),
                    (index.matrix_commitments[2].row.iter().zip(proof.evals.row[2].iter()).map(|(c, e)| (*c, *e)).collect(), None),
                    (index.matrix_commitments[0].col.iter().zip(proof.evals.col[0].iter()).map(|(c, e)| (*c, *e)).collect(), None),
                    (index.matrix_commitments[1].col.iter().zip(proof.evals.col[1].iter()).map(|(c, e)| (*c, *e)).collect(), None),
                    (index.matrix_commitments[2].col.iter().zip(proof.evals.col[2].iter()).map(|(c, e)| (*c, *e)).collect(), None),
                    (index.matrix_commitments[0].val.iter().zip(proof.evals.val[0].iter()).map(|(c, e)| (*c, *e)).collect(), None),
                    (index.matrix_commitments[1].val.iter().zip(proof.evals.val[1].iter()).map(|(c, e)| (*c, *e)).collect(), None),
                    (index.matrix_commitments[2].val.iter().zip(proof.evals.val[2].iter()).map(|(c, e)| (*c, *e)).collect(), None),
                    (index.matrix_commitments[0].rc.iter().zip(proof.evals.rc[0].iter()).map(|(c, e)| (*c, *e)).collect(), None),
                    (index.matrix_commitments[1].rc.iter().zip(proof.evals.rc[1].iter()).map(|(c, e)| (*c, *e)).collect(), None),
                    (index.matrix_commitments[2].rc.iter().zip(proof.evals.rc[2].iter()).map(|(c, e)| (*c, *e)).collect(), None),
        ],
                proof.proof3
            ));
        }
        // second, verify the commitment opening proofs
        match index.urs.verify(&batch, rng)
        {
            false => Err(ProofError::OpenProof),
            true => Ok(true)
        }
    }

    // This function queries random oracle values from non-interactive
    // argument context by verifier
    pub fn oracles
        <EFqSponge: FqSponge<E::Fq, E::G1Affine, E::Fr>,
         EFrSponge: FrSponge<E::Fr>,
        >
    (
        &self,
        index: &Index<E>,
        x_hat_comm: &Vec<E::G1Affine>,
        x_hat: &DensePolynomial<E::Fr>
    ) -> Result<RandomOracles<E::Fr>, ProofError>
    {
        let mut oracles = RandomOracles::<E::Fr>::zero();
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        // TODO: absorb previous proof context into the argument
        // absorb the public input into the argument
        fq_sponge.absorb_g(&x_hat_comm);
        // absorb W, ZA, ZB polycommitments
        fq_sponge.absorb_g(& self.w_comm);
        fq_sponge.absorb_g(& self.za_comm);
        fq_sponge.absorb_g(& self.zb_comm);
        // sample alpha, eta[0..3] oracles
        oracles.alpha = fq_sponge.challenge();
        oracles.eta_a = fq_sponge.challenge();
        oracles.eta_b = fq_sponge.challenge();
        oracles.eta_c = fq_sponge.challenge();
        // absorb H1, G1 polycommitments
        fq_sponge.absorb_g(&self.g1_comm.0);
        fq_sponge.absorb_g(&[self.g1_comm.1]);
        fq_sponge.absorb_g(&self.h1_comm);
        // sample beta[0] oracle
        oracles.beta[0] = fq_sponge.challenge();
        // absorb sigma2 scalar
        fq_sponge.absorb_fr(&self.sigma2);
        fq_sponge.absorb_g(&self.g2_comm.0);
        fq_sponge.absorb_g(&[self.g2_comm.1]);
        fq_sponge.absorb_g(&self.h2_comm);
        // sample beta[1] oracle
        oracles.beta[1] = fq_sponge.challenge();
        // absorb sigma3 scalar
        fq_sponge.absorb_fr(&self.sigma3);
        fq_sponge.absorb_g(&self.g3_comm.0);
        fq_sponge.absorb_g(&[self.g3_comm.1]);
        fq_sponge.absorb_g(&self.h3_comm);
        // sample beta[2] & batch oracles
        oracles.beta[2] = fq_sponge.challenge();
        oracles.r_k = fq_sponge.challenge();

        let digest_before_evaluations = fq_sponge.digest();
        oracles.digest_before_evaluations = digest_before_evaluations;

        let mut fr_sponge = {
            let mut s = EFrSponge::new(index.fr_sponge_params.clone());
            s.absorb(&digest_before_evaluations);
            s
        };

        let x_hat_beta1 = x_hat.eval(oracles.beta[0], index.max_poly_size);
        oracles.x_hat_beta1 = x_hat_beta1.clone();

        fr_sponge.absorb_evaluations(&x_hat_beta1, &self.evals);

        oracles.batch = fr_sponge.challenge();
        oracles.r = fr_sponge.challenge();

        Ok(oracles)
    }
}
