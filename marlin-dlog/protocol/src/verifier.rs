/********************************************************************************************

This source file implements zk-proof batch verifier functionality.

*********************************************************************************************/

use rand_core::RngCore;
use circuits::index::Index;
use oracle::{FqSponge, rndoracle::ProofError};
pub use super::prover::{ProverProof, RandomOracles};
use algebra::{Field, AffineCurve};
use ff_fft::Evaluations;
use crate::marlin_sponge::{FrSponge};

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

impl<G: AffineCurve> ProverProof<G>
{
    // This function verifies the prover's first sumcheck argument values
    //     index: Index
    //     oracles: random oracles of the argument
    //     RETURN: verification status
    pub fn sumcheck_1_verify
    (
        &self,
        index: &Index<G>,
        oracles: &RandomOracles<Fr<G>>,
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
                        0 => {self.evals.za * &oracles.eta_a}
                        1 => {self.evals.zb * &oracles.eta_b}
                        2 => {self.evals.za * &self.evals.zb * &oracles.eta_c}
                        _ => {Fr::<G>::zero()}
                    }
                }
            ).fold(Fr::<G>::zero(), |x, y| x + &y)
        ==
        (oracles.alpha - &oracles.beta[0]) *
        &(
            self.evals.h1 * &index.h_group.evaluate_vanishing_polynomial(oracles.beta[0]) +
            &(oracles.beta[0] * &self.evals.g1) +
            &(self.sigma2 * &index.h_group.size_as_field_element *
            &(self.evals.w * &index.x_group.evaluate_vanishing_polynomial(oracles.beta[0]) +
            // interpolating/evaluating public input over small domain x_group
            // TODO: investigate which of the below is faster
            &Evaluations::<Fr<G>>::from_vec_and_domain(self.public.clone(), index.x_group).interpolate().evaluate(oracles.beta[0])))
            /*
            &index.x_group.evaluate_all_lagrange_coefficients(oracles.beta[0])
            .iter()
            .zip(self.public.iter())
            .map(|(l, x)| *l * x)
            .fold(Fr<G>::zero(), |x, y| x + &y)))
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
        index: &Index<G>,
        oracles: &RandomOracles<Fr<G>>,
    ) -> bool
    {
        self.sigma3 * &index.k_group.size_as_field_element *
            &((oracles.alpha.pow([index.h_group.size]) - &oracles.beta[1].pow([index.h_group.size])))
        ==
        (oracles.alpha - &oracles.beta[1]) * &(self.evals.h2 *
            &index.h_group.evaluate_vanishing_polynomial(oracles.beta[1]) +
            &self.sigma2 + &(self.evals.g2 * &oracles.beta[1]))
    }

    // This function verifies the prover's third sumcheck argument values
    //     index: Index
    //     oracles: random oracles of the argument
    //     RETURN: verification status
    pub fn sumcheck_3_verify
    (
        &self,
        index: &Index<G>,
        oracles: &RandomOracles<Fr<G>>
    ) -> bool
    {
        let crb: Vec<Fr<G>> = (0..3).map
        (
            |i| {(oracles.beta[1] - &self.evals.row[i]) * &(oracles.beta[0] - &self.evals.col[i])}
        ).collect();

        let acc = (0..3).map
        (
            |i|
            {
                let mut x = self.evals.val[i] * &[oracles.eta_a, oracles.eta_b, oracles.eta_c][i];
                for j in 0..3 {if i != j {x *= &crb[j]}}
                x
            }
        ).fold(Fr::<G>::zero(), |x, y| x + &y);

        index.k_group.evaluate_vanishing_polynomial(oracles.beta[2]) * &self.evals.h3
        ==
        index.h_group.evaluate_vanishing_polynomial(oracles.beta[0]) *
            &(index.h_group.evaluate_vanishing_polynomial(oracles.beta[1])) *
            &acc - &((oracles.beta[2] * &self.evals.g3 + &self.sigma3) *
            &crb[0] * &crb[1] * &crb[2])
    }

    // This function verifies the batch of zk-proofs
    //     proofs: vector of Marlin proofs
    //     index: Index
    //     rng: randomness source context
    //     RETURN: verification status
    pub fn verify
        <EFqSponge: FqSponge<Fq<G>, G, Fr<G>>,
         EFrSponge: FrSponge<Fr<G>>,
        >
    (
        proofs: &Vec<ProverProof<G>>,
        index: &Index<G>,
        rng: &mut dyn RngCore
    ) -> Result<bool, ProofError>
    {
        let mut batch = Vec::with_capacity(proofs.len() * 3);
        for proof in proofs.iter()
        {
            let proof = proof.clone();
            let oracles = proof.oracles::<EFqSponge, EFrSponge>(index)?;

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
                    (proof.za_comm, proof.evals.za, index.h_group.size()),
                    (proof.zb_comm, proof.evals.zb, index.h_group.size()),
                    (proof.w_comm,  proof.evals.w,  index.h_group.size() - index.x_group.size()),
                    (proof.h1_comm, proof.evals.h1, index.h_group.size()*2-2),
                    (proof.g1_comm, proof.evals.g1, index.h_group.size()-1),
                ],
                proof.proof1
            ));
            batch.push
            ((
                oracles.beta[1],
                oracles.batch,
                vec!
                [
                    (proof.h2_comm, proof.evals.h2, index.h_group.size()-1),
                    (proof.g2_comm, proof.evals.g2, index.h_group.size()-1),
                ],
                proof.proof2
            ));
            batch.push
            ((
                oracles.beta[2],
                oracles.batch,
                vec!
                [
                    (proof.h3_comm, proof.evals.h3, index.k_group.size()*6-6),
                    (proof.g3_comm, proof.evals.g3, index.k_group.size()-1),
                    (index.compiled[0].row_comm, proof.evals.row[0], index.k_group.size()),
                    (index.compiled[1].row_comm, proof.evals.row[1], index.k_group.size()),
                    (index.compiled[2].row_comm, proof.evals.row[2], index.k_group.size()),
                    (index.compiled[0].col_comm, proof.evals.col[0], index.k_group.size()),
                    (index.compiled[1].col_comm, proof.evals.col[1], index.k_group.size()),
                    (index.compiled[2].col_comm, proof.evals.col[2], index.k_group.size()),
                    (index.compiled[0].val_comm, proof.evals.val[0], index.k_group.size()),
                    (index.compiled[1].val_comm, proof.evals.val[1], index.k_group.size()),
                    (index.compiled[2].val_comm, proof.evals.val[2], index.k_group.size()),
                ],
                proof.proof3
            ));
        }
        // second, verify the commitment opening proofs
        match index.srs.verify::<EFqSponge>(&batch, &index.fq_sponge_params.clone(), rng)
        {
            false => Err(ProofError::OpenProof),
            true => Ok(true)
        }
    }

    // This function queries random oracle values from non-interactive
    // argument context by verifier
    pub fn oracles
        <EFqSponge: FqSponge<Fq<G>, G, Fr<G>>,
         EFrSponge: FrSponge<Fr<G>>,
        >
    (
        &self,
        index: &Index<G>,
    ) -> Result<RandomOracles<Fr<G>>, ProofError>
    {
        let mut oracles = RandomOracles::<Fr<G>>::zero();
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        let x_hat =
            // TODO: Cache this interpolated polynomial.
            Evaluations::<Fr<G>>::from_vec_and_domain(self.public.clone(), index.x_group).interpolate();
        // TODO: No degree bound needed
        let x_hat_comm = index.srs.commit(&x_hat, 0)?;

        // TODO: absorb previous proof context into the argument
        fq_sponge.absorb_fr(&Fr::<G>::one());
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
        fq_sponge.absorb_g(&self.g1_comm);
        fq_sponge.absorb_g(&self.h1_comm);
        // sample beta[0] oracle
        oracles.beta[0] = fq_sponge.challenge();
        // absorb sigma2 scalar
        fq_sponge.absorb_fr(&self.sigma2);
        fq_sponge.absorb_g(&self.g2_comm);
        fq_sponge.absorb_g(&self.h2_comm);
        // sample beta[1] oracle
        oracles.beta[1] = fq_sponge.challenge();
        // absorb sigma3 scalar
        fq_sponge.absorb_fr(&self.sigma3);
        fq_sponge.absorb_g(&self.g3_comm);
        fq_sponge.absorb_g(&self.h3_comm);
        // sample beta[2] & batch oracles
        oracles.beta[2] = fq_sponge.challenge();

        let mut fr_sponge = {
            let digest_before_evaluations = fq_sponge.digest();
            let mut s = EFrSponge::new(index.fr_sponge_params.clone());
            s.absorb(&digest_before_evaluations);
            s
        };

        fr_sponge.absorb_evaluations(&x_hat.evaluate(oracles.beta[0]),&self.evals);

        oracles.batch = fr_sponge.challenge();

        Ok(oracles)
    }
}
