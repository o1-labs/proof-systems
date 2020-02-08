/********************************************************************************************

This source file implements zk-proof batch verifier functionality.

*********************************************************************************************/

use rand_core::RngCore;
use circuits_dlog::index::{VerifierIndex as Index};
use oracle::FqSponge;
pub use super::prover::{ProverProof, RandomOracles};
use algebra::{Field, AffineCurve};
use ff_fft::Evaluations;
use crate::marlin_sponge::{FrSponge};
use commitment_dlog::commitment::Utils;
use ff_fft::DensePolynomial;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

#[derive(Clone)]
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
}

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
        evals: &[ProofEvals<Fr<G>>],
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
                        0 => {evals[0].za * &oracles.eta_a}
                        1 => {evals[0].zb * &oracles.eta_b}
                        2 => {evals[0].za * &evals[0].zb * &oracles.eta_c}
                        _ => {Fr::<G>::zero()}
                    }
                }
            ).fold(Fr::<G>::zero(), |x, y| x + &y)
        ==
        (oracles.alpha - &oracles.beta[0]) *
        &(
            evals[0].h1 * &index.domains.h.evaluate_vanishing_polynomial(oracles.beta[0]) +
            &(oracles.beta[0] * &evals[0].g1) +
            &(self.sigma2 * &index.domains.h.size_as_field_element *
            &(evals[0].w * &index.domains.x.evaluate_vanishing_polynomial(oracles.beta[0]) +
            // interpolating/evaluating public input over small domain domains.x
            // TODO: investigate which of the below is faster
            &Evaluations::<Fr<G>>::from_vec_and_domain(self.public.clone(), index.domains.x).interpolate().evaluate(oracles.beta[0])))
            /*
            &index.domains.x.evaluate_all_lagrange_coefficients(oracles.beta[0])
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
        evals: &[ProofEvals<Fr<G>>],
    ) -> bool
    {
        self.sigma3 * &index.domains.k.size_as_field_element *
            &((oracles.alpha.pow([index.domains.h.size]) - &oracles.beta[1].pow([index.domains.h.size])))
        ==
        (oracles.alpha - &oracles.beta[1]) * &(evals[1].h2 *
            &index.domains.h.evaluate_vanishing_polynomial(oracles.beta[1]) +
            &self.sigma2 + &(evals[1].g2 * &oracles.beta[1]))
    }

    // This function verifies the prover's third sumcheck argument values
    //     index: Index
    //     oracles: random oracles of the argument
    //     RETURN: verification status
    pub fn sumcheck_3_verify
    (
        &self,
        index: &Index<G>,
        oracles: &RandomOracles<Fr<G>>,
        evals: &[ProofEvals<Fr<G>>],
    ) -> bool
    {
        let crb: Vec<Fr<G>> = (0..3).map
        (
            |i|
            {
                oracles.beta[1] * &oracles.beta[0] -
                &(oracles.beta[0] * &evals[2].row[i]) -
                &(oracles.beta[1] * &evals[2].col[i]) +
                &evals[2].rc[i]
            }
        ).collect();

        let acc = (0..3).map
        (
            |i|
            {
                let mut x = evals[2].val[i] * &[oracles.eta_a, oracles.eta_b, oracles.eta_c][i];
                for j in 0..3 {if i != j {x *= &crb[j]}}
                x
            }
        ).fold(Fr::<G>::zero(), |x, y| x + &y);

        index.domains.k.evaluate_vanishing_polynomial(oracles.beta[2]) * &evals[2].h3
        ==
        index.domains.h.evaluate_vanishing_polynomial(oracles.beta[0]) *
            &(index.domains.h.evaluate_vanishing_polynomial(oracles.beta[1])) *
            &acc - &((oracles.beta[2] * &evals[2].g3 + &self.sigma3) *
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
    ) -> bool
    {
        let mut batch = Vec::with_capacity(proofs.len());
        for proof in proofs.iter()
        {
            let oracles = proof.oracles::<EFqSponge, EFrSponge>(index);

            let beta =
            [
                oracles.beta[0].pow([index.max_poly_size as u64]),
                oracles.beta[1].pow([index.max_poly_size as u64]),
                oracles.beta[2].pow([index.max_poly_size as u64])
            ];

            let evals =
            {
                let evl = (0..3).map
                (
                    |i| ProofEvals
                    {
                        w  : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].w, beta[i]),
                        za : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].za, beta[i]),
                        zb : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].zb, beta[i]),
                        h1 : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].h1, beta[i]),
                        g1 : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].g1, beta[i]),
                        h2 : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].h2, beta[i]),
                        g2 : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].g2, beta[i]),
                        h3 : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].h3, beta[i]),
                        g3 : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].g3, beta[i]),
                        row:
                        [
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].row[0], beta[i]),
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].row[1], beta[i]),
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].row[2], beta[i]),
                        ],
                        col:
                        [
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].col[0], beta[i]),
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].col[1], beta[i]),
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].col[2], beta[i]),
                        ],
                        val:
                        [
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].val[0], beta[i]),
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].val[1], beta[i]),
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].val[2], beta[i]),
                        ],
                        rc:
                        [
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].rc[0], beta[i]),
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].rc[1], beta[i]),
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[i].rc[2], beta[i]),
                        ],
                    }
                ).collect::<Vec<_>>();
                [evl[0].clone(), evl[1].clone(), evl[2].clone()]
            };

            // first, verify the sumcheck argument values
            if 
                !proof.sumcheck_1_verify (index, &oracles, &evals) ||
                !proof.sumcheck_2_verify (index, &oracles, &evals) ||
                !proof.sumcheck_3_verify (index, &oracles, &evals)
            {
                return false
            }

            batch.push
            ((
                oracles.beta.to_vec(),
                oracles.polys,
                oracles.evals,
                vec!
                [
                    (&proof.za_comm,     proof.evals.iter().map(|e| &e.za).collect::<Vec<_>>(), None),
                    (&proof.zb_comm,     proof.evals.iter().map(|e| &e.zb).collect::<Vec<_>>(), None),
                    (&proof.w_comm,      proof.evals.iter().map(|e| &e.w ).collect::<Vec<_>>(), None),
                    (&proof.h1_comm,     proof.evals.iter().map(|e| &e.h1).collect::<Vec<_>>(), None),
                    (&proof.g1_comm,     proof.evals.iter().map(|e| &e.g1).collect::<Vec<_>>(), Some(index.domains.h.size()-1)),
                    (&proof.h2_comm,     proof.evals.iter().map(|e| &e.h2).collect::<Vec<_>>(), None),
                    (&proof.g2_comm,     proof.evals.iter().map(|e| &e.g2).collect::<Vec<_>>(), Some(index.domains.h.size()-1)),
                    (&proof.h3_comm,     proof.evals.iter().map(|e| &e.h3).collect::<Vec<_>>(), None),
                    (&proof.g3_comm,     proof.evals.iter().map(|e| &e.g3).collect::<Vec<_>>(), Some(index.domains.k.size()-1)),
                    
                    (&index.matrix_commitments[0].row, proof.evals.iter().map(|e| &e.row[0]).collect::<Vec<_>>(), None),
                    (&index.matrix_commitments[1].row, proof.evals.iter().map(|e| &e.row[1]).collect::<Vec<_>>(), None),
                    (&index.matrix_commitments[2].row, proof.evals.iter().map(|e| &e.row[2]).collect::<Vec<_>>(), None),
                    (&index.matrix_commitments[0].col, proof.evals.iter().map(|e| &e.col[0]).collect::<Vec<_>>(), None),
                    (&index.matrix_commitments[1].col, proof.evals.iter().map(|e| &e.col[1]).collect::<Vec<_>>(), None),
                    (&index.matrix_commitments[2].col, proof.evals.iter().map(|e| &e.col[2]).collect::<Vec<_>>(), None),
                    (&index.matrix_commitments[0].val, proof.evals.iter().map(|e| &e.val[0]).collect::<Vec<_>>(), None),
                    (&index.matrix_commitments[1].val, proof.evals.iter().map(|e| &e.val[1]).collect::<Vec<_>>(), None),
                    (&index.matrix_commitments[2].val, proof.evals.iter().map(|e| &e.val[2]).collect::<Vec<_>>(), None),
                    (&index.matrix_commitments[0].rc, proof.evals.iter().map(|e| &e.rc[0]).collect::<Vec<_>>(), None),
                    (&index.matrix_commitments[1].rc, proof.evals.iter().map(|e| &e.rc[1]).collect::<Vec<_>>(), None),
                    (&index.matrix_commitments[2].rc, proof.evals.iter().map(|e| &e.rc[2]).collect::<Vec<_>>(), None),
                ],
                &proof.proof
            ));
        }
        // second, verify the commitment opening proofs
        index.srs.get_ref().verify::<EFqSponge>(&batch, &index.fq_sponge_params.clone(), rng)
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
    ) -> RandomOracles<Fr<G>>
    {
        let mut oracles = RandomOracles::<Fr<G>>::zero();
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        let x_hat =
            // TODO: Cache this interpolated polynomial.
            Evaluations::<Fr<G>>::from_vec_and_domain(self.public.clone(), index.domains.x).interpolate();
        // TODO: No degree bound needed
        let x_hat_comm = index.srs.get_ref().commit(&x_hat, None);

        // absorb the public input into the argument
        fq_sponge.absorb_g(&x_hat_comm.unshifted);
        // absorb W, ZA, ZB polycommitments
        fq_sponge.absorb_g(& self.w_comm.unshifted);
        fq_sponge.absorb_g(& self.za_comm.unshifted);
        fq_sponge.absorb_g(& self.zb_comm.unshifted);
        // sample alpha, eta[0..3] oracles
        oracles.alpha = fq_sponge.challenge();
        oracles.eta_a = fq_sponge.challenge();
        oracles.eta_b = fq_sponge.challenge();
        oracles.eta_c = fq_sponge.challenge();
        // absorb H1, G1 polycommitments
        fq_sponge.absorb_g(&self.g1_comm.unshifted);
        fq_sponge.absorb_g(&self.h1_comm.unshifted);
        // sample beta[0] oracle
        oracles.beta[0] = fq_sponge.challenge();
        // absorb sigma2 scalar
        fq_sponge.absorb_fr(&self.sigma2);
        fq_sponge.absorb_g(&self.g2_comm.unshifted);
        fq_sponge.absorb_g(&self.h2_comm.unshifted);
        // sample beta[1] oracle
        oracles.beta[1] = fq_sponge.challenge();
        // absorb sigma3 scalar
        fq_sponge.absorb_fr(&self.sigma3);
        fq_sponge.absorb_g(&self.g3_comm.unshifted);
        fq_sponge.absorb_g(&self.h3_comm.unshifted);
        // sample beta[2] & batch oracles
        oracles.beta[2] = fq_sponge.challenge();

        let mut fr_sponge = {
            let digest_before_evaluations = fq_sponge.digest();
            oracles.digest_before_evaluations = digest_before_evaluations;
            let mut s = EFrSponge::new(index.fr_sponge_params.clone());
            s.absorb(&digest_before_evaluations);
            s
        };

        let x_hat_evals =
            [ x_hat.eval(oracles.beta[0], index.max_poly_size)
            , x_hat.eval(oracles.beta[1], index.max_poly_size)
            , x_hat.eval(oracles.beta[2], index.max_poly_size) ];

        oracles.x_hat = x_hat_evals.clone();

        for i in 0..3 {
            fr_sponge.absorb_evaluations(&x_hat_evals[i], &self.evals[i]);
        }

        oracles.polys = fr_sponge.challenge();
        oracles.evals = fr_sponge.challenge();

        oracles
    }
}
