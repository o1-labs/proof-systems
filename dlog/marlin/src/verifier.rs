/********************************************************************************************

This source file implements zk-proof batch verifier functionality.

*********************************************************************************************/

use rand_core::RngCore;
use algebra::{Field, AffineCurve, Zero, One};
pub use super::index::{VerifierIndex as Index};
pub use super::prover::{ProverProof, RandomOracles};
use oracle::{FqSponge, utils::PolyUtils, sponge::ScalarChallenge};
use ff_fft::{DensePolynomial, Evaluations, EvaluationDomain, GeneralEvaluationDomain};
use commitment_dlog::commitment::{QnrField, CommitmentCurve, PolyComm, b_poly, b_poly_coefficients, product};
use crate::marlin_sponge::{FrSponge};

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

impl<G: CommitmentCurve> ProverProof<G> where G::ScalarField : QnrField
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
        evals: &ProofEvals<Fr<G>>,
        x_hat_value: Fr<G>
    ) -> bool
    {
        let endo = &index.srs.get_ref().endo_r;
        let beta0 = oracles.beta[0].to_field(endo);
        // compute ra*zm - ram*z ?= h*v + b*g to verify the first sumcheck argument
        (oracles.alpha.pow([index.domains.h.size]) - &beta0.pow([index.domains.h.size])) *
            &(0..3).map
            (
                |i|
                {
                    match i
                    {
                        0 => {evals.za * &oracles.eta_a}
                        1 => {evals.zb * &oracles.eta_b}
                        2 => {evals.za * &evals.zb * &oracles.eta_c}
                        _ => {Fr::<G>::zero()}
                    }
                }
            ).fold(Fr::<G>::zero(), |x, y| x + &y)
        ==
        (oracles.alpha - &beta0) *
        &(
            evals.h1 * &index.domains.h.evaluate_vanishing_polynomial(beta0) +
            &(beta0 * &evals.g1) +
            &(self.sigma2 * &index.domains.h.size_as_field_element *
            &(evals.w * &index.domains.x.evaluate_vanishing_polynomial(beta0) +
            &x_hat_value))
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
        evals: &ProofEvals<Fr<G>>,
    ) -> bool
    {
        let endo = &index.srs.get_ref().endo_r;
        let beta1 = oracles.beta[1].to_field(endo);
        self.sigma3 * &index.domains.k.size_as_field_element *
            &((oracles.alpha.pow([index.domains.h.size]) - &beta1.pow([index.domains.h.size])))
        ==
        (oracles.alpha - &beta1) * &(evals.h2 *
            &index.domains.h.evaluate_vanishing_polynomial(beta1) +
            &self.sigma2 + &(evals.g2 * &beta1))
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
        evals: &ProofEvals<Fr<G>>,
    ) -> bool
    {
        let endo = &index.srs.get_ref().endo_r;
        let beta0 = oracles.beta[0].to_field(endo);
        let beta1 = oracles.beta[1].to_field(endo);
        let beta2 = oracles.beta[2].to_field(endo);

        let crb: Vec<Fr<G>> = (0..3).map
        (
            |i|
            {
                beta1 * &beta0 -
                &(beta0 * &evals.row[i]) -
                &(beta1 * &evals.col[i]) +
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
        ).fold(Fr::<G>::zero(), |x, y| x + &y);

        index.domains.k.evaluate_vanishing_polynomial(beta2) * &evals.h3
        ==
        index.domains.h.evaluate_vanishing_polynomial(beta0) *
            &(index.domains.h.evaluate_vanishing_polynomial(beta1)) *
            &acc - &((beta2 * &evals.g3 + &self.sigma3) *
            &crb[0] * &crb[1] * &crb[2])
    }

    // This function verifies the batch of zk-proofs
    //     proofs: vector of Marlin proofs
    //     index: Index
    //     rng: randomness source context
    //     RETURN: verification status
    pub fn verify
        <EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>,
         EFrSponge: FrSponge<Fr<G>>,
        >
    (
        group_map: &G::Map,
        proofs: &Vec<ProverProof<G>>,
        index: &Index<G>,
        rng: &mut dyn RngCore
    ) -> bool
    {
        let endo = &index.srs.get_ref().endo_r;
        let params = proofs.iter().map
        (
            |proof|
            {
                let x_hat =
                // TODO: Cache this interpolated polynomial.
                Evaluations::<Fr<G>>::from_vec_and_domain(proof.public.clone(), GeneralEvaluationDomain::Radix2(index.domains.x)).interpolate();
                // TODO: No degree bound needed
                let x_hat_comm = index.srs.get_ref().commit(&x_hat, None);
                let (fq_sponge, oracles) = proof.oracles::<EFqSponge, EFrSponge>(index, x_hat_comm.clone(), &x_hat);

                let beta =
                [
                    oracles.beta[0].to_field(endo).pow([index.max_poly_size as u64]),
                    oracles.beta[1].to_field(endo).pow([index.max_poly_size as u64]),
                    oracles.beta[2].to_field(endo).pow([index.max_poly_size as u64])
                ];

                let polys = proof.prev_challenges.iter().map(|(chals, poly)| {
                    // No need to check the correctness of poly explicitly. Its correctness is assured by the
                    // checking of the inner product argument.
                    // TODO: Use batch inversion across proofs
                    let chal_invs = {
                        let mut cs = chals.clone();
                        algebra::fields::batch_inversion::<Fr<G>>(&mut cs);
                        cs
                    };
                    let s0 = product(chals.iter().map(|x| *x) ).inverse().unwrap();
                    let chal_squareds : Vec<Fr<G>> = chals.iter().map(|x| x.square()).collect();
                    let b = b_poly_coefficients(s0, &chal_squareds);

                    let evals = (0..3).map
                    (
                        |i|
                        {
                            let full = b_poly(&chals, &chal_invs, oracles.beta[i].to_field(endo));
                            if index.max_poly_size == b.len() {return vec![full]}
                            let mut betaacc = Fr::<G>::one();
                            let diff = (index.max_poly_size..b.len()).map
                            (
                                |j| {let ret = betaacc * &b[j]; betaacc *= &oracles.beta[i].to_field(endo); ret}
                            ).fold(Fr::<G>::zero(), |x, y| x + &y);
                            vec![full - &(diff * &beta[i]), diff]
                        }
                    ).collect::<Vec<_>>();
    
                    (poly.clone(), evals)
                }).collect::<Vec<(PolyComm<G>, Vec<Vec<Fr<G>>>)>>();
    
                (beta, x_hat_comm, fq_sponge, oracles, polys)
            }
        ).collect::<Vec<_>>();
        
        match proofs.iter().zip(params.iter()).map
        (
            |(proof, (beta, x_hat_comm, fq_sponge, oracles, polys))|
            {
                let evals =
                {
                    ProofEvals
                    {
                        w  : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].w, beta[0]),
                        za : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].za, beta[0]),
                        zb : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].zb, beta[0]),
                        h1 : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].h1, beta[0]),
                        g1 : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].g1, beta[0]),
                        h2 : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[1].h2, beta[1]),
                        g2 : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[1].g2, beta[1]),
                        h3 : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[2].h3, beta[2]),
                        g3 : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[2].g3, beta[2]),
                        row:
                        [
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[2].row[0], beta[2]),
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[2].row[1], beta[2]),
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[2].row[2], beta[2]),
                        ],
                        col:
                        [
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[2].col[0], beta[2]),
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[2].col[1], beta[2]),
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[2].col[2], beta[2]),
                        ],
                        val:
                        [
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[2].val[0], beta[2]),
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[2].val[1], beta[2]),
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[2].val[2], beta[2]),
                        ],
                        rc:
                        [
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[2].rc[0], beta[2]),
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[2].rc[1], beta[2]),
                            DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[2].rc[2], beta[2]),
                        ],
                    }
                };

                // first, verify the sumcheck argument values
                let x_hat_value = DensePolynomial::<Fr<G>>::eval_polynomial(&oracles.x_hat[0], beta[0]);
                if 
                    !proof.sumcheck_1_verify (index, &oracles, &evals, x_hat_value) ||
                    !proof.sumcheck_2_verify (index, &oracles, &evals) ||
                    !proof.sumcheck_3_verify (index, &oracles, &evals)
                {
                    return Err(0)
                }

                let mut polynoms = polys.iter().map
                (
                    |(comm, evals)|
                    {
                        (comm, evals.iter().map(|x| x).collect(), None)
                    }
                ).collect::<Vec<(&PolyComm<G>, Vec<&Vec<Fr<G>>>, Option<usize>)>>();

                polynoms.extend
                (
                    vec!
                    [
                        (x_hat_comm,         oracles.x_hat.iter().map(|e| e).collect::<Vec<_>>(), None),
                        (&proof.w_comm,      proof.evals.iter().map(|e| &e.w).collect::<Vec<_>>(), None),
                        (&proof.za_comm,     proof.evals.iter().map(|e| &e.za).collect::<Vec<_>>(), None),
                        (&proof.zb_comm,     proof.evals.iter().map(|e| &e.zb).collect::<Vec<_>>(), None),
                        (&proof.h1_comm,     proof.evals.iter().map(|e| &e.h1).collect::<Vec<_>>(), None),
                        (&proof.h2_comm,     proof.evals.iter().map(|e| &e.h2).collect::<Vec<_>>(), None),
                        (&proof.h3_comm,     proof.evals.iter().map(|e| &e.h3).collect::<Vec<_>>(), None),
                        
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

                        (&proof.g1_comm,     proof.evals.iter().map(|e| &e.g1).collect::<Vec<_>>(), Some(index.domains.h.size()-1)),
                        (&proof.g2_comm,     proof.evals.iter().map(|e| &e.g2).collect::<Vec<_>>(), Some(index.domains.h.size()-1)),
                        (&proof.g3_comm,     proof.evals.iter().map(|e| &e.g3).collect::<Vec<_>>(), Some(index.domains.k.size()-1)),
                    ]
                );

                Ok((
                    fq_sponge.clone(),
                    oracles.beta.iter().map(|x| x.to_field(endo)).collect(),
                    oracles.polys.to_field(endo),
                    oracles.evals.to_field(endo),
                    polynoms,
                    &proof.proof
                ))
            }
        ).collect::<Result<Vec<_>, _>>()
        // second, verify the commitment opening proofs
        {
            Ok(mut batch) =>  index.srs.get_ref().verify::<EFqSponge>(group_map, &mut batch, rng),
            Err(_) => false
        }
    }

    // This function queries random oracle values from non-interactive
    // argument context by verifier
    pub fn oracles
        <EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>,
         EFrSponge: FrSponge<Fr<G>>,
        >
    (
        &self,
        index: &Index<G>,
        x_hat_comm: PolyComm<G>,
        x_hat: &DensePolynomial<Fr<G>>
    ) -> (EFqSponge, RandomOracles<Fr<G>>)
    {
        let mut oracles = RandomOracles::<Fr<G>>::zero();
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

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
        oracles.beta[0] = ScalarChallenge(fq_sponge.challenge());
        // absorb sigma2 scalar
        fq_sponge.absorb_fr(&[self.sigma2]);
        fq_sponge.absorb_g(&self.g2_comm.unshifted);
        fq_sponge.absorb_g(&self.h2_comm.unshifted);
        // sample beta[1] oracle
        oracles.beta[1] = ScalarChallenge(fq_sponge.challenge());
        // absorb sigma3 scalar
        fq_sponge.absorb_fr(&[self.sigma3]);
        fq_sponge.absorb_g(&self.g3_comm.unshifted);
        fq_sponge.absorb_g(&self.h3_comm.unshifted);
        // sample beta[2] & batch oracles
        oracles.beta[2] = ScalarChallenge(fq_sponge.challenge());

        let mut fr_sponge = {
            let digest_before_evaluations = fq_sponge.clone().digest();
            oracles.digest_before_evaluations = digest_before_evaluations;
            let mut s = EFrSponge::new(index.fr_sponge_params.clone());
            s.absorb(&digest_before_evaluations);
            s
        };

        let endo = &index.srs.get_ref().endo_r;

        let x_hat_evals =
            [ x_hat.eval(oracles.beta[0].to_field(endo), index.max_poly_size)
            , x_hat.eval(oracles.beta[1].to_field(endo), index.max_poly_size)
            , x_hat.eval(oracles.beta[2].to_field(endo), index.max_poly_size) ];

        oracles.x_hat = x_hat_evals.clone();

        for i in 0..3 {
            fr_sponge.absorb_evaluations(&x_hat_evals[i], &self.evals[i]);
        }
    
        oracles.polys = fr_sponge.challenge();
        oracles.evals = fr_sponge.challenge();

        (fq_sponge, oracles)
    }
}
