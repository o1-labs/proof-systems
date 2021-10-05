/********************************************************************************************

This source file implements zk-proof batch verifier functionality.

*********************************************************************************************/

pub use super::index::VerifierIndex as Index;
pub use super::prover::{range, ProverProof};
use crate::plonk_sponge::FrSponge;
use ark_ec::AffineCurve;
use ark_ff::{Field, One, Zero};
use ark_poly::{EvaluationDomain, Polynomial};
use commitment_dlog::commitment::{
    b_poly, b_poly_coefficients, combined_inner_product, CommitmentCurve, CommitmentField, PolyComm,
};
use oracle::{rndoracle::ProofError, sponge::ScalarChallenge, FqSponge};
use plonk_15_wires_circuits::{
    nolookup::{constraints::ConstraintSystem, scalars::RandomOracles},
    wires::*,
    gates::generic::{MUL_COEFF, CONSTANT_COEFF},
};
use rand::thread_rng;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

/// The result of running the oracle protocol
pub struct OraclesResult<G, EFqSponge>
where
    G: CommitmentCurve,
    EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>,
{
    /// A sponge that acts on the base field of a curve
    fq_sponge: EFqSponge,
    /// the last evaluation of the Fq-Sponge in this protocol
    digest: Fr<G>,
    /// the challenges produced in the protocol
    oracles: RandomOracles<Fr<G>>,
    /// pre-computed powers of the alpha challenge
    alphas: Vec<Fr<G>>,
    /// public polynomial evaluations
    p_eval: [Vec<Fr<G>>; 2],
    /// zeta^n and (zeta * omega)^n
    powers_of_eval_points_for_chunks: [Fr<G>; 2],
    /// ?
    polys: Vec<(PolyComm<G>, Vec<Vec<Fr<G>>>)>,
    /// pre-computed zeta^n
    zeta1: Fr<G>,
    /// The evaluation f(zeta) - t(zeta) * Z_H(zeta)
    ft_eval0: Fr<G>,
    /// ?
    combined_inner_product: Fr<G>,
}

impl<G: CommitmentCurve> ProverProof<G>
where
    G::ScalarField: CommitmentField,
{
    pub fn prev_chal_evals(
        &self,
        index: &Index<G>,
        evaluation_points: &[Fr<G>],
        powers_of_eval_points_for_chunks: &[Fr<G>],
    ) -> Vec<Vec<Vec<Fr<G>>>> {
        self.prev_challenges
            .iter()
            .map(|(chals, _poly)| {
                // No need to check the correctness of poly explicitly. Its correctness is assured by the
                // checking of the inner product argument.
                let b_len = 1 << chals.len();
                let mut b: Option<Vec<Fr<G>>> = None;

                (0..2)
                    .map(|i| {
                        let full = b_poly(&chals, evaluation_points[i]);
                        if index.max_poly_size == b_len {
                            return vec![full];
                        }
                        let mut betaacc = Fr::<G>::one();
                        let diff = (index.max_poly_size..b_len)
                            .map(|j| {
                                let b_j = match &b {
                                    None => {
                                        let t = b_poly_coefficients(&chals);
                                        let res = t[j];
                                        b = Some(t);
                                        res
                                    }
                                    Some(b) => b[j],
                                };

                                let ret = betaacc * &b_j;
                                betaacc *= &evaluation_points[i];
                                ret
                            })
                            .fold(Fr::<G>::zero(), |x, y| x + &y);
                        vec![full - &(diff * &powers_of_eval_points_for_chunks[i]), diff]
                    })
                    .collect()
            })
            .collect()
    }

    /// This function runs random oracle argument
    pub fn oracles<EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>, EFrSponge: FrSponge<Fr<G>>>(
        &self,
        index: &Index<G>,
        p_comm: &PolyComm<G>,
    ) -> OraclesResult<G, EFqSponge> {
        let n = index.domain.size;

        // Run random oracle argument to sample verifier oracles
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        // absorb the public input, l, r, o polycommitments into the argument
        fq_sponge.absorb_g(&p_comm.unshifted);
        self.commitments
            .w_comm
            .iter()
            .for_each(|c| fq_sponge.absorb_g(&c.unshifted));

        // sample beta, gamma oracles
        let beta = fq_sponge.challenge();
        let gamma = fq_sponge.challenge();

        // absorb the z commitment into the argument and query alpha
        fq_sponge.absorb_g(&self.commitments.z_comm.unshifted);
        let alpha_chal = ScalarChallenge(fq_sponge.challenge());
        let alpha = alpha_chal.to_field(&index.srs.get_ref().endo_r);

        // absorb the polycommitments into the argument and sample zeta
        let max_t_size = (index.max_quot_size + index.max_poly_size - 1) / index.max_poly_size;
        let dummy = G::of_coordinates(Fq::<G>::zero(), Fq::<G>::zero());
        fq_sponge.absorb_g(&self.commitments.t_comm.unshifted);
        fq_sponge.absorb_g(&vec![
            dummy;
            max_t_size - self.commitments.t_comm.unshifted.len()
        ]);

        let zeta_chal = ScalarChallenge(fq_sponge.challenge());
        let zeta = zeta_chal.to_field(&index.srs.get_ref().endo_r);
        let digest = fq_sponge.clone().digest();
        let mut fr_sponge = {
            let mut s = EFrSponge::new(index.fr_sponge_params.clone());
            s.absorb(&digest);
            s
        };

        // prepare some often used values
        let zeta1 = zeta.pow(&[n]);
        let zetaw = zeta * &index.domain.group_gen;
        let alphas = range::alpha_powers(alpha);

        // compute Lagrange base evaluation denominators
        let w = (0..self.public.len())
            .zip(index.domain.elements())
            .map(|(_, w)| w)
            .collect::<Vec<_>>();
        let mut lagrange = w.iter().map(|w| zeta - w).collect::<Vec<_>>();
        (0..self.public.len())
            .zip(w.iter())
            .for_each(|(_, w)| lagrange.push(zetaw - w));
        ark_ff::fields::batch_inversion::<Fr<G>>(&mut lagrange);

        // evaluate public input polynomials
        // NOTE: this works only in the case when the poly segment size is not smaller than that of the domain
        let p_eval = if self.public.len() > 0 {
            [
                vec![
                    (self
                        .public
                        .iter()
                        .zip(lagrange.iter())
                        .zip(index.domain.elements())
                        .map(|((p, l), w)| -*l * p * &w)
                        .fold(Fr::<G>::zero(), |x, y| x + &y))
                        * &(zeta1 - &Fr::<G>::one())
                        * &index.domain.size_inv,
                ],
                vec![
                    (self
                        .public
                        .iter()
                        .zip(lagrange[self.public.len()..].iter())
                        .zip(index.domain.elements())
                        .map(|((p, l), w)| -*l * p * &w)
                        .fold(Fr::<G>::zero(), |x, y| x + &y))
                        * &index.domain.size_inv
                        * &(zetaw.pow(&[n as u64]) - &Fr::<G>::one()),
                ],
            ]
        } else {
            [Vec::<Fr<G>>::new(), Vec::<Fr<G>>::new()]
        };
        for i in 0..2 {
            fr_sponge.absorb_evaluations(&p_eval[i], &self.evals[i])
        }
        fr_sponge.absorb(&self.ft_eval1);

        // query opening scalar challenges
        let v_chal = fr_sponge.challenge();
        let v = v_chal.to_field(&index.srs.get_ref().endo_r);
        let u_chal = fr_sponge.challenge();
        let u = u_chal.to_field(&index.srs.get_ref().endo_r);

        let ep = [zeta, zetaw];

        let powers_of_eval_points_for_chunks = [
            zeta.pow(&[index.max_poly_size as u64]),
            zetaw.pow(&[index.max_poly_size as u64]),
        ];

        let polys: Vec<(PolyComm<G>, _)> = self
            .prev_challenges
            .iter()
            .zip(self.prev_chal_evals(index, &ep, &powers_of_eval_points_for_chunks))
            .map(|(c, e)| (c.1.clone(), e))
            .collect();

        let evals = vec![
            self.evals[0].combine(powers_of_eval_points_for_chunks[0]),
            self.evals[1].combine(powers_of_eval_points_for_chunks[1]),
        ];

        // compute evaluation of ft(zeta)
        let ft_eval0 = {
            let zkp = index.zkpm.evaluate(&zeta);
            let zeta1m1 = zeta1 - &Fr::<G>::one();

            let mut ft_eval0 = evals[0]
                .w
                .iter()
                .zip(evals[0].s.iter())
                .map(|(w, s)| (beta * s) + w + &gamma)
                .fold(
                    (evals[0].w[PERMUTS - 1] + &gamma)
                        * &evals[1].z
                        * &alphas[range::PERM][0]
                        * &zkp,
                    |x, y| x * y,
                );

            ft_eval0 -= if p_eval[0].len() > 0 {
                p_eval[0][0]
            } else {
                Fr::<G>::zero()
            };

            ft_eval0 -= evals[0]
                .w
                .iter()
                .zip(index.shift.iter())
                .map(|(w, s)| gamma + &(beta * &zeta * s) + w)
                .fold(alphas[range::PERM][0] * &zkp * &evals[0].z, |x, y| x * y);

            let nominator = ((zeta1m1 * &alphas[range::PERM][1] * &(zeta - &index.w))
                + (zeta1m1 * &alphas[range::PERM][2] * &(zeta - &Fr::<G>::one())))
                * &(Fr::<G>::one() - evals[0].z);

            let denominator = (zeta - &index.w) * &(zeta - &Fr::<G>::one());
            let denominator = denominator.inverse().expect("negligible probability");

            ft_eval0 += nominator * &denominator;

            ft_eval0
        };

        let combined_inner_product = {
            let ft_eval0 = vec![ft_eval0];
            let ft_eval1 = vec![self.ft_eval1];
            let mut es: Vec<(Vec<&Vec<Fr<G>>>, Option<usize>)> = polys
                .iter()
                .map(|(_, e)| (e.iter().map(|x| x).collect(), None))
                .collect();
            es.push((p_eval.iter().map(|e| e).collect::<Vec<_>>(), None));
            es.extend(
                (0..COLUMNS)
                    .map(|c| (self.evals.iter().map(|e| &e.w[c]).collect::<Vec<_>>(), None))
                    .collect::<Vec<_>>(),
            );
            es.push((self.evals.iter().map(|e| &e.z).collect::<Vec<_>>(), None));
            es.extend(
                (0..PERMUTS - 1)
                    .map(|c| (self.evals.iter().map(|e| &e.s[c]).collect::<Vec<_>>(), None))
                    .collect::<Vec<_>>(),
            );
            es.push((vec![&ft_eval0, &ft_eval1], None));

            combined_inner_product::<G>(&ep, &v, &u, &es, index.srs.get_ref().g.len())
        };

        let oracles = RandomOracles {
            beta,
            gamma,
            alpha_chal,
            alpha: alpha,
            zeta,
            v,
            u,
            zeta_chal,
            v_chal,
            u_chal,
        };

        OraclesResult {
            fq_sponge,
            digest,
            oracles,
            alphas,
            p_eval,
            powers_of_eval_points_for_chunks,
            polys,
            zeta1,
            ft_eval0,
            combined_inner_product,
        }
    }

    /// This function verifies the batch of zk-proofs
    ///     proofs: vector of Plonk proofs
    ///     index: Index
    ///     RETURN: verification status
    pub fn verify<EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>, EFrSponge: FrSponge<Fr<G>>>(
        group_map: &G::Map,
        proofs: &Vec<(&Index<G>, &Vec<PolyComm<G>>, &ProverProof<G>)>,
    ) -> Result<bool, ProofError> {
        // if there's no proof to verify, return early
        if proofs.len() == 0 {
            return Ok(true);
        }

        // TODO: Account for the different SRS lengths
        let srs = proofs[0].0.srs.get_ref();
        for (index, _, _) in proofs.iter() {
            assert_eq!(index.srs.get_ref().g.len(), srs.g.len());
        }

        // Validate each proof separately (f(zeta) = t(zeta) * Z_H(zeta))
        // + build objects required to batch verify all the evaluation proofs
        let mut params = vec![];
        for (index, lgr_comm, proof) in proofs {
            // commit to public input polynomial
            let p_comm = PolyComm::<G>::multi_scalar_mul(
                &lgr_comm
                    .iter()
                    .take(proof.public.len())
                    .map(|l| l)
                    .collect(),
                &proof.public.iter().map(|s| -*s).collect(),
            );

            // run the oracles argument
            let OraclesResult {
                fq_sponge,
                oracles,
                alphas,
                p_eval,
                powers_of_eval_points_for_chunks,
                polys,
                zeta1,
                ft_eval0,
                ..
            } = proof.oracles::<EFqSponge, EFrSponge>(index, &p_comm);

            // combine the committed chunked polynomials
            // with the right powers of zeta^n or (zeta * omega)^n
            let evals = vec![
                proof.evals[0].combine(powers_of_eval_points_for_chunks[0]),
                proof.evals[1].combine(powers_of_eval_points_for_chunks[1]),
            ];

            //
            // compute the commitment to the linearized polynomial f
            //

            let f_comm = {
                // permutation
                let zkp = index.zkpm.evaluate(&oracles.zeta);
                let mut commitments_part = vec![&index.sigma_comm[PERMUTS - 1]];
                let mut scalars_part = vec![ConstraintSystem::perm_scalars(
                    &evals,
                    oracles.beta,
                    oracles.gamma,
                    &alphas[range::PERM],
                    zkp,
                )];

                // generic
                commitments_part.push(&index.coefficients_comm[MUL_COEFF]);
                commitments_part.extend(index.coefficients_comm.iter().take(GENERICS).map(|c| c).collect::<Vec<_>>());
                scalars_part.extend(&ConstraintSystem::gnrc_scalars(&evals[0].w, evals[0].generic_selector));

                commitments_part.push(&index.coefficients_comm[CONSTANT_COEFF]);
                scalars_part.push(evals[0].generic_selector);

                // poseidon
                scalars_part.extend(&ConstraintSystem::psdn_scalars(
                    &evals,
                    &index.fr_sponge_params,
                    &alphas[range::PSDN],
                ));
                commitments_part.push(&index.psm_comm);
                commitments_part.extend(
                    index
                        .coefficients_comm
                        .iter()
                        .map(|c| c)
                        .collect::<Vec<_>>(),
                );

                // EC addition
                scalars_part.push(ConstraintSystem::ecad_scalars(&evals, &alphas[range::ADD]));
                commitments_part.push(&index.add_comm);

                // EC doubling
                scalars_part.push(ConstraintSystem::double_scalars(
                    &evals,
                    &alphas[range::DBL],
                ));
                commitments_part.push(&index.double_comm);

                // variable base endoscalar multiplication
                scalars_part.push(ConstraintSystem::endomul_scalars(
                    &evals,
                    index.endo,
                    &alphas[range::ENDML],
                ));
                commitments_part.push(&index.emul_comm);

                // EC variable base scalar multiplication
                scalars_part.push(ConstraintSystem::vbmul_scalars(&evals, &alphas[range::MUL]));
                commitments_part.push(&index.mul_comm);

                // MSM
                PolyComm::multi_scalar_mul(&commitments_part, &scalars_part)
            };

            // Maller's optimization (see https://o1-labs.github.io/mina-book/crypto/plonk/maller_15.html)
            let chunked_f_comm = f_comm.chunk_commitment(zeta1);
            let chunked_t_comm = &proof.commitments.t_comm.chunk_commitment(zeta1);
            let ft_comm = &chunked_f_comm - &chunked_t_comm.scale(zeta1 - Fr::<G>::one());

            params.push((
                p_eval,
                p_comm,
                ft_comm,
                fq_sponge,
                oracles,
                vec![ft_eval0],
                vec![proof.ft_eval1],
                polys,
            ));
        }

        // batch verify all the evaluation proofs
        let mut batch = vec![];
        for (proof, params) in proofs.iter().zip(params.iter()) {
            let (index, _lgr_comm, proof) = proof;
            let (p_eval, p_comm, ft_comm, fq_sponge, oracles, ft_eval0, ft_eval1, polys) = params;

            // recursion stuff
            let mut polynomials = polys
                .iter()
                .map(|(comm, evals)| (comm, evals.iter().map(|x| x).collect(), None))
                .collect::<Vec<(&PolyComm<G>, Vec<&Vec<Fr<G>>>, Option<usize>)>>();

            // public input commitment
            polynomials.push((p_comm, p_eval.iter().map(|e| e).collect::<Vec<_>>(), None));

            // witness commitments
            /*
            let mut w_comm = vec![];
            for w in proof.commitments.w_comm.iter() {
                let mut ee = vec![];
                for i in 0..COLUMNS {
                    for e in proof.evals {
                        ee.push(e.w[i])
                    }
                }
                let ee = e.
                w_comm.push((w, ee, None));
            }
            */
            polynomials.extend(
                proof
                    .commitments
                    .w_comm
                    .iter()
                    .zip(
                        (0..COLUMNS)
                            .map(|i| proof.evals.iter().map(|e| &e.w[i]).collect::<Vec<_>>())
                            .collect::<Vec<_>>()
                            .iter(),
                    )
                    .map(|(c, e)| (c, e.clone(), None))
                    .collect::<Vec<_>>(),
            );

            // permutation commitment
            polynomials.push((
                &proof.commitments.z_comm,
                proof.evals.iter().map(|e| &e.z).collect::<Vec<_>>(),
                None,
            ));

            // sigma commitments
            polynomials.extend(
                index
                    .sigma_comm
                    .iter()
                    .zip(
                        (0..PERMUTS - 1)
                            .map(|i| proof.evals.iter().map(|e| &e.s[i]).collect::<Vec<_>>())
                            .collect::<Vec<_>>()
                            .iter(),
                    )
                    .map(|(c, e)| (c, e.clone(), None))
                    .collect::<Vec<_>>(),
            );

            // ft commitment (chunks of it)
            polynomials.push((&ft_comm, vec![ft_eval0, ft_eval1], None));

            // prepare for the opening proof verification
            let omega = index.domain.group_gen;
            batch.push((
                fq_sponge.clone(),
                vec![oracles.zeta, oracles.zeta * &omega],
                oracles.v,
                oracles.u,
                polynomials,
                &proof.proof,
            ));
        }

        // final check to verify the evaluation proofs
        match srs.verify::<EFqSponge, _>(group_map, &mut batch, &mut thread_rng()) {
            false => Err(ProofError::OpenProof),
            true => Ok(true),
        }
    }
}
