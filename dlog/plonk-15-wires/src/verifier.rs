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
};
use rand::thread_rng;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

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
    ) -> (
        EFqSponge,
        Fr<G>,
        RandomOracles<Fr<G>>,
        Vec<Fr<G>>,
        [Vec<Fr<G>>; 2],
        [Fr<G>; 2],
        Vec<(PolyComm<G>, Vec<Vec<Fr<G>>>)>,
        Fr<G>,
        Fr<G>,
    ) {
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
        {
            let s = self.commitments.t_comm.shifted.unwrap();
            if s.is_zero() {
                fq_sponge.absorb_g(&[dummy])
            } else {
                fq_sponge.absorb_g(&[s])
            }
        };

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

        let combined_inner_product = {
            let mut es: Vec<(Vec<&Vec<Fr<G>>>, Option<usize>)> = polys
                .iter()
                .map(|(_, e)| (e.iter().map(|x| x).collect(), None))
                .collect();
            es.extend(vec![(p_eval.iter().map(|e| e).collect::<Vec<_>>(), None)]);
            es.extend(
                (0..COLUMNS)
                    .map(|c| (self.evals.iter().map(|e| &e.w[c]).collect::<Vec<_>>(), None))
                    .collect::<Vec<_>>(),
            );
            es.extend(vec![
                (self.evals.iter().map(|e| &e.z).collect::<Vec<_>>(), None),
                (self.evals.iter().map(|e| &e.f).collect::<Vec<_>>(), None),
            ]);
            es.extend(
                (0..PERMUTS - 1)
                    .map(|c| (self.evals.iter().map(|e| &e.s[c]).collect::<Vec<_>>(), None))
                    .collect::<Vec<_>>(),
            );
            es.extend(vec![(
                self.evals.iter().map(|e| &e.t).collect::<Vec<_>>(),
                Some(index.max_quot_size),
            )]);

            combined_inner_product::<G>(&ep, &v, &u, &es, index.srs.get_ref().g.len())
        };

        (
            fq_sponge,
            digest,
            RandomOracles {
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
            },
            alphas,
            p_eval,
            powers_of_eval_points_for_chunks,
            polys,
            zeta1,
            combined_inner_product,
        )
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

        let params = proofs
            .iter()
            .map(|(index, lgr_comm, proof)| {
                // commit to public input polynomial
                let p_comm = PolyComm::<G>::multi_scalar_mul(
                    &lgr_comm
                        .iter()
                        .take(proof.public.len())
                        .map(|l| l)
                        .collect(),
                    &proof.public.iter().map(|s| -*s).collect(),
                );

                let (fq_sponge, _, oracles, alpha, p_eval, evlp, polys, zeta1, _) =
                    proof.oracles::<EFqSponge, EFrSponge>(index, &p_comm);

                // evaluate committed polynoms
                let evals = (0..2)
                    .map(|i| proof.evals[i].combine(evlp[i]))
                    .collect::<Vec<_>>();

                // compute linearization polynomial commitment

                // permutation
                let zkp = index.zkpm.evaluate(&oracles.zeta);
                let mut p = vec![&index.sigma_comm[PERMUTS - 1]];
                let mut s = vec![ConstraintSystem::perm_scalars(
                    &evals,
                    &oracles,
                    &alpha[range::PERM],
                    zkp,
                )];

                // generic
                p.push(&index.qm_comm);
                p.extend(index.qw_comm.iter().map(|c| c).collect::<Vec<_>>());
                p.push(&index.qc_comm);
                s.extend(&ConstraintSystem::gnrc_scalars(&evals[0].w));

                // poseidon
                s.extend(&ConstraintSystem::psdn_scalars(
                    &evals,
                    &index.fr_sponge_params,
                    &alpha[range::PSDN],
                ));
                p.push(&index.psm_comm);
                p.extend(
                    index
                        .rcm_comm
                        .iter()
                        .flatten()
                        .map(|c| c)
                        .collect::<Vec<_>>(),
                );

                // EC addition
                s.push(ConstraintSystem::ecad_scalars(&evals, &alpha[range::ADD]));
                p.push(&index.add_comm);

                // EC doubling
                s.push(ConstraintSystem::double_scalars(&evals, &alpha[range::DBL]));
                p.push(&index.double_comm);

                // variable base endoscalar multiplication
                s.push(ConstraintSystem::endomul_scalars(
                    &evals,
                    index.endo,
                    &alpha[range::ENDML],
                ));
                p.push(&index.emul_comm);

                // EC variable base scalar multiplication
                s.push(ConstraintSystem::vbmul_scalars(&evals, &alpha[range::MUL]));
                p.push(&index.mul_comm);

                let f_comm = PolyComm::multi_scalar_mul(&p, &s);

                // check linearization polynomial evaluation consistency
                let zeta1m1 = zeta1 - &Fr::<G>::one();
                if (evals[0].f
                    + &(if p_eval[0].len() > 0 {
                        p_eval[0][0]
                    } else {
                        Fr::<G>::zero()
                    })
                    - evals[0]
                        .w
                        .iter()
                        .zip(evals[0].s.iter())
                        .map(|(w, s)| (oracles.beta * s) + w + &oracles.gamma)
                        .fold(
                            (evals[0].w[PERMUTS - 1] + &oracles.gamma)
                                * &evals[1].z
                                * &alpha[range::PERM][0]
                                * &zkp,
                            |x, y| x * y,
                        )
                    + evals[0]
                        .w
                        .iter()
                        .zip(index.shift.iter())
                        .map(|(w, s)| oracles.gamma + &(oracles.beta * &oracles.zeta * s) + w)
                        .fold(alpha[range::PERM][0] * &zkp * &evals[0].z, |x, y| x * y)
                    - evals[0].t * &zeta1m1)
                    * &(oracles.zeta - &index.w)
                    * &(oracles.zeta - &Fr::<G>::one())
                    != ((zeta1m1 * &alpha[range::PERM][1] * &(oracles.zeta - &index.w))
                        + (zeta1m1 * &alpha[range::PERM][2] * &(oracles.zeta - &Fr::<G>::one())))
                        * &(Fr::<G>::one() - evals[0].z)
                {
                    return Err(ProofError::ProofVerification);
                }

                Ok((p_eval, p_comm, f_comm, fq_sponge, oracles, polys))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut batch = proofs
            .iter()
            .zip(params.iter())
            .map(
                |(
                    (index, _lgr_comm, proof),
                    (p_eval, p_comm, f_comm, fq_sponge, oracles, polys),
                )| {
                    let mut polynomials = polys
                        .iter()
                        .map(|(comm, evals)| (comm, evals.iter().map(|x| x).collect(), None))
                        .collect::<Vec<(&PolyComm<G>, Vec<&Vec<Fr<G>>>, Option<usize>)>>();

                    polynomials.extend(vec![(
                        p_comm,
                        p_eval.iter().map(|e| e).collect::<Vec<_>>(),
                        None,
                    )]);
                    polynomials.extend(
                        proof
                            .commitments
                            .w_comm
                            .iter()
                            .zip(
                                (0..COLUMNS)
                                    .map(|i| {
                                        proof.evals.iter().map(|e| &e.w[i]).collect::<Vec<_>>()
                                    })
                                    .collect::<Vec<_>>()
                                    .iter(),
                            )
                            .map(|(c, e)| (c, e.clone(), None))
                            .collect::<Vec<_>>(),
                    );
                    polynomials.extend(vec![
                        (
                            &proof.commitments.z_comm,
                            proof.evals.iter().map(|e| &e.z).collect::<Vec<_>>(),
                            None,
                        ),
                        (
                            f_comm,
                            proof.evals.iter().map(|e| &e.f).collect::<Vec<_>>(),
                            None,
                        ),
                    ]);
                    polynomials.extend(
                        index
                            .sigma_comm
                            .iter()
                            .zip(
                                (0..PERMUTS - 1)
                                    .map(|i| {
                                        proof.evals.iter().map(|e| &e.s[i]).collect::<Vec<_>>()
                                    })
                                    .collect::<Vec<_>>()
                                    .iter(),
                            )
                            .map(|(c, e)| (c, e.clone(), None))
                            .collect::<Vec<_>>(),
                    );
                    polynomials.extend(vec![(
                        &proof.commitments.t_comm,
                        proof.evals.iter().map(|e| &e.t).collect::<Vec<_>>(),
                        Some(index.max_quot_size),
                    )]);

                    // prepare for the opening proof verification
                    (
                        fq_sponge.clone(),
                        vec![oracles.zeta, oracles.zeta * &index.domain.group_gen],
                        oracles.v,
                        oracles.u,
                        polynomials,
                        &proof.proof,
                    )
                },
            )
            .collect::<Vec<_>>();

        // verify the opening proofs
        // TODO: Account for the different SRS lengths
        let srs = proofs[0].0.srs.get_ref();
        for (index, _, _) in proofs.iter() {
            assert_eq!(index.srs.get_ref().g.len(), srs.g.len());
        }

        match srs.verify::<EFqSponge, _>(group_map, &mut batch, &mut thread_rng()) {
            false => Err(ProofError::OpenProof),
            true => Ok(true),
        }
    }
}
