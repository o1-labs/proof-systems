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
    lookup::{constraints::ConstraintSystem, scalars::RandomOracles},
    nolookup::constraints::ConstraintSystem as CS,
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
        evlp: &[Fr<G>],
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
                            .fold(Fr::<G>::zero(), |x, y| x + y);
                        vec![full - (diff * evlp[i]), diff]
                    })
                    .collect()
            })
            .collect()
    }

    // This function runs random oracle argument
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
        let mut oracles = RandomOracles::<Fr<G>>::zero();
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());
        // absorb the public input, l, r, o polycommitments into the argument
        fq_sponge.absorb_g(&p_comm.unshifted);
        self.commitments
            .w_comm
            .iter()
            .for_each(|c| fq_sponge.absorb_g(&c.unshifted));
        // sample beta1, gamma1 oracles
        oracles.po.beta = fq_sponge.challenge();
        oracles.po.gamma = fq_sponge.challenge();
        // absorb the z commitment into the argument and query beta1, gamma1
        fq_sponge.absorb_g(&self.commitments.z_comm.unshifted);
        fq_sponge.absorb_g(&self.commitments.lw_comm.unshifted);
        fq_sponge.absorb_g(&self.commitments.h1_comm.unshifted);
        fq_sponge.absorb_g(&self.commitments.h2_comm.unshifted);
        oracles.beta = fq_sponge.challenge();
        oracles.gamma = fq_sponge.challenge();
        // absorb the lookup aggregation commitment into the argument and query alpha
        fq_sponge.absorb_g(&self.commitments.l_comm.unshifted);
        oracles.po.alpha_chal = ScalarChallenge(fq_sponge.challenge());
        oracles.po.alpha = oracles.po.alpha_chal.to_field(&index.srs.get_ref().endo_r);
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

        oracles.po.zeta_chal = ScalarChallenge(fq_sponge.challenge());
        oracles.po.zeta = oracles.po.zeta_chal.to_field(&index.srs.get_ref().endo_r);
        let digest = fq_sponge.clone().digest();
        let mut fr_sponge = {
            let mut s = EFrSponge::new(index.fr_sponge_params.clone());
            s.absorb(&digest);
            s
        };

        // prepare some often used values
        let zeta1 = oracles.po.zeta.pow(&[n]);
        let zetaw = oracles.po.zeta * index.domain.group_gen;
        let alpha = range::alpha_powers(oracles.po.alpha);

        // compute Lagrange base evaluation denominators
        let w = (0..self.public.len())
            .zip(index.domain.elements())
            .map(|(_, w)| w)
            .collect::<Vec<_>>();
        let mut lagrange = w.iter().map(|w| oracles.po.zeta - w).collect::<Vec<_>>();
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
                        .map(|((p, l), w)| -*l * p * w)
                        .fold(Fr::<G>::zero(), |x, y| x + y))
                        * (zeta1 - Fr::<G>::one())
                        * index.domain.size_inv,
                ],
                vec![
                    (self
                        .public
                        .iter()
                        .zip(lagrange[self.public.len()..].iter())
                        .zip(index.domain.elements())
                        .map(|((p, l), w)| -*l * p * w)
                        .fold(Fr::<G>::zero(), |x, y| x + y))
                        * index.domain.size_inv
                        * (zetaw.pow(&[n as u64]) - Fr::<G>::one()),
                ],
            ]
        } else {
            [Vec::<Fr<G>>::new(), Vec::<Fr<G>>::new()]
        };
        for i in 0..2 {
            fr_sponge.absorb_evaluations(&p_eval[i], &self.evals[i])
        }

        // query opening scaler challenges
        oracles.po.v_chal = fr_sponge.challenge();
        oracles.po.v = oracles.po.v_chal.to_field(&index.srs.get_ref().endo_r);
        oracles.po.u_chal = fr_sponge.challenge();
        oracles.po.u = oracles.po.u_chal.to_field(&index.srs.get_ref().endo_r);

        let ep = [oracles.po.zeta, zetaw];

        let evlp = [
            oracles.po.zeta.pow(&[index.max_poly_size as u64]),
            zetaw.pow(&[index.max_poly_size as u64]),
        ];

        let polys: Vec<(PolyComm<G>, _)> = self
            .prev_challenges
            .iter()
            .zip(self.prev_chal_evals(index, &ep, &evlp))
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
                    .map(|c| {
                        (
                            self.evals.iter().map(|e| &e.pe.w[c]).collect::<Vec<_>>(),
                            None,
                        )
                    })
                    .collect::<Vec<_>>(),
            );
            es.extend(vec![
                (self.evals.iter().map(|e| &e.pe.z).collect::<Vec<_>>(), None),
                (self.evals.iter().map(|e| &e.pe.f).collect::<Vec<_>>(), None),
            ]);
            es.extend(
                (0..PERMUTS - 1)
                    .map(|c| {
                        (
                            self.evals.iter().map(|e| &e.pe.s[c]).collect::<Vec<_>>(),
                            None,
                        )
                    })
                    .collect::<Vec<_>>(),
            );
            es.extend(vec![(
                self.evals.iter().map(|e| &e.pe.t).collect::<Vec<_>>(),
                Some(index.max_quot_size),
            )]);

            combined_inner_product::<G>(
                &ep,
                &oracles.po.v,
                &oracles.po.u,
                &es,
                index.srs.get_ref().g.len(),
            )
        };

        (
            fq_sponge,
            digest,
            oracles,
            alpha,
            p_eval,
            evlp,
            polys,
            zeta1,
            combined_inner_product,
        )
    }

    // This function verifies the batch of zk-proofs
    //     proofs: vector of Plonk proofs
    //     index: Index
    //     RETURN: verification status
    pub fn verify<EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>, EFrSponge: FrSponge<Fr<G>>>(
        group_map: &G::Map,
        proofs: &Vec<(&Index<G>, &Vec<PolyComm<G>>, &ProverProof<G>)>,
    ) -> Result<bool, ProofError> {
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

                // evaluate committed polynomials
                let evals = (0..2)
                    .map(|i| proof.evals[i].combine(evlp[i]))
                    .collect::<Vec<_>>();
                let pevals = evals.iter().map(|e| e.pe.clone()).collect::<Vec<_>>();

                // compute linearization polynomial commitment

                // permutation
                let zkp = index.zkpm.evaluate(&oracles.po.zeta);
                let mut p = vec![&index.sigma_comm[PERMUTS - 1]];
                let mut s = vec![CS::perm_scalars(
                    &pevals,
                    &oracles.po,
                    &alpha[range::PERM],
                    zkp,
                )];

                // generic
                p.push(&index.qm_comm);
                p.extend(index.qw_comm.iter().map(|c| c).collect::<Vec<_>>());
                p.push(&index.qc_comm);
                s.extend(&CS::gnrc_scalars(&pevals[0].w));

                // poseidon
                s.extend(&CS::psdn_scalars(
                    &pevals,
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
                s.push(CS::ecad_scalars(&pevals, &alpha[range::ADD]));
                p.push(&index.add_comm);

                // EC doubling
                s.push(CS::double_scalars(&pevals, &alpha[range::DBL]));
                p.push(&index.double_comm);

                // variable base endoscalar multiplication
                s.push(CS::endomul_scalars(
                    &pevals,
                    index.endo,
                    &alpha[range::ENDML],
                ));
                p.push(&index.emul_comm);

                // lookup
                s.push(ConstraintSystem::lookup_scalars(
                    &pevals,
                    &alpha[range::LKP],
                ));
                p.push(&index.lkp_comm);

                // EC variable base scalar multiplication
                s.push(CS::vbmul_scalars(&pevals, &alpha[range::MUL]));
                p.push(&index.mul_comm);

                let f_comm = PolyComm::multi_scalar_mul(&p, &s);

                // check linearization polynomial evaluation consistency
                let zeta1m1 = zeta1 - Fr::<G>::one();
                let zm1 = (Fr::<G>::one() - pevals[0].z) * zeta1m1;
                let lm1 = (Fr::<G>::one() - evals[0].l) * zeta1m1;
                let zetam1 = oracles.po.zeta - Fr::<G>::one();
                let zetamw1 = oracles.po.zeta - index.w1;
                let zetamw3 = oracles.po.zeta - index.w3;
                let beta1 = Fr::<G>::one() + oracles.beta;
                let gammabeta1 = beta1 * oracles.gamma;

                if (if p_eval[0].len() > 0 {
                    p_eval[0][0]
                } else {
                    Fr::<G>::zero()
                } - pevals[0]
                    .w
                    .iter()
                    .zip(pevals[0].s.iter())
                    .map(|(w, s)| (oracles.po.beta * s) + w + oracles.po.gamma)
                    .fold(
                        (pevals[0].w[PERMUTS - 1] + oracles.po.gamma)
                            * pevals[1].z
                            * alpha[range::PERM][0]
                            * zkp,
                        |x, y| x * y,
                    )
                    + pevals[0]
                        .w
                        .iter()
                        .zip(index.shift.iter())
                        .map(|(w, s)| {
                            oracles.po.gamma + (oracles.po.beta * oracles.po.zeta * s) + w
                        })
                        .fold(alpha[range::PERM][0] * zkp * pevals[0].z, |x, y| x * y)
                    + ((((evals[0].l * beta1 * (oracles.gamma + evals[0].lw))
                        * (gammabeta1 + (evals[0].tb + evals[1].tb * oracles.beta)))
                        - ((evals[1].l
                            * (gammabeta1 + (evals[0].h1 + evals[1].h1 * oracles.beta)))
                            * (gammabeta1 + (evals[0].h2 + evals[1].h2 * oracles.beta))))
                        * zetamw1)
                        * alpha[range::TABLE][0]
                    - pevals[0].t * zeta1m1
                    + pevals[0].f)
                    * zetam1
                    * zetamw1
                    * zetamw3
                    != (zm1 * zetamw1 * zetamw3 * alpha[range::PERM][1])
                        + (zm1 * zetam1 * zetamw1 * alpha[range::PERM][2])
                        + (lm1 * zetamw1 * zetamw3 * alpha[range::TABLE][1])
                        + ((lm1 * alpha[range::TABLE][2]
                            + ((evals[1].h2 - evals[0].h1) * alpha[range::TABLE][3]) * zeta1m1)
                            * zetam1
                            * zetamw3)
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
                                        proof.evals.iter().map(|e| &e.pe.w[i]).collect::<Vec<_>>()
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
                            proof.evals.iter().map(|e| &e.pe.z).collect::<Vec<_>>(),
                            None,
                        ),
                        (
                            f_comm,
                            proof.evals.iter().map(|e| &e.pe.f).collect::<Vec<_>>(),
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
                                        proof.evals.iter().map(|e| &e.pe.s[i]).collect::<Vec<_>>()
                                    })
                                    .collect::<Vec<_>>()
                                    .iter(),
                            )
                            .map(|(c, e)| (c, e.clone(), None))
                            .collect::<Vec<_>>(),
                    );
                    polynomials.extend(vec![(
                        &proof.commitments.t_comm,
                        proof.evals.iter().map(|e| &e.pe.t).collect::<Vec<_>>(),
                        Some(index.max_quot_size),
                    )]);
                    polynomials.extend(vec![(
                        &proof.commitments.l_comm,
                        proof.evals.iter().map(|e| &e.l).collect::<Vec<_>>(),
                        None,
                    )]);
                    polynomials.extend(vec![(
                        &proof.commitments.lw_comm,
                        proof.evals.iter().map(|e| &e.lw).collect::<Vec<_>>(),
                        None,
                    )]);
                    polynomials.extend(vec![(
                        &proof.commitments.h1_comm,
                        proof.evals.iter().map(|e| &e.h1).collect::<Vec<_>>(),
                        None,
                    )]);
                    polynomials.extend(vec![(
                        &proof.commitments.h2_comm,
                        proof.evals.iter().map(|e| &e.h2).collect::<Vec<_>>(),
                        None,
                    )]);
                    polynomials.extend(vec![(
                        &index.table_comm,
                        proof.evals.iter().map(|e| &e.tb).collect::<Vec<_>>(),
                        None,
                    )]);

                    // prepare for the opening proof verification
                    (
                        fq_sponge.clone(),
                        vec![oracles.po.zeta, oracles.po.zeta * &index.domain.group_gen],
                        oracles.po.v,
                        oracles.po.u,
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
