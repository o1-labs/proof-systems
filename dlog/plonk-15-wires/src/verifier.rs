/********************************************************************************************

This source file implements zk-proof batch verifier functionality.

*********************************************************************************************/

pub use super::index::VerifierIndex as Index;
pub use super::prover::{range, ProverProof};
use crate::plonk_sponge::FrSponge;
use algebra::{AffineCurve, Field, One, Zero};
use commitment_dlog::commitment::{
    b_poly, b_poly_coefficients, combined_inner_product, CommitmentCurve, CommitmentField, PolyComm,
};
use ff_fft::EvaluationDomain;
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
                            .fold(Fr::<G>::zero(), |x, y| x + &y);
                        vec![full - &(diff * &evlp[i]), diff]
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
        let omega = index.domain.group_gen;

        // Run random oracle argument to sample verifier oracles
        let mut oracles = RandomOracles::<Fr<G>>::zero();
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        // absorb the public input, l, r, o polycommitments into the argument
        fq_sponge.absorb_g(&p_comm.unshifted);
        self.commitments
            .w_comm
            .iter()
            .for_each(|c| fq_sponge.absorb_g(&c.unshifted));

        // sample beta, gamma oracles
        oracles.beta = fq_sponge.challenge();
        oracles.gamma = fq_sponge.challenge();

        // absorb the z commitment into the argument and query alpha
        fq_sponge.absorb_g(&self.commitments.z_comm.unshifted);
        oracles.alpha_chal = ScalarChallenge(fq_sponge.challenge());
        oracles.alpha = oracles.alpha_chal.to_field(&index.srs.get_ref().endo_r);

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

        oracles.zeta_chal = ScalarChallenge(fq_sponge.challenge());
        oracles.zeta = oracles.zeta_chal.to_field(&index.srs.get_ref().endo_r);
        let digest = fq_sponge.clone().digest();
        let mut fr_sponge = {
            let mut s = EFrSponge::new(index.fr_sponge_params.clone());
            s.absorb(&digest);
            s
        };

        // prepare some often used values
        let zeta_n = oracles.zeta.pow(&[n]);
        let zetaw = oracles.zeta * &omega;
        let alpha = range::alpha_powers(oracles.alpha);

        // compute Lagrange base evaluation denominators
        // TODO(mimoo): this could belong to the if branch (if self.public.len() > 0)

        // w = [1, w, w^2, ..., w^{public_len - 1}]
        let w = (0..self.public.len())
            .zip(index.domain.elements())
            .map(|(_, w)| w)
            .collect::<Vec<_>>();
        // lagrange = [z - 1, z - w, z - w^2, ...]
        let mut lagrange = w.iter().map(|w| oracles.zeta - w).collect::<Vec<_>>();
        // lagrange.append([z*w - 1, z*w - w, z*w - w^2, ...])
        (0..self.public.len())
            .zip(w.iter())
            .for_each(|(_, w)| lagrange.push(zetaw - w));
        // lagrange contains [1/(X-1), 1/(X-w), 1/(X-w^2), etc.] evaluated at z and z*w
        // TODO(mimoo): separate the z from the zw evaluations
        algebra::fields::batch_inversion::<Fr<G>>(&mut lagrange);

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
                        * &(zeta_n - &Fr::<G>::one())
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
        /*
        TODO(mimoo): refactor with this:
        let mut eval_z = Fr::<G>::zero();
        // does izip uses the length of public here?
        let stuff = itertools::izip!(self.public, lagrange, index.domain.elements());
        for (public, lagrange, witness) in stuff {
            eval_z -= lagrange * public * witness
        }
        eval_z *= zeta_n - Fr::<G>::one();
        eval_z *= index.domain.size_inv;
        */
        } else {
            [Vec::<Fr<G>>::new(), Vec::<Fr<G>>::new()]
        };
        for i in 0..2 {
            fr_sponge.absorb_evaluations(&p_eval[i], &self.evals[i])
        }

        // query opening scalar challenges
        oracles.v_chal = fr_sponge.challenge();
        oracles.v = oracles.v_chal.to_field(&index.srs.get_ref().endo_r);
        oracles.u_chal = fr_sponge.challenge();
        oracles.u = oracles.u_chal.to_field(&index.srs.get_ref().endo_r);

        let ep = [oracles.zeta, zetaw];

        let evlp = [
            oracles.zeta.pow(&[index.max_poly_size as u64]),
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

            combined_inner_product::<G>(
                &ep,
                &oracles.v,
                &oracles.u,
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
            zeta_n,
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
        println!("verify(group_map, proofs)");
        if proofs.len() == 0 {
            return Ok(true);
        }

        let params = proofs
            .iter()
            // TODO(mimoo): shouldn't these lagrange commitments come pre-computed?
            .map(|(index, lgr_comm, proof)| {
                println!("one iteration of proofs.iter().map(): ");

                // debug
                let GENERIC = true;
                let POSEIDON = false;
                let EC_ADD = true;
                let EC_DBL = true;
                let ENDO_SCALAR_MUL = true;
                let SCALAR_MUL = true;
                let PERMUTATION = false;

                // commit to public input polynomial
                println!("- commit to public input polynomial");
                let p_comm = PolyComm::<G>::multi_scalar_mul(
                    &lgr_comm
                        .iter()
                        .take(proof.public.len())
                        .map(|l| l)
                        .collect(),
                    &proof.public.iter().map(|s| -*s).collect(),
                );

                let (fq_sponge, _, oracles, alpha, p_eval, evlp, polys, zeta_n, _) =
                    proof.oracles::<EFqSponge, EFrSponge>(index, &p_comm);
                println!("debug verifier:");
                println!("oracles: {:?}", oracles);
                println!("alpha: {:?}", alpha);
                println!("p_eval: {:?}", p_eval);
                println!("evlp: {:?}", evlp);
                println!("polys: {:?}", polys);

                // evaluate committed polynomials
                println!("- evaluate committed polynomials");

                let evals = vec![
                    proof.evals[0].combine(evlp[0]),
                    proof.evals[1].combine(evlp[1]),
                ];

                let evals_zeta = &evals[0];
                let evals_zeta_omega = &evals[1];

                let f_zeta = &evals[0].f;
                let t_zeta = &evals[0].t;
                let w_zeta = &evals[0].w;
                let s_zeta = &evals[0].s;
                let z_zeta = &evals[0].z;

                let z_zeta_omega = &evals[1].z;

                let zeta_n_minus_1 = zeta_n - &Fr::<G>::one(); // zeta^n - 1

                // compute linearization polynomial commitment
                println!("- compute linearization polynomial commitment");

                // permutation
                println!("- permutation");
                let zkp = index.zkpm.evaluate(oracles.zeta);
                let mut p = vec![&index.sigma_comm[PERMUTS - 1]];
                let mut s = vec![ConstraintSystem::perm_scalars(
                    &evals,
                    &oracles,
                    &alpha[range::PERM],
                    zkp,
                )];

                // generic
                println!("- generic");
                p.push(&index.qm_comm);
                p.extend(index.qw_comm.iter().map(|c| c).collect::<Vec<_>>());
                p.push(&index.qc_comm);
                s.extend(&ConstraintSystem::gnrc_scalars(&evals_zeta));

                // poseidon
                println!("- poseidon");
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
                println!("- EC addition");
                s.push(ConstraintSystem::ecad_scalars(&evals, &alpha[range::ADD]));
                p.push(&index.add_comm);

                // EC doubling
                println!("- EC doubling");
                s.push(ConstraintSystem::double_scalars(&evals, &alpha[range::DBL]));
                p.push(&index.double_comm);

                // variable base endoscalar multiplication
                println!("- variable base endoscalar multiplication");
                s.push(ConstraintSystem::endomul_scalars(
                    &evals,
                    index.endo,
                    &alpha[range::ENDML],
                ));
                p.push(&index.emul_comm);

                // EC variable base scalar multiplication
                println!("- EC variable base scalar multiplication");
                s.push(ConstraintSystem::vbmul_scalars(&evals, &alpha[range::MUL]));
                p.push(&index.mul_comm);

                let f_comm = PolyComm::multi_scalar_mul(&p, &s);

                //
                // check linearization polynomial evaluation consistency
                // see https://hackmd.io/@mimoo/HkuQJKxgY
                //

                println!("- check linearization polynomial evaluation consistency");

                // [f(zeta) + pub(zeta) + permutation_stuff - t(zeta) * (zeta^n - 1)](zeta - w^{n-3})(zeta - 1)
                let left = {
                    let public_zeta = if p_eval[0].len() > 0 {
                        p_eval[0][0]
                    } else {
                        Fr::<G>::zero()
                    };

                    println!("{} public_zeta: {:?}", line!(), public_zeta);

                    let perm_sigmas = w_zeta
                        .iter()
                        .zip(s_zeta.iter())
                        .map(|(w, s)| (oracles.beta * s) + w + &oracles.gamma)
                        .fold(
                            (w_zeta[PERMUTS - 1] + &oracles.gamma)
                                * z_zeta_omega
                                * &alpha[range::PERM][0]
                                * &zkp,
                            |x, y| x * y,
                        );
                    println!("number of s_zeta: {:?}", s_zeta.len());

                    let perm_shifts = w_zeta
                        .iter()
                        .zip(index.shift.iter())
                        .map(|(w, s)| oracles.gamma + &(oracles.beta * &oracles.zeta * s) + w)
                        .fold(alpha[range::PERM][0] * zkp * z_zeta, |x, y| x * y);
                    println!(
                        "number of shift: {:?} (should have one more)",
                        index.shift.len()
                    );

                    let permutation_stuff = perm_shifts - perm_sigmas;
                    let permutation_lagrange_stuff =
                        (oracles.zeta - &index.w) * (oracles.zeta - Fr::<G>::one());

                    let mut left_hand_side = *f_zeta + public_zeta;
                    if PERMUTATION {
                        left_hand_side = left_hand_side + &permutation_stuff;
                    }
                    let moving_t = left_hand_side - *t_zeta * zeta_n_minus_1;

                    // let's write left == right ourselves
                    {
                        let left = public_zeta + f_zeta;
                        let left = left + &permutation_stuff;

                        let right = *t_zeta * zeta_n_minus_1;
                        println!("my left = {:?}", left);
                        println!("my right = {:?}", right);
                    }

                    if PERMUTATION {
                        moving_t
                    } else {
                        moving_t * permutation_lagrange_stuff
                    }
                };

                // (1 - z(zeta)) * [(zeta^n - 1) * alpha^PERM1 * (zeta - w^{n-3}) + (zeta^n - 1) * alpha^PERM2 * (zeta - 1)]
                let right = if PERMUTATION {
                    // (zeta^n - 1) * alpha^PERM1 * (zeta - w^{n-3})
                    let acc_init =
                        zeta_n_minus_1 * &alpha[range::PERM][1] * &(oracles.zeta - &index.w);
                    // (zeta^n - 1) * alpha^PERM2 * (zeta - 1)
                    let acc_final =
                        zeta_n_minus_1 * &alpha[range::PERM][2] * &(oracles.zeta - &Fr::<G>::one());
                    // multiply by (1 - z(zeta)) to finish both lagrange polynomials
                    (acc_init + acc_final) * &(Fr::<G>::one() - z_zeta)
                } else {
                    Fr::<G>::zero()
                };

                println!("- left/right check");
                if left != right {
                    println!("left = {:?}", left);
                    println!("right = {:?}", right);
                    return Err(ProofError::ProofVerification);
                }

                println!("- left = right!");
                println!("left = {:?}", left);
                println!("right = {:?}", right);
                Ok((p_eval, p_comm, f_comm, fq_sponge, oracles, polys))
            })
            .collect::<Result<Vec<_>, _>>()?;

        println!("- batch proofs");
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
                    println!("- prepare for the opening proof verification");
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
        println!("- verify the opening proofs");
        // TODO: Account for the different SRS lengths
        let srs = proofs[0].0.srs.get_ref();
        for (index, _, _) in proofs.iter() {
            // TODO(mimoo): do we really want to panic here?
            assert_eq!(index.srs.get_ref().g.len(), srs.g.len());
        }

        if srs.verify::<EFqSponge>(group_map, &mut batch, &mut thread_rng()) {
            Ok(true)
        } else {
            Err(ProofError::OpenProof)
        }
    }
}
