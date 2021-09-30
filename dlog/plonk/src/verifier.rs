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
use plonk_circuits::{constraints::ConstraintSystem, scalars::RandomOracles};
use rand::thread_rng;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

#[derive(Clone)]
pub struct CachedValues<Fs> {
    pub zeta1: Fs,
    pub zetaw: Fs,
    pub alpha: Vec<Fs>,
}

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

    // This function runs random oracle argument
    pub fn oracles<EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>, EFrSponge: FrSponge<Fr<G>>>(
        &self,
        index: &Index<G>,
        p_comm: &PolyComm<G>,
    ) -> Option<(
        EFqSponge,
        Fr<G>,
        RandomOracles<Fr<G>>,
        Vec<Fr<G>>,
        [Vec<Fr<G>>; 2],
        [Fr<G>; 2],
        Vec<(PolyComm<G>, Vec<Vec<Fr<G>>>)>,
        Fr<G>,
        Fr<G>,
    )> {
        let n = index.domain.size;
        // Run random oracle argument to sample verifier oracles
        let mut oracles = RandomOracles::<Fr<G>>::zero();
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());
        // absorb the public input, l, r, o polycommitments into the argument
        fq_sponge.absorb_g(&p_comm.unshifted);
        fq_sponge.absorb_g(&self.commitments.l_comm.unshifted);
        fq_sponge.absorb_g(&self.commitments.r_comm.unshifted);
        fq_sponge.absorb_g(&self.commitments.o_comm.unshifted);
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
            let s = self.commitments.t_comm.shifted?;
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
        let zeta1 = oracles.zeta.pow(&[n]);
        let zetaw = oracles.zeta * &index.domain.group_gen;
        let mut alpha = oracles.alpha;
        let alpha = (0..17)
            .map(|_| {
                alpha *= &oracles.alpha;
                alpha
            })
            .collect::<Vec<_>>();

        // compute Lagrange base evaluation denominators
        let w = (0..self.public.len())
            .zip(index.domain.elements())
            .map(|(_, w)| w)
            .collect::<Vec<_>>();
        let mut lagrange = w.iter().map(|w| oracles.zeta - w).collect::<Vec<_>>();
        (0..self.public.len())
            .zip(w.iter())
            .for_each(|(_, w)| lagrange.push(zetaw - w));
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

        // query opening scaler challenges
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
            es.extend(vec![
                (p_eval.iter().map(|e| e).collect::<Vec<_>>(), None),
                (self.evals.iter().map(|e| &e.l).collect::<Vec<_>>(), None),
                (self.evals.iter().map(|e| &e.r).collect::<Vec<_>>(), None),
                (self.evals.iter().map(|e| &e.o).collect::<Vec<_>>(), None),
                (self.evals.iter().map(|e| &e.z).collect::<Vec<_>>(), None),
                (self.evals.iter().map(|e| &e.f).collect::<Vec<_>>(), None),
                (
                    self.evals.iter().map(|e| &e.sigma1).collect::<Vec<_>>(),
                    None,
                ),
                (
                    self.evals.iter().map(|e| &e.sigma2).collect::<Vec<_>>(),
                    None,
                ),
                (
                    self.evals.iter().map(|e| &e.t).collect::<Vec<_>>(),
                    Some(index.max_quot_size),
                ),
            ]);

            combined_inner_product::<G>(
                &ep,
                &oracles.v,
                &oracles.u,
                &es,
                index.srs.get_ref().g.len(),
            )
        };

        Some((
            fq_sponge,
            digest,
            oracles,
            alpha,
            p_eval,
            evlp,
            polys,
            zeta1,
            combined_inner_product,
        ))
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
                let n = index.domain.size;
                // commit to public input polynomial
                let p_comm = PolyComm::<G>::multi_scalar_mul(
                    &lgr_comm
                        .iter()
                        .take(proof.public.len())
                        .map(|l| l)
                        .collect(),
                    &proof.public.iter().map(|s| -*s).collect(),
                ).ok_or(ProofError::BadMultiScalarMul)?;

                let (fq_sponge, _, oracles, alpha, p_eval, evlp, polys, zeta1, _) =
                    proof.oracles::<EFqSponge, EFrSponge>(index, &p_comm).ok_or(ProofError::OracleCommit)?;

                // evaluate committed polynoms
                let evals = (0..2)
                    .map(|i| proof.evals[i].combine(evlp[i]))
                    .collect::<Vec<_>>();

                // compute linearization polynomial commitment
                let p = vec![
                    // permutation polynomial commitments
                    &proof.commitments.z_comm,
                    &index.sigma_comm[2],
                    // generic constraint polynomial commitments
                    &index.qm_comm,
                    &index.ql_comm,
                    &index.qr_comm,
                    &index.qo_comm,
                    &index.qc_comm,
                    // poseidon constraint polynomial commitments
                    &index.psm_comm,
                    &index.rcm_comm[0],
                    &index.rcm_comm[1],
                    &index.rcm_comm[2],
                    // EC addition constraint polynomial commitments
                    &index.add_comm,
                    // EC variable base scalar multiplication constraint polynomial commitments
                    &index.mul1_comm,
                    &index.mul2_comm,
                    // group endomorphism optimised variable base scalar multiplication constraint polynomial commitments
                    &index.emul1_comm,
                    &index.emul2_comm,
                    &index.emul3_comm,
                ];

                // permutation linearization scalars
                let zkp = index.zkpm.evaluate(oracles.zeta);
                let mut s = ConstraintSystem::perm_scalars(
                    &evals,
                    &oracles,
                    (index.r, index.o),
                    &alpha[range::PERM],
                    n,
                    zkp,
                    index.w,
                );
                // generic constraint/permutation linearization scalars
                s.extend(&ConstraintSystem::gnrc_scalars(&evals[0]));
                // poseidon constraint linearization scalars
                s.extend(&ConstraintSystem::psdn_scalars(
                    &evals,
                    &index.fr_sponge_params,
                    &alpha[range::PSDN],
                ));
                // EC addition constraint linearization scalars
                s.extend(&ConstraintSystem::ecad_scalars(&evals, &alpha[range::ADD]));
                // EC variable base scalar multiplication constraint linearization scalars
                s.extend(&ConstraintSystem::vbmul_scalars(&evals, &alpha[range::MUL]));
                // group endomorphism optimised variable base scalar multiplication constraint linearization scalars
                s.extend(&ConstraintSystem::endomul_scalars(
                    &evals,
                    index.endo,
                    &alpha[range::ENDML],
                ));

                let f_comm =
                    PolyComm::multi_scalar_mul(&p, &s).ok_or(ProofError::BadMultiScalarMul)?;

                // check linearization polynomial evaluation consistency
                if (evals[0].f
                    + &(if p_eval[0].len() > 0 {
                        p_eval[0][0]
                    } else {
                        Fr::<G>::zero()
                    })
                    - ((evals[0].l + &(oracles.beta * &evals[0].sigma1) + &oracles.gamma)
                        * &(evals[0].r + &(oracles.beta * &evals[0].sigma2) + &oracles.gamma)
                        * (evals[0].o + &oracles.gamma)
                        * &evals[1].z
                        * &zkp
                        * &oracles.alpha)
                    - evals[0].t * &(zeta1 - &Fr::<G>::one()))
                    * &(oracles.zeta - &Fr::<G>::one())
                    * &(oracles.zeta - &index.w)
                    != ((zeta1 - &Fr::<G>::one()) * &alpha[3] * &(oracles.zeta - &index.w))
                        + ((zeta1 - &Fr::<G>::one())
                            * &alpha[4]
                            * &(oracles.zeta - &Fr::<G>::one()))
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
                    let mut polynoms = polys
                        .iter()
                        .map(|(comm, evals)| (comm, evals.iter().map(|x| x).collect(), None))
                        .collect::<Vec<(&PolyComm<G>, Vec<&Vec<Fr<G>>>, Option<usize>)>>();

                    polynoms.extend(vec![
                        (p_comm, p_eval.iter().map(|e| e).collect::<Vec<_>>(), None),
                        (
                            &proof.commitments.l_comm,
                            proof.evals.iter().map(|e| &e.l).collect::<Vec<_>>(),
                            None,
                        ),
                        (
                            &proof.commitments.r_comm,
                            proof.evals.iter().map(|e| &e.r).collect::<Vec<_>>(),
                            None,
                        ),
                        (
                            &proof.commitments.o_comm,
                            proof.evals.iter().map(|e| &e.o).collect::<Vec<_>>(),
                            None,
                        ),
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
                        (
                            &index.sigma_comm[0],
                            proof.evals.iter().map(|e| &e.sigma1).collect::<Vec<_>>(),
                            None,
                        ),
                        (
                            &index.sigma_comm[1],
                            proof.evals.iter().map(|e| &e.sigma2).collect::<Vec<_>>(),
                            None,
                        ),
                        (
                            &proof.commitments.t_comm,
                            proof.evals.iter().map(|e| &e.t).collect::<Vec<_>>(),
                            Some(index.max_quot_size),
                        ),
                    ]);

                    // prepare for the opening proof verification
                    (
                        fq_sponge.clone(),
                        vec![oracles.zeta, oracles.zeta * &index.domain.group_gen],
                        oracles.v,
                        oracles.u,
                        polynoms,
                        &proof.proof,
                    )
                },
            )
            .collect::<Vec<_>>();

        // verify the opening proofs
        // TODO: Account for the different SRS lengths
        let index0 = &proofs[0].0;
        let trimmed_length = (index0.domain.size as u64).trailing_zeros() as usize;
        let srs = index0.srs.get_ref().trim(trimmed_length);

        for (index, _, _) in proofs.iter() {
            let trimmed_length = (index.domain.size as u64).trailing_zeros() as usize;
            if index.srs.get_ref().trim(trimmed_length).len() != srs.len() {
                return Err(ProofError::BadSrsLength);
            }
        }

        match srs.verify::<EFqSponge>(group_map, &mut batch, &mut thread_rng()) {
            false => Err(ProofError::OpenProof),
            true => Ok(true),
        }
    }
}
