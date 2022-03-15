//! This module implements zk-proof batch verifier functionality.

use crate::{
    alphas::Alphas,
    circuits::{
        argument::ArgumentType,
        constraints::ConstraintSystem,
        expr::{Column, Constants, PolishToken},
        gate::{GateType, LookupsUsed},
        polynomials::{generic, permutation},
        scalars::RandomOracles,
        wires::*,
    },
    error::{ProofError, Result},
    plonk_sponge::FrSponge,
    prover::ProverProof,
    verifier_index::{LookupVerifierIndex, VerifierIndex},
};
use ark_ec::AffineCurve;
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{EvaluationDomain, Polynomial};
use commitment_dlog::commitment::{
    b_poly, b_poly_coefficients, combined_inner_product, CommitmentCurve, PolyComm,
};
use oracle::{sponge::ScalarChallenge, FqSponge};
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
    pub fq_sponge: EFqSponge,
    /// the last evaluation of the Fq-Sponge in this protocol
    pub digest: Fr<G>,
    /// the challenges produced in the protocol
    pub oracles: RandomOracles<Fr<G>>,
    /// the computed powers of alpha
    pub all_alphas: Alphas<Fr<G>>,
    /// public polynomial evaluations
    pub p_eval: [Vec<Fr<G>>; 2],
    /// zeta^n and (zeta * omega)^n
    pub powers_of_eval_points_for_chunks: [Fr<G>; 2],
    /// ?
    #[allow(clippy::type_complexity)]
    pub polys: Vec<(PolyComm<G>, Vec<Vec<Fr<G>>>)>,
    /// pre-computed zeta^n
    pub zeta1: Fr<G>,
    /// The evaluation f(zeta) - t(zeta) * Z_H(zeta)
    pub ft_eval0: Fr<G>,
    /// ?
    pub combined_inner_product: Fr<G>,
}

impl<G: CommitmentCurve> ProverProof<G>
where
    G::BaseField: PrimeField,
{
    pub fn prev_chal_evals(
        &self,
        index: &VerifierIndex<G>,
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
                        let full = b_poly(chals, evaluation_points[i]);
                        if index.max_poly_size == b_len {
                            return vec![full];
                        }
                        let mut betaacc = Fr::<G>::one();
                        let diff = (index.max_poly_size..b_len)
                            .map(|j| {
                                let b_j = match &b {
                                    None => {
                                        let t = b_poly_coefficients(chals);
                                        let res = t[j];
                                        b = Some(t);
                                        res
                                    }
                                    Some(b) => b[j],
                                };

                                let ret = betaacc * b_j;
                                betaacc *= &evaluation_points[i];
                                ret
                            })
                            .fold(Fr::<G>::zero(), |x, y| x + y);
                        vec![full - (diff * powers_of_eval_points_for_chunks[i]), diff]
                    })
                    .collect()
            })
            .collect()
    }

    /// This function runs the random oracle argument
    pub fn oracles<EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>, EFrSponge: FrSponge<Fr<G>>>(
        &self,
        index: &VerifierIndex<G>,
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

        let joint_combiner = {
            let s = match index.lookup_index {
                None
                | Some(LookupVerifierIndex {
                    lookup_used: LookupsUsed::Single,
                    ..
                }) => ScalarChallenge(Fr::<G>::zero()),
                Some(LookupVerifierIndex {
                    lookup_used: LookupsUsed::Joint,
                    ..
                }) => ScalarChallenge(fq_sponge.challenge()),
            };
            (s, s.to_field(&index.srs.endo_r))
        };

        self.commitments.lookup.iter().for_each(|l| {
            l.sorted
                .iter()
                .for_each(|c| fq_sponge.absorb_g(&c.unshifted));
        });

        // sample beta, gamma oracles
        let beta = fq_sponge.challenge();
        let gamma = fq_sponge.challenge();

        self.commitments.lookup.iter().for_each(|l| {
            fq_sponge.absorb_g(&l.aggreg.unshifted);
        });

        // absorb the z commitment into the argument and query alpha
        fq_sponge.absorb_g(&self.commitments.z_comm.unshifted);
        let alpha_chal = ScalarChallenge(fq_sponge.challenge());
        let alpha = alpha_chal.to_field(&index.srs.endo_r);

        // absorb the polycommitments into the argument and sample zeta
        let expected_t_size = PERMUTS;
        assert_eq!(expected_t_size, self.commitments.t_comm.unshifted.len());
        fq_sponge.absorb_g(&self.commitments.t_comm.unshifted);

        let zeta_chal = ScalarChallenge(fq_sponge.challenge());
        let zeta = zeta_chal.to_field(&index.srs.endo_r);
        let digest = fq_sponge.clone().digest();
        let mut fr_sponge = {
            let mut s = EFrSponge::new(index.fr_sponge_params.clone());
            s.absorb(&digest);
            s
        };

        // prepare some often used values
        let zeta1 = zeta.pow(&[n]);
        let zetaw = zeta * index.domain.group_gen;
        let mut all_alphas = index.powers_of_alpha.clone();
        all_alphas.instantiate(alpha);

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
        let p_eval = if !self.public.is_empty() {
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
        for (p, e) in p_eval.iter().zip(&self.evals) {
            fr_sponge.absorb_evaluations(p, e);
        }
        fr_sponge.absorb(&self.ft_eval1);

        // query opening scalar challenges
        let v_chal = fr_sponge.challenge();
        let v = v_chal.to_field(&index.srs.endo_r);
        let u_chal = fr_sponge.challenge();
        let u = u_chal.to_field(&index.srs.endo_r);

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
            let zeta1m1 = zeta1 - Fr::<G>::one();

            let mut alpha_powers =
                all_alphas.get_alphas(ArgumentType::Permutation, permutation::CONSTRAINTS);
            let alpha0 = alpha_powers
                .next()
                .expect("missing power of alpha for permutation");
            let alpha1 = alpha_powers
                .next()
                .expect("missing power of alpha for permutation");
            let alpha2 = alpha_powers
                .next()
                .expect("missing power of alpha for permutation");

            let init = (evals[0].w[PERMUTS - 1] + gamma) * evals[1].z * alpha0 * zkp;
            let mut ft_eval0 = evals[0]
                .w
                .iter()
                .zip(evals[0].s.iter())
                .map(|(w, s)| (beta * s) + w + gamma)
                .fold(init, |x, y| x * y);

            ft_eval0 -= if !p_eval[0].is_empty() {
                p_eval[0][0]
            } else {
                Fr::<G>::zero()
            };

            ft_eval0 -= evals[0]
                .w
                .iter()
                .zip(index.shift.iter())
                .map(|(w, s)| gamma + (beta * zeta * s) + w)
                .fold(alpha0 * zkp * evals[0].z, |x, y| x * y);

            let nominator = ((zeta1m1 * alpha1 * (zeta - index.w))
                + (zeta1m1 * alpha2 * (zeta - Fr::<G>::one())))
                * (Fr::<G>::one() - evals[0].z);

            let denominator = (zeta - index.w) * (zeta - Fr::<G>::one());
            let denominator = denominator.inverse().expect("negligible probability");

            ft_eval0 += nominator * denominator;

            let cs = Constants {
                alpha,
                beta,
                gamma,
                joint_combiner: joint_combiner.1,
                endo_coefficient: index.endo,
                mds: index.fr_sponge_params.mds.clone(),
            };
            ft_eval0 -= PolishToken::evaluate(
                &index.linearization.constant_term,
                index.domain,
                zeta,
                &evals,
                &cs,
            )
            .unwrap();

            ft_eval0
        };

        let combined_inner_product = {
            let ft_eval0 = vec![ft_eval0];
            let ft_eval1 = vec![self.ft_eval1];

            #[allow(clippy::type_complexity)]
            let mut es: Vec<(Vec<&Vec<Fr<G>>>, Option<usize>)> = polys
                .iter()
                .map(|(_, e)| (e.iter().collect(), None))
                .collect();
            es.push((p_eval.iter().collect::<Vec<_>>(), None));
            es.push((vec![&ft_eval0, &ft_eval1], None));
            es.push((self.evals.iter().map(|e| &e.z).collect::<Vec<_>>(), None));
            es.push((
                self.evals
                    .iter()
                    .map(|e| &e.generic_selector)
                    .collect::<Vec<_>>(),
                None,
            ));
            es.push((
                self.evals
                    .iter()
                    .map(|e| &e.poseidon_selector)
                    .collect::<Vec<_>>(),
                None,
            ));
            es.extend(
                (0..COLUMNS)
                    .map(|c| (self.evals.iter().map(|e| &e.w[c]).collect::<Vec<_>>(), None))
                    .collect::<Vec<_>>(),
            );
            es.extend(
                (0..PERMUTS - 1)
                    .map(|c| (self.evals.iter().map(|e| &e.s[c]).collect::<Vec<_>>(), None))
                    .collect::<Vec<_>>(),
            );

            combined_inner_product::<G>(&ep, &v, &u, &es, index.srs.g.len())
        };

        let oracles = RandomOracles {
            beta,
            gamma,
            alpha_chal,
            alpha,
            zeta,
            v,
            u,
            zeta_chal,
            v_chal,
            u_chal,
            joint_combiner,
        };

        OraclesResult {
            fq_sponge,
            digest,
            oracles,
            all_alphas,
            p_eval,
            powers_of_eval_points_for_chunks,
            polys,
            zeta1,
            ft_eval0,
            combined_inner_product,
        }
    }
}

/// This function verifies the batch of zk-proofs
///     proofs: vector of Plonk proofs
///     index: VerifierIndex
///     RETURN: verification status
#[allow(clippy::type_complexity)]
pub fn batch_verify<G, EFqSponge, EFrSponge>(
    group_map: &G::Map,
    proofs: &[(&VerifierIndex<G>, &ProverProof<G>)],
) -> Result<()>
where
    G: CommitmentCurve,
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>,
    EFrSponge: FrSponge<Fr<G>>,
{
    // if there's no proof to verify, return early
    if proofs.is_empty() {
        return Ok(());
    }

    // TODO: Account for the different SRS lengths
    let srs = &proofs[0].0.srs;
    for (index, _) in proofs.iter() {
        assert_eq!(index.srs.g.len(), srs.g.len());
    }

    // Validate each proof separately (f(zeta) = t(zeta) * Z_H(zeta))
    // + build objects required to batch verify all the evaluation proofs
    let mut params = vec![];
    for (index, proof) in proofs {
        // commit to public input polynomial
        let lgr_comm = index
            .srs
            .lagrange_bases
            .get(&index.domain.size())
            .expect("pre-computed committed lagrange bases not found");
        let com: Vec<_> = lgr_comm
            .iter()
            .map(|c| PolyComm {
                unshifted: vec![*c],
                shifted: None,
            })
            .take(proof.public.len())
            .collect();
        let com_ref: Vec<_> = com.iter().collect();
        let elm: Vec<_> = proof.public.iter().map(|s| -*s).collect();
        let p_comm = PolyComm::<G>::multi_scalar_mul(&com_ref, &elm);

        // run the oracles argument
        let OraclesResult {
            fq_sponge,
            oracles,
            all_alphas,
            p_eval,
            powers_of_eval_points_for_chunks,
            polys,
            zeta1: zeta_to_domain_size,
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

            let alphas = all_alphas.get_alphas(ArgumentType::Permutation, permutation::CONSTRAINTS);

            let mut commitments = vec![&index.sigma_comm[PERMUTS - 1]];
            let mut scalars = vec![ConstraintSystem::perm_scalars(
                &evals,
                oracles.beta,
                oracles.gamma,
                alphas,
                zkp,
            )];

            // generic
            {
                let alphas = all_alphas
                    .get_alphas(ArgumentType::Gate(GateType::Generic), generic::CONSTRAINTS);

                let generic_scalars =
                    &ConstraintSystem::gnrc_scalars(alphas, &evals[0].w, evals[0].generic_selector);

                let generic_com = index.coefficients_comm.iter().take(generic_scalars.len());

                assert_eq!(generic_scalars.len(), generic_com.len());

                scalars.extend(generic_scalars);
                commitments.extend(generic_com);
            }

            // other gates are implemented using the expression framework
            {
                // TODO: Reuse constants from oracles function
                let constants = Constants {
                    alpha: oracles.alpha,
                    beta: oracles.beta,
                    gamma: oracles.gamma,
                    joint_combiner: oracles.joint_combiner.1,
                    endo_coefficient: index.endo,
                    mds: index.fr_sponge_params.mds.clone(),
                };

                for (col, tokens) in &index.linearization.index_terms {
                    let scalar = PolishToken::evaluate(
                        tokens,
                        index.domain,
                        oracles.zeta,
                        &evals,
                        &constants,
                    )
                    .expect("should evaluate");
                    let l = proof.commitments.lookup.as_ref();
                    use Column::*;
                    match col {
                        Witness(i) => {
                            scalars.push(scalar);
                            commitments.push(&proof.commitments.w_comm[*i])
                        }
                        Coefficient(i) => {
                            scalars.push(scalar);
                            commitments.push(&index.coefficients_comm[*i])
                        }
                        Z => {
                            scalars.push(scalar);
                            commitments.push(&proof.commitments.z_comm);
                        }
                        LookupSorted(i) => {
                            scalars.push(scalar);
                            commitments.push(&l.unwrap().sorted[*i])
                        }
                        LookupAggreg => {
                            scalars.push(scalar);
                            commitments.push(&l.unwrap().aggreg)
                        }
                        LookupKindIndex(i) => match index.lookup_index.as_ref() {
                            None => {
                                panic!("Attempted to use {:?}, but no lookup index was given", col)
                            }
                            Some(lindex) => {
                                scalars.push(scalar);
                                commitments.push(&lindex.lookup_selectors[*i]);
                            }
                        },
                        LookupTable => match index.lookup_index.as_ref() {
                            None => {
                                panic!("Attempted to use {:?}, but no lookup index was given", col)
                            }
                            Some(lindex) => {
                                let mut j = Fr::<G>::one();
                                scalars.push(scalar);
                                commitments.push(&lindex.lookup_tables[0][0]);
                                for t in lindex.lookup_tables[0].iter().skip(1) {
                                    j *= constants.joint_combiner;
                                    scalars.push(scalar * j);
                                    commitments.push(t);
                                }
                            }
                        },
                        Index(t) => {
                            use GateType::*;
                            let c = match t {
                                Zero | Generic => panic!("Selector for {:?} not defined", t),
                                CompleteAdd => &index.complete_add_comm,
                                VarBaseMul => &index.mul_comm,
                                EndoMul => &index.emul_comm,
                                EndoMulScalar => &index.endomul_scalar_comm,
                                Poseidon => &index.psm_comm,
                                ChaCha0 => &index.chacha_comm.as_ref().unwrap()[0],
                                ChaCha1 => &index.chacha_comm.as_ref().unwrap()[1],
                                ChaCha2 => &index.chacha_comm.as_ref().unwrap()[2],
                                ChaChaFinal => &index.chacha_comm.as_ref().unwrap()[3],
                                CairoInstruction => panic!("TODO"), // TODO: querolita
                                CairoTransition => panic!("TODO"),  // TODO: querolita
                                CairoClaim => panic!("TODO"),       // TODO: querolita
                            };
                            scalars.push(scalar);
                            commitments.push(c);
                        }
                    }
                }
            }

            // MSM
            PolyComm::multi_scalar_mul(&commitments, &scalars)
        };

        let zeta_to_srs_len = oracles.zeta.pow(&[index.max_poly_size as u64]);
        // Maller's optimization (see https://o1-labs.github.io/mina-book/crypto/plonk/maller_15.html)
        let chunked_f_comm = f_comm.chunk_commitment(zeta_to_srs_len);
        let chunked_t_comm = &proof.commitments.t_comm.chunk_commitment(zeta_to_srs_len);
        let ft_comm = &chunked_f_comm - &chunked_t_comm.scale(zeta_to_domain_size - Fr::<G>::one());

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
        let (index, proof) = proof;
        let (p_eval, p_comm, ft_comm, fq_sponge, oracles, ft_eval0, ft_eval1, polys) = params;

        // recursion stuff
        let mut polynomials = polys
            .iter()
            .map(|(comm, evals)| (comm, evals.iter().collect(), None))
            .collect::<Vec<(&PolyComm<G>, Vec<&Vec<Fr<G>>>, Option<usize>)>>();

        // public input commitment
        polynomials.push((p_comm, p_eval.iter().collect::<Vec<_>>(), None));

        // ft commitment (chunks of it)
        polynomials.push((ft_comm, vec![ft_eval0, ft_eval1], None));

        // permutation commitment
        polynomials.push((
            &proof.commitments.z_comm,
            proof.evals.iter().map(|e| &e.z).collect::<Vec<_>>(),
            None,
        ));

        // index commitments that use the coefficients
        polynomials.push((
            &index.generic_comm,
            proof
                .evals
                .iter()
                .map(|e| &e.generic_selector)
                .collect::<Vec<_>>(),
            None,
        ));
        polynomials.push((
            &index.psm_comm,
            proof
                .evals
                .iter()
                .map(|e| &e.poseidon_selector)
                .collect::<Vec<_>>(),
            None,
        ));

        // witness commitments
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

        // prepare for the opening proof verification
        let omega = index.domain.group_gen;
        batch.push((
            fq_sponge.clone(),
            vec![oracles.zeta, oracles.zeta * omega],
            oracles.v,
            oracles.u,
            polynomials,
            &proof.proof,
        ));
    }

    // final check to verify the evaluation proofs
    match srs.verify::<EFqSponge, _>(group_map, &mut batch, &mut thread_rng()) {
        false => Err(ProofError::OpenProof),
        true => Ok(()),
    }
}
