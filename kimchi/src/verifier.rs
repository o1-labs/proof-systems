//! This module implements zk-proof batch verifier functionality.

use crate::{
    alphas::Alphas,
    circuits::{
        argument::ArgumentType,
        constraints::ConstraintSystem,
        expr::{Column, Constants, PolishToken},
        gate::GateType,
        lookup::lookups::LookupsUsed,
        polynomials::{generic, permutation},
        scalars::RandomOracles,
        wires::*,
    },
    error::VerifyError,
    plonk_sponge::FrSponge,
    prover::ProverProof,
    verifier_index::{LookupVerifierIndex, VerifierIndex},
};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{EvaluationDomain, Polynomial};
use commitment_dlog::commitment::{
    b_poly, b_poly_coefficients, BatchEvaluationProof, CommitmentCurve, Evaluation, PolyComm,
};
use o1_utils::types::fields::*;
use oracle::{sponge::ScalarChallenge, FqSponge};
use rand::thread_rng;

/// The result of a proof verification.
pub type Result<T> = std::result::Result<T, VerifyError>;

/// The result of running the oracle protocol
pub struct OraclesResult<G, EFqSponge>
where
    G: CommitmentCurve,
    EFqSponge: Clone + FqSponge<BaseField<G>, G, ScalarField<G>>,
{
    /// A sponge that acts on the base field of a curve
    pub fq_sponge: EFqSponge,
    /// the last evaluation of the Fq-Sponge in this protocol
    pub digest: ScalarField<G>,
    /// the challenges produced in the protocol
    pub oracles: RandomOracles<ScalarField<G>>,
    /// the computed powers of alpha
    pub all_alphas: Alphas<ScalarField<G>>,
    /// public polynomial evaluations
    pub p_eval: Vec<Vec<ScalarField<G>>>,
    /// zeta^n and (zeta * omega)^n
    pub powers_of_eval_points_for_chunks: [ScalarField<G>; 2],
    /// ?
    #[allow(clippy::type_complexity)]
    pub polys: Vec<(PolyComm<G>, Vec<Vec<ScalarField<G>>>)>,
    /// pre-computed zeta^n
    pub zeta1: ScalarField<G>,
    /// The evaluation f(zeta) - t(zeta) * Z_H(zeta)
    pub ft_eval0: ScalarField<G>,
}

impl<G: CommitmentCurve> ProverProof<G>
where
    G::BaseField: PrimeField,
{
    pub fn prev_chal_evals(
        &self,
        index: &VerifierIndex<G>,
        evaluation_points: &[ScalarField<G>],
        powers_of_eval_points_for_chunks: &[ScalarField<G>],
    ) -> Vec<Vec<Vec<ScalarField<G>>>> {
        self.prev_challenges
            .iter()
            .map(|(chals, _poly)| {
                // No need to check the correctness of poly explicitly. Its correctness is assured by the
                // checking of the inner product argument.
                let b_len = 1 << chals.len();
                let mut b: Option<Vec<ScalarField<G>>> = None;

                (0..2)
                    .map(|i| {
                        let full = b_poly(chals, evaluation_points[i]);
                        if index.max_poly_size == b_len {
                            return vec![full];
                        }
                        let mut betaacc = ScalarField::<G>::one();
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
                            .fold(ScalarField::<G>::zero(), |x, y| x + y);
                        vec![full - (diff * powers_of_eval_points_for_chunks[i]), diff]
                    })
                    .collect()
            })
            .collect()
    }

    /// This function runs the random oracle argument
    pub fn oracles<
        EFqSponge: Clone + FqSponge<BaseField<G>, G, ScalarField<G>>,
        EFrSponge: FrSponge<ScalarField<G>>,
    >(
        &self,
        index: &VerifierIndex<G>,
        p_comm: &PolyComm<G>,
    ) -> Result<OraclesResult<G, EFqSponge>> {
        //~
        //~ #### Fiat-Shamir argument
        //~
        //~ We run the following algorithm:
        //~
        let n = index.domain.size;

        //~ 1. Setup the Fq-Sponge.
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        //~ 2. Absorb the commitment of the public input polynomial with the Fq-Sponge.
        fq_sponge.absorb_g(&p_comm.unshifted);

        //~ 3. Absorb the commitments to the registers / witness columns with the Fq-Sponge.
        self.commitments
            .w_comm
            .iter()
            .for_each(|c| fq_sponge.absorb_g(&c.unshifted));

        //~ 4. TODO: lookup (joint combiner challenge)
        let joint_combiner = {
            let s = match index.lookup_index {
                None
                | Some(LookupVerifierIndex {
                    lookup_used: LookupsUsed::Single,
                    ..
                }) => ScalarChallenge(ScalarField::<G>::zero()),
                Some(LookupVerifierIndex {
                    lookup_used: LookupsUsed::Joint,
                    ..
                }) => ScalarChallenge(fq_sponge.challenge()),
            };
            (s, s.to_field(&index.srs.endo_r))
        };

        //~ 5. TODO: lookup (absorb)
        self.commitments.lookup.iter().for_each(|l| {
            l.sorted
                .iter()
                .for_each(|c| fq_sponge.absorb_g(&c.unshifted));
        });

        //~ 6. Sample $\beta$ with the Fq-Sponge.
        let beta = fq_sponge.challenge();

        //~ 7. Sample $\gamma$ with the Fq-Sponge.
        let gamma = fq_sponge.challenge();

        //~ 8. TODO: lookup
        self.commitments.lookup.iter().for_each(|l| {
            fq_sponge.absorb_g(&l.aggreg.unshifted);
        });

        //~ 9. Absorb the commitment to the permutation trace with the Fq-Sponge.
        fq_sponge.absorb_g(&self.commitments.z_comm.unshifted);

        //~ 10. Sample $\alpha'$ with the Fq-Sponge.
        let alpha_chal = ScalarChallenge(fq_sponge.challenge());

        //~ 11. Derive $\alpha$ from $\alpha'$ using the endomorphism (TODO: details).
        let alpha = alpha_chal.to_field(&index.srs.endo_r);

        //~ 12. Enforce that the length of the $t$ commitment is of size `PERMUTS`.
        if self.commitments.t_comm.unshifted.len() != PERMUTS {
            return Err(VerifyError::IncorrectCommitmentLength("t"));
        }

        //~ 13. Absorb the commitment to the quotient polynomial $t$ into the argument.
        fq_sponge.absorb_g(&self.commitments.t_comm.unshifted);

        //~ 14. Sample $\zeta'$ with the Fq-Sponge.
        let zeta_chal = ScalarChallenge(fq_sponge.challenge());

        //~ 15. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify).
        let zeta = zeta_chal.to_field(&index.srs.endo_r);

        //~ 16. Setup the Fr-Sponge.
        let digest = fq_sponge.clone().digest();
        let mut fr_sponge = EFrSponge::new(index.fr_sponge_params.clone());

        //~ 17. Squeeze the Fq-sponge and absorb the result with the Fr-Sponge.
        fr_sponge.absorb(&digest);

        // prepare some often used values
        let zeta1 = zeta.pow(&[n]);
        let zetaw = zeta * index.domain.group_gen;

        // retrieve ranges for the powers of alphas
        let mut all_alphas = index.powers_of_alpha.clone();
        all_alphas.instantiate(alpha);

        // compute Lagrange base evaluation denominators
        let w: Vec<_> = index.domain.elements().take(self.public.len()).collect();

        let mut zeta_minus_x: Vec<_> = w.iter().map(|w| zeta - w).collect();

        w.iter()
            .take(self.public.len())
            .for_each(|w| zeta_minus_x.push(zetaw - w));

        ark_ff::fields::batch_inversion::<ScalarField<G>>(&mut zeta_minus_x);

        //~ 18. Evaluate the negated public polynomial (if present) at $\zeta$ and $\zeta\omega$.
        //~     NOTE: this works only in the case when the poly segment size is not smaller than that of the domain.
        let p_eval = if !self.public.is_empty() {
            vec![
                vec![
                    (self
                        .public
                        .iter()
                        .zip(zeta_minus_x.iter())
                        .zip(index.domain.elements())
                        .map(|((p, l), w)| -*l * p * w)
                        .fold(ScalarField::<G>::zero(), |x, y| x + y))
                        * (zeta1 - ScalarField::<G>::one())
                        * index.domain.size_inv,
                ],
                vec![
                    (self
                        .public
                        .iter()
                        .zip(zeta_minus_x[self.public.len()..].iter())
                        .zip(index.domain.elements())
                        .map(|((p, l), w)| -*l * p * w)
                        .fold(ScalarField::<G>::zero(), |x, y| x + y))
                        * index.domain.size_inv
                        * (zetaw.pow(&[n as u64]) - ScalarField::<G>::one()),
                ],
            ]
        } else {
            vec![Vec::<ScalarField<G>>::new(), Vec::<ScalarField<G>>::new()]
        };

        //~ 19. Absorb all the polynomial evaluations in $\zeta$ and $\zeta\omega$:
        //~     - the public polynomial
        //~     - z
        //~     - generic selector
        //~     - poseidon selector
        //~     - the 15 register/witness
        //~     - 6 sigmas evaluations (the last one is not evaluated)
        for (p, e) in p_eval.iter().zip(&self.evals) {
            fr_sponge.absorb_evaluations(p, e);
        }

        //~ 20. Absorb the unique evaluation of ft: $ft(\zeta\omega)$.
        fr_sponge.absorb(&self.ft_eval1);

        //~ 21. Sample $v'$ with the Fr-Sponge.
        let v_chal = fr_sponge.challenge();

        //~ 22. Derive $v$ from $v'$ using the endomorphism (TODO: specify).
        let v = v_chal.to_field(&index.srs.endo_r);

        //~ 23. Sample $u'$ with the Fr-Sponge.
        let u_chal = fr_sponge.challenge();

        //~ 24. Derive $u$ from $u'$ using the endomorphism (TODO: specify).
        let u = u_chal.to_field(&index.srs.endo_r);

        //~ 25. Create a list of all polynomials that have an evaluation proof.
        let evaluation_points = [zeta, zetaw];
        let powers_of_eval_points_for_chunks = [
            zeta.pow(&[index.max_poly_size as u64]),
            zetaw.pow(&[index.max_poly_size as u64]),
        ];

        let polys: Vec<(PolyComm<G>, _)> = self
            .prev_challenges
            .iter()
            .zip(self.prev_chal_evals(index, &evaluation_points, &powers_of_eval_points_for_chunks))
            .map(|(c, e)| (c.1.clone(), e))
            .collect();

        let evals = vec![
            self.evals[0].combine(powers_of_eval_points_for_chunks[0]),
            self.evals[1].combine(powers_of_eval_points_for_chunks[1]),
        ];

        //~ 26. Compute the evaluation of $ft(\zeta)$.
        let ft_eval0 = {
            let zkp = index.zkpm.evaluate(&zeta);
            let zeta1m1 = zeta1 - ScalarField::<G>::one();

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
                ScalarField::<G>::zero()
            };

            ft_eval0 -= evals[0]
                .w
                .iter()
                .zip(index.shift.iter())
                .map(|(w, s)| gamma + (beta * zeta * s) + w)
                .fold(alpha0 * zkp * evals[0].z, |x, y| x * y);

            let nominator = ((zeta1m1 * alpha1 * (zeta - index.w))
                + (zeta1m1 * alpha2 * (zeta - ScalarField::<G>::one())))
                * (ScalarField::<G>::one() - evals[0].z);

            let denominator = (zeta - index.w) * (zeta - ScalarField::<G>::one());
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

        Ok(OraclesResult {
            fq_sponge,
            digest,
            oracles,
            all_alphas,
            p_eval,
            powers_of_eval_points_for_chunks,
            polys,
            zeta1,
            ft_eval0,
        })
    }
}

fn to_batch<'a, G, EFqSponge, EFrSponge>(
    index: &VerifierIndex<G>,
    proof: &'a ProverProof<G>,
) -> Result<BatchEvaluationProof<'a, G, EFqSponge>>
where
    G: CommitmentCurve,
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<BaseField<G>, G, ScalarField<G>>,
    EFrSponge: FrSponge<ScalarField<G>>,
{
    //~
    //~ #### Partial verification
    //~
    //~ For every proof we want to verify, we defer the proof opening to the very end.
    //~ This allows us to potentially batch verify a number of partially verified proofs.
    //~ Essentially, this steps verifies that $f(\zeta) = t(\zeta) * Z_H(\zeta)$.
    //~

    //~ 1. Commit to the negated public input polynomial.
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

    //~ 2. Run the [Fiat-Shamir argument](#fiat-shamir-argument).
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
    } = proof.oracles::<EFqSponge, EFrSponge>(index, &p_comm)?;

    //~ 3. Combine the chunked polynomials' evaluations
    //~    (TODO: most likely only the quotient polynomial is chunked)
    //~    with the right powers of $\zeta^n$ and $(\zeta * \omega)^n$.
    let evals = vec![
        proof.evals[0].combine(powers_of_eval_points_for_chunks[0]),
        proof.evals[1].combine(powers_of_eval_points_for_chunks[1]),
    ];

    //~ 4. Compute the commitment to the linearized polynomial $f$.
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
            let alphas =
                all_alphas.get_alphas(ArgumentType::Gate(GateType::Generic), generic::CONSTRAINTS);

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
                let scalar =
                    PolishToken::evaluate(tokens, index.domain, oracles.zeta, &evals, &constants)
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
                            let mut j = ScalarField::<G>::one();
                            scalars.push(scalar);
                            commitments.push(&lindex.lookup_table[0]);
                            for t in lindex.lookup_table.iter().skip(1) {
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
                            CairoInitial => &index.cairo_comm[0],
                            CairoMemory => &index.cairo_comm[1],
                            CairoInstruction => &index.cairo_comm[2],
                            CairoFlags => &index.cairo_comm[3],
                            CairoTransition => &index.cairo_comm[4],
                            CairoAuxiliary => &index.cairo_comm[5],
                            CairoClaim => &index.cairo_comm[6],
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

    //~ 5. Compute the (chuncked) commitment of $ft$
    //~    (see [Maller's optimization](../crypto/plonk/maller_15.html)).
    let ft_comm = {
        let zeta_to_srs_len = oracles.zeta.pow(&[index.max_poly_size as u64]);
        let chunked_f_comm = f_comm.chunk_commitment(zeta_to_srs_len);
        let chunked_t_comm = &proof.commitments.t_comm.chunk_commitment(zeta_to_srs_len);
        &chunked_f_comm - &chunked_t_comm.scale(zeta_to_domain_size - ScalarField::<G>::one())
    };

    //~ 6. List the polynomial commitments, and their associated evaluations,
    //~    that are associated to the aggregated evaluation proof in the proof:
    let mut evaluations = vec![];

    //~     - recursion
    evaluations.extend(polys.into_iter().map(|(c, e)| Evaluation {
        commitment: c,
        evaluations: e,
        degree_bound: None,
    }));

    //~     - public input commitment
    evaluations.push(Evaluation {
        commitment: p_comm,
        evaluations: p_eval,
        degree_bound: None,
    });

    //~     - ft commitment (chunks of it)
    evaluations.push(Evaluation {
        commitment: ft_comm,
        evaluations: vec![vec![ft_eval0], vec![proof.ft_eval1]],
        degree_bound: None,
    });

    //~     - permutation commitment
    evaluations.push(Evaluation {
        commitment: proof.commitments.z_comm.clone(),
        evaluations: proof.evals.iter().map(|e| e.z.clone()).collect(),
        degree_bound: None,
    });

    //~     - index commitments that use the coefficients
    evaluations.push(Evaluation {
        commitment: index.generic_comm.clone(),
        evaluations: proof
            .evals
            .iter()
            .map(|e| e.generic_selector.clone())
            .collect(),
        degree_bound: None,
    });
    evaluations.push(Evaluation {
        commitment: index.psm_comm.clone(),
        evaluations: proof
            .evals
            .iter()
            .map(|e| e.poseidon_selector.clone())
            .collect(),
        degree_bound: None,
    });

    //~     - witness commitments
    evaluations.extend(
        proof
            .commitments
            .w_comm
            .iter()
            .zip(
                (0..COLUMNS)
                    .map(|i| {
                        proof
                            .evals
                            .iter()
                            .map(|e| e.w[i].clone())
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>(),
            )
            .map(|(c, e)| Evaluation {
                commitment: c.clone(),
                evaluations: e,
                degree_bound: None,
            }),
    );

    //~     - sigma commitments
    evaluations.extend(
        index
            .sigma_comm
            .iter()
            .zip(
                (0..PERMUTS - 1)
                    .map(|i| {
                        proof
                            .evals
                            .iter()
                            .map(|e| e.s[i].clone())
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>(),
            )
            .map(|(c, e)| Evaluation {
                commitment: c.clone(),
                evaluations: e,
                degree_bound: None,
            }),
    );

    // prepare for the opening proof verification
    let evaluation_points = vec![oracles.zeta, oracles.zeta * index.domain.group_gen];
    Ok(BatchEvaluationProof {
        sponge: fq_sponge,
        evaluations,
        evaluation_points,
        xi: oracles.v,
        r: oracles.u,
        opening: &proof.proof,
    })
}

/// Verify a proof [ProverProof] using a [VerifierIndex] and a `group_map`.
pub fn verify<G, EFqSponge, EFrSponge>(
    group_map: &G::Map,
    verifier_index: &VerifierIndex<G>,
    proof: &ProverProof<G>,
) -> Result<()>
where
    G: CommitmentCurve,
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<BaseField<G>, G, ScalarField<G>>,
    EFrSponge: FrSponge<ScalarField<G>>,
{
    let proofs = vec![(verifier_index, proof)];
    batch_verify::<G, EFqSponge, EFrSponge>(group_map, &proofs)
}

/// This function verifies the batch of zk-proofs
///     proofs: vector of Plonk proofs
///     index: VerifierIndex
///     RETURN: verification status
pub fn batch_verify<G, EFqSponge, EFrSponge>(
    group_map: &G::Map,
    proofs: &[(&VerifierIndex<G>, &ProverProof<G>)],
) -> Result<()>
where
    G: CommitmentCurve,
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<BaseField<G>, G, ScalarField<G>>,
    EFrSponge: FrSponge<ScalarField<G>>,
{
    //~ #### Batch verification of proofs
    //~
    //~ Below, we define the steps to verify a number of proofs
    //~ (each associated to a [verifier index](#verifier-index)).
    //~ You can, of course, use it to verify a single proof.
    //~

    //~ 1. If there's no proof to verify, the proof validates trivially.
    if proofs.is_empty() {
        return Ok(());
    }

    //~ 2. Ensure that all the proof's verifier index have a URS of the same length. (TODO: do they have to be the same URS though? should we check for that?)
    // TODO: Account for the different SRS lengths
    let srs = &proofs[0].0.srs;
    for (index, _) in proofs.iter() {
        assert_eq!(index.srs.g.len(), srs.g.len());
    }

    //~ 3. Validate each proof separately following the [partial verification](#partial-verification) steps.
    let mut batch = vec![];
    for (index, proof) in proofs {
        batch.push(to_batch::<G, EFqSponge, EFrSponge>(index, proof)?);
    }

    //~ 4. Use the [`PolyCom.verify`](#polynomial-commitments) to verify the partially evaluated proofs.
    match srs.verify::<EFqSponge, _>(group_map, &mut batch, &mut thread_rng()) {
        false => Err(VerifyError::OpenProof),
        true => Ok(()),
    }
}
