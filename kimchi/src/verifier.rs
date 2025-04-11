//! This module implements zk-proof batch verifier functionality.

use crate::{
    circuits::{
        argument::ArgumentType,
        berkeley_columns::{BerkeleyChallenges, Column},
        constraints::ConstraintSystem,
        expr::{Constants, PolishToken},
        gate::GateType,
        lookup::{lookups::LookupPattern, tables::combine_table},
        polynomials::permutation,
        scalars::RandomOracles,
        wires::{COLUMNS, PERMUTS},
    },
    curve::KimchiCurve,
    error::VerifyError,
    oracles::OraclesResult,
    plonk_sponge::FrSponge,
    proof::{PointEvaluations, ProofEvaluations, ProverProof, RecursionChallenge},
    verifier_index::VerifierIndex,
};
use ark_ec::AffineRepr;
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Polynomial};
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use o1_utils::ExtendedDensePolynomial;
use poly_commitment::{
    commitment::{
        absorb_commitment, combined_inner_product, BatchEvaluationProof, Evaluation, PolyComm,
    },
    OpenProof, SRS as _,
};
use rand::thread_rng;

/// The result of a proof verification.
pub type Result<T> = core::result::Result<T, VerifyError>;

#[derive(Debug)]
pub struct Context<'a, G: KimchiCurve, OpeningProof: OpenProof<G>> {
    /// The [VerifierIndex] associated to the proof
    pub verifier_index: &'a VerifierIndex<G, OpeningProof>,

    /// The proof to verify
    pub proof: &'a ProverProof<G, OpeningProof>,

    /// The public input used in the creation of the proof
    pub public_input: &'a [G::ScalarField],
}

impl<'a, G: KimchiCurve, OpeningProof: OpenProof<G>> Context<'a, G, OpeningProof> {
    pub fn get_column(&self, col: Column) -> Option<&'a PolyComm<G>> {
        use Column::*;
        match col {
            Witness(i) => Some(&self.proof.commitments.w_comm[i]),
            Coefficient(i) => Some(&self.verifier_index.coefficients_comm[i]),
            Permutation(i) => Some(&self.verifier_index.sigma_comm[i]),
            Z => Some(&self.proof.commitments.z_comm),
            LookupSorted(i) => Some(&self.proof.commitments.lookup.as_ref()?.sorted[i]),
            LookupAggreg => Some(&self.proof.commitments.lookup.as_ref()?.aggreg),
            LookupKindIndex(i) => {
                Some(self.verifier_index.lookup_index.as_ref()?.lookup_selectors[i].as_ref()?)
            }
            LookupTable => None,
            LookupRuntimeSelector => Some(
                self.verifier_index
                    .lookup_index
                    .as_ref()?
                    .runtime_tables_selector
                    .as_ref()?,
            ),
            LookupRuntimeTable => self.proof.commitments.lookup.as_ref()?.runtime.as_ref(),
            Index(t) => {
                use GateType::*;
                match t {
                    Zero => None,
                    Generic => Some(&self.verifier_index.generic_comm),
                    Lookup => None,
                    CompleteAdd => Some(&self.verifier_index.complete_add_comm),
                    VarBaseMul => Some(&self.verifier_index.mul_comm),
                    EndoMul => Some(&self.verifier_index.emul_comm),
                    EndoMulScalar => Some(&self.verifier_index.endomul_scalar_comm),
                    Poseidon => Some(&self.verifier_index.psm_comm),
                    CairoClaim | CairoInstruction | CairoFlags | CairoTransition => None,
                    RangeCheck0 => Some(self.verifier_index.range_check0_comm.as_ref()?),
                    RangeCheck1 => Some(self.verifier_index.range_check1_comm.as_ref()?),
                    ForeignFieldAdd => Some(self.verifier_index.foreign_field_add_comm.as_ref()?),
                    ForeignFieldMul => Some(self.verifier_index.foreign_field_mul_comm.as_ref()?),
                    Xor16 => Some(self.verifier_index.xor_comm.as_ref()?),
                    Rot64 => Some(self.verifier_index.rot_comm.as_ref()?),
                }
            }
        }
    }
}

impl<G: KimchiCurve, OpeningProof: OpenProof<G>> ProverProof<G, OpeningProof>
where
    G::BaseField: PrimeField,
{
    /// This function runs the random oracle argument
    ///
    /// # Errors
    ///
    /// Will give error if `commitment(s)` are invalid(missing or wrong length), or `proof` is verified as invalid.
    ///
    /// # Panics
    ///
    /// Will panic if `PolishToken` evaluation is invalid.
    pub fn oracles<
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
        EFrSponge: FrSponge<G::ScalarField>,
    >(
        &self,
        index: &VerifierIndex<G, OpeningProof>,
        public_comm: &PolyComm<G>,
        public_input: Option<&[G::ScalarField]>,
    ) -> Result<OraclesResult<G, EFqSponge>> {
        //~
        //~ #### Fiat-Shamir argument
        //~
        //~ We run the following algorithm:
        //~
        let n = index.domain.size;
        let (_, endo_r) = G::endos();

        let chunk_size = {
            let d1_size = index.domain.size();
            if d1_size < index.max_poly_size {
                1
            } else {
                d1_size / index.max_poly_size
            }
        };

        let zk_rows = index.zk_rows;

        //~ 1. Setup the Fq-Sponge. This sponge mostly absorbs group
        // elements (points as tuples over the base field), but it
        // squeezes out elements of the group's scalar field.
        let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());

        //~ 1. Absorb the digest of the VerifierIndex.
        let verifier_index_digest = index.digest::<EFqSponge>();
        fq_sponge.absorb_fq(&[verifier_index_digest]);

        //~ 1. Absorb the commitments of the previous challenges with the Fq-sponge.
        for RecursionChallenge { comm, .. } in &self.prev_challenges {
            absorb_commitment(&mut fq_sponge, comm);
        }

        //~ 1. Absorb the commitment of the public input polynomial with the Fq-Sponge.
        absorb_commitment(&mut fq_sponge, public_comm);

        //~ 1. Absorb the commitments to the registers / witness columns with the Fq-Sponge.
        self.commitments
            .w_comm
            .iter()
            .for_each(|c| absorb_commitment(&mut fq_sponge, c));

        //~ 1. If lookup is used:
        if let Some(l) = &index.lookup_index {
            let lookup_commits = self
                .commitments
                .lookup
                .as_ref()
                .ok_or(VerifyError::LookupCommitmentMissing)?;

            // if runtime is used, absorb the commitment
            if l.runtime_tables_selector.is_some() {
                let runtime_commit = lookup_commits
                    .runtime
                    .as_ref()
                    .ok_or(VerifyError::IncorrectRuntimeProof)?;
                absorb_commitment(&mut fq_sponge, runtime_commit);
            }
        }

        let joint_combiner = if let Some(l) = &index.lookup_index {
            //~~ * If it involves queries to a multiple-column lookup table,
            //~~   then squeeze the Fq-Sponge to obtain the joint combiner challenge $j'$,
            //~~   otherwise set the joint combiner challenge $j'$ to $0$.
            let joint_combiner = if l.joint_lookup_used {
                fq_sponge.challenge()
            } else {
                G::ScalarField::zero()
            };

            //~~ * Derive the scalar joint combiner challenge $j$ from $j'$ using the endomorphism.
            //~~   (TODO: specify endomorphism)
            let joint_combiner = ScalarChallenge(joint_combiner);
            let joint_combiner_field = joint_combiner.to_field(endo_r);
            let joint_combiner = (joint_combiner, joint_combiner_field);

            Some(joint_combiner)
        } else {
            None
        };

        if index.lookup_index.is_some() {
            let lookup_commits = self
                .commitments
                .lookup
                .as_ref()
                .ok_or(VerifyError::LookupCommitmentMissing)?;

            //~~ * absorb the commitments to the sorted polynomials.
            for com in &lookup_commits.sorted {
                absorb_commitment(&mut fq_sponge, com);
            }
        }

        // --- PlonK - Round 2
        //~ 1. Sample the first permutation challenge $\beta$ with the Fq-Sponge.
        let beta = fq_sponge.challenge();

        //~ 1. Sample the second permutation challenge $\gamma$ with the Fq-Sponge.
        let gamma = fq_sponge.challenge();

        //~ 1. If using lookup, absorb the commitment to the aggregation lookup polynomial.
        if index.lookup_index.is_some() {
            // Should not fail, as the lookup index is present
            let lookup_commits = self
                .commitments
                .lookup
                .as_ref()
                .ok_or(VerifyError::LookupCommitmentMissing)?;
            absorb_commitment(&mut fq_sponge, &lookup_commits.aggreg);
        }

        //~ 1. Absorb the commitment to the permutation trace with the Fq-Sponge.
        absorb_commitment(&mut fq_sponge, &self.commitments.z_comm);

        // --- PlonK - Round 3
        //~ 1. Sample the quotient challenge $\alpha'$ with the Fq-Sponge.
        let alpha_chal = ScalarChallenge(fq_sponge.challenge());

        //~ 1. Derive $\alpha$ from $\alpha'$ using the endomorphism (TODO: details).
        let alpha = alpha_chal.to_field(endo_r);

        //~ 1. Enforce that the length of the $t$ commitment is of size 7.
        if self.commitments.t_comm.len() > chunk_size * 7 {
            return Err(VerifyError::IncorrectCommitmentLength(
                "t",
                chunk_size * 7,
                self.commitments.t_comm.len(),
            ));
        }

        //~ 1. Absorb the commitment to the quotient polynomial $t$ into the argument.
        absorb_commitment(&mut fq_sponge, &self.commitments.t_comm);

        // --- PlonK - Round 4
        //~ 1. Sample $\zeta'$ with the Fq-Sponge.
        let zeta_chal = ScalarChallenge(fq_sponge.challenge());

        //~ 1. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify).
        let zeta = zeta_chal.to_field(endo_r);

        //~ 1. Setup the Fr-Sponge. This sponge absorbs elements from
        // the scalar field of the curve (equal to the base field of
        // the previous recursion round), and squeezes scalar elements
        // of the field. The squeeze result is the same as with the
        // `fq_sponge`.
        let digest = fq_sponge.clone().digest();
        let mut fr_sponge = EFrSponge::new(G::sponge_params());

        //~ 1. Squeeze the Fq-sponge and absorb the result with the Fr-Sponge.
        fr_sponge.absorb(&digest);

        //~ 1. Absorb the previous recursion challenges.
        let prev_challenge_digest = {
            // Note: we absorb in a new sponge here to limit the scope in which we need the
            // more-expensive 'optional sponge'.
            let mut fr_sponge = EFrSponge::new(G::sponge_params());
            for RecursionChallenge { chals, .. } in &self.prev_challenges {
                fr_sponge.absorb_multiple(chals);
            }
            fr_sponge.digest()
        };
        fr_sponge.absorb(&prev_challenge_digest);

        // prepare some often used values
        let zeta1 = zeta.pow([n]);
        let zetaw = zeta * index.domain.group_gen;
        let evaluation_points = [zeta, zetaw];
        let powers_of_eval_points_for_chunks = PointEvaluations {
            zeta: zeta.pow([index.max_poly_size as u64]),
            zeta_omega: zetaw.pow([index.max_poly_size as u64]),
        };

        //~ 1. Compute evaluations for the previous recursion challenges.
        let polys: Vec<(PolyComm<G>, _)> = self
            .prev_challenges
            .iter()
            .map(|challenge| {
                let evals = challenge.evals(
                    index.max_poly_size,
                    &evaluation_points,
                    &[
                        powers_of_eval_points_for_chunks.zeta,
                        powers_of_eval_points_for_chunks.zeta_omega,
                    ],
                );
                let RecursionChallenge { chals: _, comm } = challenge;
                (comm.clone(), evals)
            })
            .collect();

        // retrieve ranges for the powers of alphas
        let mut all_alphas = index.powers_of_alpha.clone();
        all_alphas.instantiate(alpha);

        let public_evals = if let Some(public_evals) = &self.evals.public {
            [public_evals.zeta.clone(), public_evals.zeta_omega.clone()]
        } else if chunk_size > 1 {
            return Err(VerifyError::MissingPublicInputEvaluation);
        } else if let Some(public_input) = public_input {
            // compute Lagrange base evaluation denominators
            let w: Vec<_> = index.domain.elements().take(public_input.len()).collect();

            let mut zeta_minus_x: Vec<_> = w.iter().map(|w| zeta - w).collect();

            w.iter()
                .take(public_input.len())
                .for_each(|w| zeta_minus_x.push(zetaw - w));

            ark_ff::fields::batch_inversion::<G::ScalarField>(&mut zeta_minus_x);

            //~ 1. Evaluate the negated public polynomial (if present) at $\zeta$ and $\zeta\omega$.
            //~
            //~    NOTE: this works only in the case when the poly segment size is not smaller than that of the domain.
            if public_input.is_empty() {
                [vec![G::ScalarField::zero()], vec![G::ScalarField::zero()]]
            } else {
                [
                    vec![
                        (public_input
                            .iter()
                            .zip(zeta_minus_x.iter())
                            .zip(index.domain.elements())
                            .map(|((p, l), w)| -*l * p * w)
                            .fold(G::ScalarField::zero(), |x, y| x + y))
                            * (zeta1 - G::ScalarField::one())
                            * index.domain.size_inv,
                    ],
                    vec![
                        (public_input
                            .iter()
                            .zip(zeta_minus_x[public_input.len()..].iter())
                            .zip(index.domain.elements())
                            .map(|((p, l), w)| -*l * p * w)
                            .fold(G::ScalarField::zero(), |x, y| x + y))
                            * index.domain.size_inv
                            * (zetaw.pow([n]) - G::ScalarField::one()),
                    ],
                ]
            }
        } else {
            return Err(VerifyError::MissingPublicInputEvaluation);
        };

        //~ 1. Absorb the unique evaluation of ft: $ft(\zeta\omega)$.
        fr_sponge.absorb(&self.ft_eval1);

        //~ 1. Absorb all the polynomial evaluations in $\zeta$ and $\zeta\omega$:
        //~~ * the public polynomial
        //~~ * z
        //~~ * generic selector
        //~~ * poseidon selector
        //~~ * the 15 register/witness
        //~~ * 6 sigmas evaluations (the last one is not evaluated)
        fr_sponge.absorb_multiple(&public_evals[0]);
        fr_sponge.absorb_multiple(&public_evals[1]);
        fr_sponge.absorb_evaluations(&self.evals);

        //~ 1. Sample the "polyscale" $v'$ with the Fr-Sponge.
        let v_chal = fr_sponge.challenge();

        //~ 1. Derive $v$ from $v'$ using the endomorphism (TODO: specify).
        let v = v_chal.to_field(endo_r);

        //~ 1. Sample the "evalscale" $u'$ with the Fr-Sponge.
        let u_chal = fr_sponge.challenge();

        //~ 1. Derive $u$ from $u'$ using the endomorphism (TODO: specify).
        let u = u_chal.to_field(endo_r);

        //~ 1. Create a list of all polynomials that have an evaluation proof.

        let evals = self.evals.combine(&powers_of_eval_points_for_chunks);

        //~ 1. Compute the evaluation of $ft(\zeta)$.
        let ft_eval0 = {
            let permutation_vanishing_polynomial =
                index.permutation_vanishing_polynomial_m().evaluate(&zeta);
            let zeta1m1 = zeta1 - G::ScalarField::one();

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

            let init = (evals.w[PERMUTS - 1].zeta + gamma)
                * evals.z.zeta_omega
                * alpha0
                * permutation_vanishing_polynomial;
            let mut ft_eval0 = evals
                .w
                .iter()
                .zip(evals.s.iter())
                .map(|(w, s)| (beta * s.zeta) + w.zeta + gamma)
                .fold(init, |x, y| x * y);

            ft_eval0 -= DensePolynomial::eval_polynomial(
                &public_evals[0],
                powers_of_eval_points_for_chunks.zeta,
            );

            ft_eval0 -= evals
                .w
                .iter()
                .zip(index.shift.iter())
                .map(|(w, s)| gamma + (beta * zeta * s) + w.zeta)
                .fold(
                    alpha0 * permutation_vanishing_polynomial * evals.z.zeta,
                    |x, y| x * y,
                );

            let numerator = ((zeta1m1 * alpha1 * (zeta - index.w()))
                + (zeta1m1 * alpha2 * (zeta - G::ScalarField::one())))
                * (G::ScalarField::one() - evals.z.zeta);

            let denominator = (zeta - index.w()) * (zeta - G::ScalarField::one());
            let denominator = denominator.inverse().expect("negligible probability");

            ft_eval0 += numerator * denominator;

            let constants = Constants {
                endo_coefficient: index.endo,
                mds: &G::sponge_params().mds,
                zk_rows,
            };
            let challenges = BerkeleyChallenges {
                alpha,
                beta,
                gamma,
                joint_combiner: joint_combiner
                    .as_ref()
                    .map(|j| j.1)
                    .unwrap_or(G::ScalarField::zero()),
            };

            ft_eval0 -= PolishToken::evaluate(
                &index.linearization.constant_term,
                index.domain,
                zeta,
                &evals,
                &constants,
                &challenges,
            )
            .unwrap();

            ft_eval0
        };

        let combined_inner_product =
            {
                let ft_eval0 = vec![ft_eval0];
                let ft_eval1 = vec![self.ft_eval1];

                #[allow(clippy::type_complexity)]
                let mut es: Vec<Vec<Vec<G::ScalarField>>> =
                    polys.iter().map(|(_, e)| e.clone()).collect();
                es.push(public_evals.to_vec());
                es.push(vec![ft_eval0, ft_eval1]);
                for col in [
                    Column::Z,
                    Column::Index(GateType::Generic),
                    Column::Index(GateType::Poseidon),
                    Column::Index(GateType::CompleteAdd),
                    Column::Index(GateType::VarBaseMul),
                    Column::Index(GateType::EndoMul),
                    Column::Index(GateType::EndoMulScalar),
                ]
                .into_iter()
                .chain((0..COLUMNS).map(Column::Witness))
                .chain((0..COLUMNS).map(Column::Coefficient))
                .chain((0..PERMUTS - 1).map(Column::Permutation))
                .chain(
                    index
                        .range_check0_comm
                        .as_ref()
                        .map(|_| Column::Index(GateType::RangeCheck0)),
                )
                .chain(
                    index
                        .range_check1_comm
                        .as_ref()
                        .map(|_| Column::Index(GateType::RangeCheck1)),
                )
                .chain(
                    index
                        .foreign_field_add_comm
                        .as_ref()
                        .map(|_| Column::Index(GateType::ForeignFieldAdd)),
                )
                .chain(
                    index
                        .foreign_field_mul_comm
                        .as_ref()
                        .map(|_| Column::Index(GateType::ForeignFieldMul)),
                )
                .chain(
                    index
                        .xor_comm
                        .as_ref()
                        .map(|_| Column::Index(GateType::Xor16)),
                )
                .chain(
                    index
                        .rot_comm
                        .as_ref()
                        .map(|_| Column::Index(GateType::Rot64)),
                )
                .chain(
                    index
                        .lookup_index
                        .as_ref()
                        .map(|li| {
                            (0..li.lookup_info.max_per_row + 1)
                                .map(Column::LookupSorted)
                                .chain([Column::LookupAggreg, Column::LookupTable].into_iter())
                                .chain(
                                    li.runtime_tables_selector
                                        .as_ref()
                                        .map(|_| [Column::LookupRuntimeTable].into_iter())
                                        .into_iter()
                                        .flatten(),
                                )
                                .chain(
                                    self.evals
                                        .runtime_lookup_table_selector
                                        .as_ref()
                                        .map(|_| Column::LookupRuntimeSelector),
                                )
                                .chain(
                                    self.evals
                                        .xor_lookup_selector
                                        .as_ref()
                                        .map(|_| Column::LookupKindIndex(LookupPattern::Xor)),
                                )
                                .chain(
                                    self.evals
                                        .lookup_gate_lookup_selector
                                        .as_ref()
                                        .map(|_| Column::LookupKindIndex(LookupPattern::Lookup)),
                                )
                                .chain(
                                    self.evals.range_check_lookup_selector.as_ref().map(|_| {
                                        Column::LookupKindIndex(LookupPattern::RangeCheck)
                                    }),
                                )
                                .chain(self.evals.foreign_field_mul_lookup_selector.as_ref().map(
                                    |_| Column::LookupKindIndex(LookupPattern::ForeignFieldMul),
                                ))
                        })
                        .into_iter()
                        .flatten(),
                ) {
                    es.push({
                        let evals = self
                            .evals
                            .get_column(col)
                            .ok_or(VerifyError::MissingEvaluation(col))?;
                        vec![evals.zeta.clone(), evals.zeta_omega.clone()]
                    })
                }

                combined_inner_product(&v, &u, &es)
            };

        let oracles = RandomOracles {
            joint_combiner,
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
        };

        Ok(OraclesResult {
            fq_sponge,
            digest,
            oracles,
            all_alphas,
            public_evals,
            powers_of_eval_points_for_chunks,
            polys,
            zeta1,
            ft_eval0,
            combined_inner_product,
        })
    }
}

/// Enforce the length of evaluations inside [`Proof`].
/// Atm, the length of evaluations(both `zeta` and `zeta_omega`) SHOULD be 1.
/// The length value is prone to future change.
fn check_proof_evals_len<G, OpeningProof>(
    proof: &ProverProof<G, OpeningProof>,
    expected_size: usize,
) -> Result<()>
where
    G: KimchiCurve,
    G::BaseField: PrimeField,
{
    let ProofEvaluations {
        public,
        w,
        z,
        s,
        coefficients,
        generic_selector,
        poseidon_selector,
        complete_add_selector,
        mul_selector,
        emul_selector,
        endomul_scalar_selector,
        range_check0_selector,
        range_check1_selector,
        foreign_field_add_selector,
        foreign_field_mul_selector,
        xor_selector,
        rot_selector,
        lookup_aggregation,
        lookup_table,
        lookup_sorted,
        runtime_lookup_table,
        runtime_lookup_table_selector,
        xor_lookup_selector,
        lookup_gate_lookup_selector,
        range_check_lookup_selector,
        foreign_field_mul_lookup_selector,
    } = &proof.evals;

    let check_eval_len = |eval: &PointEvaluations<Vec<_>>, str: &'static str| -> Result<()> {
        if eval.zeta.len() != expected_size {
            Err(VerifyError::IncorrectEvaluationsLength(
                expected_size,
                eval.zeta.len(),
                str,
            ))
        } else if eval.zeta_omega.len() != expected_size {
            Err(VerifyError::IncorrectEvaluationsLength(
                expected_size,
                eval.zeta_omega.len(),
                str,
            ))
        } else {
            Ok(())
        }
    };

    if let Some(public) = public {
        check_eval_len(public, "public input")?;
    }

    for w_i in w {
        check_eval_len(w_i, "witness")?;
    }
    check_eval_len(z, "permutation accumulator")?;
    for s_i in s {
        check_eval_len(s_i, "permutation shifts")?;
    }
    for coeff in coefficients {
        check_eval_len(coeff, "coefficients")?;
    }

    // Lookup evaluations
    for sorted in lookup_sorted.iter().flatten() {
        check_eval_len(sorted, "lookup sorted")?
    }

    if let Some(lookup_aggregation) = lookup_aggregation {
        check_eval_len(lookup_aggregation, "lookup aggregation")?;
    }
    if let Some(lookup_table) = lookup_table {
        check_eval_len(lookup_table, "lookup table")?;
    }
    if let Some(runtime_lookup_table) = runtime_lookup_table {
        check_eval_len(runtime_lookup_table, "runtime lookup table")?;
    }

    check_eval_len(generic_selector, "generic selector")?;
    check_eval_len(poseidon_selector, "poseidon selector")?;
    check_eval_len(complete_add_selector, "complete add selector")?;
    check_eval_len(mul_selector, "mul selector")?;
    check_eval_len(emul_selector, "endomul selector")?;
    check_eval_len(endomul_scalar_selector, "endomul scalar selector")?;

    // Optional gates

    if let Some(range_check0_selector) = range_check0_selector {
        check_eval_len(range_check0_selector, "range check 0 selector")?
    }
    if let Some(range_check1_selector) = range_check1_selector {
        check_eval_len(range_check1_selector, "range check 1 selector")?
    }
    if let Some(foreign_field_add_selector) = foreign_field_add_selector {
        check_eval_len(foreign_field_add_selector, "foreign field add selector")?
    }
    if let Some(foreign_field_mul_selector) = foreign_field_mul_selector {
        check_eval_len(foreign_field_mul_selector, "foreign field mul selector")?
    }
    if let Some(xor_selector) = xor_selector {
        check_eval_len(xor_selector, "xor selector")?
    }
    if let Some(rot_selector) = rot_selector {
        check_eval_len(rot_selector, "rot selector")?
    }

    // Lookup selectors

    if let Some(runtime_lookup_table_selector) = runtime_lookup_table_selector {
        check_eval_len(
            runtime_lookup_table_selector,
            "runtime lookup table selector",
        )?
    }
    if let Some(xor_lookup_selector) = xor_lookup_selector {
        check_eval_len(xor_lookup_selector, "xor lookup selector")?
    }
    if let Some(lookup_gate_lookup_selector) = lookup_gate_lookup_selector {
        check_eval_len(lookup_gate_lookup_selector, "lookup gate lookup selector")?
    }
    if let Some(range_check_lookup_selector) = range_check_lookup_selector {
        check_eval_len(range_check_lookup_selector, "range check lookup selector")?
    }
    if let Some(foreign_field_mul_lookup_selector) = foreign_field_mul_lookup_selector {
        check_eval_len(
            foreign_field_mul_lookup_selector,
            "foreign field mul lookup selector",
        )?
    }

    Ok(())
}

fn to_batch<'a, G, EFqSponge, EFrSponge, OpeningProof: OpenProof<G>>(
    verifier_index: &VerifierIndex<G, OpeningProof>,
    proof: &'a ProverProof<G, OpeningProof>,
    public_input: &'a [<G as AffineRepr>::ScalarField],
) -> Result<BatchEvaluationProof<'a, G, EFqSponge, OpeningProof>>
where
    G: KimchiCurve,
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    //~
    //~ #### Partial verification
    //~
    //~ For every proof we want to verify, we defer the proof opening to the very end.
    //~ This allows us to potentially batch verify a number of partially verified proofs.
    //~ Essentially, this steps verifies that $f(\zeta) = t(\zeta) * Z_H(\zeta)$.
    //~

    let zk_rows = verifier_index.zk_rows;

    if proof.prev_challenges.len() != verifier_index.prev_challenges {
        return Err(VerifyError::IncorrectPrevChallengesLength(
            verifier_index.prev_challenges,
            proof.prev_challenges.len(),
        ));
    }
    if public_input.len() != verifier_index.public {
        return Err(VerifyError::IncorrectPubicInputLength(
            verifier_index.public,
        ));
    }

    //~ 1. Check the length of evaluations inside the proof.
    let chunk_size = {
        let d1_size = verifier_index.domain.size();
        if d1_size < verifier_index.max_poly_size {
            1
        } else {
            d1_size / verifier_index.max_poly_size
        }
    };
    check_proof_evals_len(proof, chunk_size)?;

    //~ 1. Commit to the negated public input polynomial.
    let public_comm = {
        if public_input.len() != verifier_index.public {
            return Err(VerifyError::IncorrectPubicInputLength(
                verifier_index.public,
            ));
        }
        let lgr_comm = verifier_index
            .srs()
            .get_lagrange_basis(verifier_index.domain);
        let com: Vec<_> = lgr_comm.iter().take(verifier_index.public).collect();
        if public_input.is_empty() {
            PolyComm::new(vec![verifier_index.srs().blinding_commitment(); chunk_size])
        } else {
            let elm: Vec<_> = public_input.iter().map(|s| -*s).collect();
            let public_comm = PolyComm::<G>::multi_scalar_mul(&com, &elm);
            verifier_index
                .srs()
                .mask_custom(
                    public_comm.clone(),
                    &public_comm.map(|_| G::ScalarField::one()),
                )
                .unwrap()
                .commitment
        }
    };

    //~ 1. Run the [Fiat-Shamir argument](#fiat-shamir-argument).
    let OraclesResult {
        fq_sponge,
        oracles,
        all_alphas,
        public_evals,
        powers_of_eval_points_for_chunks,
        polys,
        zeta1: zeta_to_domain_size,
        ft_eval0,
        combined_inner_product,
        ..
    } = proof.oracles::<EFqSponge, EFrSponge>(verifier_index, &public_comm, Some(public_input))?;

    //~ 1. Combine the chunked polynomials' evaluations
    //~    (TODO: most likely only the quotient polynomial is chunked)
    //~    with the right powers of $\zeta^n$ and $(\zeta * \omega)^n$.
    let evals = proof.evals.combine(&powers_of_eval_points_for_chunks);

    let context = Context {
        verifier_index,
        proof,
        public_input,
    };

    //~ 1. Compute the commitment to the linearized polynomial $f$.
    //~    To do this, add the constraints of all of the gates, of the permutation,
    //~    and optionally of the lookup.
    //~    (See the separate sections in the [constraints](#constraints) section.)
    //~    Any polynomial should be replaced by its associated commitment,
    //~    contained in the verifier index or in the proof,
    //~    unless a polynomial has its evaluation provided by the proof
    //~    in which case the evaluation should be used in place of the commitment.
    let f_comm = {
        // the permutation is written manually (not using the expr framework)
        let permutation_vanishing_polynomial = verifier_index
            .permutation_vanishing_polynomial_m()
            .evaluate(&oracles.zeta);

        let alphas = all_alphas.get_alphas(ArgumentType::Permutation, permutation::CONSTRAINTS);

        let mut commitments = vec![&verifier_index.sigma_comm[PERMUTS - 1]];
        let mut scalars = vec![ConstraintSystem::<G::ScalarField>::perm_scalars(
            &evals,
            oracles.beta,
            oracles.gamma,
            alphas,
            permutation_vanishing_polynomial,
        )];

        // other gates are implemented using the expression framework
        {
            // TODO: Reuse constants and challenges from oracles function
            let constants = Constants {
                endo_coefficient: verifier_index.endo,
                mds: &G::sponge_params().mds,
                zk_rows,
            };
            let challenges = BerkeleyChallenges {
                alpha: oracles.alpha,
                beta: oracles.beta,
                gamma: oracles.gamma,
                joint_combiner: oracles
                    .joint_combiner
                    .as_ref()
                    .map(|j| j.1)
                    .unwrap_or(G::ScalarField::zero()),
            };

            for (col, tokens) in &verifier_index.linearization.index_terms {
                let scalar = PolishToken::evaluate(
                    tokens,
                    verifier_index.domain,
                    oracles.zeta,
                    &evals,
                    &constants,
                    &challenges,
                )
                .expect("should evaluate");

                let col = *col;
                scalars.push(scalar);
                commitments.push(
                    context
                        .get_column(col)
                        .ok_or(VerifyError::MissingCommitment(col))?,
                );
            }
        }

        // MSM
        PolyComm::multi_scalar_mul(&commitments, &scalars)
    };

    //~ 1. Compute the (chunked) commitment of $ft$
    //~    (see [Maller's optimization](../kimchi/maller_15.md)).
    let ft_comm = {
        let zeta_to_srs_len = oracles.zeta.pow([verifier_index.max_poly_size as u64]);
        let chunked_f_comm = f_comm.chunk_commitment(zeta_to_srs_len);
        let chunked_t_comm = &proof.commitments.t_comm.chunk_commitment(zeta_to_srs_len);
        &chunked_f_comm - &chunked_t_comm.scale(zeta_to_domain_size - G::ScalarField::one())
    };

    //~ 1. List the polynomial commitments, and their associated evaluations,
    //~    that are associated to the aggregated evaluation proof in the proof:
    let mut evaluations = vec![];

    //~~ * recursion
    evaluations.extend(polys.into_iter().map(|(c, e)| Evaluation {
        commitment: c,
        evaluations: e,
    }));

    //~~ * public input commitment
    evaluations.push(Evaluation {
        commitment: public_comm,
        evaluations: public_evals.to_vec(),
    });

    //~~ * ft commitment (chunks of it)
    evaluations.push(Evaluation {
        commitment: ft_comm,
        evaluations: vec![vec![ft_eval0], vec![proof.ft_eval1]],
    });

    for col in [
        //~~ * permutation commitment
        Column::Z,
        //~~ * index commitments that use the coefficients
        Column::Index(GateType::Generic),
        Column::Index(GateType::Poseidon),
        Column::Index(GateType::CompleteAdd),
        Column::Index(GateType::VarBaseMul),
        Column::Index(GateType::EndoMul),
        Column::Index(GateType::EndoMulScalar),
    ]
    .into_iter()
    //~~ * witness commitments
    .chain((0..COLUMNS).map(Column::Witness))
    //~~ * coefficient commitments
    .chain((0..COLUMNS).map(Column::Coefficient))
    //~~ * sigma commitments
    .chain((0..PERMUTS - 1).map(Column::Permutation))
    //~~ * optional gate commitments
    .chain(
        verifier_index
            .range_check0_comm
            .as_ref()
            .map(|_| Column::Index(GateType::RangeCheck0)),
    )
    .chain(
        verifier_index
            .range_check1_comm
            .as_ref()
            .map(|_| Column::Index(GateType::RangeCheck1)),
    )
    .chain(
        verifier_index
            .foreign_field_add_comm
            .as_ref()
            .map(|_| Column::Index(GateType::ForeignFieldAdd)),
    )
    .chain(
        verifier_index
            .foreign_field_mul_comm
            .as_ref()
            .map(|_| Column::Index(GateType::ForeignFieldMul)),
    )
    .chain(
        verifier_index
            .xor_comm
            .as_ref()
            .map(|_| Column::Index(GateType::Xor16)),
    )
    .chain(
        verifier_index
            .rot_comm
            .as_ref()
            .map(|_| Column::Index(GateType::Rot64)),
    )
    //~~ * lookup commitments
    //~
    .chain(
        verifier_index
            .lookup_index
            .as_ref()
            .map(|li| {
                // add evaluations of sorted polynomials
                (0..li.lookup_info.max_per_row + 1)
                    .map(Column::LookupSorted)
                    // add evaluations of the aggreg polynomial
                    .chain([Column::LookupAggreg].into_iter())
            })
            .into_iter()
            .flatten(),
    ) {
        let evals = proof
            .evals
            .get_column(col)
            .ok_or(VerifyError::MissingEvaluation(col))?;
        evaluations.push(Evaluation {
            commitment: context
                .get_column(col)
                .ok_or(VerifyError::MissingCommitment(col))?
                .clone(),
            evaluations: vec![evals.zeta.clone(), evals.zeta_omega.clone()],
        });
    }

    if let Some(li) = &verifier_index.lookup_index {
        let lookup_comms = proof
            .commitments
            .lookup
            .as_ref()
            .ok_or(VerifyError::LookupCommitmentMissing)?;

        let lookup_table = proof
            .evals
            .lookup_table
            .as_ref()
            .ok_or(VerifyError::LookupEvalsMissing)?;
        let runtime_lookup_table = proof.evals.runtime_lookup_table.as_ref();

        // compute table commitment
        let table_comm = {
            let joint_combiner = oracles
                .joint_combiner
                .expect("joint_combiner should be present if lookups are used");
            // The table ID is added as the last column of the vector.
            // Therefore, the exponent for the combiner for the table ID is the
            // width of the concatenated table, i.e. max_joint_size.
            let table_id_combiner = joint_combiner
                .1
                .pow([u64::from(li.lookup_info.max_joint_size)]);
            let lookup_table: Vec<_> = li.lookup_table.iter().collect();
            let runtime = lookup_comms.runtime.as_ref();

            combine_table(
                &lookup_table,
                joint_combiner.1,
                table_id_combiner,
                li.table_ids.as_ref(),
                runtime,
            )
        };

        // add evaluation of the table polynomial
        evaluations.push(Evaluation {
            commitment: table_comm,
            evaluations: vec![lookup_table.zeta.clone(), lookup_table.zeta_omega.clone()],
        });

        // add evaluation of the runtime table polynomial
        if li.runtime_tables_selector.is_some() {
            let runtime = lookup_comms
                .runtime
                .as_ref()
                .ok_or(VerifyError::IncorrectRuntimeProof)?;
            let runtime_eval = runtime_lookup_table
                .as_ref()
                .map(|x| x.map_ref(&|x| x.clone()))
                .ok_or(VerifyError::IncorrectRuntimeProof)?;

            evaluations.push(Evaluation {
                commitment: runtime.clone(),
                evaluations: vec![runtime_eval.zeta, runtime_eval.zeta_omega],
            });
        }
    }

    for col in verifier_index
        .lookup_index
        .as_ref()
        .map(|li| {
            (li.runtime_tables_selector
                .as_ref()
                .map(|_| Column::LookupRuntimeSelector))
            .into_iter()
            .chain(
                li.lookup_selectors
                    .xor
                    .as_ref()
                    .map(|_| Column::LookupKindIndex(LookupPattern::Xor)),
            )
            .chain(
                li.lookup_selectors
                    .lookup
                    .as_ref()
                    .map(|_| Column::LookupKindIndex(LookupPattern::Lookup)),
            )
            .chain(
                li.lookup_selectors
                    .range_check
                    .as_ref()
                    .map(|_| Column::LookupKindIndex(LookupPattern::RangeCheck)),
            )
            .chain(
                li.lookup_selectors
                    .ffmul
                    .as_ref()
                    .map(|_| Column::LookupKindIndex(LookupPattern::ForeignFieldMul)),
            )
        })
        .into_iter()
        .flatten()
    {
        let evals = proof
            .evals
            .get_column(col)
            .ok_or(VerifyError::MissingEvaluation(col))?;
        evaluations.push(Evaluation {
            commitment: context
                .get_column(col)
                .ok_or(VerifyError::MissingCommitment(col))?
                .clone(),
            evaluations: vec![evals.zeta.clone(), evals.zeta_omega.clone()],
        });
    }

    // prepare for the opening proof verification
    let evaluation_points = vec![oracles.zeta, oracles.zeta * verifier_index.domain.group_gen];
    Ok(BatchEvaluationProof {
        sponge: fq_sponge,
        evaluations,
        evaluation_points,
        polyscale: oracles.v,
        evalscale: oracles.u,
        opening: &proof.proof,
        combined_inner_product,
    })
}

/// Verify a proof [`ProverProof`] using a [`VerifierIndex`] and a `group_map`.
///
/// # Errors
///
/// Will give error if `proof(s)` are not verified as valid.
pub fn verify<G, EFqSponge, EFrSponge, OpeningProof: OpenProof<G>>(
    group_map: &G::Map,
    verifier_index: &VerifierIndex<G, OpeningProof>,
    proof: &ProverProof<G, OpeningProof>,
    public_input: &[G::ScalarField],
) -> Result<()>
where
    G: KimchiCurve,
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    let proofs = vec![Context {
        verifier_index,
        proof,
        public_input,
    }];
    batch_verify::<G, EFqSponge, EFrSponge, OpeningProof>(group_map, &proofs)
}

/// This function verifies the batch of zk-proofs
///     proofs: vector of Plonk proofs
///     RETURN: verification status
///
/// # Errors
///
/// Will give error if `srs` of `proof` is invalid or `verify` process fails.
pub fn batch_verify<G, EFqSponge, EFrSponge, OpeningProof: OpenProof<G>>(
    group_map: &G::Map,
    proofs: &[Context<G, OpeningProof>],
) -> Result<()>
where
    G: KimchiCurve,
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
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

    //~ 1. Ensure that all the proof's verifier index have a URS of the same length. (TODO: do they have to be the same URS though? should we check for that?)
    // TODO: Account for the different SRS lengths
    let srs = proofs[0].verifier_index.srs();
    for &Context { verifier_index, .. } in proofs {
        if verifier_index.srs().max_poly_size() != srs.max_poly_size() {
            return Err(VerifyError::DifferentSRS);
        }
    }

    //~ 1. Validate each proof separately following the [partial verification](#partial-verification) steps.
    let mut batch = vec![];
    for &Context {
        verifier_index,
        proof,
        public_input,
    } in proofs
    {
        batch.push(to_batch::<G, EFqSponge, EFrSponge, OpeningProof>(
            verifier_index,
            proof,
            public_input,
        )?);
    }

    //~ 1. Use the [`PolyCom.verify`](#polynomial-commitments) to verify the partially evaluated proofs.
    if OpeningProof::verify(srs, group_map, &mut batch, &mut thread_rng()) {
        Ok(())
    } else {
        Err(VerifyError::OpenProof)
    }
}
