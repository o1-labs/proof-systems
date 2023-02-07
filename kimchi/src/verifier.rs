//! This module implements zk-proof batch verifier functionality.

use crate::{
    circuits::{
        argument::ArgumentType,
        constraints::ConstraintSystem,
        expr::{Column, Constants, PolishToken},
        gate::GateType,
        lookup::tables::combine_table,
        polynomials::permutation,
        scalars::RandomOracles,
        wires::{COLUMNS, PERMUTS},
    },
    curve::KimchiCurve,
    error::VerifyError,
    oracles::OraclesResult,
    plonk_sponge::FrSponge,
    proof::{PointEvaluations, ProverProof, RecursionChallenge},
    verifier_index::VerifierIndex,
};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{EvaluationDomain, Polynomial};
use commitment_dlog::commitment::{
    absorb_commitment, combined_inner_product, BatchEvaluationProof, Evaluation, PolyComm,
};
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use rand::thread_rng;

/// The result of a proof verification.
pub type Result<T> = std::result::Result<T, VerifyError>;

pub struct Context<'a, G: KimchiCurve> {
    proof: &'a ProverProof<G>,
    index: &'a VerifierIndex<G>,
}

impl<'a, G: KimchiCurve> Context<'a, G> {
    pub fn get_column(&self, col: Column) -> Option<&'a PolyComm<G>> {
        use Column::*;
        match col {
            Witness(i) => Some(&self.proof.commitments.w_comm[i]),
            Coefficient(i) => Some(&self.index.coefficients_comm[i]),
            Permutation(i) => Some(&self.index.sigma_comm[i]),
            Z => Some(&self.proof.commitments.z_comm),
            LookupSorted(i) => Some(&self.proof.commitments.lookup.as_ref()?.sorted[i]),
            LookupAggreg => Some(&self.proof.commitments.lookup.as_ref()?.aggreg),
            LookupKindIndex(i) => {
                Some(self.index.lookup_index.as_ref()?.lookup_selectors[i].as_ref()?)
            }
            LookupTable => None,
            LookupRuntimeSelector => Some(
                self.index
                    .lookup_index
                    .as_ref()?
                    .runtime_tables_selector
                    .as_ref()?,
            ),
            LookupRuntimeTable => None,
            Index(t) => {
                use GateType::*;
                match t {
                    Zero => None,
                    Generic => Some(&self.index.generic_comm),
                    Lookup => None,
                    CompleteAdd => Some(&self.index.complete_add_comm),
                    VarBaseMul => Some(&self.index.mul_comm),
                    EndoMul => Some(&self.index.emul_comm),
                    EndoMulScalar => Some(&self.index.endomul_scalar_comm),
                    Poseidon => Some(&self.index.psm_comm),
                    ChaCha0 => Some(&self.index.chacha_comm.as_ref()?[0]),
                    ChaCha1 => Some(&self.index.chacha_comm.as_ref()?[1]),
                    ChaCha2 => Some(&self.index.chacha_comm.as_ref()?[2]),
                    ChaChaFinal => Some(&self.index.chacha_comm.as_ref()?[3]),
                    CairoClaim | CairoInstruction | CairoFlags | CairoTransition => None,
                    RangeCheck0 => Some(&self.index.range_check_comm.as_ref()?[0]),
                    RangeCheck1 => Some(&self.index.range_check_comm.as_ref()?[1]),
                    ForeignFieldAdd => Some(self.index.foreign_field_add_comm.as_ref()?),
                    ForeignFieldMul => Some(self.index.foreign_field_mul_comm.as_ref()?),
                    Xor16 => Some(self.index.xor_comm.as_ref()?),
                    Rot64 => Some(self.index.rot_comm.as_ref()?),
                }
            }
        }
    }
}

impl<G: KimchiCurve> ProverProof<G>
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
        index: &VerifierIndex<G>,
        public_comm: &PolyComm<G>,
    ) -> Result<OraclesResult<G, EFqSponge>> {
        //~
        //~ #### Fiat-Shamir argument
        //~
        //~ We run the following algorithm:
        //~
        let n = index.domain.size;
        let (_, endo_r) = G::endos();

        //~ 1. Setup the Fq-Sponge.
        let mut fq_sponge = EFqSponge::new(G::OtherCurve::sponge_params());

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
            //~~ - If it involves queries to a multiple-column lookup table,
            //~~   then squeeze the Fq-Sponge to obtain the joint combiner challenge $j'$,
            //~~   otherwise set the joint combiner challenge $j'$ to $0$.
            let joint_combiner = if l.joint_lookup_used {
                fq_sponge.challenge()
            } else {
                G::ScalarField::zero()
            };

            //~~ - Derive the scalar joint combiner challenge $j$ from $j'$ using the endomorphism.
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

            //~~ - absorb the commitments to the sorted polynomials.
            for com in &lookup_commits.sorted {
                absorb_commitment(&mut fq_sponge, com);
            }
        }

        //~ 1. Sample $\beta$ with the Fq-Sponge.
        let beta = fq_sponge.challenge();

        //~ 1. Sample $\gamma$ with the Fq-Sponge.
        let gamma = fq_sponge.challenge();

        //~ 1. If using lookup, absorb the commitment to the aggregation lookup polynomial.
        self.commitments.lookup.iter().for_each(|l| {
            absorb_commitment(&mut fq_sponge, &l.aggreg);
        });

        //~ 1. Absorb the commitment to the permutation trace with the Fq-Sponge.
        absorb_commitment(&mut fq_sponge, &self.commitments.z_comm);

        //~ 1. Sample $\alpha'$ with the Fq-Sponge.
        let alpha_chal = ScalarChallenge(fq_sponge.challenge());

        //~ 1. Derive $\alpha$ from $\alpha'$ using the endomorphism (TODO: details).
        let alpha = alpha_chal.to_field(endo_r);

        //~ 1. Enforce that the length of the $t$ commitment is of size `PERMUTS`.
        if self.commitments.t_comm.unshifted.len() != PERMUTS {
            return Err(VerifyError::IncorrectCommitmentLength("t"));
        }

        //~ 1. Absorb the commitment to the quotient polynomial $t$ into the argument.
        absorb_commitment(&mut fq_sponge, &self.commitments.t_comm);

        //~ 1. Sample $\zeta'$ with the Fq-Sponge.
        let zeta_chal = ScalarChallenge(fq_sponge.challenge());

        //~ 1. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify).
        let zeta = zeta_chal.to_field(endo_r);

        //~ 1. Setup the Fr-Sponge.
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
        let zeta1 = zeta.pow(&[n]);
        let zetaw = zeta * index.domain.group_gen;
        let evaluation_points = [zeta, zetaw];
        let powers_of_eval_points_for_chunks = PointEvaluations {
            zeta: zeta.pow(&[index.max_poly_size as u64]),
            zeta_omega: zetaw.pow(&[index.max_poly_size as u64]),
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

        // compute Lagrange base evaluation denominators
        let w: Vec<_> = index.domain.elements().take(self.public.len()).collect();

        let (zeta_minus_x, zeta_minus_1_inv, zeta_minus_w3_inv, vanishing_poly_zeta_inv) = {
            let mut to_invert: Vec<G::ScalarField> = 
                w.iter().map(|w| zeta - w)
                .chain(w.iter().take(self.public.len()).map(|w| zetaw - w))
                .collect();
            /*
            w.iter()
                .take(self.public.len())
                .for_each(|w| to_invert.push(zetaw - w)); */

            let n = to_invert.len();

            to_invert.push(zeta - G::ScalarField::one());
            to_invert.push(zeta - index.w());
            to_invert.push(zeta1 - G::ScalarField::one());

            ark_ff::fields::batch_inversion::<G::ScalarField>(&mut to_invert);
            (to_invert[0..n].to_vec(), to_invert[n], to_invert[n + 1], to_invert[n + 2])
        };

        /*
        let mut zeta_minus_x: Vec<_> = w.iter().map(|w| zeta - w).collect();

        w.iter()
            .take(self.public.len())
            .for_each(|w| zeta_minus_x.push(zetaw - w));

        ark_ff::fields::batch_inversion::<G::ScalarField>(&mut zeta_minus_x);
        */

        //~ 1. Evaluate the negated public polynomial (if present) at $\zeta$ and $\zeta\omega$.
        //~
        //~    NOTE: this works only in the case when the poly segment size is not smaller than that of the domain.
        let public_evals = if self.public.is_empty() {
            [vec![G::ScalarField::zero()], vec![G::ScalarField::zero()]]
        } else {
            [
                vec![
                    (self
                        .public
                        .iter()
                        .zip(zeta_minus_x.iter())
                        .zip(index.domain.elements())
                        .map(|((p, l), w)| -*l * p * w)
                        .fold(G::ScalarField::zero(), |x, y| x + y))
                        * (zeta1 - G::ScalarField::one())
                        * index.domain.size_inv,
                ],
                vec![
                    (self
                        .public
                        .iter()
                        .zip(zeta_minus_x[self.public.len()..].iter())
                        .zip(index.domain.elements())
                        .map(|((p, l), w)| -*l * p * w)
                        .fold(G::ScalarField::zero(), |x, y| x + y))
                        * index.domain.size_inv
                        * (zetaw.pow(&[n as u64]) - G::ScalarField::one()),
                ],
            ]
        };

        //~ 1. Absorb the unique evaluation of ft: $ft(\zeta\omega)$.
        fr_sponge.absorb(&self.ft_eval1);

        //~ 1. Absorb all the polynomial evaluations in $\zeta$ and $\zeta\omega$:
        //~~ - the public polynomial
        //~~ - z
        //~~ - generic selector
        //~~ - poseidon selector
        //~~ - complete add selector
        //~~ - mul selector
        //~~ - emul selector
        //~~ - emul scalar selector
        //~~ - the 15 register/witness
        //~~ - 6 sigmas evaluations (the last one is not evaluated)
        fr_sponge.absorb_multiple(&public_evals[0]);
        fr_sponge.absorb_multiple(&public_evals[1]);
        fr_sponge.absorb_evaluations(&self.evals);

        //~ 1. Sample $v'$ with the Fr-Sponge.
        let v_chal = fr_sponge.challenge();

        //~ 1. Derive $v$ from $v'$ using the endomorphism (TODO: specify).
        let v = v_chal.to_field(endo_r);

        //~ 1. Sample $u'$ with the Fr-Sponge.
        let u_chal = fr_sponge.challenge();

        //~ 1. Derive $u$ from $u'$ using the endomorphism (TODO: specify).
        let u = u_chal.to_field(endo_r);

        //~ 1. Create a list of all polynomials that have an evaluation proof.

        let evals = self.evals.combine(&powers_of_eval_points_for_chunks);

        println!("evals w[7] {}", evals.w[7].zeta);
        println!("evals generic {}", evals.generic_selector.zeta);
        println!("evals poseidon {}", evals.poseidon_selector.zeta);
        println!("evals complete_add {}", evals.complete_add_selector.zeta);
        println!("evals mul {}", evals.mul_selector.zeta);
        println!("evals emul {}", evals.emul_selector.zeta);
        println!("evals emul_scalar {}", evals.emul_scalar_selector.zeta);

        //~ 1. Compute the evaluation of $ft(\zeta)$.
        let ft_eval0: G::ScalarField = {
            let zkp = index.zkpm().evaluate(&zeta);
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

            let init = (evals.w[PERMUTS - 1].zeta + gamma) * evals.z.zeta_omega * alpha0 * zkp;
            let mut ft_eval0 = evals
                .w
                .iter()
                .zip(evals.s.iter())
                .map(|(w, s)| (beta * s.zeta) + w.zeta + gamma)
                .fold(init, |x, y| x * y);
            
            println!("ft_eval0 {}: {}", line!(), ft_eval0);

            ft_eval0 -= {
                let a = evals
                .w
                .iter()
                .zip(index.shift.iter())
                .map(|(w, s)| (beta * zeta * s) + w.zeta + gamma)
                .fold(alpha0 * zkp * evals.z.zeta, |x, y| x * y);
                println!("a {}: {}", line!(), a);
                a
            };

            ft_eval0 -= if public_evals[0].is_empty() {
                G::ScalarField::zero()
            } else {
                public_evals[0][0]
            };

            let numerator = ((zeta1m1 * alpha1 * (zeta - index.w()))
                + (zeta1m1 * alpha2 * (zeta - G::ScalarField::one())))
                * (G::ScalarField::one() - evals.z.zeta);

            let denominator = (zeta - index.w()) * (zeta - G::ScalarField::one());
            let denominator = denominator.inverse().expect("negligible probability");

                println!("b {}: {}", line!(), numerator * denominator);
            ft_eval0 += numerator * denominator;

            let constants = Constants {
                alpha,
                beta,
                gamma,
                joint_combiner: joint_combiner.as_ref().map(|j| j.1),
                endo_coefficient: index.endo,
                mds: &G::sponge_params().mds,
            };
            // println!("v linearization {:?}", index.linearization);

            /*
            ft_eval0 -= {
                let a = PolishToken::evaluate(
                &index.linearization.constant_term,
                index.domain,
                zeta,
                &evals,
                &constants,
            )
            .unwrap();
                println!("v constant_term {}", a);
                a
            }; */

            let ft_eval_0 = G::ScalarField::zero();

            /*
            let mut all_alphas = index.powers_of_alpha.clone();
            all_alphas.instantiate(alpha);
            use crate::circuits::argument::Argument;
            PolishToken::evaluate(
                crate::circuits::polynomials::complete_add::CompleteAdd::<_>::
                combined_constraints(&all_alphas)
            );
            */

            // t_eval0 = (perm_part + expr_part) / z_H(zeta) 
            let expr_part: G::ScalarField = {
                /*
                let lookup_features = crate::circuits::lookup::lookups::LookupFeatures::from_gates::<G::ScalarField>(
                    &vec![], false);
                let feature_flags = crate::circuits::constraints::FeatureFlags {
                    chacha: false,
                    range_check: false,
                    lookup_features,
                    foreign_field_add: false,
                    foreign_field_mul: false,
                    xor: false,
                    rot: false,
                }; */

                evals.lookup.iter().for_each(|l| {
                    println!("verifier range check {}", l.range_check.is_some());
                });

                println!("expr = {:?}", index.constraints_expr);
                // let (constraints_expr, powers_of_alpha) = crate::linearization::constraints_expr(Some(&feature_flags), true);
                index.constraints_expr.evaluate__(
                    index.domain,
                    zeta,
                    &evals,
                    &constants).unwrap()
            };
            /*
            let expr_part = PolishToken::evaluate(
                &index.constraints_expr,
                index.domain,
                zeta,
                &evals,
                &constants,
            )
            .unwrap(); */

            let (perm, bnd) = {
                let unpermuted = evals
                    .w
                    .iter()
                    .zip(index.shift.iter())
                    .map(|(w, s)| (beta * zeta * s) + w.zeta + gamma)
                    .fold(evals.z.zeta, |x, y| x * y);
                let permuted = evals
                    .w
                    .iter()
                    .zip(evals.s.iter())
                    .map(|(w, s)| (beta * s.zeta) + w.zeta + gamma)
                    .fold(evals.z.zeta_omega, |x, y| x * y);
                let perm = alpha0 * zkp * (unpermuted - permuted);
                {
                    println!("v: z - 1 = {}", evals.z.zeta - G::ScalarField::one());
                    println!("v: zeta_minus_1_inv = {}", zeta_minus_1_inv);
                    println!("v: zeta_minus_w3_inv = {}", zeta_minus_w3_inv);
                    println!("v: bnd eq1 {}",
                           (evals.z.zeta - G::ScalarField::one()) * zeta_minus_1_inv);
                    println!("v: bnd eq2 {}",
                           (evals.z.zeta - G::ScalarField::one()) * zeta_minus_w3_inv);
                }
                let bnd = (evals.z.zeta - G::ScalarField::one()) * (alpha1 * zeta_minus_1_inv + alpha2 * zeta_minus_w3_inv);
                println!("V zeta {}", zeta);
                println!("V bnd {}", bnd);
                println!("V perm {}", perm);
                (perm, bnd)
            };

            println!("V expr {}", expr_part);

            let public_input_part = if public_evals[0].is_empty() {
                G::ScalarField::zero()
            } else {
                public_evals[0][0]
            };

            (perm + expr_part + public_input_part) * vanishing_poly_zeta_inv + bnd
        };

        let combined_inner_product = {
            println!("v ft_evals {} {}", ft_eval0, self.ft_eval1);
            let ft_eval0 = vec![ft_eval0];
            let ft_eval1 = vec![self.ft_eval1];

            #[allow(clippy::type_complexity)]
            let mut es: Vec<(Vec<Vec<G::ScalarField>>, Option<usize>)> =
                polys.iter().map(|(_, e)| (e.clone(), None)).collect();
            es.push((public_evals.to_vec(), None));
            es.push((vec![ft_eval0, ft_eval1], None));
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
            .chain((0..PERMUTS).map(Column::Permutation))
            {
                es.push((
                    {
                        let evals = self
                            .evals
                            .get_column(col)
                            .ok_or(VerifyError::MissingEvaluation(col))?;
                        vec![evals.zeta.clone(), evals.zeta_omega.clone()]
                    },
                    None,
                ))
            }

            combined_inner_product(&evaluation_points, &v, &u, &es, index.srs().g.len())
        };

        println!("combined inner product verifier = {}", combined_inner_product);

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

fn to_batch<'a, G, EFqSponge, EFrSponge>(
    index: &VerifierIndex<G>,
    proof: &'a ProverProof<G>,
) -> Result<BatchEvaluationProof<'a, G, EFqSponge>>
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

    if proof.prev_challenges.len() != index.prev_challenges {
        return Err(VerifyError::IncorrectPrevChallengesLength(
            index.prev_challenges,
            proof.prev_challenges.len(),
        ));
    }
    if proof.public.len() != index.public {
        return Err(VerifyError::IncorrectPubicInputLength(index.public));
    }

    //~ 1. Commit to the negated public input polynomial.
    let public_comm = {
        if proof.public.len() != index.public {
            return Err(VerifyError::IncorrectPubicInputLength(index.public));
        }
        let lgr_comm = index
            .srs()
            .lagrange_bases
            .get(&index.domain.size())
            .expect("pre-computed committed lagrange bases not found");
        let com: Vec<_> = lgr_comm.iter().take(index.public).collect();
        let elm: Vec<_> = proof.public.iter().map(|s| -*s).collect();
        let public_comm = PolyComm::<G>::multi_scalar_mul(&com, &elm);
        index
            .srs()
            .mask_custom(
                public_comm,
                &PolyComm {
                    unshifted: vec![G::ScalarField::one(); 1],
                    shifted: None,
                },
            )
            .unwrap()
            .commitment
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
        ..
    } = proof.oracles::<EFqSponge, EFrSponge>(index, &public_comm)?;

    //~ 1. Combine the chunked polynomials' evaluations
    //~    (TODO: most likely only the quotient polynomial is chunked)
    //~    with the right powers of $\zeta^n$ and $(\zeta * \omega)^n$.
    let evals = proof.evals.combine(&powers_of_eval_points_for_chunks);

    let context = Context { proof, index };

    //~ 4. Compute the commitment to the linearized polynomial $f$.
    //~    To do this, add the constraints of all of the gates, of the permutation,
    //~    and optionally of the lookup.
    //~    (See the separate sections in the [constraints](#constraints) section.)
    //~    Any polynomial should be replaced by its associated commitment,
    //~    contained in the verifier index or in the proof,
    //~    unless a polynomial has its evaluation provided by the proof
    //~    in which case the evaluation should be used in place of the commitment.
    let f_comm = {
        // the permutation is written manually (not using the expr framework)
        let zkp = index.zkpm().evaluate(&oracles.zeta);

        let alphas = all_alphas.get_alphas(ArgumentType::Permutation, permutation::CONSTRAINTS);

        let mut commitments = vec![&index.sigma_comm[PERMUTS - 1]];
        let scalars = vec![ConstraintSystem::<G::ScalarField>::perm_scalars(
            &evals,
            oracles.beta,
            oracles.gamma,
            alphas,
            zkp,
        )];

        // other gates are implemented using the expression framework
        {
            // TODO: Reuse constants from oracles function
            let constants = Constants {
                alpha: oracles.alpha,
                beta: oracles.beta,
                gamma: oracles.gamma,
                joint_combiner: oracles.joint_combiner.as_ref().map(|j| j.1),
                endo_coefficient: index.endo,
                mds: &G::sponge_params().mds,
            };

            /*
            for (col, tokens) in &index.linearization.index_terms {
                let scalar =
                    PolishToken::evaluate(tokens, index.domain, oracles.zeta, &evals, &constants)
                        .expect("should evaluate");

                let col = *col;
                scalars.push(scalar);
                commitments.push(
                    context
                        .get_column(col)
                        .ok_or(VerifyError::MissingCommitment(col))?,
                );
            } */
        }

        // MSM
        PolyComm::multi_scalar_mul(&commitments, &scalars)
    };

    //~ 1. Compute the (chuncked) commitment of $ft$
    //~    (see [Maller's optimization](../crypto/plonk/maller_15.html)).
    let ft_comm = {
        let zeta_to_srs_len = oracles.zeta.pow(&[index.max_poly_size as u64]);
        // let chunked_f_comm = f_comm.chunk_commitment(zeta_to_srs_len);
        let chunked_t_comm = proof.commitments.t_comm.chunk_commitment(zeta_to_srs_len);
        chunked_t_comm
        // &chunked_f_comm - &chunked_t_comm.scale(zeta_to_domain_size - G::ScalarField::one())
    };

    //~ 1. List the polynomial commitments, and their associated evaluations,
    //~    that are associated to the aggregated evaluation proof in the proof:
    let mut evaluations = vec![];

    //~~ - recursion
    evaluations.extend(polys.into_iter().map(|(c, e)| Evaluation {
        commitment: c,
        evaluations: e,
        degree_bound: None,
    }));

    //~~ - public input commitment
    evaluations.push(Evaluation {
        commitment: public_comm,
        evaluations: public_evals.to_vec(),
        degree_bound: None,
    });

    //~~ - ft commitment (chunks of it)
    evaluations.push(Evaluation {
        commitment: ft_comm,
        evaluations: vec![vec![ft_eval0], vec![proof.ft_eval1]],
        degree_bound: None,
    });

    for col in [
        //~~ - permutation commitment
        Column::Z,
        //~~ - index commitments that use the coefficients
        Column::Index(GateType::Generic),
        Column::Index(GateType::Poseidon),
        Column::Index(GateType::CompleteAdd),
        Column::Index(GateType::VarBaseMul),
        Column::Index(GateType::EndoMul),
        Column::Index(GateType::EndoMulScalar),
    ]
    .into_iter()
    //~~ - witness commitments
    .chain((0..COLUMNS).map(Column::Witness))
    //~~ - coefficient commitments
    .chain((0..COLUMNS).map(Column::Coefficient))
    //~~ - sigma commitments
    .chain((0..PERMUTS).map(Column::Permutation))
    //~~ - lookup commitments
    .chain(
        index
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
            degree_bound: None,
        });
    }

    if let Some(li) = &index.lookup_index {
        let lookup_comms = proof
            .commitments
            .lookup
            .as_ref()
            .ok_or(VerifyError::LookupCommitmentMissing)?;
        let lookup_eval = proof
            .evals
            .lookup
            .as_ref()
            .ok_or(VerifyError::LookupEvalsMissing)?;

        // compute table commitment
        let table_comm = {
            let joint_combiner = oracles
                .joint_combiner
                .expect("joint_combiner should be present if lookups are used");
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
        
        let mk_eval = |c: PolyComm<G>, e: &PointEvaluations<Vec<G::ScalarField>>| Evaluation {
            commitment: c.clone(),
            evaluations: vec![e.zeta.clone(), e.zeta_omega.clone()],
            degree_bound: None,
        };

        // add evaluation of the table polynomial
        evaluations.push(mk_eval(table_comm, &lookup_eval.table));

        // Used to check that both the commitments and the evaluations are
        // both present or both not present.
        fn both<'a, A, B>(x: &'a Option<A>, y: &'a Option<B>) -> Result<Option<(&'a A, &'a B)>> {
            match (x.as_ref(), y.as_ref()) {
                (Some(x), Some(y)) => Ok(Some((x,y))),
                (None, None) => Ok(None),
                _ => Err(VerifyError::IncorrectRuntimeProof)
            }
        }

        let add_single = |es: &mut Vec<_>, c: &Option<PolyComm<G>>, e: &Option<PointEvaluations<_>>| -> Result<()> {
            es.extend(
                // Check the commitment and the evaluation are either both there
                // or both not there
                both(c, e)?
                // This is iter on an Option. So, add nothing in the "None" case.
                .iter()
                .map(|(c, e)| mk_eval((*c).clone(), e)));
            Ok(())
        };
        
        add_single(&mut evaluations, &lookup_comms.runtime, &lookup_eval.runtime)?;

        evaluations.extend(
            both(&index.chacha_comm, &lookup_eval.chacha)?
            .iter()
            .flat_map(|(cs, es)| cs.iter().zip(es.iter()))
            .map(|(c, e)| mk_eval(c.clone(), e)));

        evaluations.extend(
            both(&index.range_check_comm, &lookup_eval.range_check)?
            .iter()
            .flat_map(|(cs, es)| cs.iter().zip(es.iter()))
            .map(|(c, e)| mk_eval(c.clone(), e)));

        add_single(&mut evaluations, &index.foreign_field_add_comm, &lookup_eval.foreign_field_add)?;
        add_single(&mut evaluations, &index.foreign_field_mul_comm, &lookup_eval.foreign_field_mul)?;
        add_single(&mut evaluations, &index.xor_comm, &lookup_eval.xor16)?;
        add_single(&mut evaluations, &index.rot_comm, &lookup_eval.rot64)?;
    }

    // prepare for the opening proof verification
    let evaluation_points = vec![oracles.zeta, oracles.zeta * index.domain.group_gen];
    Ok(BatchEvaluationProof {
        sponge: fq_sponge,
        evaluations,
        evaluation_points,
        polyscale: oracles.v,
        evalscale: oracles.u,
        opening: &proof.proof,
    })
}

/// Verify a proof [`ProverProof`] using a [`VerifierIndex`] and a `group_map`.
///
/// # Errors
///
/// Will give error if `proof(s)` are not verified as valid.
pub fn verify<G, EFqSponge, EFrSponge>(
    group_map: &G::Map,
    verifier_index: &VerifierIndex<G>,
    proof: &ProverProof<G>,
) -> Result<()>
where
    G: KimchiCurve,
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    let proofs = vec![(verifier_index, proof)];
    batch_verify::<G, EFqSponge, EFrSponge>(group_map, &proofs)
}

/// This function verifies the batch of zk-proofs
///     proofs: vector of Plonk proofs
///     index: `VerifierIndex`
///     RETURN: verification status
///
/// # Errors
///
/// Will give error if `srs` of `proof` is invalid or `verify` process fails.
pub fn batch_verify<G, EFqSponge, EFrSponge>(
    group_map: &G::Map,
    proofs: &[(&VerifierIndex<G>, &ProverProof<G>)],
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
    let srs = &proofs[0].0.srs();
    for (index, _) in proofs.iter() {
        if index.srs().g.len() != srs.g.len() {
            return Err(VerifyError::DifferentSRS);
        }

        // also make sure that the SRS is not smaller than the domain size
        if index.srs().max_degree() < index.domain.size() {
            return Err(VerifyError::SRSTooSmall);
        }
    }

    //~ 1. Validate each proof separately following the [partial verification](#partial-verification) steps.
    let mut batch = vec![];
    for (index, proof) in proofs {
        batch.push(to_batch::<G, EFqSponge, EFrSponge>(index, proof)?);
    }

    //~ 1. Use the [`PolyCom.verify`](#polynomial-commitments) to verify the partially evaluated proofs.
    if srs.verify::<EFqSponge, _>(group_map, &mut batch, &mut thread_rng()) {
        Ok(())
    } else {
        Err(VerifyError::OpenProof)
    }
}
