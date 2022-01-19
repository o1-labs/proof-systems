//! This module implements prover's zk-proof primitive.

use crate::{index::Index, plonk_sponge::FrSponge};
use ark_ec::AffineCurve;
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, Evaluations, Polynomial, Radix2EvaluationDomain as D, UVPolynomial,
};
use array_init::array_init;
use commitment_dlog::commitment::{
    b_poly_coefficients, CommitmentCurve, CommitmentField, OpeningProof, PolyComm,
};
use itertools::Itertools;
use kimchi_circuits::{
    expr::{l0_1, Constants, Environment, LookupEnvironment},
    gate::{combine_table_entry, GateType, LookupInfo, LookupsUsed},
    nolookup::constraints::ZK_ROWS,
    nolookup::scalars::{LookupEvaluations, ProofEvaluations},
    polynomials::{chacha, complete_add, endomul_scalar, endosclmul, lookup, poseidon, varbasemul},
    wires::{COLUMNS, PERMUTS},
};
use lookup::CombinedEntry;
use o1_utils::ExtendedDensePolynomial;
use oracle::{rndoracle::ProofError, sponge::ScalarChallenge, FqSponge};
use std::collections::HashMap;

use crate::alphas::{Alphas, ConstraintType};

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

#[derive(Clone)]
pub struct LookupCommitments<G: AffineCurve> {
    pub sorted: Vec<PolyComm<G>>,
    pub aggreg: PolyComm<G>,
}

#[derive(Clone)]
pub struct ProverCommitments<G: AffineCurve> {
    // polynomial commitments
    pub w_comm: [PolyComm<G>; COLUMNS],
    pub z_comm: PolyComm<G>,
    pub t_comm: PolyComm<G>,
    pub lookup: Option<LookupCommitments<G>>,
}

#[derive(Clone)]
pub struct ProverProof<G: AffineCurve> {
    // polynomial commitments
    pub commitments: ProverCommitments<G>,

    // batched commitment opening proof
    pub proof: OpeningProof<G>,

    // polynomial evaluations
    // TODO(mimoo): that really should be a type Evals { z: PE, zw: PE }
    pub evals: [ProofEvaluations<Vec<Fr<G>>>; 2],

    pub ft_eval1: Fr<G>,

    // public part of the witness
    pub public: Vec<Fr<G>>,

    // The challenges underlying the optional polynomials folded into the proof
    pub prev_challenges: Vec<(Vec<Fr<G>>, PolyComm<G>)>,
}

impl<G: CommitmentCurve> ProverProof<G>
where
    G::ScalarField: CommitmentField,
    G::BaseField: PrimeField,
{
    // This function constructs prover's zk-proof from the witness & the Index against SRS instance
    //     witness: computation witness
    //     index: Index
    //     RETURN: prover's zk-proof
    pub fn create<EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>, EFrSponge: FrSponge<Fr<G>>>(
        group_map: &G::Map,
        mut witness: [Vec<Fr<G>>; COLUMNS],
        index: &Index<G>,
        prev_challenges: Vec<(Vec<Fr<G>>, PolyComm<G>)>,
    ) -> Result<Self, ProofError> {
        let d1_size = index.cs.domain.d1.size as usize;
        // TODO: rng should be passed as arg
        let rng = &mut rand::rngs::OsRng;

        // double-check the witness
        if cfg!(test) {
            index.cs.verify(&witness).expect("incorrect witness");
        }

        // ensure we have room for the zero-knowledge rows
        let length_witness = witness[0].len();
        let length_padding = d1_size
            .checked_sub(length_witness)
            .ok_or(ProofError::NoRoomForZkInWitness)?;
        if length_padding < ZK_ROWS as usize {
            return Err(ProofError::NoRoomForZkInWitness);
        }

        // pad and add zero-knowledge rows to the witness columns
        for w in &mut witness {
            if w.len() != length_witness {
                return Err(ProofError::WitnessCsInconsistent);
            }

            // padding
            w.extend(std::iter::repeat(Fr::<G>::zero()).take(length_padding));

            // zk-rows
            for row in w.iter_mut().rev().take(ZK_ROWS as usize) {
                *row = Fr::<G>::rand(rng);
            }
        }

        // the transcript of the random oracle non-interactive argument
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        // compute public input polynomial
        let public = witness[0][0..index.cs.public].to_vec();
        let public_poly = -Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(
            public.clone(),
            index.cs.domain.d1,
        )
        .interpolate();

        // commit to the wire values
        let w_comm: [(PolyComm<G>, PolyComm<Fr<G>>); COLUMNS] = array_init(|i| {
            let e = Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(
                witness[i].clone(),
                index.cs.domain.d1,
            );
            index
                .srs
                .commit_evaluations(index.cs.domain.d1, &e, None, rng)
        });

        // compute witness polynomials
        let witness_poly: [DensePolynomial<Fr<G>>; COLUMNS] = array_init(|i| {
            Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(
                witness[i].clone(),
                index.cs.domain.d1,
            )
            .interpolate()
        });

        // absorb the wire polycommitments into the argument
        fq_sponge.absorb_g(&index.srs.commit_non_hiding(&public_poly, None).unshifted);
        w_comm
            .iter()
            .for_each(|c| fq_sponge.absorb_g(&c.0.unshifted));

        let lookup_info = LookupInfo::<Fr<G>>::create();
        let lookup_used = lookup_info.lookup_used(&index.cs.gates);

        let joint_combiner_ = {
            // TODO: how will the verifier circuit handle these kind of things? same with powers of alpha...
            let s = match lookup_used.as_ref() {
                None | Some(LookupsUsed::Single) => ScalarChallenge(Fr::<G>::zero()),
                Some(LookupsUsed::Joint) => ScalarChallenge(fq_sponge.challenge()),
            };
            (s, s.to_field(&index.srs.endo_r))
        };

        // TODO: that seems like an unecessary line
        let joint_combiner: Fr<G> = joint_combiner_.1;

        // TODO: Looking-up a tuple (f_0, f_1, ..., f_{m-1}) in a tuple of tables (T_0, ..., T_{m-1}) is
        // reduced to a single lookup
        // sum_i joint_combiner^i f_i
        // in the "joint table"
        // sum_i joint_combiner^i T_i
        //
        // We write down all these combined joint lookups in the sorted-lookup
        // table, so `lookup_sorted` ends up being a list of all these combined values.
        //
        // We will commit to the columns of lookup_sorted. For example, the 0th one,
        //
        // as
        //
        // sum_i lookup_sorted[0][i] L_i
        //
        // where L_i is the ith normalized lagrange commitment, and where
        // lookup_sorted[0][i] = sum_j joint_combiner^j f_{0, i, j}
        //
        // for some lookup values f_{0, i, j}
        //
        // Computing it that way is not the best, since for example, in our four-bit xor table,
        // all the individual f_{0, i, j} are only four bits while the combined scalar
        //
        // sum_j joint_combiner^j f_{0, i, j}
        //
        // will (with overwhelming probability) be a basically full width field element.
        //
        // As a result, if the lookup values are smaller, it will be better not to
        // combine the joint lookup values and instead to compute the commitment to
        // lookup_sorted[0][i] (for example) as
        //
        // sum_j joint_combiner^j (sum_i f_{0, i, j} L_i)
        // = sum_i (sum_j joint_combiner^j f_{0, i, j}) L_i
        // = sum_i lookup_sorted[0][i] L_i
        //
        // This should be quite a lot cheaper when the scalars f_{0, i, j} are small.
        // We should try it to see how it is in practice. It would be nice if there
        // were some cheap computation we could run on the lookup values to determine
        // whether we should combine the scalars before the multi-exp or not, like computing
        // their average length or something like that.

        let dummy_lookup_value = {
            let x = match lookup_used.as_ref() {
                None => Fr::<G>::zero(),
                Some(_) => {
                    combine_table_entry(joint_combiner, index.cs.dummy_lookup_values[0].iter())
                }
            };
            CombinedEntry(x)
        };

        let (lookup_sorted, lookup_sorted_coeffs, lookup_sorted_comm, lookup_sorted8) =
            match lookup_used.as_ref() {
                None => (None, None, None, None),
                Some(_) => {
                    let iter_lookup_table = || {
                        (0..d1_size).map(|i| {
                            let row = index.cs.lookup_tables8[0].iter().map(|e| &e.evals[8 * i]);
                            CombinedEntry(combine_table_entry(joint_combiner, row))
                        })
                    };

                    // TODO: Once we switch to committing using lagrange commitments,
                    // `witness` will be consumed when we interpolate, so interpolation will
                    // have to moved below this.
                    let lookup_sorted: Vec<Vec<CombinedEntry<Fr<G>>>> = lookup::sorted(
                        dummy_lookup_value,
                        iter_lookup_table,
                        index.cs.domain.d1,
                        &index.cs.gates,
                        &witness,
                        joint_combiner,
                    )?;

                    let lookup_sorted: Vec<_> = lookup_sorted
                        .into_iter()
                        .map(|chunk| {
                            let v: Vec<_> = chunk.into_iter().map(|x| x.0).collect();
                            lookup::zk_patch(v, index.cs.domain.d1, rng)
                        })
                        .collect();

                    let comm: Vec<_> = lookup_sorted
                        .iter()
                        .map(|v| {
                            index
                                .srs
                                .commit_evaluations(index.cs.domain.d1, v, None, rng)
                        })
                        .collect();
                    let coeffs : Vec<_> =
                        // TODO: We can avoid storing these coefficients.
                        lookup_sorted.iter().map(|e| e.clone().interpolate()).collect();
                    let evals8: Vec<_> = coeffs
                        .iter()
                        .map(|v| v.evaluate_over_domain_by_ref(index.cs.domain.d8))
                        .collect();

                    // absorb lookup polynomials
                    comm.iter().for_each(|c| fq_sponge.absorb_g(&c.0.unshifted));

                    (Some(lookup_sorted), Some(coeffs), Some(comm), Some(evals8))
                }
            };

        // sample beta, gamma oracles
        let beta = fq_sponge.challenge();
        let gamma = fq_sponge.challenge();

        let (lookup_aggreg_coeffs, lookup_aggreg_comm, lookup_aggreg8) =
            // compute lookup aggregation polynomial
            match lookup_sorted {
                None => (None, None, None),
                Some(lookup_sorted) => {
                    let iter_lookup_table = || (0..d1_size).map(|i| {
                        let row = index.cs.lookup_tables8[0].iter().map(|e| & e.evals[8 * i]);
                        combine_table_entry(joint_combiner, row)
                    });

                    let aggreg =
                        lookup::aggregation::<_, Fr<G>, _>(
                            dummy_lookup_value.0,
                            iter_lookup_table(),
                            index.cs.domain.d1,
                            &index.cs.gates,
                            &witness,
                            joint_combiner,
                            beta, gamma,
                            &lookup_sorted,
                            rng)?;

                    drop(lookup_sorted);
                    if aggreg.evals[d1_size - (ZK_ROWS as usize + 1)] != Fr::<G>::one() {
                        panic!("aggregation incorrect: {}", aggreg.evals[d1_size-(ZK_ROWS as usize + 1)]);
                    }

                    let comm = index.srs.commit_evaluations(index.cs.domain.d1, &aggreg, None, rng);
                    fq_sponge.absorb_g(&comm.0.unshifted);

                    let coeffs = aggreg.interpolate();

                    // TODO: There's probably a clever way to expand the domain without
                    // interpolating
                    let evals8 = coeffs.evaluate_over_domain_by_ref(index.cs.domain.d8);
                    (Some(coeffs), Some(comm), Some(evals8))
                },
            };

        // compute permutation aggregation polynomial
        let z_poly = index.cs.perm_aggreg(&witness, &beta, &gamma, rng)?;
        // commit to z
        let z_comm = index.srs.commit(&z_poly, None, rng);

        // absorb the z commitment into the argument and query alpha
        fq_sponge.absorb_g(&z_comm.0.unshifted);
        let alpha_chal = ScalarChallenge(fq_sponge.challenge());
        let alpha = alpha_chal.to_field(&index.srs.endo_r);
        let mut all_alphas = Alphas::new(alpha, &index.powers_of_alpha);

        // evaluate witness and permutation polynomials over domains
        let lagrange = index.cs.evaluate(&witness_poly, &z_poly);

        let lookup_table_combined = lookup_used.as_ref().map(|_| {
            let joint_table = &index.cs.lookup_tables8[0];
            let mut res = joint_table[joint_table.len() - 1].clone();
            for col in joint_table.iter().rev().skip(1) {
                res.evals.iter_mut().for_each(|e| *e *= joint_combiner);
                res += col;
            }
            res
        });

        let lookup_env = lookup_table_combined
            .as_ref()
            .zip(lookup_sorted8.as_ref())
            .zip(lookup_aggreg8.as_ref())
            .map(
                |((lookup_table_combined, lookup_sorted), lookup_aggreg)| LookupEnvironment {
                    aggreg: lookup_aggreg,
                    sorted: lookup_sorted,
                    table: lookup_table_combined,
                    selectors: &index.cs.lookup_selectors,
                },
            );

        let env = {
            let mut index_evals = HashMap::new();
            use GateType::*;
            index_evals.insert(Poseidon, &index.cs.ps8);
            index_evals.insert(CompleteAdd, &index.cs.complete_addl4);
            index_evals.insert(VarBaseMul, &index.cs.mull8);
            index_evals.insert(EndoMul, &index.cs.emull);
            index_evals.insert(EndoMulScalar, &index.cs.endomul_scalar8);
            [ChaCha0, ChaCha1, ChaCha2, ChaChaFinal]
                .iter()
                .enumerate()
                .for_each(|(i, g)| {
                    if let Some(c) = &index.cs.chacha8 {
                        index_evals.insert(*g, &c[i]);
                    }
                });

            Environment {
                constants: Constants {
                    alpha,
                    beta,
                    gamma,
                    joint_combiner,
                    endo_coefficient: index.cs.endo,
                    mds: index.cs.fr_sponge_params.mds.clone(),
                },
                witness: &lagrange.d8.this.w,
                coefficient: &index.cs.coefficients8,
                vanishes_on_last_4_rows: &index.cs.vanishes_on_last_4_rows,
                z: &lagrange.d8.this.z,
                l0_1: l0_1(index.cs.domain.d1),
                domain: index.cs.domain,
                index: index_evals,
                lookup: lookup_env,
            }
        };

        //
        // compute quotient polynomial
        //

        let quotient_poly = {
            // generic
            let alphas = all_alphas.get_alphas(ConstraintType::Gate, 1);
            let mut t4 = index.cs.gnrc_quot(alphas, &lagrange.d4.this.w);

            // subtract the public values
            let public4 = public_poly.evaluate_over_domain_by_ref(index.cs.domain.d4);
            t4 += &public4; // already negated earlier

            if cfg!(test) {
                let (_, res) = t4
                    .clone()
                    .interpolate()
                    .divide_by_vanishing_poly(index.cs.domain.d1)
                    .unwrap();
                assert!(res.is_zero());
            }

            // complete addition
            let alphas = all_alphas.get_powers(ConstraintType::Gate, 7);
            let add_constraint = complete_add::constraint(alphas);
            let add4 = add_constraint.evaluations(&env);
            t4 += &add4;

            if cfg!(test) {
                let (_, res) = add4
                    .clone()
                    .interpolate()
                    .divide_by_vanishing_poly(index.cs.domain.d1)
                    .unwrap();
                assert!(res.is_zero());
            }

            drop(add4);

            // permutation
            let alphas = all_alphas.get_alphas(ConstraintType::Permutation, 3);
            let (perm, bnd) = index
                .cs
                .perm_quot(&lagrange, beta, gamma, &z_poly, alphas)?;
            let mut t8 = perm;

            if cfg!(test) {
                let (_, res) = t8
                    .clone()
                    .interpolate()
                    .divide_by_vanishing_poly(index.cs.domain.d1)
                    .unwrap();
                assert!(res.is_zero());
            }

            // scalar multiplication
            let alphas = all_alphas.get_powers(ConstraintType::Gate, 21);
            let mul8 = varbasemul::constraint(alphas).evaluations(&env);
            t8 += &mul8;

            if cfg!(test) {
                let (_, res) = mul8
                    .clone()
                    .interpolate()
                    .divide_by_vanishing_poly(index.cs.domain.d1)
                    .unwrap();
                assert!(res.is_zero());
            }

            drop(mul8);

            // endoscaling
            let alphas = all_alphas.get_powers(ConstraintType::Gate, 11);
            let emul8 = endosclmul::constraint(alphas).evaluations(&env);
            t8 += &emul8;

            if cfg!(test) {
                let (_, res) = emul8
                    .clone()
                    .interpolate()
                    .divide_by_vanishing_poly(index.cs.domain.d1)
                    .unwrap();
                assert!(res.is_zero());
            }

            drop(emul8);

            // endoscaling scalar computation
            let alphas = all_alphas.get_powers(ConstraintType::Gate, 11);
            let emulscalar8 = endomul_scalar::constraint(alphas).evaluations(&env);
            t8 += &emulscalar8;

            if cfg!(test) {
                let (_, res) = emulscalar8
                    .clone()
                    .interpolate()
                    .divide_by_vanishing_poly(index.cs.domain.d1)
                    .unwrap();
                assert!(res.is_zero());
            }

            drop(emulscalar8);

            // poseidon
            let alphas = all_alphas.get_powers(ConstraintType::Gate, 15);
            let pos8 = poseidon::constraint(alphas).evaluations(&env);
            t8 += &pos8;

            if cfg!(test) {
                let (_, res) = pos8
                    .clone()
                    .interpolate()
                    .divide_by_vanishing_poly(index.cs.domain.d1)
                    .unwrap();
                assert!(res.is_zero());
            }

            drop(pos8);

            // chacha
            if index.cs.chacha8.as_ref().is_some() {
                let alphas = all_alphas.get_powers(ConstraintType::Gate, 5);
                let chacha0 = chacha::constraint_chacha0(alphas).evaluations(&env);
                t4 += &chacha0;

                let alphas = all_alphas.get_powers(ConstraintType::Gate, 5);
                let chacha1 = chacha::constraint_chacha1(alphas).evaluations(&env);
                t4 += &chacha1;

                let alphas = all_alphas.get_powers(ConstraintType::Gate, 5);
                let chacha2 = chacha::constraint_chacha2(alphas).evaluations(&env);
                t4 += &chacha2;

                let alphas = all_alphas.get_powers(ConstraintType::Gate, 9);
                let chacha_final = chacha::constraint_chacha_final(alphas).evaluations(&env);
                t4 += &chacha_final;

                if cfg!(test) {
                    let (_, res) = chacha0
                        .clone()
                        .interpolate()
                        .divide_by_vanishing_poly(index.cs.domain.d1)
                        .unwrap();
                    assert!(res.is_zero());

                    let (_, res) = chacha1
                        .clone()
                        .interpolate()
                        .divide_by_vanishing_poly(index.cs.domain.d1)
                        .unwrap();
                    assert!(res.is_zero());

                    let (_, res) = chacha2
                        .clone()
                        .interpolate()
                        .divide_by_vanishing_poly(index.cs.domain.d1)
                        .unwrap();
                    assert!(res.is_zero());

                    let (_, res) = chacha_final
                        .clone()
                        .interpolate()
                        .divide_by_vanishing_poly(index.cs.domain.d1)
                        .unwrap();
                    assert!(res.is_zero());
                }

                drop(chacha0);
                drop(chacha1);
                drop(chacha2);
                drop(chacha_final);
            }

            // lookup
            if lookup_used.is_some() {
                let lookup_alphas = all_alphas.get_alphas(ConstraintType::Lookup, 7);
                let evals: Vec<Evaluations<Fr<G>, D<Fr<G>>>> =
                    lookup::constraints(&index.cs.dummy_lookup_values[0], index.cs.domain.d1)
                        .iter()
                        .map(|e| e.evaluations(&env))
                        .collect();
                for (mut e, alpha_pow) in evals.into_iter().zip_eq(lookup_alphas) {
                    e.evals.iter_mut().for_each(|x| *x *= alpha_pow);
                    if e.domain().size == t4.domain().size {
                        t4 += &e;
                    } else if e.domain().size == t8.domain().size {
                        t8 += &e;
                    } else {
                        panic!("Bad evaluation")
                    }
                }
            }

            // divide contributions with vanishing polynomial
            let f = t4.interpolate() + t8.interpolate();
            let (mut quotient, res) = f
                .divide_by_vanishing_poly(index.cs.domain.d1)
                .ok_or(ProofError::PolyDivision)?;
            if !res.is_zero() {
                return Err(ProofError::PolyDivision);
            }

            quotient += &bnd; // already divided by Z_H
            quotient
        };

        // commit to t
        let t_comm = {
            let (mut t_comm, mut omega_t) = index.srs.commit(&quotient_poly, None, rng);

            let expected_t_size = PERMUTS;
            let dummies = expected_t_size - t_comm.unshifted.len();
            // Add `dummies` many hiding commitments to the 0 polynomial, since if the
            // number of commitments in `t_comm` is less than the max size, it means that
            // the higher degree coefficients of `t` are 0.
            for _ in 0..dummies {
                use ark_ec::ProjectiveCurve;
                let w = Fr::<G>::rand(rng);
                t_comm.unshifted.push(index.srs.h.mul(w).into_affine());
                omega_t.unshifted.push(w);
            }
            (t_comm, omega_t)
        };

        // absorb the polycommitments into the argument and sample zeta
        fq_sponge.absorb_g(&t_comm.0.unshifted);

        let zeta_chal = ScalarChallenge(fq_sponge.challenge());
        let zeta = zeta_chal.to_field(&index.srs.endo_r);
        let omega = index.cs.domain.d1.group_gen;
        let zeta_omega = zeta * omega;

        let lookup_evals = |e: Fr<G>| {
            lookup_aggreg_coeffs
                .as_ref()
                .zip(lookup_sorted_coeffs.as_ref())
                .map(|(aggreg, sorted)| LookupEvaluations {
                    aggreg: aggreg.eval(e, index.max_poly_size),
                    sorted: sorted
                        .iter()
                        .map(|c| c.eval(e, index.max_poly_size))
                        .collect(),
                    table: index.cs.lookup_tables[0]
                        .iter()
                        .map(|p| p.eval(e, index.max_poly_size))
                        .rev()
                        .fold(vec![Fr::<G>::zero()], |acc, x| {
                            acc.into_iter()
                                .zip(x.iter())
                                .map(|(acc, x)| acc * joint_combiner + x)
                                .collect()
                        }),
                })
        };

        // evaluate the polynomials
        let chunked_evals_zeta = ProofEvaluations::<Vec<Fr<G>>> {
            s: array_init(|i| index.cs.sigmam[0..PERMUTS - 1][i].eval(zeta, index.max_poly_size)),
            w: array_init(|i| witness_poly[i].eval(zeta, index.max_poly_size)),
            z: z_poly.eval(zeta, index.max_poly_size),
            lookup: lookup_evals(zeta),
            generic_selector: index.cs.genericm.eval(zeta, index.max_poly_size),
            poseidon_selector: index.cs.psm.eval(zeta, index.max_poly_size),
        };
        let chunked_evals_zeta_omega = ProofEvaluations::<Vec<Fr<G>>> {
            s: array_init(|i| {
                index.cs.sigmam[0..PERMUTS - 1][i].eval(zeta_omega, index.max_poly_size)
            }),
            w: array_init(|i| witness_poly[i].eval(zeta_omega, index.max_poly_size)),
            z: z_poly.eval(zeta_omega, index.max_poly_size),
            lookup: lookup_evals(zeta_omega),
            generic_selector: index.cs.genericm.eval(zeta_omega, index.max_poly_size),
            poseidon_selector: index.cs.psm.eval(zeta_omega, index.max_poly_size),
        };

        drop(lookup_aggreg_coeffs);
        drop(lookup_sorted_coeffs);

        let chunked_evals = [chunked_evals_zeta, chunked_evals_zeta_omega];

        let zeta_to_srs_len = zeta.pow(&[index.max_poly_size as u64]);
        let zeta_omega_to_srs_len = zeta.pow(&[index.max_poly_size as u64]);

        let zeta_to_domain_size = zeta.pow(&[d1_size as u64]);

        // normal evaluations
        let power_of_eval_points_for_chunks = [zeta_to_srs_len, zeta_omega_to_srs_len];
        let evals = &chunked_evals
            .iter()
            .zip(power_of_eval_points_for_chunks.iter())
            .map(|(es, &e1)| ProofEvaluations::<Fr<G>> {
                s: array_init(|i| DensePolynomial::eval_polynomial(&es.s[i], e1)),
                w: array_init(|i| DensePolynomial::eval_polynomial(&es.w[i], e1)),
                z: DensePolynomial::eval_polynomial(&es.z, e1),
                lookup: es.lookup.as_ref().map(|l| LookupEvaluations {
                    table: DensePolynomial::eval_polynomial(&l.table, e1),
                    aggreg: DensePolynomial::eval_polynomial(&l.aggreg, e1),
                    sorted: l
                        .sorted
                        .iter()
                        .map(|p| DensePolynomial::eval_polynomial(p, e1))
                        .collect(),
                }),
                generic_selector: DensePolynomial::eval_polynomial(&es.generic_selector, e1),
                poseidon_selector: DensePolynomial::eval_polynomial(&es.poseidon_selector, e1),
            })
            .collect::<Vec<_>>();

        // compute and evaluate linearization polynomial
        let f_chunked = {
            // TODO: compute the linearization polynomial in evaluation form so
            // that we can drop the coefficient forms of the index polynomials from
            // the constraint system struct

            // generic
            let alphas = all_alphas.get_alphas(ConstraintType::Gate, 1);
            let mut f = index
                .cs
                .gnrc_lnrz(alphas, &evals[0].w, evals[0].generic_selector)
                .interpolate();

            // permutation
            let alphas = all_alphas.get_alphas(ConstraintType::Permutation, 3);
            f += &index.cs.perm_lnrz(evals, zeta, beta, gamma, alphas);

            let f = {
                let (_lin_constant, lin) = index.linearization.to_polynomial(&env, zeta, evals);
                f + lin
            };

            drop(env);
            drop(lookup_sorted8);
            drop(lookup_aggreg8);
            drop(lookup_table_combined);

            f.chunk_polynomial(zeta_to_srs_len, index.max_poly_size)
        };

        let t_chunked = quotient_poly.chunk_polynomial(zeta_to_srs_len, index.max_poly_size);

        let ft: DensePolynomial<Fr<G>> =
            &f_chunked - &t_chunked.scale(zeta_to_domain_size - Fr::<G>::one());
        let ft_eval1 = ft.evaluate(&zeta_omega);

        let fq_sponge_before_evaluations = fq_sponge.clone();
        let mut fr_sponge = {
            let mut s = EFrSponge::new(index.cs.fr_sponge_params.clone());
            s.absorb(&fq_sponge.digest());
            s
        };
        let p_eval = if public_poly.is_zero() {
            [Vec::new(), Vec::new()]
        } else {
            [
                vec![public_poly.evaluate(&zeta)],
                vec![public_poly.evaluate(&zeta_omega)],
            ]
        };
        for i in 0..2 {
            fr_sponge.absorb_evaluations(&p_eval[i], &chunked_evals[i])
        }
        fr_sponge.absorb(&ft_eval1);

        // query opening scaler challenges
        let v_chal = fr_sponge.challenge();
        let v = v_chal.to_field(&index.srs.endo_r);
        let u_chal = fr_sponge.challenge();
        let u = u_chal.to_field(&index.srs.endo_r);

        // construct the proof
        // --------------------------------------------------------------------
        let polys = prev_challenges
            .iter()
            .map(|(chals, comm)| {
                (
                    DensePolynomial::from_coefficients_vec(b_poly_coefficients(chals)),
                    comm.unshifted.len(),
                )
            })
            .collect::<Vec<_>>();
        let non_hiding = |d1_size: usize| PolyComm {
            unshifted: vec![Fr::<G>::zero(); d1_size],
            shifted: None,
        };

        // construct the blinding part of the ft polynomial for Maller's optimization
        // (see https://o1-labs.github.io/mina-book/crypto/plonk/maller_15.html)
        let blinding_ft = {
            let blinding_t = t_comm.1.chunk_blinding(zeta_to_srs_len);
            let blinding_f = Fr::<G>::zero();

            PolyComm {
                // blinding_f - Z_H(zeta) * blinding_t
                unshifted: vec![blinding_f - (zeta_to_domain_size - Fr::<G>::one()) * blinding_t],
                shifted: None,
            }
        };

        // construct evaluation proof
        let mut polynomials = polys
            .iter()
            .map(|(p, d1_size)| (p, None, non_hiding(*d1_size)))
            .collect::<Vec<_>>();
        polynomials.extend(vec![(&public_poly, None, non_hiding(1))]);
        polynomials.extend(vec![(&ft, None, blinding_ft)]);
        polynomials.extend(vec![(&z_poly, None, z_comm.1)]);
        polynomials.extend(vec![(&index.cs.genericm, None, non_hiding(1))]);
        polynomials.extend(vec![(&index.cs.psm, None, non_hiding(1))]);
        polynomials.extend(
            witness_poly
                .iter()
                .zip(w_comm.iter())
                .map(|(w, c)| (w, None, c.1.clone()))
                .collect::<Vec<_>>(),
        );
        polynomials.extend(
            index.cs.sigmam[0..PERMUTS - 1]
                .iter()
                .map(|w| (w, None, non_hiding(1)))
                .collect::<Vec<_>>(),
        );

        Ok(Self {
            commitments: ProverCommitments {
                w_comm: array_init(|i| w_comm[i].0.clone()),
                z_comm: z_comm.0,
                t_comm: t_comm.0,
                lookup: lookup_aggreg_comm.zip(lookup_sorted_comm).map(|(a, s)| {
                    LookupCommitments {
                        aggreg: a.0,
                        sorted: s.iter().map(|(x, _)| x.clone()).collect(),
                    }
                }),
            },
            proof: index.srs.open(
                group_map,
                &polynomials,
                &[zeta, zeta_omega],
                v,
                u,
                fq_sponge_before_evaluations,
                rng,
            ),
            evals: chunked_evals,
            ft_eval1,
            public,
            prev_challenges,
        })
    }
}

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use commitment_dlog::commitment::caml::{CamlOpeningProof, CamlPolyComm};
    use kimchi_circuits::nolookup::scalars::caml::CamlProofEvaluations;

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlProverProof<CamlG, CamlF> {
        pub commitments: CamlProverCommitments<CamlG>,
        pub proof: CamlOpeningProof<CamlG, CamlF>,
        // OCaml doesn't have sized arrays, so we have to convert to a tuple..
        pub evals: (CamlProofEvaluations<CamlF>, CamlProofEvaluations<CamlF>),
        pub ft_eval1: CamlF,
        pub public: Vec<CamlF>,
        pub prev_challenges: Vec<(Vec<CamlF>, CamlPolyComm<CamlG>)>,
    }

    #[derive(Clone, ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlProverCommitments<CamlG> {
        // polynomial commitments
        pub w_comm: (
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
        ),
        pub z_comm: CamlPolyComm<CamlG>,
        pub t_comm: CamlPolyComm<CamlG>,
    }

    // These implementations are handy for conversions such as:
    // InternalType <-> Ocaml::Value
    //
    // It does this by hiding the required middle conversion step:
    // InternalType <-> CamlInternalType <-> Ocaml::Value
    //
    // Note that some conversions are not always possible to shorten,
    // because we don't always know how to convert the types.
    // For example, to implement the conversion
    // ProverCommitments<G> -> CamlProverCommitments<CamlG>
    // we need to know how to convert G to CamlG.
    // we don't know that information, unless we implemented some trait (e.g. ToCaml)
    // we can do that, but instead we implemented the From trait for the reverse operations (From<G> for CamlG).
    // it reduces the complexity, but forces us to do the conversion in two phases instead of one.

    //
    // CamlProverCommitments<CamlG> <-> ProverCommitments<G>
    //

    impl<G, CamlG> From<ProverCommitments<G>> for CamlProverCommitments<CamlG>
    where
        G: AffineCurve,
        CamlPolyComm<CamlG>: From<PolyComm<G>>,
    {
        fn from(prover_comm: ProverCommitments<G>) -> Self {
            let [w_comm0, w_comm1, w_comm2, w_comm3, w_comm4, w_comm5, w_comm6, w_comm7, w_comm8, w_comm9, w_comm10, w_comm11, w_comm12, w_comm13, w_comm14] =
                prover_comm.w_comm;
            Self {
                w_comm: (
                    w_comm0.into(),
                    w_comm1.into(),
                    w_comm2.into(),
                    w_comm3.into(),
                    w_comm4.into(),
                    w_comm5.into(),
                    w_comm6.into(),
                    w_comm7.into(),
                    w_comm8.into(),
                    w_comm9.into(),
                    w_comm10.into(),
                    w_comm11.into(),
                    w_comm12.into(),
                    w_comm13.into(),
                    w_comm14.into(),
                ),
                z_comm: prover_comm.z_comm.into(),
                t_comm: prover_comm.t_comm.into(),
            }
        }
    }

    impl<G, CamlG> From<CamlProverCommitments<CamlG>> for ProverCommitments<G>
    where
        G: AffineCurve,
        PolyComm<G>: From<CamlPolyComm<CamlG>>,
    {
        fn from(caml_prover_comm: CamlProverCommitments<CamlG>) -> ProverCommitments<G> {
            let (
                w_comm0,
                w_comm1,
                w_comm2,
                w_comm3,
                w_comm4,
                w_comm5,
                w_comm6,
                w_comm7,
                w_comm8,
                w_comm9,
                w_comm10,
                w_comm11,
                w_comm12,
                w_comm13,
                w_comm14,
            ) = caml_prover_comm.w_comm;
            ProverCommitments {
                w_comm: [
                    w_comm0.into(),
                    w_comm1.into(),
                    w_comm2.into(),
                    w_comm3.into(),
                    w_comm4.into(),
                    w_comm5.into(),
                    w_comm6.into(),
                    w_comm7.into(),
                    w_comm8.into(),
                    w_comm9.into(),
                    w_comm10.into(),
                    w_comm11.into(),
                    w_comm12.into(),
                    w_comm13.into(),
                    w_comm14.into(),
                ],
                z_comm: caml_prover_comm.z_comm.into(),
                t_comm: caml_prover_comm.t_comm.into(),
                lookup: None,
            }
        }
    }

    //
    // ProverProof<G> <-> CamlProverProof<CamlG, CamlF>
    //

    impl<G, CamlG, CamlF> From<ProverProof<G>> for CamlProverProof<CamlG, CamlF>
    where
        G: AffineCurve,
        CamlG: From<G>,
        CamlF: From<G::ScalarField>,
    {
        fn from(pp: ProverProof<G>) -> Self {
            Self {
                commitments: pp.commitments.into(),
                proof: pp.proof.into(),
                evals: (pp.evals[0].clone().into(), pp.evals[1].clone().into()),
                ft_eval1: pp.ft_eval1.into(),
                public: pp.public.into_iter().map(Into::into).collect(),
                prev_challenges: pp
                    .prev_challenges
                    .into_iter()
                    .map(|(v, c)| {
                        let v = v.into_iter().map(Into::into).collect();
                        (v, c.into())
                    })
                    .collect(),
            }
        }
    }

    impl<G, CamlG, CamlF> From<CamlProverProof<CamlG, CamlF>> for ProverProof<G>
    where
        G: AffineCurve + From<CamlG>,
        G::ScalarField: From<CamlF>,
    {
        fn from(caml_pp: CamlProverProof<CamlG, CamlF>) -> ProverProof<G> {
            ProverProof {
                commitments: caml_pp.commitments.into(),
                proof: caml_pp.proof.into(),
                evals: [caml_pp.evals.0.into(), caml_pp.evals.1.into()],
                ft_eval1: caml_pp.ft_eval1.into(),
                public: caml_pp.public.into_iter().map(Into::into).collect(),
                prev_challenges: caml_pp
                    .prev_challenges
                    .into_iter()
                    .map(|(v, c)| {
                        let v = v.into_iter().map(Into::into).collect();
                        (v, c.into())
                    })
                    .collect(),
            }
        }
    }
}
