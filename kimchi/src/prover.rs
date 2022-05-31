//! This module implements prover's zk-proof primitive.

use crate::{
    circuits::{
        argument::{Argument, ArgumentType},
        expr::{l0_1, Constants, Environment, LookupEnvironment},
        gate::GateType,
        lookup::{
            self, lookups::LookupsUsed, runtime_tables::RuntimeTable, tables::combine_table_entry,
        },
        polynomials::{
            chacha::{ChaCha0, ChaCha1, ChaCha2, ChaChaFinal},
            complete_add::CompleteAdd,
            endomul_scalar::EndomulScalar,
            endosclmul::EndosclMul,
            generic, permutation,
            permutation::ZK_ROWS,
            poseidon::Poseidon,
            range_check,
            varbasemul::VarbaseMul,
        },
        wires::{COLUMNS, PERMUTS},
    },
    error::ProverError,
    plonk_sponge::FrSponge,
    proof::{
        LookupCommitments, LookupEvaluations, ProofEvaluations, ProverCommitments, ProverProof,
    },
    prover_index::ProverIndex,
};
use ark_ff::{FftField, Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain as D, UVPolynomial,
};
use array_init::array_init;
use commitment_dlog::commitment::{b_poly_coefficients, CommitmentCurve, PolyComm};
use itertools::Itertools;
use o1_utils::{types::fields::*, ExtendedDensePolynomial as _};
use oracle::{sponge::ScalarChallenge, FqSponge};
use std::collections::HashMap;

/// The result of a proof creation or verification.
type Result<T> = std::result::Result<T, ProverError>;

/// Helper to quickly test if a witness satisfies a constraint
macro_rules! check_constraint {
    ($index:expr, $evaluation:expr) => {{
        check_constraint!($index, stringify!($evaluation), $evaluation);
    }};
    ($index:expr, $label:expr, $evaluation:expr) => {{
        if cfg!(debug_assertions) {
            let (_, res) = $evaluation
                .interpolate_by_ref()
                .divide_by_vanishing_poly($index.cs.domain.d1)
                .unwrap();
            if !res.is_zero() {
                panic!("couldn't divide by vanishing polynomial: {}", $label);
            }
        }
    }};
}

/// Contains variables needed for lookup in the prover algorithm.
#[derive(Default)]
struct LookupContext<G, F>
where
    G: CommitmentCurve,
    F: FftField,
{
    /// The joint combiner used to join the columns of lookup tables
    joint_combiner: Option<F>,

    /// The power of the joint_combiner that can be used to add a table_id column
    /// to the concatenated lookup tables.
    table_id_combiner: Option<F>,

    /// The combined lookup entry that can be used as dummy value
    dummy_lookup_value: Option<F>,

    /// The combined lookup table
    joint_lookup_table: Option<DensePolynomial<F>>,
    joint_lookup_table_d8: Option<Evaluations<F, D<F>>>,

    /// The sorted polynomials `s` in different forms
    sorted: Option<Vec<Evaluations<F, D<F>>>>,
    sorted_coeffs: Option<Vec<DensePolynomial<F>>>,
    sorted_comms: Option<Vec<(PolyComm<G>, PolyComm<F>)>>,
    sorted8: Option<Vec<Evaluations<F, D<F>>>>,

    /// The aggregation polynomial in different forms
    aggreg_coeffs: Option<DensePolynomial<F>>,
    aggreg_comm: Option<(PolyComm<G>, PolyComm<F>)>,
    aggreg8: Option<Evaluations<F, D<F>>>,

    /// The evaluations of the aggregation polynomial for the proof
    eval_zeta: Option<LookupEvaluations<Vec<F>>>,
    eval_zeta_omega: Option<LookupEvaluations<Vec<F>>>,

    /// Runtime table
    runtime_table: Option<DensePolynomial<F>>,
    runtime_table_d8: Option<Evaluations<F, D<F>>>,
    runtime_table_comm: Option<(PolyComm<G>, PolyComm<ScalarField<G>>)>,
    runtime_second_col_d8: Option<Evaluations<F, D<F>>>,
}

impl<G: CommitmentCurve> ProverProof<G>
where
    G::BaseField: PrimeField,
{
    /// This function constructs prover's zk-proof from the witness & the ProverIndex against SRS instance
    pub fn create<
        EFqSponge: Clone + FqSponge<BaseField<G>, G, ScalarField<G>>,
        EFrSponge: FrSponge<ScalarField<G>>,
    >(
        groupmap: &G::Map,
        witness: [Vec<ScalarField<G>>; COLUMNS],
        runtime_tables: &[RuntimeTable<ScalarField<G>>],
        index: &ProverIndex<G>,
    ) -> Result<Self> {
        Self::create_recursive::<EFqSponge, EFrSponge>(
            groupmap,
            witness,
            runtime_tables,
            index,
            Vec::new(),
        )
    }

    /// This function constructs prover's recursive zk-proof from the witness & the ProverIndex against SRS instance
    pub fn create_recursive<
        EFqSponge: Clone + FqSponge<BaseField<G>, G, ScalarField<G>>,
        EFrSponge: FrSponge<ScalarField<G>>,
    >(
        group_map: &G::Map,
        mut witness: [Vec<ScalarField<G>>; COLUMNS],
        runtime_tables: &[RuntimeTable<ScalarField<G>>],
        index: &ProverIndex<G>,
        prev_challenges: Vec<(Vec<ScalarField<G>>, PolyComm<G>)>,
    ) -> Result<Self> {
        // make sure that the SRS is not smaller than the domain size
        let d1_size = index.cs.domain.d1.size();
        if index.srs.max_degree() < d1_size {
            return Err(ProverError::SRSTooSmall);
        }

        // TODO: rng should be passed as arg
        let rng = &mut rand::rngs::OsRng;

        // double-check the witness
        if cfg!(test) {
            let public = witness[0][0..index.cs.public].to_vec();
            index
                .cs
                .verify(&witness, &public)
                .expect("incorrect witness");
        }

        //~ 1. Ensure we have room in the witness for the zero-knowledge rows.
        //~    We currently expect the witness not to be of the same length as the domain,
        //~    but instead be of the length of the (smaller) circuit.
        //~    If we cannot add `ZK_ROWS` rows to the columns of the witness before reaching
        //~    the size of the domain, abort.
        let length_witness = witness[0].len();
        let length_padding = d1_size
            .checked_sub(length_witness)
            .ok_or(ProverError::NoRoomForZkInWitness)?;
        if length_padding < ZK_ROWS as usize {
            return Err(ProverError::NoRoomForZkInWitness);
        }

        //~ 1. Pad the witness columns with Zero gates to make them the same length as the domain.
        //~    Then, randomize the last `ZK_ROWS` of each columns.
        for w in &mut witness {
            if w.len() != length_witness {
                return Err(ProverError::WitnessCsInconsistent);
            }

            // padding
            w.extend(std::iter::repeat(ScalarField::<G>::zero()).take(length_padding));

            // zk-rows
            for row in w.iter_mut().rev().take(ZK_ROWS as usize) {
                *row = <ScalarField<G> as UniformRand>::rand(rng);
            }
        }

        //~ 1. Setup the Fq-Sponge.
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        //~ 1. Compute the negated public input polynomial as
        //~    the polynomial that evaluates to $-p_i$ for the first `public_input_size` values of the domain,
        //~    and $0$ for the rest.
        let public = witness[0][0..index.cs.public].to_vec();
        let public_poly = -Evaluations::<ScalarField<G>, D<ScalarField<G>>>::from_vec_and_domain(
            public.clone(),
            index.cs.domain.d1,
        )
        .interpolate();

        //~ 1. Commit (non-hiding) to the negated public input polynomial.
        let public_comm = index.srs.commit_non_hiding(&public_poly, None);

        //~ 1. Absorb the commitment to the public polynomial with the Fq-Sponge.
        //~
        //~    Note: unlike the original PLONK protocol,
        //~    the prover also provides evaluations of the public polynomial to help the verifier circuit.
        //~    This is why we need to absorb the commitment to the public polynomial at this point.
        fq_sponge.absorb_g(&public_comm.unshifted);

        //~ 1. Commit to the witness columns by creating `COLUMNS` hidding commitments.
        //~
        //~    Note: since the witness is in evaluation form,
        //~    we can use the `commit_evaluation` optimization.
        let w_comm: [(PolyComm<G>, PolyComm<ScalarField<G>>); COLUMNS] = array_init(|i| {
            let e = Evaluations::<ScalarField<G>, D<ScalarField<G>>>::from_vec_and_domain(
                witness[i].clone(),
                index.cs.domain.d1,
            );
            index
                .srs
                .commit_evaluations(index.cs.domain.d1, &e, None, rng)
        });

        //~ 1. Absorb the witness commitments with the Fq-Sponge.
        w_comm
            .iter()
            .for_each(|c| fq_sponge.absorb_g(&c.0.unshifted));

        //~ 1. Compute the witness polynomials by interpolating each `COLUMNS` of the witness.
        //~    TODO: why not do this first, and then commit? Why commit from evaluation directly?
        let witness_poly: [DensePolynomial<ScalarField<G>>; COLUMNS] = array_init(|i| {
            Evaluations::<ScalarField<G>, D<ScalarField<G>>>::from_vec_and_domain(
                witness[i].clone(),
                index.cs.domain.d1,
            )
            .interpolate()
        });

        let mut lookup_context = LookupContext::default();

        //~ 1. If using lookup:
        if let Some(lcs) = &index.cs.lookup_constraint_system {
            // if using runtime table
            if let Some(cfg_runtime_tables) = &lcs.configuration.runtime_tables {
                // check that all the provided runtime tables have length and IDs that match the runtime table configuration of the index
                // we expect the given runtime tables to be sorted as configured, this makes it easier afterwards
                let expected_runtime: Vec<_> = cfg_runtime_tables
                    .iter()
                    .map(|rt| (rt.id, rt.len))
                    .collect();
                let runtime: Vec<_> = runtime_tables
                    .iter()
                    .map(|rt| (rt.id, rt.data.len()))
                    .collect();
                if expected_runtime != runtime {
                    return Err(ProverError::RuntimeTablesInconsistent);
                }

                // calculate the contribution to the second column of the lookup table
                // (the runtime vector)
                let (runtime_table_contribution, runtime_table_contribution_d8) = {
                    let mut offset = lcs
                        .configuration
                        .runtime_table_offset
                        .expect("runtime configuration missing offset");

                    let mut evals = vec![ScalarField::<G>::zero(); d1_size];
                    for rt in runtime_tables {
                        let range = offset..(offset + rt.data.len());
                        evals[range].copy_from_slice(&rt.data);
                        offset += rt.data.len();
                    }

                    // zero-knowledge
                    for e in evals.iter_mut().rev().take(ZK_ROWS as usize) {
                        *e = <ScalarField<G> as UniformRand>::rand(rng);
                    }

                    // get coeff and evaluation form
                    let runtime_table_contribution =
                        Evaluations::from_vec_and_domain(evals, index.cs.domain.d1).interpolate();

                    let runtime_table_contribution_d8 =
                        runtime_table_contribution.evaluate_over_domain_by_ref(index.cs.domain.d8);

                    (runtime_table_contribution, runtime_table_contribution_d8)
                };

                // commit the runtime polynomial
                // (and save it to the proof)
                let runtime_table_comm = index.srs.commit(&runtime_table_contribution, None, rng);

                // absorb the commitment
                fq_sponge.absorb_g(&runtime_table_comm.0.unshifted);

                // pre-compute the updated second column of the lookup table
                let mut second_column_d8 = runtime_table_contribution_d8.clone();
                for (row, e) in second_column_d8.evals.iter_mut().enumerate() {
                    *e += lcs.lookup_table8[1][row];
                }

                lookup_context.runtime_table = Some(runtime_table_contribution);
                lookup_context.runtime_table_d8 = Some(runtime_table_contribution_d8);
                lookup_context.runtime_table_comm = Some(runtime_table_comm);
                lookup_context.runtime_second_col_d8 = Some(second_column_d8);
            }

            //~~ - If queries involve a lookup table with multiple columns
            //~~   then squeeze the Fq-Sponge to obtain the joint combiner challenge $j'$,
            //~~   otherwise set the joint combiner challenge $j'$ to $0$.
            let joint_lookup_used = matches!(lcs.configuration.lookup_used, LookupsUsed::Joint);

            let joint_combiner = if joint_lookup_used {
                fq_sponge.challenge()
            } else {
                ScalarField::<G>::zero()
            };

            //~~ - Derive the scalar joint combiner $j$ from $j'$ using the endomorphism (TOOD: specify)
            let joint_combiner: ScalarField<G> =
                ScalarChallenge(joint_combiner).to_field(&index.srs.endo_r);

            //~~ - If multiple lookup tables are involved,
            //~~   set the `table_id_combiner` as the $j^i$ with $i$ the maximum width of any used table.
            //~~   Essentially, this is to add a last column of table ids to the concatenated lookup tables.
            let table_id_combiner: ScalarField<G> = if lcs.table_ids8.as_ref().is_some() {
                joint_combiner.pow([lcs.configuration.max_joint_size as u64])
            } else {
                // TODO: just set this to None in case multiple tables are not used
                ScalarField::<G>::zero()
            };
            lookup_context.table_id_combiner = Some(table_id_combiner);

            //~~ - Compute the dummy lookup value as the combination of the last entry of the XOR table (so `(0, 0, 0)`).
            //~~   Warning: This assumes that we always use the XOR table when using lookups.
            let dummy_lookup_value = lcs
                .configuration
                .dummy_lookup
                .evaluate(&joint_combiner, &table_id_combiner);
            lookup_context.dummy_lookup_value = Some(dummy_lookup_value);

            //~~ - Compute the lookup table values as the combination of the lookup table entries.
            let joint_lookup_table_d8 = {
                let mut evals = Vec::with_capacity(d1_size);

                for idx in 0..(d1_size * 8) {
                    let table_id = match lcs.table_ids8.as_ref() {
                        Some(table_ids8) => table_ids8.evals[idx],
                        None =>
                        // If there is no `table_ids8` in the constraint system,
                        // every table ID is identically 0.
                        {
                            ScalarField::<G>::zero()
                        }
                    };

                    let combined_entry = if lcs.configuration.runtime_tables.is_none() {
                        let table_row = lcs.lookup_table8.iter().map(|e| &e.evals[idx]);

                        combine_table_entry(
                            &joint_combiner,
                            &table_id_combiner,
                            table_row,
                            &table_id,
                        )
                    } else {
                        // if runtime table are used, the second row is modified
                        let second_col = lookup_context.runtime_second_col_d8.as_ref().unwrap();

                        let table_row = lcs.lookup_table8.iter().enumerate().map(|(col, e)| {
                            if col == 1 {
                                &second_col.evals[idx]
                            } else {
                                &e.evals[idx]
                            }
                        });

                        combine_table_entry(
                            &joint_combiner,
                            &table_id_combiner,
                            table_row,
                            &table_id,
                        )
                    };
                    evals.push(combined_entry);
                }

                Evaluations::from_vec_and_domain(evals, index.cs.domain.d8)
            };

            let joint_lookup_table = joint_lookup_table_d8.interpolate_by_ref();

            //~~ - Compute the sorted evaluations.
            // TODO: Once we switch to committing using lagrange commitments,
            // `witness` will be consumed when we interpolate, so interpolation will
            // have to moved below this.
            let sorted: Vec<_> = lookup::constraints::sorted(
                dummy_lookup_value,
                &joint_lookup_table_d8,
                index.cs.domain.d1,
                &index.cs.gates,
                &witness,
                joint_combiner,
                table_id_combiner,
            )?;

            //~~ - Randomize the last `EVALS` rows in each of the sorted polynomials
            //~~   in order to add zero-knowledge to the protocol.
            let sorted: Vec<_> = sorted
                .into_iter()
                .map(|chunk| lookup::constraints::zk_patch(chunk, index.cs.domain.d1, rng))
                .collect();

            //~~ - Commit each of the sorted polynomials.
            let sorted_comms: Vec<_> = sorted
                .iter()
                .map(|v| {
                    index
                        .srs
                        .commit_evaluations(index.cs.domain.d1, v, None, rng)
                })
                .collect();

            //~~ - Absorb each commitments to the sorted polynomials.
            sorted_comms
                .iter()
                .for_each(|c| fq_sponge.absorb_g(&c.0.unshifted));

            // precompute different forms of the sorted polynomials for later
            // TODO: We can avoid storing these coefficients.
            let sorted_coeffs: Vec<_> = sorted.iter().map(|e| e.clone().interpolate()).collect();
            let sorted8: Vec<_> = sorted_coeffs
                .iter()
                .map(|v| v.evaluate_over_domain_by_ref(index.cs.domain.d8))
                .collect();

            lookup_context.joint_combiner = Some(joint_combiner);
            lookup_context.sorted = Some(sorted);
            lookup_context.sorted_coeffs = Some(sorted_coeffs);
            lookup_context.sorted_comms = Some(sorted_comms);
            lookup_context.sorted8 = Some(sorted8);
            lookup_context.joint_lookup_table_d8 = Some(joint_lookup_table_d8);
            lookup_context.joint_lookup_table = Some(joint_lookup_table);
        }

        //~ 1. Sample $\beta$ with the Fq-Sponge.
        let beta = fq_sponge.challenge();

        //~ 1. Sample $\gamma$ with the Fq-Sponge.
        let gamma = fq_sponge.challenge();

        //~ 1. If using lookup:
        if index.cs.lookup_constraint_system.is_some() {
            //~~ - Compute the lookup aggregation polynomial.
            let joint_lookup_table_d8 = lookup_context.joint_lookup_table_d8.as_ref().unwrap();

            let aggreg = lookup::constraints::aggregation::<_, ScalarField<G>>(
                lookup_context.dummy_lookup_value.unwrap(),
                joint_lookup_table_d8,
                index.cs.domain.d1,
                &index.cs.gates,
                &witness,
                &lookup_context.joint_combiner.unwrap(),
                &lookup_context.table_id_combiner.unwrap(),
                beta,
                gamma,
                lookup_context.sorted.as_ref().unwrap(),
                rng,
            )?;

            //~~ - Commit to the aggregation polynomial.
            let aggreg_comm = index
                .srs
                .commit_evaluations(index.cs.domain.d1, &aggreg, None, rng);

            //~~ - Absorb the commitment to the aggregation polynomial with the Fq-Sponge.
            fq_sponge.absorb_g(&aggreg_comm.0.unshifted);

            // precompute different forms of the aggregation polynomial for later
            let aggreg_coeffs = aggreg.interpolate();
            // TODO: There's probably a clever way to expand the domain without
            // interpolating
            let aggreg8 = aggreg_coeffs.evaluate_over_domain_by_ref(index.cs.domain.d8);

            lookup_context.aggreg_comm = Some(aggreg_comm);
            lookup_context.aggreg_coeffs = Some(aggreg_coeffs);
            lookup_context.aggreg8 = Some(aggreg8);
        }

        //~ 1. Compute the permutation aggregation polynomial $z$.
        let z_poly = index.cs.perm_aggreg(&witness, &beta, &gamma, rng)?;

        //~ 1. Commit (hidding) to the permutation aggregation polynomial $z$.
        let z_comm = index.srs.commit(&z_poly, None, rng);

        //~ 1. Absorb the permutation aggregation polynomial $z$ with the Fq-Sponge.
        fq_sponge.absorb_g(&z_comm.0.unshifted);

        //~ 1. Sample $\alpha'$ with the Fq-Sponge.
        let alpha_chal = ScalarChallenge(fq_sponge.challenge());

        //~ 1. Derive $\alpha$ from $\alpha'$ using the endomorphism (TODO: details)
        let alpha: ScalarField<G> = alpha_chal.to_field(&index.srs.endo_r);

        //~ 1. TODO: instantiate alpha?
        let mut all_alphas = index.powers_of_alpha.clone();
        all_alphas.instantiate(alpha);

        //~ 1. Compute the quotient polynomial (the $t$ in $f = Z_H \cdot t$).
        //~    The quotient polynomial is computed by adding all these polynomials together:
        //~~ - the combined constraints for all the gates
        //~~ - the combined constraints for the permutation
        //~~ - TODO: lookup
        //~~ - the negated public polynomial
        //~    and by then dividing the resulting polynomial with the vanishing polynomial $Z_H$.
        //~    TODO: specify the split of the permutation polynomial into perm and bnd?
        let lookup_env = if let Some(lcs) = &index.cs.lookup_constraint_system {
            let joint_lookup_table_d8 = lookup_context.joint_lookup_table_d8.as_ref().unwrap();

            Some(LookupEnvironment {
                aggreg: lookup_context.aggreg8.as_ref().unwrap(),
                sorted: lookup_context.sorted8.as_ref().unwrap(),
                selectors: &lcs.lookup_selectors,
                table: joint_lookup_table_d8,
                runtime_selector: lcs.runtime_selector.as_ref(),
                runtime_table: lookup_context.runtime_table_d8.as_ref(),
            })
        } else {
            None
        };

        let lagrange = index.cs.evaluate(&witness_poly, &z_poly);
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
            if !index.cs.range_check_selector_polys.is_empty() {
                index_evals.extend(range_check::circuit_gates().iter().enumerate().map(
                    |(i, gate_type)| (*gate_type, &index.cs.range_check_selector_polys[i].eval8),
                ));
            }

            Environment {
                constants: Constants {
                    alpha,
                    beta,
                    gamma,
                    joint_combiner: lookup_context.joint_combiner,
                    endo_coefficient: index.cs.endo,
                    mds: index.cs.fr_sponge_params.mds.clone(),
                },
                witness: &lagrange.d8.this.w,
                coefficient: &index.cs.coefficients8,
                vanishes_on_last_4_rows: &index.cs.precomputations().vanishes_on_last_4_rows,
                z: &lagrange.d8.this.z,
                l0_1: l0_1(index.cs.domain.d1),
                domain: index.cs.domain,
                index: index_evals,
                lookup: lookup_env,
            }
        };

        let quotient_poly = {
            // generic
            let alphas =
                all_alphas.get_alphas(ArgumentType::Gate(GateType::Generic), generic::CONSTRAINTS);
            let mut t4 = index.cs.gnrc_quot(alphas, &lagrange.d4.this.w);

            if cfg!(debug_assertions) {
                let p4 = public_poly.evaluate_over_domain_by_ref(index.cs.domain.d4);
                let gen_minus_pub = &t4 + &p4;

                check_constraint!(index, gen_minus_pub);
            }

            // complete addition
            {
                let add_constraint = CompleteAdd::combined_constraints(&all_alphas);
                let add4 = add_constraint.evaluations(&env);
                t4 += &add4;

                check_constraint!(index, add4);
            }

            // permutation
            let (mut t8, bnd) = {
                let alphas =
                    all_alphas.get_alphas(ArgumentType::Permutation, permutation::CONSTRAINTS);
                let (perm, bnd) = index
                    .cs
                    .perm_quot(&lagrange, beta, gamma, &z_poly, alphas)?;

                check_constraint!(index, perm);

                (perm, bnd)
            };

            if !index.cs.range_check_selector_polys.is_empty() {
                // Range check gate
                for gate_type in range_check::circuit_gates() {
                    let expr = range_check::circuit_gate_constraints(gate_type, &all_alphas);

                    let evals = expr.evaluations(&env);

                    if evals.domain().size == t4.domain().size {
                        t4 += &evals;
                    } else if evals.domain().size == t8.domain().size {
                        t8 += &evals;
                    } else {
                        panic!(
                            "Bad evaluation domain size {} for {:?}",
                            evals.domain().size,
                            gate_type
                        );
                    }

                    if cfg!(test) {
                        let (_, res) = evals
                            .interpolate()
                            .divide_by_vanishing_poly(index.cs.domain.d1)
                            .unwrap();
                        if !res.is_zero() {
                            panic!("Nonzero vanishing polynomial division for {:?}", gate_type);
                        }
                    }
                }
            }

            // scalar multiplication
            {
                let mul8 = VarbaseMul::combined_constraints(&all_alphas).evaluations(&env);
                t8 += &mul8;

                check_constraint!(index, mul8);
            }

            // endoscaling
            {
                let emul8 = EndosclMul::combined_constraints(&all_alphas).evaluations(&env);
                t8 += &emul8;

                check_constraint!(index, emul8);
            }

            // endoscaling scalar computation
            {
                let emulscalar8 =
                    EndomulScalar::combined_constraints(&all_alphas).evaluations(&env);
                t8 += &emulscalar8;

                check_constraint!(index, emulscalar8);
            }

            // poseidon
            {
                let pos8 = Poseidon::combined_constraints(&all_alphas).evaluations(&env);
                t8 += &pos8;

                check_constraint!(index, pos8);
            }

            // chacha
            {
                if index.cs.chacha8.as_ref().is_some() {
                    let chacha0 = ChaCha0::combined_constraints(&all_alphas).evaluations(&env);
                    t4 += &chacha0;

                    let chacha1 = ChaCha1::combined_constraints(&all_alphas).evaluations(&env);
                    t4 += &chacha1;

                    let chacha2 = ChaCha2::combined_constraints(&all_alphas).evaluations(&env);
                    t4 += &chacha2;

                    let chacha_final =
                        ChaChaFinal::combined_constraints(&all_alphas).evaluations(&env);
                    t4 += &chacha_final;

                    check_constraint!(index, chacha0);
                    check_constraint!(index, chacha1);
                    check_constraint!(index, chacha2);
                    check_constraint!(index, chacha_final);
                }
            }

            // lookup
            {
                if let Some(lcs) = index.cs.lookup_constraint_system.as_ref() {
                    let constraints =
                        lookup::constraints::constraints(&lcs.configuration, index.cs.domain.d1);
                    let constraints_len = u32::try_from(constraints.len())
                        .expect("not expecting a large amount of constraints");
                    let lookup_alphas =
                        all_alphas.get_alphas(ArgumentType::Lookup, constraints_len);

                    // as lookup constraints are computed with the expression framework,
                    // each of them can result in Evaluations of different domains
                    for (ii, (constraint, alpha_pow)) in
                        constraints.into_iter().zip_eq(lookup_alphas).enumerate()
                    {
                        let mut eval = constraint.evaluations(&env);
                        eval.evals.iter_mut().for_each(|x| *x *= alpha_pow);

                        if eval.domain().size == t4.domain().size {
                            t4 += &eval;
                        } else if eval.domain().size == t8.domain().size {
                            t8 += &eval;
                        } else {
                            panic!("Bad evaluation")
                        }

                        check_constraint!(index, format!("lookup constraint #{ii}"), eval);
                    }
                }
            }

            // public polynomial
            let mut f = t4.interpolate() + t8.interpolate();
            f += &public_poly;

            // divide contributions with vanishing polynomial
            let (mut quotient, res) = f
                .divide_by_vanishing_poly(index.cs.domain.d1)
                .ok_or(ProverError::Prover("division by vanishing polynomial"))?;
            if !res.is_zero() {
                return Err(ProverError::Prover(
                    "rest of division by vanishing polynomial",
                ));
            }

            quotient += &bnd; // already divided by Z_H
            quotient
        };

        //~ 1. commit (hiding) to the quotient polynomial $t$
        //~    TODO: specify the dummies
        let t_comm = {
            let (mut t_comm, mut omega_t) = index.srs.commit(&quotient_poly, None, rng);

            let expected_t_size = PERMUTS;
            let dummies = expected_t_size - t_comm.unshifted.len();
            // Add `dummies` many hiding commitments to the 0 polynomial, since if the
            // number of commitments in `t_comm` is less than the max size, it means that
            // the higher degree coefficients of `t` are 0.
            for _ in 0..dummies {
                use ark_ec::ProjectiveCurve;
                let w = <ScalarField<G> as UniformRand>::rand(rng);
                t_comm.unshifted.push(index.srs.h.mul(w).into_affine());
                omega_t.unshifted.push(w);
            }
            (t_comm, omega_t)
        };

        //~ 1. Absorb the the commitment of the quotient polynomial with the Fq-Sponge.
        fq_sponge.absorb_g(&t_comm.0.unshifted);

        //~ 1. Sample $\zeta'$ with the Fq-Sponge.
        let zeta_chal = ScalarChallenge(fq_sponge.challenge());

        //~ 1. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify)
        let zeta = zeta_chal.to_field(&index.srs.endo_r);

        let omega = index.cs.domain.d1.group_gen;
        let zeta_omega = zeta * omega;

        //~ 1. If lookup is used, evaluate the following polynomials at $\zeta$ and $\zeta \omega$:
        if index.cs.lookup_constraint_system.is_some() {
            //~~ - the aggregation polynomial
            let aggreg = lookup_context
                .aggreg_coeffs
                .as_ref()
                .unwrap()
                .to_chunked_polynomial(index.max_poly_size);

            //~~ - the sorted polynomials
            let sorted = lookup_context
                .sorted_coeffs
                .as_ref()
                .unwrap()
                .iter()
                .map(|c| c.to_chunked_polynomial(index.max_poly_size));

            //~~ - the table polynonial
            let joint_table = lookup_context.joint_lookup_table.as_ref().unwrap();
            let joint_table = joint_table.to_chunked_polynomial(index.max_poly_size);

            let lookup_evals = |eval_point: ScalarField<G>| {
                let table = joint_table.evaluate_chunks(eval_point);

                // the runtime table polynomial
                let runtime_table = lookup_context.runtime_table.as_ref().map(|rt| {
                    rt.to_chunked_polynomial(index.max_poly_size)
                        .evaluate_chunks(eval_point)
                });

                LookupEvaluations {
                    aggreg: aggreg.evaluate_chunks(eval_point),
                    sorted: sorted
                        .clone()
                        .map(|s| s.evaluate_chunks(eval_point))
                        .collect(),
                    table,
                    runtime: runtime_table,
                }
            };

            lookup_context.eval_zeta = Some(lookup_evals(zeta));
            lookup_context.eval_zeta_omega = Some(lookup_evals(zeta_omega));
        }

        //~ 1. Chunk evaluate the following polynomials at both $\zeta$ and $\zeta \omega$:
        //~~ - $s_i$
        //~~ - $w_i$
        //~~ - $z$
        //~~ - lookup (TODO)
        //~~ - generic selector
        //~~ - poseidon selector
        //~
        //~    By "chunk evaluate" we mean that the evaluation of each polynomial can potentially be a vector of values.
        //~    This is because the index's `max_poly_size` parameter dictates the maximum size of a polynomial in the protocol.
        //~    If a polynomial $f$ exceeds this size, it must be split into several polynomials like so:
        //~    $$f(x) = f_0(x) + x^n f_1(x) + x^{2n} f_2(x) + \cdots$$
        //~
        //~    And the evaluation of such a polynomial is the following list for $x \in {\zeta, \zeta\omega}$:
        //~
        //~    $$(f_0(x), f_1(x), f_2(x), \ldots)$$
        //~
        //~    TODO: do we want to specify more on that? It seems unecessary except for the t polynomial (or if for some reason someone sets that to a low value)
        let chunked_evals = {
            let chunked_evals_zeta = ProofEvaluations::<Vec<ScalarField<G>>> {
                s: array_init(|i| {
                    index.cs.sigmam[0..PERMUTS - 1][i]
                        .to_chunked_polynomial(index.max_poly_size)
                        .evaluate_chunks(zeta)
                }),
                w: array_init(|i| {
                    witness_poly[i]
                        .to_chunked_polynomial(index.max_poly_size)
                        .evaluate_chunks(zeta)
                }),

                z: z_poly
                    .to_chunked_polynomial(index.max_poly_size)
                    .evaluate_chunks(zeta),

                lookup: lookup_context.eval_zeta.take(),

                generic_selector: index
                    .cs
                    .genericm
                    .to_chunked_polynomial(index.max_poly_size)
                    .evaluate_chunks(zeta),

                poseidon_selector: index
                    .cs
                    .psm
                    .to_chunked_polynomial(index.max_poly_size)
                    .evaluate_chunks(zeta),
            };
            let chunked_evals_zeta_omega = ProofEvaluations::<Vec<ScalarField<G>>> {
                s: array_init(|i| {
                    index.cs.sigmam[0..PERMUTS - 1][i]
                        .to_chunked_polynomial(index.max_poly_size)
                        .evaluate_chunks(zeta_omega)
                }),

                w: array_init(|i| {
                    witness_poly[i]
                        .to_chunked_polynomial(index.max_poly_size)
                        .evaluate_chunks(zeta_omega)
                }),

                z: z_poly
                    .to_chunked_polynomial(index.max_poly_size)
                    .evaluate_chunks(zeta_omega),

                lookup: lookup_context.eval_zeta_omega.take(),

                generic_selector: index
                    .cs
                    .genericm
                    .to_chunked_polynomial(index.max_poly_size)
                    .evaluate_chunks(zeta_omega),

                poseidon_selector: index
                    .cs
                    .psm
                    .to_chunked_polynomial(index.max_poly_size)
                    .evaluate_chunks(zeta_omega),
            };

            [chunked_evals_zeta, chunked_evals_zeta_omega]
        };

        let zeta_to_srs_len = zeta.pow(&[index.max_poly_size as u64]);
        let zeta_omega_to_srs_len = zeta.pow(&[index.max_poly_size as u64]);
        let zeta_to_domain_size = zeta.pow(&[d1_size as u64]);

        //~ 1. Evaluate the same polynomials without chunking them
        //~    (so that each polynomial should correspond to a single value this time).
        let evals = {
            let power_of_eval_points_for_chunks = [zeta_to_srs_len, zeta_omega_to_srs_len];
            &chunked_evals
                .iter()
                .zip(power_of_eval_points_for_chunks.iter())
                .map(|(es, &e1)| ProofEvaluations::<ScalarField<G>> {
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
                        runtime: l
                            .runtime
                            .as_ref()
                            .map(|p| DensePolynomial::eval_polynomial(p, e1)),
                    }),
                    generic_selector: DensePolynomial::eval_polynomial(&es.generic_selector, e1),
                    poseidon_selector: DensePolynomial::eval_polynomial(&es.poseidon_selector, e1),
                })
                .collect::<Vec<_>>()
        };

        //~ 1. Compute the ft polynomial.
        //~    This is to implement [Maller's optimization](https://o1-labs.github.io/mina-book/crypto/plonk/maller_15.html).
        let ft: DensePolynomial<ScalarField<G>> = {
            let f_chunked = {
                // TODO: compute the linearization polynomial in evaluation form so
                // that we can drop the coefficient forms of the index polynomials from
                // the constraint system struct

                // generic (not part of linearization yet)
                let alphas = all_alphas
                    .get_alphas(ArgumentType::Gate(GateType::Generic), generic::CONSTRAINTS);
                let mut f = index
                    .cs
                    .gnrc_lnrz(alphas, &evals[0].w, evals[0].generic_selector)
                    .interpolate();

                // permutation (not part of linearization yet)
                let alphas =
                    all_alphas.get_alphas(ArgumentType::Permutation, permutation::CONSTRAINTS);
                f += &index.cs.perm_lnrz(evals, zeta, beta, gamma, alphas);

                // the circuit polynomial
                let f = {
                    let (_lin_constant, lin) = index.linearization.to_polynomial(&env, zeta, evals);
                    f + lin
                };

                drop(env);

                // see https://o1-labs.github.io/mina-book/crypto/plonk/maller_15.html#the-prover-side
                f.to_chunked_polynomial(index.max_poly_size)
                    .linearize(zeta_to_srs_len)
            };

            let t_chunked = quotient_poly
                .to_chunked_polynomial(index.max_poly_size)
                .linearize(zeta_to_srs_len);

            &f_chunked - &t_chunked.scale(zeta_to_domain_size - ScalarField::<G>::one())
        };

        //~ 1. construct the blinding part of the ft polynomial commitment
        //~    see https://o1-labs.github.io/mina-book/crypto/plonk/maller_15.html#evaluation-proof-and-blinding-factors
        let blinding_ft = {
            let blinding_t = t_comm.1.chunk_blinding(zeta_to_srs_len);
            let blinding_f = ScalarField::<G>::zero();

            PolyComm {
                // blinding_f - Z_H(zeta) * blinding_t
                unshifted: vec![
                    blinding_f - (zeta_to_domain_size - ScalarField::<G>::one()) * blinding_t,
                ],
                shifted: None,
            }
        };

        //~ 1. Evaluate the ft polynomial at $\zeta\omega$ only.
        let ft_eval1 = ft.evaluate(&zeta_omega);

        //~ 1. Setup the Fr-Sponge
        let fq_sponge_before_evaluations = fq_sponge.clone();
        let mut fr_sponge = EFrSponge::new(index.cs.fr_sponge_params.clone());

        //~ 1. Squeeze the Fq-sponge and absorb the result with the Fr-Sponge.
        fr_sponge.absorb(&fq_sponge.digest());

        //~ 1. Evaluate the negated public polynomial (if present) at $\zeta$ and $\zeta\omega$.
        let public_evals = if public_poly.is_zero() {
            [Vec::new(), Vec::new()]
        } else {
            [
                vec![public_poly.evaluate(&zeta)],
                vec![public_poly.evaluate(&zeta_omega)],
            ]
        };

        //~ 1. Absorb all the polynomial evaluations in $\zeta$ and $\zeta\omega$:
        //~~ - the public polynomial
        //~~ - z
        //~~ - generic selector
        //~~ - poseidon selector
        //~~ - the 15 register/witness
        //~~ - 6 sigmas evaluations (the last one is not evaluated)
        for i in 0..2 {
            fr_sponge.absorb_evaluations(&public_evals[i], &chunked_evals[i])
        }

        //~ 1. Absorb the unique evaluation of ft: $ft(\zeta\omega)$.
        fr_sponge.absorb(&ft_eval1);

        //~ 1. Sample $v'$ with the Fr-Sponge
        let v_chal = fr_sponge.challenge();

        //~ 1. Derive $v$ from $v'$ using the endomorphism (TODO: specify)
        let v = v_chal.to_field(&index.srs.endo_r);

        //~ 1. Sample $u'$ with the Fr-Sponge
        let u_chal = fr_sponge.challenge();

        //~ 1. Derive $u$ from $u'$ using the endomorphism (TODO: specify)
        let u = u_chal.to_field(&index.srs.endo_r);

        //~ 1. Create a list of all polynomials that will require evaluations
        //~    (and evaluation proofs) in the protocol.
        //~    First, include the previous challenges, in case we are in a recursive prover.
        let non_hiding = |d1_size: usize| PolyComm {
            unshifted: vec![ScalarField::<G>::zero(); d1_size],
            shifted: None,
        };

        let polys = prev_challenges
            .iter()
            .map(|(chals, comm)| {
                (
                    DensePolynomial::from_coefficients_vec(b_poly_coefficients(chals)),
                    comm.unshifted.len(),
                )
            })
            .collect::<Vec<_>>();

        let mut polynomials = polys
            .iter()
            .map(|(p, d1_size)| (p, None, non_hiding(*d1_size)))
            .collect::<Vec<_>>();

        //~ 1. Then, include:
        //~~ - the negated public polynomial
        //~~ - the ft polynomial
        //~~ - the permutation aggregation polynomial z polynomial
        //~~ - the generic selector
        //~~ - the poseidon selector
        //~~ - the 15 registers/witness columns
        //~~ - the 6 sigmas
        //~~ - optionally, the runtime table
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

        // if using lookup

        if let Some(lcs) = &index.cs.lookup_constraint_system {
            // add the sorted polynomials
            let sorted_poly = lookup_context.sorted_coeffs.as_ref().unwrap();
            let sorted_comms = lookup_context.sorted_comms.as_ref().unwrap();

            for (poly, comm) in sorted_poly.iter().zip(sorted_comms) {
                polynomials.push((poly, None, comm.1.clone()));
            }

            // add the aggreg polynomial
            let aggreg_poly = lookup_context.aggreg_coeffs.as_ref().unwrap();
            let aggreg_comm = lookup_context.aggreg_comm.as_ref().unwrap();
            polynomials.push((aggreg_poly, None, aggreg_comm.1.clone()));

            // add the combined table polynomial
            let table_blinding = if lcs.runtime_selector.is_some() {
                let runtime_comm = lookup_context.runtime_table_comm.as_ref().unwrap();
                let joint_combiner = lookup_context.joint_combiner.as_ref().unwrap();

                let blinding = runtime_comm.1.unshifted[0];

                PolyComm {
                    unshifted: vec![*joint_combiner * blinding],
                    shifted: None,
                }
            } else {
                non_hiding(1)
            };

            let joint_lookup_table = lookup_context.joint_lookup_table.as_ref().unwrap();

            polynomials.push((joint_lookup_table, None, table_blinding));

            // add the runtime table polynomial
            if lcs.runtime_selector.is_some() {
                let runtime_table_comm = lookup_context.runtime_table_comm.as_ref().unwrap();
                let runtime_table = lookup_context.runtime_table.as_ref().unwrap();

                polynomials.push((runtime_table, None, runtime_table_comm.1.clone()));
            }
        }

        //~ 1. Create an aggregated evaluation proof for all of these polynomials at $\zeta$ and $\zeta\omega$ using $u$ and $v$.
        let proof = index.srs.open(
            group_map,
            &polynomials,
            &[zeta, zeta_omega],
            v,
            u,
            fq_sponge_before_evaluations,
            rng,
        );

        let lookup = lookup_context
            .aggreg_comm
            .zip(lookup_context.sorted_comms)
            .map(|(a, s)| LookupCommitments {
                aggreg: a.0,
                sorted: s.iter().map(|(x, _)| x.clone()).collect(),
                runtime: lookup_context.runtime_table_comm.map(|x| x.0),
            });

        Ok(Self {
            commitments: ProverCommitments {
                w_comm: array_init(|i| w_comm[i].0.clone()),
                z_comm: z_comm.0,
                t_comm: t_comm.0,
                lookup,
            },
            proof,
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
    use crate::proof::caml::CamlProofEvaluations;
    use ark_ec::AffineCurve;
    use commitment_dlog::commitment::caml::{CamlOpeningProof, CamlPolyComm};

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
