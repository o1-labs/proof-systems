//! This module implements prover's zk-proof primitive.

use crate::{
    circuits::{
        argument::{Argument, ArgumentType},
        berkeley_columns::{BerkeleyChallenges, Environment, LookupEnvironment},
        constraints::zk_rows_strict_lower_bound,
        expr::{self, l0_1, Constants},
        gate::GateType,
        lookup::{self, runtime_tables::RuntimeTable, tables::combine_table_entry},
        polynomials::{
            complete_add::CompleteAdd,
            endomul_scalar::EndomulScalar,
            endosclmul::EndosclMul,
            foreign_field_add::circuitgates::ForeignFieldAdd,
            foreign_field_mul::{self, circuitgates::ForeignFieldMul},
            generic, permutation,
            poseidon::Poseidon,
            range_check::circuitgates::{RangeCheck0, RangeCheck1},
            rot::Rot64,
            varbasemul::VarbaseMul,
            xor::Xor16,
        },
        wires::{COLUMNS, PERMUTS},
    },
    curve::KimchiCurve,
    error::ProverError,
    lagrange_basis_evaluations::LagrangeBasisEvaluations,
    plonk_sponge::FrSponge,
    proof::{
        LookupCommitments, PointEvaluations, ProofEvaluations, ProverCommitments, ProverProof,
        RecursionChallenge,
    },
    prover_index::ProverIndex,
    verifier_index::VerifierIndex,
};
use ark_ff::{FftField, Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain as D,
};
use core::array;
use itertools::Itertools;
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use o1_utils::ExtendedDensePolynomial as _;
use poly_commitment::{
    commitment::{
        absorb_commitment, b_poly_coefficients, BlindedCommitment, CommitmentCurve, PolyComm,
    },
    utils::DensePolynomialOrEvaluations,
    OpenProof, SRS as _,
};
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;
use std::collections::HashMap;

/// The result of a proof creation or verification.
type Result<T> = core::result::Result<T, ProverError>;

/// Helper to quickly test if a witness satisfies a constraint
macro_rules! check_constraint {
    ($index:expr, $evaluation:expr) => {{
        check_constraint!($index, stringify!($evaluation), $evaluation);
    }};
    ($index:expr, $label:expr, $evaluation:expr) => {{
        if cfg!(debug_assertions) {
            let (_, res) = $evaluation
                .interpolate_by_ref()
                .divide_by_vanishing_poly($index.cs.domain.d1);
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
    sorted_comms: Option<Vec<BlindedCommitment<G>>>,
    sorted8: Option<Vec<Evaluations<F, D<F>>>>,

    /// The aggregation polynomial in different forms
    aggreg_coeffs: Option<DensePolynomial<F>>,
    aggreg_comm: Option<BlindedCommitment<G>>,
    aggreg8: Option<Evaluations<F, D<F>>>,

    // lookup-related evaluations
    /// evaluation of lookup aggregation polynomial
    pub lookup_aggregation_eval: Option<PointEvaluations<Vec<F>>>,
    /// evaluation of lookup table polynomial
    pub lookup_table_eval: Option<PointEvaluations<Vec<F>>>,
    /// evaluation of lookup sorted polynomials
    pub lookup_sorted_eval: [Option<PointEvaluations<Vec<F>>>; 5],
    /// evaluation of runtime lookup table polynomial
    pub runtime_lookup_table_eval: Option<PointEvaluations<Vec<F>>>,

    /// Runtime table
    runtime_table: Option<DensePolynomial<F>>,
    runtime_table_d8: Option<Evaluations<F, D<F>>>,
    runtime_table_comm: Option<BlindedCommitment<G>>,
    runtime_second_col_d8: Option<Evaluations<F, D<F>>>,
}

impl<G: KimchiCurve, OpeningProof: OpenProof<G>> ProverProof<G, OpeningProof>
where
    G::BaseField: PrimeField,
{
    /// This function constructs prover's zk-proof from the witness & the `ProverIndex` against SRS instance
    ///
    /// # Errors
    ///
    /// Will give error if `create_recursive` process fails.
    pub fn create<
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
        EFrSponge: FrSponge<G::ScalarField>,
        RNG: RngCore + CryptoRng,
    >(
        groupmap: &G::Map,
        witness: [Vec<G::ScalarField>; COLUMNS],
        runtime_tables: &[RuntimeTable<G::ScalarField>],
        index: &ProverIndex<G, OpeningProof>,
        rng: &mut RNG,
    ) -> Result<Self>
    where
        VerifierIndex<G, OpeningProof>: Clone,
    {
        Self::create_recursive::<EFqSponge, EFrSponge, RNG>(
            groupmap,
            witness,
            runtime_tables,
            index,
            Vec::new(),
            None,
            rng,
        )
    }

    /// This function constructs prover's recursive zk-proof from the witness &
    /// the `ProverIndex` against SRS instance
    ///
    /// # Errors
    ///
    /// Will give error if inputs(like `lookup_context.joint_lookup_table_d8`)
    /// are None.
    ///
    /// # Panics
    ///
    /// Will panic if `lookup_context.joint_lookup_table_d8` is None.
    pub fn create_recursive<
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
        EFrSponge: FrSponge<G::ScalarField>,
        RNG: RngCore + CryptoRng,
    >(
        group_map: &G::Map,
        mut witness: [Vec<G::ScalarField>; COLUMNS],
        runtime_tables: &[RuntimeTable<G::ScalarField>],
        index: &ProverIndex<G, OpeningProof>,
        prev_challenges: Vec<RecursionChallenge<G>>,
        blinders: Option<[Option<PolyComm<G::ScalarField>>; COLUMNS]>,
        rng: &mut RNG,
    ) -> Result<Self>
    where
        VerifierIndex<G, OpeningProof>: Clone,
    {
        internal_tracing::checkpoint!(internal_traces; create_recursive);
        let d1_size = index.cs.domain.d1.size();

        let (_, endo_r) = G::endos();

        let num_chunks = if d1_size < index.max_poly_size {
            1
        } else {
            d1_size / index.max_poly_size
        };

        // Verify the circuit satisfiability by the computed witness (baring plookup constraints)
        // Catch mistakes before proof generation.
        if cfg!(debug_assertions) && !index.cs.disable_gates_checks {
            let public = witness[0][0..index.cs.public].to_vec();
            index.verify(&witness, &public).expect("incorrect witness");
        }

        //~ 1. Ensure we have room in the witness for the zero-knowledge rows.
        //~    We currently expect the witness not to be of the same length as the domain,
        //~    but instead be of the length of the (smaller) circuit.
        //~    If we cannot add `zk_rows` rows to the columns of the witness before reaching
        //~    the size of the domain, abort.
        let length_witness = witness[0].len();
        let length_padding = d1_size
            .checked_sub(length_witness)
            .ok_or(ProverError::NoRoomForZkInWitness)?;

        let zero_knowledge_limit = zk_rows_strict_lower_bound(num_chunks);
        // Because the lower bound is strict, the result of the function above
        // is not a sufficient number of zero knowledge rows, so the error must
        // be raised anytime the number of zero knowledge rows is not greater
        // than the strict lower bound.
        // Example:
        //   for 1 chunk, `zero_knowledge_limit` is 2, and we need at least 3,
        //   thus the error should be raised and the message should say that the
        //   expected number of zero knowledge rows is 3 (hence the + 1).
        if (index.cs.zk_rows as usize) <= zero_knowledge_limit {
            return Err(ProverError::NotZeroKnowledge(
                zero_knowledge_limit + 1,
                index.cs.zk_rows as usize,
            ));
        }

        if length_padding < index.cs.zk_rows as usize {
            return Err(ProverError::NoRoomForZkInWitness);
        }

        //~ 1. Pad the witness columns with Zero gates to make them the same length as the domain.
        //~    Then, randomize the last `zk_rows` of each columns.
        internal_tracing::checkpoint!(internal_traces; pad_witness);
        for w in &mut witness {
            if w.len() != length_witness {
                return Err(ProverError::WitnessCsInconsistent);
            }

            // padding
            w.extend(core::iter::repeat(G::ScalarField::zero()).take(length_padding));

            // zk-rows
            for row in w.iter_mut().rev().take(index.cs.zk_rows as usize) {
                *row = <G::ScalarField as UniformRand>::rand(rng);
            }
        }

        //~ 1. Setup the Fq-Sponge.
        internal_tracing::checkpoint!(internal_traces; set_up_fq_sponge);
        let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());

        //~ 1. Absorb the digest of the VerifierIndex.
        let verifier_index_digest = index.verifier_index_digest::<EFqSponge>();
        fq_sponge.absorb_fq(&[verifier_index_digest]);

        //~ 1. Absorb the commitments of the previous challenges with the Fq-sponge.
        for RecursionChallenge { comm, .. } in &prev_challenges {
            absorb_commitment(&mut fq_sponge, comm)
        }

        //~ 1. Compute the negated public input polynomial as
        //~    the polynomial that evaluates to $-p_i$ for the first `public_input_size` values of the domain,
        //~    and $0$ for the rest.
        let public = witness[0][0..index.cs.public].to_vec();
        let public_poly = -Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
            public,
            index.cs.domain.d1,
        )
        .interpolate();

        //~ 1. Commit (non-hiding) to the negated public input polynomial.
        let public_comm = index.srs.commit_non_hiding(&public_poly, num_chunks);
        let public_comm = {
            index
                .srs
                .mask_custom(
                    public_comm.clone(),
                    &public_comm.map(|_| G::ScalarField::one()),
                )
                .unwrap()
                .commitment
        };

        //~ 1. Absorb the commitment to the public polynomial with the Fq-Sponge.
        //~
        //~    Note: unlike the original PLONK protocol,
        //~    the prover also provides evaluations of the public polynomial to help the verifier circuit.
        //~    This is why we need to absorb the commitment to the public polynomial at this point.
        absorb_commitment(&mut fq_sponge, &public_comm);

        //~ 1. Commit to the witness columns by creating `COLUMNS` hiding commitments.
        //~
        //~    Note: since the witness is in evaluation form,
        //~    we can use the `commit_evaluation` optimization.
        internal_tracing::checkpoint!(internal_traces; commit_to_witness_columns);
        // generate blinders if not given externally
        let blinders_final: Vec<PolyComm<G::ScalarField>> = match blinders {
            None => (0..COLUMNS)
                .map(|_| PolyComm::new(vec![UniformRand::rand(rng); num_chunks]))
                .collect(),
            Some(blinders_arr) => blinders_arr
                .into_iter()
                .map(|blinder_el| match blinder_el {
                    None => PolyComm::new(vec![UniformRand::rand(rng); num_chunks]),
                    Some(blinder_el_some) => blinder_el_some,
                })
                .collect(),
        };
        let w_comm_opt_res: Vec<Result<_>> = witness
            .clone()
            .into_par_iter()
            .zip(blinders_final.into_par_iter())
            .map(|(witness, blinder)| {
                let witness_eval =
                    Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                        witness,
                        index.cs.domain.d1,
                    );

                // TODO: make this a function rather no? mask_with_custom()
                let witness_com = index
                    .srs
                    .commit_evaluations_non_hiding(index.cs.domain.d1, &witness_eval);
                let com = index
                    .srs
                    .mask_custom(witness_com, &blinder)
                    .map_err(ProverError::WrongBlinders)?;

                Ok(com)
            })
            .collect();

        let w_comm_res: Result<Vec<BlindedCommitment<G>>> = w_comm_opt_res.into_iter().collect();

        let w_comm = w_comm_res?;

        let w_comm: [BlindedCommitment<G>; COLUMNS] = w_comm
            .try_into()
            .expect("previous loop is of the correct length");

        //~ 1. Absorb the witness commitments with the Fq-Sponge.
        w_comm
            .iter()
            .for_each(|c| absorb_commitment(&mut fq_sponge, &c.commitment));

        //~ 1. Compute the witness polynomials by interpolating each `COLUMNS` of the witness.
        //~    As mentioned above, we commit using the evaluations form rather than the coefficients
        //~    form so we can take advantage of the sparsity of the evaluations (i.e., there are many
        //~    0 entries and entries that have less-than-full-size field elemnts.)
        let witness_poly: [DensePolynomial<G::ScalarField>; COLUMNS] = (0..COLUMNS)
            .into_par_iter()
            .map(|i| {
                Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                    witness[i].clone(),
                    index.cs.domain.d1,
                )
                .interpolate()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let mut lookup_context = LookupContext::default();

        //~ 1. If using lookup:
        let lookup_constraint_system = index
            .cs
            .lookup_constraint_system
            .try_get_or_err()
            .map_err(ProverError::from)?;
        if let Some(lcs) = lookup_constraint_system {
            internal_tracing::checkpoint!(internal_traces; use_lookup, {
                "uses_lookup": true,
                "uses_runtime_tables": lcs.runtime_tables.is_some(),
            });
            //~~ * if using runtime table:
            if let Some(cfg_runtime_tables) = &lcs.runtime_tables {
                //~~~ * check that all the provided runtime tables have length and IDs that match the runtime table configuration of the index
                //~~~   we expect the given runtime tables to be sorted as configured, this makes it easier afterwards
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

                //~~~ * calculate the contribution to the second column of the lookup table
                //~~~   (the runtime vector)
                let (runtime_table_contribution, runtime_table_contribution_d8) = {
                    let mut offset = lcs
                        .runtime_table_offset
                        .expect("runtime configuration missing offset");

                    let mut evals = vec![G::ScalarField::zero(); d1_size];
                    for rt in runtime_tables {
                        let range = offset..(offset + rt.data.len());
                        evals[range].copy_from_slice(&rt.data);
                        offset += rt.data.len();
                    }

                    // zero-knowledge
                    for e in evals.iter_mut().rev().take(index.cs.zk_rows as usize) {
                        *e = <G::ScalarField as UniformRand>::rand(rng);
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
                let runtime_table_comm =
                    index
                        .srs
                        .commit(&runtime_table_contribution, num_chunks, rng);

                // absorb the commitment
                absorb_commitment(&mut fq_sponge, &runtime_table_comm.commitment);

                // pre-compute the updated second column of the lookup table
                let mut second_column_d8 = runtime_table_contribution_d8.clone();
                second_column_d8
                    .evals
                    .par_iter_mut()
                    .enumerate()
                    .for_each(|(row, e)| {
                        *e += lcs.lookup_table8[1][row];
                    });

                lookup_context.runtime_table = Some(runtime_table_contribution);
                lookup_context.runtime_table_d8 = Some(runtime_table_contribution_d8);
                lookup_context.runtime_table_comm = Some(runtime_table_comm);
                lookup_context.runtime_second_col_d8 = Some(second_column_d8);
            }

            //~~ * If queries involve a lookup table with multiple columns
            //~~   then squeeze the Fq-Sponge to obtain the joint combiner challenge $j'$,
            //~~   otherwise set the joint combiner challenge $j'$ to $0$.
            let joint_combiner = if lcs.configuration.lookup_info.features.joint_lookup_used {
                fq_sponge.challenge()
            } else {
                G::ScalarField::zero()
            };

            //~~ * Derive the scalar joint combiner $j$ from $j'$ using the endomorphism (TODO: specify)
            let joint_combiner: G::ScalarField = ScalarChallenge(joint_combiner).to_field(endo_r);

            //~~ * If multiple lookup tables are involved,
            //~~   set the `table_id_combiner` as the $j^i$ with $i$ the maximum width of any used table.
            //~~   Essentially, this is to add a last column of table ids to the concatenated lookup tables.
            let table_id_combiner: G::ScalarField = if lcs.table_ids8.as_ref().is_some() {
                joint_combiner.pow([lcs.configuration.lookup_info.max_joint_size as u64])
            } else {
                // TODO: just set this to None in case multiple tables are not used
                G::ScalarField::zero()
            };
            lookup_context.table_id_combiner = Some(table_id_combiner);

            //~~ * Compute the dummy lookup value as the combination of the last entry of the XOR table (so `(0, 0, 0)`).
            //~~   Warning: This assumes that we always use the XOR table when using lookups.
            let dummy_lookup_value = lcs
                .configuration
                .dummy_lookup
                .evaluate(&joint_combiner, &table_id_combiner);
            lookup_context.dummy_lookup_value = Some(dummy_lookup_value);

            //~~ * Compute the lookup table values as the combination of the lookup table entries.
            let joint_lookup_table_d8 = {
                let mut evals = Vec::with_capacity(d1_size);

                for idx in 0..(d1_size * 8) {
                    let table_id = match lcs.table_ids8.as_ref() {
                        Some(table_ids8) => table_ids8.evals[idx],
                        None =>
                        // If there is no `table_ids8` in the constraint system,
                        // every table ID is identically 0.
                        {
                            G::ScalarField::zero()
                        }
                    };

                    let combined_entry =
                        if !lcs.configuration.lookup_info.features.uses_runtime_tables {
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

            // TODO: This interpolation is avoidable.
            let joint_lookup_table = joint_lookup_table_d8.interpolate_by_ref();

            //~~ * Compute the sorted evaluations.
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
                &lcs.configuration.lookup_info,
                index.cs.zk_rows as usize,
            )?;

            //~~ * Randomize the last `EVALS` rows in each of the sorted polynomials
            //~~   in order to add zero-knowledge to the protocol.
            let sorted: Vec<_> = sorted
                .into_iter()
                .map(|chunk| {
                    lookup::constraints::zk_patch(
                        chunk,
                        index.cs.domain.d1,
                        index.cs.zk_rows as usize,
                        rng,
                    )
                })
                .collect();

            //~~ * Commit each of the sorted polynomials.
            let sorted_comms: Vec<_> = sorted
                .iter()
                .map(|v| index.srs.commit_evaluations(index.cs.domain.d1, v, rng))
                .collect();

            //~~ * Absorb each commitments to the sorted polynomials.
            sorted_comms
                .iter()
                .for_each(|c| absorb_commitment(&mut fq_sponge, &c.commitment));

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
        if let Some(lcs) = lookup_constraint_system {
            //~~ * Compute the lookup aggregation polynomial.
            let joint_lookup_table_d8 = lookup_context.joint_lookup_table_d8.as_ref().unwrap();

            let aggreg = lookup::constraints::aggregation::<_, G::ScalarField>(
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
                &lcs.configuration.lookup_info,
                index.cs.zk_rows as usize,
            )?;

            //~~ * Commit to the aggregation polynomial.
            let aggreg_comm = index
                .srs
                .commit_evaluations(index.cs.domain.d1, &aggreg, rng);

            //~~ * Absorb the commitment to the aggregation polynomial with the Fq-Sponge.
            absorb_commitment(&mut fq_sponge, &aggreg_comm.commitment);

            // precompute different forms of the aggregation polynomial for later
            let aggreg_coeffs = aggreg.interpolate();
            // TODO: There's probably a clever way to expand the domain without
            // interpolating
            let aggreg8 = aggreg_coeffs.evaluate_over_domain_by_ref(index.cs.domain.d8);

            lookup_context.aggreg_comm = Some(aggreg_comm);
            lookup_context.aggreg_coeffs = Some(aggreg_coeffs);
            lookup_context.aggreg8 = Some(aggreg8);
        }

        let column_evaluations = index.column_evaluations.get();

        //~ 1. Compute the permutation aggregation polynomial $z$.
        internal_tracing::checkpoint!(internal_traces; z_permutation_aggregation_polynomial);
        let z_poly = index.perm_aggreg(&witness, &beta, &gamma, rng)?;

        //~ 1. Commit (hiding) to the permutation aggregation polynomial $z$.
        let z_comm = index.srs.commit(&z_poly, num_chunks, rng);

        //~ 1. Absorb the permutation aggregation polynomial $z$ with the Fq-Sponge.
        absorb_commitment(&mut fq_sponge, &z_comm.commitment);

        //~ 1. Sample $\alpha'$ with the Fq-Sponge.
        let alpha_chal = ScalarChallenge(fq_sponge.challenge());

        //~ 1. Derive $\alpha$ from $\alpha'$ using the endomorphism (TODO: details)
        let alpha: G::ScalarField = alpha_chal.to_field(endo_r);

        //~ 1. TODO: instantiate alpha?
        let mut all_alphas = index.powers_of_alpha.clone();
        all_alphas.instantiate(alpha);

        //~ 1. Compute the quotient polynomial (the $t$ in $f = Z_H \cdot t$).
        //~    The quotient polynomial is computed by adding all these polynomials together:
        //~~ * the combined constraints for all the gates
        //~~ * the combined constraints for the permutation
        //~~ * TODO: lookup
        //~~ * the negated public polynomial
        //~    and by then dividing the resulting polynomial with the vanishing polynomial $Z_H$.
        //~    TODO: specify the split of the permutation polynomial into perm and bnd?
        let lookup_env = if let Some(lcs) = lookup_constraint_system {
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

        internal_tracing::checkpoint!(internal_traces; eval_witness_polynomials_over_domains);
        let lagrange = index.cs.evaluate(&witness_poly, &z_poly);
        internal_tracing::checkpoint!(internal_traces; compute_index_evals);
        let env = {
            let mut index_evals = HashMap::new();
            use GateType::*;
            index_evals.insert(Generic, &column_evaluations.generic_selector4);
            index_evals.insert(Poseidon, &column_evaluations.poseidon_selector8);
            index_evals.insert(CompleteAdd, &column_evaluations.complete_add_selector4);
            index_evals.insert(VarBaseMul, &column_evaluations.mul_selector8);
            index_evals.insert(EndoMul, &column_evaluations.emul_selector8);
            index_evals.insert(EndoMulScalar, &column_evaluations.endomul_scalar_selector8);

            if let Some(selector) = &column_evaluations.range_check0_selector8 {
                index_evals.insert(GateType::RangeCheck0, selector);
            }

            if let Some(selector) = &column_evaluations.range_check1_selector8 {
                index_evals.insert(GateType::RangeCheck1, selector);
            }

            if let Some(selector) = &column_evaluations.foreign_field_add_selector8 {
                index_evals.insert(GateType::ForeignFieldAdd, selector);
            }

            if let Some(selector) = &column_evaluations.foreign_field_mul_selector8 {
                index_evals.extend(
                    foreign_field_mul::gadget::circuit_gates()
                        .iter()
                        .map(|gate_type| (*gate_type, selector)),
                );
            }

            if let Some(selector) = &column_evaluations.xor_selector8 {
                index_evals.insert(GateType::Xor16, selector);
            }

            if let Some(selector) = &column_evaluations.rot_selector8 {
                index_evals.insert(GateType::Rot64, selector);
            }

            let mds = &G::sponge_params().mds;
            Environment {
                constants: Constants {
                    endo_coefficient: index.cs.endo,
                    mds,
                    zk_rows: index.cs.zk_rows,
                },
                challenges: BerkeleyChallenges {
                    alpha,
                    beta,
                    gamma,
                    joint_combiner: lookup_context
                        .joint_combiner
                        .unwrap_or(G::ScalarField::zero()),
                },
                witness: &lagrange.d8.this.w,
                coefficient: &column_evaluations.coefficients8,
                vanishes_on_zero_knowledge_and_previous_rows: &index
                    .cs
                    .precomputations()
                    .vanishes_on_zero_knowledge_and_previous_rows,
                z: &lagrange.d8.this.z,
                l0_1: l0_1(index.cs.domain.d1),
                domain: index.cs.domain,
                index: index_evals,
                lookup: lookup_env,
            }
        };

        let mut cache = expr::Cache::default();

        internal_tracing::checkpoint!(internal_traces; compute_quotient_poly);

        let quotient_poly = {
            // generic
            let mut t4 = {
                let generic_constraint =
                    generic::Generic::combined_constraints(&all_alphas, &mut cache);
                let generic4 = generic_constraint.evaluations(&env);

                if cfg!(debug_assertions) {
                    let p4 = public_poly.evaluate_over_domain_by_ref(index.cs.domain.d4);
                    let gen_minus_pub = &generic4 + &p4;

                    check_constraint!(index, gen_minus_pub);
                }

                generic4
            };

            // permutation
            let (mut t8, bnd) = {
                let alphas =
                    all_alphas.get_alphas(ArgumentType::Permutation, permutation::CONSTRAINTS);
                let (perm, bnd) = index.perm_quot(&lagrange, beta, gamma, &z_poly, alphas)?;

                check_constraint!(index, perm);

                (perm, bnd)
            };

            {
                use crate::circuits::argument::DynArgument;

                let range_check0_enabled = column_evaluations.range_check0_selector8.is_some();
                let range_check1_enabled = column_evaluations.range_check1_selector8.is_some();
                let foreign_field_addition_enabled =
                    column_evaluations.foreign_field_add_selector8.is_some();
                let foreign_field_multiplication_enabled =
                    column_evaluations.foreign_field_mul_selector8.is_some();
                let xor_enabled = column_evaluations.xor_selector8.is_some();
                let rot_enabled = column_evaluations.rot_selector8.is_some();

                for gate in [
                    (
                        (&CompleteAdd::default() as &dyn DynArgument<G::ScalarField>),
                        true,
                    ),
                    (&VarbaseMul::default(), true),
                    (&EndosclMul::default(), true),
                    (&EndomulScalar::default(), true),
                    (&Poseidon::default(), true),
                    // Range check gates
                    (&RangeCheck0::default(), range_check0_enabled),
                    (&RangeCheck1::default(), range_check1_enabled),
                    // Foreign field addition gate
                    (&ForeignFieldAdd::default(), foreign_field_addition_enabled),
                    // Foreign field multiplication gate
                    (
                        &ForeignFieldMul::default(),
                        foreign_field_multiplication_enabled,
                    ),
                    // Xor gate
                    (&Xor16::default(), xor_enabled),
                    // Rot gate
                    (&Rot64::default(), rot_enabled),
                ]
                .into_iter()
                .filter_map(|(gate, is_enabled)| if is_enabled { Some(gate) } else { None })
                {
                    let constraint = gate.combined_constraints(&all_alphas, &mut cache);
                    let eval = constraint.evaluations(&env);
                    if eval.domain().size == t4.domain().size {
                        t4 += &eval;
                    } else if eval.domain().size == t8.domain().size {
                        t8 += &eval;
                    } else {
                        panic!("Bad evaluation")
                    }
                    check_constraint!(index, format!("{:?}", gate.argument_type()), eval);
                }
            };

            // lookup
            {
                if let Some(lcs) = lookup_constraint_system {
                    let constraints = lookup::constraints::constraints(&lcs.configuration, false);
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
                        eval.evals.par_iter_mut().for_each(|x| *x *= alpha_pow);

                        if eval.domain().size == t4.domain().size {
                            t4 += &eval;
                        } else if eval.domain().size == t8.domain().size {
                            t8 += &eval;
                        } else if eval.evals.iter().all(|x| x.is_zero()) {
                            // Skip any 0-valued evaluations
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
            let (mut quotient, res) = f.divide_by_vanishing_poly(index.cs.domain.d1);
            if !res.is_zero() {
                return Err(ProverError::Prover(
                    "rest of division by vanishing polynomial",
                ));
            }

            quotient += &bnd; // already divided by Z_H
            quotient
        };

        //~ 1. commit (hiding) to the quotient polynomial $t$
        let t_comm = { index.srs.commit(&quotient_poly, 7 * num_chunks, rng) };

        //~ 1. Absorb the commitment of the quotient polynomial with the Fq-Sponge.
        absorb_commitment(&mut fq_sponge, &t_comm.commitment);

        //~ 1. Sample $\zeta'$ with the Fq-Sponge.
        let zeta_chal = ScalarChallenge(fq_sponge.challenge());

        //~ 1. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify)
        let zeta = zeta_chal.to_field(endo_r);

        let omega = index.cs.domain.d1.group_gen;
        let zeta_omega = zeta * omega;

        //~ 1. If lookup is used, evaluate the following polynomials at $\zeta$ and $\zeta \omega$:
        if lookup_constraint_system.is_some() {
            //~~ * the aggregation polynomial
            let aggreg = lookup_context
                .aggreg_coeffs
                .as_ref()
                .unwrap()
                .to_chunked_polynomial(num_chunks, index.max_poly_size);

            //~~ * the sorted polynomials
            let sorted = lookup_context
                .sorted_coeffs
                .as_ref()
                .unwrap()
                .iter()
                .map(|c| c.to_chunked_polynomial(num_chunks, index.max_poly_size))
                .collect::<Vec<_>>();

            //~~ * the table polynonial
            let joint_table = lookup_context.joint_lookup_table.as_ref().unwrap();
            let joint_table = joint_table.to_chunked_polynomial(num_chunks, index.max_poly_size);

            lookup_context.lookup_aggregation_eval = Some(PointEvaluations {
                zeta: aggreg.evaluate_chunks(zeta),
                zeta_omega: aggreg.evaluate_chunks(zeta_omega),
            });
            lookup_context.lookup_table_eval = Some(PointEvaluations {
                zeta: joint_table.evaluate_chunks(zeta),
                zeta_omega: joint_table.evaluate_chunks(zeta_omega),
            });
            lookup_context.lookup_sorted_eval = array::from_fn(|i| {
                if i < sorted.len() {
                    let sorted = &sorted[i];
                    Some(PointEvaluations {
                        zeta: sorted.evaluate_chunks(zeta),
                        zeta_omega: sorted.evaluate_chunks(zeta_omega),
                    })
                } else {
                    None
                }
            });
            lookup_context.runtime_lookup_table_eval =
                lookup_context.runtime_table.as_ref().map(|runtime_table| {
                    let runtime_table =
                        runtime_table.to_chunked_polynomial(num_chunks, index.max_poly_size);
                    PointEvaluations {
                        zeta: runtime_table.evaluate_chunks(zeta),
                        zeta_omega: runtime_table.evaluate_chunks(zeta_omega),
                    }
                });
        }

        //~ 1. Chunk evaluate the following polynomials at both $\zeta$ and $\zeta \omega$:
        //~~ * $s_i$
        //~~ * $w_i$
        //~~ * $z$
        //~~ * lookup (TODO, see [this issue](https://github.com/MinaProtocol/mina/issues/13886))
        //~~ * generic selector
        //~~ * poseidon selector
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
        //~    TODO: do we want to specify more on that? It seems unnecessary except for the t polynomial (or if for some reason someone sets that to a low value)

        internal_tracing::checkpoint!(internal_traces; lagrange_basis_eval_zeta_poly);
        let zeta_evals =
            LagrangeBasisEvaluations::new(index.max_poly_size, index.cs.domain.d1, zeta);
        internal_tracing::checkpoint!(internal_traces; lagrange_basis_eval_zeta_omega_poly);
        let zeta_omega_evals =
            LagrangeBasisEvaluations::new(index.max_poly_size, index.cs.domain.d1, zeta_omega);

        let chunked_evals_for_selector =
            |p: &Evaluations<G::ScalarField, D<G::ScalarField>>| PointEvaluations {
                zeta: zeta_evals.evaluate_boolean(p),
                zeta_omega: zeta_omega_evals.evaluate_boolean(p),
            };

        let chunked_evals_for_evaluations =
            |p: &Evaluations<G::ScalarField, D<G::ScalarField>>| PointEvaluations {
                zeta: zeta_evals.evaluate(p),
                zeta_omega: zeta_omega_evals.evaluate(p),
            };

        internal_tracing::checkpoint!(internal_traces; chunk_eval_zeta_omega_poly);
        let chunked_evals = ProofEvaluations::<PointEvaluations<Vec<G::ScalarField>>> {
            public: {
                let chunked = public_poly.to_chunked_polynomial(num_chunks, index.max_poly_size);
                Some(PointEvaluations {
                    zeta: chunked.evaluate_chunks(zeta),
                    zeta_omega: chunked.evaluate_chunks(zeta_omega),
                })
            },
            s: array::from_fn(|i| {
                chunked_evals_for_evaluations(&column_evaluations.permutation_coefficients8[i])
            }),
            coefficients: array::from_fn(|i| {
                chunked_evals_for_evaluations(&column_evaluations.coefficients8[i])
            }),
            w: array::from_fn(|i| {
                let chunked =
                    witness_poly[i].to_chunked_polynomial(num_chunks, index.max_poly_size);
                PointEvaluations {
                    zeta: chunked.evaluate_chunks(zeta),
                    zeta_omega: chunked.evaluate_chunks(zeta_omega),
                }
            }),

            z: {
                let chunked = z_poly.to_chunked_polynomial(num_chunks, index.max_poly_size);
                PointEvaluations {
                    zeta: chunked.evaluate_chunks(zeta),
                    zeta_omega: chunked.evaluate_chunks(zeta_omega),
                }
            },

            lookup_aggregation: lookup_context.lookup_aggregation_eval.take(),
            lookup_table: lookup_context.lookup_table_eval.take(),
            lookup_sorted: array::from_fn(|i| lookup_context.lookup_sorted_eval[i].take()),
            runtime_lookup_table: lookup_context.runtime_lookup_table_eval.take(),
            generic_selector: chunked_evals_for_selector(&column_evaluations.generic_selector4),
            poseidon_selector: chunked_evals_for_selector(&column_evaluations.poseidon_selector8),
            complete_add_selector: chunked_evals_for_selector(
                &column_evaluations.complete_add_selector4,
            ),
            mul_selector: chunked_evals_for_selector(&column_evaluations.mul_selector8),
            emul_selector: chunked_evals_for_selector(&column_evaluations.emul_selector8),
            endomul_scalar_selector: chunked_evals_for_selector(
                &column_evaluations.endomul_scalar_selector8,
            ),

            range_check0_selector: column_evaluations
                .range_check0_selector8
                .as_ref()
                .map(chunked_evals_for_selector),
            range_check1_selector: column_evaluations
                .range_check1_selector8
                .as_ref()
                .map(chunked_evals_for_selector),
            foreign_field_add_selector: column_evaluations
                .foreign_field_add_selector8
                .as_ref()
                .map(chunked_evals_for_selector),
            foreign_field_mul_selector: column_evaluations
                .foreign_field_mul_selector8
                .as_ref()
                .map(chunked_evals_for_selector),
            xor_selector: column_evaluations
                .xor_selector8
                .as_ref()
                .map(chunked_evals_for_selector),
            rot_selector: column_evaluations
                .rot_selector8
                .as_ref()
                .map(chunked_evals_for_selector),

            runtime_lookup_table_selector: lookup_constraint_system.as_ref().and_then(|lcs| {
                lcs.runtime_selector
                    .as_ref()
                    .map(chunked_evals_for_selector)
            }),
            xor_lookup_selector: lookup_constraint_system.as_ref().and_then(|lcs| {
                lcs.lookup_selectors
                    .xor
                    .as_ref()
                    .map(chunked_evals_for_selector)
            }),
            lookup_gate_lookup_selector: lookup_constraint_system.as_ref().and_then(|lcs| {
                lcs.lookup_selectors
                    .lookup
                    .as_ref()
                    .map(chunked_evals_for_selector)
            }),
            range_check_lookup_selector: lookup_constraint_system.as_ref().and_then(|lcs| {
                lcs.lookup_selectors
                    .range_check
                    .as_ref()
                    .map(chunked_evals_for_selector)
            }),
            foreign_field_mul_lookup_selector: lookup_constraint_system.as_ref().and_then(|lcs| {
                lcs.lookup_selectors
                    .ffmul
                    .as_ref()
                    .map(chunked_evals_for_selector)
            }),
        };

        let zeta_to_srs_len = zeta.pow([index.max_poly_size as u64]);
        let zeta_omega_to_srs_len = zeta_omega.pow([index.max_poly_size as u64]);
        let zeta_to_domain_size = zeta.pow([d1_size as u64]);

        //~ 1. Evaluate the same polynomials without chunking them
        //~    (so that each polynomial should correspond to a single value this time).
        let evals: ProofEvaluations<PointEvaluations<G::ScalarField>> = {
            let powers_of_eval_points_for_chunks = PointEvaluations {
                zeta: zeta_to_srs_len,
                zeta_omega: zeta_omega_to_srs_len,
            };
            chunked_evals.combine(&powers_of_eval_points_for_chunks)
        };

        //~ 1. Compute the ft polynomial.
        //~    This is to implement [Maller's optimization](https://o1-labs.github.io/proof-systems/kimchi/maller_15.html).
        internal_tracing::checkpoint!(internal_traces; compute_ft_poly);
        let ft: DensePolynomial<G::ScalarField> = {
            let f_chunked = {
                // TODO: compute the linearization polynomial in evaluation form so
                // that we can drop the coefficient forms of the index polynomials from
                // the constraint system struct

                // permutation (not part of linearization yet)
                let alphas =
                    all_alphas.get_alphas(ArgumentType::Permutation, permutation::CONSTRAINTS);
                let f = index.perm_lnrz(&evals, zeta, beta, gamma, alphas);

                // the circuit polynomial
                let f = {
                    let (_lin_constant, mut lin) =
                        index.linearization.to_polynomial(&env, zeta, &evals);
                    lin += &f;
                    lin.interpolate()
                };

                drop(env);

                // see https://o1-labs.github.io/proof-systems/kimchi/maller_15.html#the-prover-side
                f.to_chunked_polynomial(num_chunks, index.max_poly_size)
                    .linearize(zeta_to_srs_len)
            };

            let t_chunked = quotient_poly
                .to_chunked_polynomial(7 * num_chunks, index.max_poly_size)
                .linearize(zeta_to_srs_len);

            &f_chunked - &t_chunked.scale(zeta_to_domain_size - G::ScalarField::one())
        };

        //~ 1. construct the blinding part of the ft polynomial commitment
        //~    [see this section](https://o1-labs.github.io/proof-systems/kimchi/maller_15.html#evaluation-proof-and-blinding-factors)
        let blinding_ft = {
            let blinding_t = t_comm.blinders.chunk_blinding(zeta_to_srs_len);
            let blinding_f = G::ScalarField::zero();

            PolyComm {
                // blinding_f - Z_H(zeta) * blinding_t
                chunks: vec![
                    blinding_f - (zeta_to_domain_size - G::ScalarField::one()) * blinding_t,
                ],
            }
        };

        //~ 1. Evaluate the ft polynomial at $\zeta\omega$ only.
        internal_tracing::checkpoint!(internal_traces; ft_eval_zeta_omega);
        let ft_eval1 = ft.evaluate(&zeta_omega);

        //~ 1. Setup the Fr-Sponge
        let fq_sponge_before_evaluations = fq_sponge.clone();
        let mut fr_sponge = EFrSponge::new(G::sponge_params());

        //~ 1. Squeeze the Fq-sponge and absorb the result with the Fr-Sponge.
        fr_sponge.absorb(&fq_sponge.digest());

        //~ 1. Absorb the previous recursion challenges.
        let prev_challenge_digest = {
            // Note: we absorb in a new sponge here to limit the scope in which we need the
            // more-expensive 'optional sponge'.
            let mut fr_sponge = EFrSponge::new(G::sponge_params());
            for RecursionChallenge { chals, .. } in &prev_challenges {
                fr_sponge.absorb_multiple(chals);
            }
            fr_sponge.digest()
        };
        fr_sponge.absorb(&prev_challenge_digest);

        //~ 1. Compute evaluations for the previous recursion challenges.
        internal_tracing::checkpoint!(internal_traces; build_polynomials);
        let polys = prev_challenges
            .iter()
            .map(|RecursionChallenge { chals, comm }| {
                (
                    DensePolynomial::from_coefficients_vec(b_poly_coefficients(chals)),
                    comm.len(),
                )
            })
            .collect::<Vec<_>>();

        //~ 1. Absorb the unique evaluation of ft: $ft(\zeta\omega)$.
        fr_sponge.absorb(&ft_eval1);

        //~ 1. Absorb all the polynomial evaluations in $\zeta$ and $\zeta\omega$:
        //~~ * the public polynomial
        //~~ * z
        //~~ * generic selector
        //~~ * poseidon selector
        //~~ * the 15 register/witness
        //~~ * 6 sigmas evaluations (the last one is not evaluated)
        fr_sponge.absorb_multiple(&chunked_evals.public.as_ref().unwrap().zeta);
        fr_sponge.absorb_multiple(&chunked_evals.public.as_ref().unwrap().zeta_omega);
        fr_sponge.absorb_evaluations(&chunked_evals);

        //~ 1. Sample $v'$ with the Fr-Sponge
        let v_chal = fr_sponge.challenge();

        //~ 1. Derive $v$ from $v'$ using the endomorphism (TODO: specify)
        let v = v_chal.to_field(endo_r);

        //~ 1. Sample $u'$ with the Fr-Sponge
        let u_chal = fr_sponge.challenge();

        //~ 1. Derive $u$ from $u'$ using the endomorphism (TODO: specify)
        let u = u_chal.to_field(endo_r);

        //~ 1. Create a list of all polynomials that will require evaluations
        //~    (and evaluation proofs) in the protocol.
        //~    First, include the previous challenges, in case we are in a recursive prover.
        let non_hiding = |n_chunks: usize| PolyComm {
            chunks: vec![G::ScalarField::zero(); n_chunks],
        };

        let fixed_hiding = |n_chunks: usize| PolyComm {
            chunks: vec![G::ScalarField::one(); n_chunks],
        };

        let coefficients_form = DensePolynomialOrEvaluations::DensePolynomial;
        let evaluations_form = |e| DensePolynomialOrEvaluations::Evaluations(e, index.cs.domain.d1);

        let mut polynomials = polys
            .iter()
            .map(|(p, n_chunks)| (coefficients_form(p), non_hiding(*n_chunks)))
            .collect::<Vec<_>>();

        //~ 1. Then, include:
        //~~ * the negated public polynomial
        //~~ * the ft polynomial
        //~~ * the permutation aggregation polynomial z polynomial
        //~~ * the generic selector
        //~~ * the poseidon selector
        //~~ * the 15 registers/witness columns
        //~~ * the 6 sigmas
        polynomials.push((coefficients_form(&public_poly), fixed_hiding(num_chunks)));
        polynomials.push((coefficients_form(&ft), blinding_ft));
        polynomials.push((coefficients_form(&z_poly), z_comm.blinders));
        polynomials.push((
            evaluations_form(&column_evaluations.generic_selector4),
            fixed_hiding(num_chunks),
        ));
        polynomials.push((
            evaluations_form(&column_evaluations.poseidon_selector8),
            fixed_hiding(num_chunks),
        ));
        polynomials.push((
            evaluations_form(&column_evaluations.complete_add_selector4),
            fixed_hiding(num_chunks),
        ));
        polynomials.push((
            evaluations_form(&column_evaluations.mul_selector8),
            fixed_hiding(num_chunks),
        ));
        polynomials.push((
            evaluations_form(&column_evaluations.emul_selector8),
            fixed_hiding(num_chunks),
        ));
        polynomials.push((
            evaluations_form(&column_evaluations.endomul_scalar_selector8),
            fixed_hiding(num_chunks),
        ));
        polynomials.extend(
            witness_poly
                .iter()
                .zip(w_comm.iter())
                .map(|(w, c)| (coefficients_form(w), c.blinders.clone()))
                .collect::<Vec<_>>(),
        );
        polynomials.extend(
            column_evaluations
                .coefficients8
                .iter()
                .map(|coefficientm| (evaluations_form(coefficientm), non_hiding(num_chunks)))
                .collect::<Vec<_>>(),
        );
        polynomials.extend(
            column_evaluations.permutation_coefficients8[0..PERMUTS - 1]
                .iter()
                .map(|w| (evaluations_form(w), non_hiding(num_chunks)))
                .collect::<Vec<_>>(),
        );

        //~~ * the optional gates
        if let Some(range_check0_selector8) = &column_evaluations.range_check0_selector8 {
            polynomials.push((
                evaluations_form(range_check0_selector8),
                non_hiding(num_chunks),
            ));
        }
        if let Some(range_check1_selector8) = &column_evaluations.range_check1_selector8 {
            polynomials.push((
                evaluations_form(range_check1_selector8),
                non_hiding(num_chunks),
            ));
        }
        if let Some(foreign_field_add_selector8) = &column_evaluations.foreign_field_add_selector8 {
            polynomials.push((
                evaluations_form(foreign_field_add_selector8),
                non_hiding(num_chunks),
            ));
        }
        if let Some(foreign_field_mul_selector8) = &column_evaluations.foreign_field_mul_selector8 {
            polynomials.push((
                evaluations_form(foreign_field_mul_selector8),
                non_hiding(num_chunks),
            ));
        }
        if let Some(xor_selector8) = &column_evaluations.xor_selector8 {
            polynomials.push((evaluations_form(xor_selector8), non_hiding(num_chunks)));
        }
        if let Some(rot_selector8) = &column_evaluations.rot_selector8 {
            polynomials.push((evaluations_form(rot_selector8), non_hiding(num_chunks)));
        }

        //~~ * optionally, the runtime table
        //~ 1. if using lookup:
        if let Some(lcs) = lookup_constraint_system {
            //~~ * add the lookup sorted polynomials
            let sorted_poly = lookup_context.sorted_coeffs.as_ref().unwrap();
            let sorted_comms = lookup_context.sorted_comms.as_ref().unwrap();

            for (poly, comm) in sorted_poly.iter().zip(sorted_comms) {
                polynomials.push((coefficients_form(poly), comm.blinders.clone()));
            }

            //~~ * add the lookup aggreg polynomial
            let aggreg_poly = lookup_context.aggreg_coeffs.as_ref().unwrap();
            let aggreg_comm = lookup_context.aggreg_comm.as_ref().unwrap();
            polynomials.push((coefficients_form(aggreg_poly), aggreg_comm.blinders.clone()));

            //~~ * add the combined table polynomial
            let table_blinding = {
                let joint_combiner = lookup_context.joint_combiner.as_ref().unwrap();
                let table_id_combiner = lookup_context.table_id_combiner.as_ref().unwrap();
                let max_fixed_lookup_table_size = {
                    // CAUTION: This is not `lcs.configuration.lookup_info.max_joint_size` because
                    // the lookup table may be strictly narrower, and as such will not contribute
                    // the associated blinders.
                    // For example, using a runtime table with the lookup gate (width 2), but only
                    // width-1 fixed tables (e.g. range check), it would be incorrect to use the
                    // wider width (2) because there are no such contributing commitments!
                    // Note that lookup_table8 is a list of polynomials
                    lcs.lookup_table8.len()
                };
                let base_blinding = {
                    let fixed_table_blinding = if max_fixed_lookup_table_size == 0 {
                        G::ScalarField::zero()
                    } else {
                        (1..max_fixed_lookup_table_size).fold(G::ScalarField::one(), |acc, _| {
                            G::ScalarField::one() + *joint_combiner * acc
                        })
                    };
                    fixed_table_blinding + *table_id_combiner
                };
                if lcs.runtime_selector.is_some() {
                    let runtime_comm = lookup_context.runtime_table_comm.as_ref().unwrap();

                    let chunks = runtime_comm
                        .blinders
                        .into_iter()
                        .map(|blinding| *joint_combiner * *blinding + base_blinding)
                        .collect();

                    PolyComm::new(chunks)
                } else {
                    let chunks = vec![base_blinding; num_chunks];
                    PolyComm::new(chunks)
                }
            };

            let joint_lookup_table = lookup_context.joint_lookup_table.as_ref().unwrap();

            polynomials.push((coefficients_form(joint_lookup_table), table_blinding));

            //~~ * if present, add the runtime table polynomial
            if lcs.runtime_selector.is_some() {
                let runtime_table_comm = lookup_context.runtime_table_comm.as_ref().unwrap();
                let runtime_table = lookup_context.runtime_table.as_ref().unwrap();

                polynomials.push((
                    coefficients_form(runtime_table),
                    runtime_table_comm.blinders.clone(),
                ));
            }

            //~~ * the lookup selectors

            if let Some(runtime_lookup_table_selector) = &lcs.runtime_selector {
                polynomials.push((
                    evaluations_form(runtime_lookup_table_selector),
                    non_hiding(1),
                ))
            }
            if let Some(xor_lookup_selector) = &lcs.lookup_selectors.xor {
                polynomials.push((evaluations_form(xor_lookup_selector), non_hiding(1)))
            }
            if let Some(lookup_gate_selector) = &lcs.lookup_selectors.lookup {
                polynomials.push((evaluations_form(lookup_gate_selector), non_hiding(1)))
            }
            if let Some(range_check_lookup_selector) = &lcs.lookup_selectors.range_check {
                polynomials.push((evaluations_form(range_check_lookup_selector), non_hiding(1)))
            }
            if let Some(foreign_field_mul_lookup_selector) = &lcs.lookup_selectors.ffmul {
                polynomials.push((
                    evaluations_form(foreign_field_mul_lookup_selector),
                    non_hiding(1),
                ))
            }
        }

        //~ 1. Create an aggregated evaluation proof for all of these polynomials at $\zeta$ and $\zeta\omega$ using $u$ and $v$.
        internal_tracing::checkpoint!(internal_traces; create_aggregated_ipa);
        let proof = OpenProof::open(
            &*index.srs,
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
                aggreg: a.commitment,
                sorted: s.iter().map(|c| c.commitment.clone()).collect(),
                runtime: lookup_context.runtime_table_comm.map(|x| x.commitment),
            });

        let proof = Self {
            commitments: ProverCommitments {
                w_comm: array::from_fn(|i| w_comm[i].commitment.clone()),
                z_comm: z_comm.commitment,
                t_comm: t_comm.commitment,
                lookup,
            },
            proof,
            evals: chunked_evals,
            ft_eval1,
            prev_challenges,
        };

        internal_tracing::checkpoint!(internal_traces; create_recursive_done);

        Ok(proof)
    }
}

internal_tracing::decl_traces!(internal_traces;
    pasta_fp_plonk_proof_create,
    pasta_fq_plonk_proof_create,
    create_recursive,
    pad_witness,
    set_up_fq_sponge,
    commit_to_witness_columns,
    use_lookup,
    z_permutation_aggregation_polynomial,
    eval_witness_polynomials_over_domains,
    compute_index_evals,
    compute_quotient_poly,
    lagrange_basis_eval_zeta_poly,
    lagrange_basis_eval_zeta_omega_poly,
    chunk_eval_zeta_omega_poly,
    compute_ft_poly,
    ft_eval_zeta_omega,
    build_polynomials,
    create_aggregated_ipa,
    create_recursive_done);

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use crate::proof::caml::{CamlProofEvaluations, CamlRecursionChallenge};
    use ark_ec::AffineRepr;
    use poly_commitment::{
        commitment::caml::CamlPolyComm,
        ipa::{caml::CamlOpeningProof, OpeningProof},
    };

    #[cfg(feature = "internal_tracing")]
    pub use internal_traces::caml::CamlTraces as CamlProverTraces;

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlProofWithPublic<CamlG, CamlF> {
        pub public_evals: Option<PointEvaluations<Vec<CamlF>>>,
        pub proof: CamlProverProof<CamlG, CamlF>,
    }

    //
    // CamlProverProof<CamlG, CamlF>
    //

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlProverProof<CamlG, CamlF> {
        pub commitments: CamlProverCommitments<CamlG>,
        pub proof: CamlOpeningProof<CamlG, CamlF>,
        // OCaml doesn't have sized arrays, so we have to convert to a tuple..
        pub evals: CamlProofEvaluations<CamlF>,
        pub ft_eval1: CamlF,
        pub public: Vec<CamlF>,
        //Vec<(Vec<CamlF>, CamlPolyComm<CamlG>)>,
        pub prev_challenges: Vec<CamlRecursionChallenge<CamlG, CamlF>>,
    }

    //
    // CamlProverCommitments<CamlG>
    //

    #[derive(Clone, ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlLookupCommitments<CamlG> {
        pub sorted: Vec<CamlPolyComm<CamlG>>,
        pub aggreg: CamlPolyComm<CamlG>,
        pub runtime: Option<CamlPolyComm<CamlG>>,
    }

    #[allow(clippy::type_complexity)]
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
        pub lookup: Option<CamlLookupCommitments<CamlG>>,
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
    // we can do that, but instead we implemented the From trait for the reverse
    // operations (From<G> for CamlG).
    // it reduces the complexity, but forces us to do the conversion in two
    // phases instead of one.

    //
    // CamlLookupCommitments<CamlG> <-> LookupCommitments<G>
    //

    impl<G, CamlG> From<LookupCommitments<G>> for CamlLookupCommitments<CamlG>
    where
        G: AffineRepr,
        CamlPolyComm<CamlG>: From<PolyComm<G>>,
    {
        fn from(
            LookupCommitments {
                aggreg,
                sorted,
                runtime,
            }: LookupCommitments<G>,
        ) -> Self {
            Self {
                aggreg: aggreg.into(),
                sorted: sorted.into_iter().map(Into::into).collect(),
                runtime: runtime.map(Into::into),
            }
        }
    }

    impl<G, CamlG> From<CamlLookupCommitments<CamlG>> for LookupCommitments<G>
    where
        G: AffineRepr,
        PolyComm<G>: From<CamlPolyComm<CamlG>>,
    {
        fn from(
            CamlLookupCommitments {
                aggreg,
                sorted,
                runtime,
            }: CamlLookupCommitments<CamlG>,
        ) -> LookupCommitments<G> {
            LookupCommitments {
                aggreg: aggreg.into(),
                sorted: sorted.into_iter().map(Into::into).collect(),
                runtime: runtime.map(Into::into),
            }
        }
    }

    //
    // CamlProverCommitments<CamlG> <-> ProverCommitments<G>
    //

    impl<G, CamlG> From<ProverCommitments<G>> for CamlProverCommitments<CamlG>
    where
        G: AffineRepr,
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
                lookup: prover_comm.lookup.map(Into::into),
            }
        }
    }

    impl<G, CamlG> From<CamlProverCommitments<CamlG>> for ProverCommitments<G>
    where
        G: AffineRepr,
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
                lookup: caml_prover_comm.lookup.map(Into::into),
            }
        }
    }

    //
    // ProverProof<G> <-> CamlProofWithPublic<CamlG, CamlF>
    //

    impl<G, CamlG, CamlF> From<(ProverProof<G, OpeningProof<G>>, Vec<G::ScalarField>)>
        for CamlProofWithPublic<CamlG, CamlF>
    where
        G: AffineRepr,
        CamlG: From<G>,
        CamlF: From<G::ScalarField>,
    {
        fn from(pp: (ProverProof<G, OpeningProof<G>>, Vec<G::ScalarField>)) -> Self {
            let (public_evals, evals) = pp.0.evals.into();
            CamlProofWithPublic {
                public_evals,
                proof: CamlProverProof {
                    commitments: pp.0.commitments.into(),
                    proof: pp.0.proof.into(),
                    evals,
                    ft_eval1: pp.0.ft_eval1.into(),
                    public: pp.1.into_iter().map(Into::into).collect(),
                    prev_challenges: pp.0.prev_challenges.into_iter().map(Into::into).collect(),
                },
            }
        }
    }

    impl<G, CamlG, CamlF> From<CamlProofWithPublic<CamlG, CamlF>>
        for (ProverProof<G, OpeningProof<G>>, Vec<G::ScalarField>)
    where
        CamlF: Clone,
        G: AffineRepr + From<CamlG>,
        G::ScalarField: From<CamlF>,
    {
        fn from(
            caml_pp: CamlProofWithPublic<CamlG, CamlF>,
        ) -> (ProverProof<G, OpeningProof<G>>, Vec<G::ScalarField>) {
            let CamlProofWithPublic {
                public_evals,
                proof: caml_pp,
            } = caml_pp;
            let proof = ProverProof {
                commitments: caml_pp.commitments.into(),
                proof: caml_pp.proof.into(),
                evals: (public_evals, caml_pp.evals).into(),
                ft_eval1: caml_pp.ft_eval1.into(),
                prev_challenges: caml_pp
                    .prev_challenges
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            };

            (proof, caml_pp.public.into_iter().map(Into::into).collect())
        }
    }
}
