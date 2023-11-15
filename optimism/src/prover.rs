use crate::mips::{
    columns::{ColumnsEnv, NUM_LOOKUP_TERMS},
    proof::{Proof, ProofCommitments, ProofEvaluations},
    prover_index::ProverIndex,
    witness::{Lookup, Witness},
};
use crate::{
    circuits::expr::Constants, curve::KimchiCurve,
    lagrange_basis_evaluations::LagrangeBasisEvaluations, plonk_sponge::FrSponge,
    proof::PointEvaluations,
};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain as D,
};
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use o1_utils::ExtendedDensePolynomial;
use poly_commitment::commitment::{absorb_commitment, PolyComm};
use poly_commitment::evaluation_proof::DensePolynomialOrEvaluations;
use std::array;
use strum::IntoEnumIterator;

impl<G: KimchiCurve> Proof<G>
where
    G::BaseField: PrimeField,
{
    pub fn create<
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
        EFrSponge: FrSponge<G::ScalarField>,
    >(
        group_map: &G::Map,
        witness: Witness<G::ScalarField>,
        index: &ProverIndex<G>,
    ) -> Result<Self, &'static str> {
        // TODO: rng should be passed as arg
        let rng = &mut rand::rngs::OsRng;

        let d1_size = index.domain.d1.size();

        let Witness {
            instruction_parts,
            instruction_selectors,
            lookups,
            initial_memory,
            final_memory,
            final_memory_write_index,
            initial_registers,
            final_registers,
            final_registers_write_index,
            instruction_pointers,
            scratch_states,
            lookup_counters,
            halt,
        } = witness;

        let (_, endo_r) = G::endos();

        // Create sponge
        let mut fq_sponge = EFqSponge::new(G::OtherCurve::sponge_params());

        // Fixed column commitments
        for comm in index.fixed_columns_commitments.as_ref().into_iter() {
            absorb_commitment(&mut fq_sponge, &comm);
        }

        // Memory commitments
        let initial_memory = initial_memory
            .into_iter()
            .map(|(_offset, initial_memory)| {
                let evals = initial_memory
                    .into_iter()
                    .map(|x| G::ScalarField::from(x as u64))
                    .collect::<Vec<_>>();
                let evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                    evals,
                    index.domain.d1,
                );
                evals.interpolate().evaluate_over_domain(index.domain.d8)
            })
            .collect::<Vec<_>>();
        let initial_memory_comms = initial_memory
            .iter()
            .map(|initial_memory| {
                let comm = index
                    .srs
                    .commit_evaluations_non_hiding(index.domain.d1, &initial_memory);
                absorb_commitment(&mut fq_sponge, &comm);
                comm
            })
            .collect();

        let final_memory = final_memory
            .into_iter()
            .map(|(_offset, final_memory)| {
                let evals = final_memory
                    .into_iter()
                    .map(|x| G::ScalarField::from(x as u64))
                    .collect::<Vec<_>>();
                let evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                    evals,
                    index.domain.d1,
                );
                evals.interpolate().evaluate_over_domain(index.domain.d8)
            })
            .collect::<Vec<_>>();
        let final_memory_comms = final_memory
            .iter()
            .map(|final_memory| {
                let comm = index
                    .srs
                    .commit_evaluations_non_hiding(index.domain.d1, &final_memory);
                absorb_commitment(&mut fq_sponge, &comm);
                comm
            })
            .collect();

        let final_memory_write_index = {
            final_memory_write_index
                .into_iter()
                .map(|(_offset, final_memory_write_index)| {
                    let evals = final_memory_write_index
                        .into_iter()
                        .map(|x| G::ScalarField::from(x as u64))
                        .collect::<Vec<_>>();
                    let evals =
                        Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                            evals,
                            index.domain.d1,
                        );
                    evals.interpolate().evaluate_over_domain(index.domain.d8)
                })
                .collect::<Vec<_>>()
        };
        let final_memory_write_index_comms = final_memory_write_index
            .iter()
            .map(|final_memory_write_index| {
                let comm = index
                    .srs
                    .commit_evaluations_non_hiding(index.domain.d1, &final_memory_write_index);
                absorb_commitment(&mut fq_sponge, &comm);
                comm
            })
            .collect();

        // Registers commitments
        let initial_registers = {
            let evals = initial_registers
                .iter()
                .map(|x| G::ScalarField::from(*x as u64))
                .collect::<Vec<_>>();
            let evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                evals,
                index.domain.d1,
            );
            evals.interpolate().evaluate_over_domain(index.domain.d8)
        };
        let initial_registers_comm = index
            .srs
            .commit_evaluations_non_hiding(index.domain.d1, &initial_registers);
        absorb_commitment(&mut fq_sponge, &initial_registers_comm);

        let final_registers = {
            let evals = final_registers
                .iter()
                .map(|x| G::ScalarField::from(*x as u64))
                .collect::<Vec<_>>();
            let evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                evals,
                index.domain.d1,
            );
            evals.interpolate().evaluate_over_domain(index.domain.d8)
        };
        let final_registers_comm = index
            .srs
            .commit_evaluations_non_hiding(index.domain.d1, &final_registers);
        absorb_commitment(&mut fq_sponge, &final_registers_comm);

        let final_registers_write_index = {
            let evals = final_registers_write_index
                .iter()
                .map(|x| G::ScalarField::from(*x as u64))
                .collect::<Vec<_>>();
            let evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                evals,
                index.domain.d1,
            );
            evals.interpolate().evaluate_over_domain(index.domain.d8)
        };
        let final_registers_write_index_comm = index
            .srs
            .commit_evaluations_non_hiding(index.domain.d1, &final_registers_write_index);
        absorb_commitment(&mut fq_sponge, &final_registers_write_index_comm);

        // Instruction decoding commitments
        let instruction_parts = instruction_parts.map(|evals| {
            let evals = evals
                .into_iter()
                .map(|x| G::ScalarField::from(x as u64))
                .collect::<Vec<_>>();
            let evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                evals,
                index.domain.d1,
            );
            evals.interpolate().evaluate_over_domain(index.domain.d8)
        });

        let parts_comms = instruction_parts.as_ref().map(|evals| {
            index
                .srs
                .commit_evaluations_non_hiding(index.domain.d1, evals)
        });

        for comm in parts_comms.as_ref().into_iter() {
            absorb_commitment(&mut fq_sponge, &comm);
        }

        // Selector commitments
        let instruction_selectors = instruction_selectors.map(|bools| {
            let field_bools = bools
                .into_iter()
                .map(|x| {
                    if x {
                        G::ScalarField::one()
                    } else {
                        G::ScalarField::zero()
                    }
                })
                .collect::<Vec<_>>();
            let evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                field_bools,
                index.domain.d1,
            );
            evals.interpolate().evaluate_over_domain(index.domain.d8)
        });

        let selector_comms = instruction_selectors.as_ref().map(|evals| {
            index
                .srs
                .commit_evaluations_non_hiding(index.domain.d1, evals)
        });

        for comm in selector_comms.as_ref().into_iter() {
            absorb_commitment(&mut fq_sponge, &comm);
        }

        // Instruction pointer
        let instruction_pointer = {
            let evals = instruction_pointers
                .into_iter()
                .map(|ip| G::ScalarField::from(ip as u64))
                .collect();
            let evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                evals,
                index.domain.d1,
            );
            evals.interpolate().evaluate_over_domain(index.domain.d8)
        };
        let instruction_pointer_comm = index
            .srs
            .commit_evaluations_non_hiding(index.domain.d1, &instruction_pointer);
        absorb_commitment(&mut fq_sponge, &instruction_pointer_comm);

        // Scratch state
        let scratch_state = array::from_fn(|i| {
            let evals = scratch_states.iter().map(|state| state[i]).collect();
            let evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                evals,
                index.domain.d1,
            );
            evals.interpolate().evaluate_over_domain(index.domain.d8)
        });
        let scratch_state_comms = array::from_fn(|i| {
            index
                .srs
                .commit_evaluations_non_hiding(index.domain.d1, &scratch_state[i])
        });

        for comm in scratch_state_comms.iter() {
            absorb_commitment(&mut fq_sponge, comm);
        }

        // Halt
        let halt = {
            let evals = halt
                .into_iter()
                .map(|b| {
                    if b {
                        G::ScalarField::one()
                    } else {
                        G::ScalarField::zero()
                    }
                })
                .collect();
            let evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                evals,
                index.domain.d1,
            );
            evals.interpolate().evaluate_over_domain(index.domain.d8)
        };
        let halt_comm = index
            .srs
            .commit_evaluations_non_hiding(index.domain.d1, &halt);

        absorb_commitment(&mut fq_sponge, &halt_comm);

        // Lookup counters
        let lookup_counters = lookup_counters.map(|evals| {
            let evals = evals
                .into_iter()
                .map(|x| G::ScalarField::from(x as u64))
                .collect();
            let evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                evals,
                index.domain.d1,
            );
            evals.interpolate().evaluate_over_domain(index.domain.d8)
        });

        let lookup_counters_comms = lookup_counters.as_ref().map(|evals| {
            index
                .srs
                .commit_evaluations_non_hiding(index.domain.d1, evals)
        });

        for comm in lookup_counters_comms.as_ref().into_iter() {
            absorb_commitment(&mut fq_sponge, &comm);
        }

        let vector_lookup_value_combiner = fq_sponge.challenge();

        let beta = fq_sponge.challenge();

        // Lookup terms
        let lookup_terms: [_; NUM_LOOKUP_TERMS] = array::from_fn(|i| {
            let mut denominators = Vec::with_capacity(6 * d1_size);
            for row_lookups in lookups.iter() {
                for Lookup {
                    numerator: _,
                    table_id,
                    value,
                } in row_lookups[i].iter()
                {
                    let combined_value = value.iter().rev().fold(G::ScalarField::zero(), |x, y| {
                        x * vector_lookup_value_combiner + y
                    }) * vector_lookup_value_combiner
                        + table_id;

                    let lookup_denominator = beta + combined_value;
                    denominators.push(lookup_denominator);
                }
            }
            ark_ff::fields::batch_inversion(&mut denominators);

            let mut evals = Vec::with_capacity(d1_size);
            let mut denominator_index = 0;
            for row_lookups in lookups.iter() {
                let mut row_acc = G::ScalarField::zero();
                for Lookup {
                    numerator,
                    table_id: _,
                    value: _,
                } in row_lookups[i].iter()
                {
                    row_acc += *numerator * denominators[denominator_index];
                    denominator_index += 1;
                }
                evals.push(row_acc)
            }
            //
            let evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                evals,
                index.domain.d1,
            );
            //
            evals.interpolate().evaluate_over_domain(index.domain.d8)
        });

        let lookup_terms_comms = array::from_fn(|i| {
            index
                .srs
                .commit_evaluations_non_hiding(index.domain.d1, &lookup_terms[i])
        });

        for comm in lookup_terms_comms.iter() {
            absorb_commitment(&mut fq_sponge, &comm);
        }

        // Lookup aggregation
        let lookup_aggregation = {
            let mut evals = Vec::with_capacity(d1_size);
            let mut acc = G::ScalarField::zero();
            // Accumulate lookup terms
            for i in 0..d1_size {
                evals.push(acc);
                for terms in lookup_terms.iter() {
                    acc += terms[8 * i];
                }
            }
            assert_eq!(acc, G::ScalarField::zero());
            let evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                evals,
                index.domain.d1,
            );
            evals.interpolate().evaluate_over_domain(index.domain.d8)
        };

        let lookup_aggregation_comm = index
            .srs
            .commit_evaluations_non_hiding(index.domain.d1, &lookup_aggregation);

        absorb_commitment(&mut fq_sponge, &lookup_aggregation_comm);

        // Squeeze constraint combiner
        let constraint_combiner_chal = ScalarChallenge(fq_sponge.challenge());
        let constraint_combiner: G::ScalarField = constraint_combiner_chal.to_field(endo_r);

        let constants = Constants {
            alpha: constraint_combiner,
            beta,
            gamma: G::ScalarField::zero(),
            joint_combiner: Some(vector_lookup_value_combiner),
            endo_coefficient: *endo_r,
            mds: &G::sponge_params().mds,
        };

        let env = ColumnsEnv {
            constants,
            domain: index.domain,
            instruction_parts: instruction_parts.as_ref(),
            instruction_selectors: instruction_selectors.as_ref(),
            fixed_columns: index.fixed_columns.as_ref(),
            initial_memory: &initial_memory,
            final_memory: &final_memory,
            final_memory_write_index: &final_memory_write_index,
            initial_registers: &initial_registers,
            final_registers: &final_registers,
            final_registers_write_index: &final_registers_write_index,
            lookup_aggregation: &lookup_aggregation,
            lookup_terms: &lookup_terms,
            instruction_pointer: &instruction_pointer,
            scratch_state: &scratch_state,
            halt: &halt,
            lookup_counters: lookup_counters.as_ref(),
            vanishes_on_last_row: &index.vanishes_on_last_row,
            l0_1: index.l0_1,
        };

        // Quotient polynomial
        let quotient_poly = {
            let f = index.constraints.evaluations(&env);
            // Debugging; delete
            let step_size = f.evals.len() / d1_size;
            for i in 0..d1_size {
                if !f.evals[step_size * i].is_zero() {
                    println!("constraints: {}", index.constraints);
                    println!("eval: {}", f.evals[step_size * i]);
                    println!("eval: {}", -f.evals[step_size * i]);
                    println!("i: {}", i);
                    println!("halt: {}", halt.evals[i * (halt.evals.len() / d1_size)]);
                    println!(
                        "ip: {}",
                        instruction_pointer.evals[i * (instruction_pointer.evals.len() / d1_size)]
                    );
                    if i < d1_size - 1 {
                        println!(
                            "ip next: {}",
                            instruction_pointer.evals
                                [(i + 1) * (instruction_pointer.evals.len() / d1_size)]
                        );
                    }
                    for sel in crate::mips::columns::InstructionSelector::iter() {
                        let sel_evals = &instruction_selectors[sel];
                        let step_size = sel_evals.evals.len() / d1_size;
                        if !sel_evals.evals[step_size * i].is_zero() {
                            println!("sel: {:?}", sel);
                        }
                    }
                    if i > 0 {
                        for sel in crate::mips::columns::InstructionSelector::iter() {
                            let sel_evals = &instruction_selectors[sel];
                            let step_size = sel_evals.evals.len() / d1_size;
                            if !sel_evals.evals[step_size * (i - 1)].is_zero() {
                                println!("previous sel: {:?}", sel);
                            }
                        }
                    }
                    panic!("Found the failing instruction");
                }
            }
            let (quotient, res) = f
                .interpolate()
                .divide_by_vanishing_poly(index.domain.d1)
                .ok_or("division by vanishing polynomial")?;
            if !res.is_zero() {
                return Err("rest of division by vanishing polynomial");
            }
            quotient
        };

        // Quotient commitment
        let t_comm = {
            let mut t_comm = index.srs.commit_non_hiding(&quotient_poly, None);
            let expected_t_size = 7;
            let dummies = expected_t_size - t_comm.unshifted.len();
            for _ in 0..dummies {
                t_comm.unshifted.push(G::zero());
            }
            t_comm
        };
        absorb_commitment(&mut fq_sponge, &t_comm);

        // Absorb commitments

        // Sample evaluation point
        let evaluation_point_chal = ScalarChallenge(fq_sponge.challenge());
        let evaluation_point = evaluation_point_chal.to_field(endo_r);

        let omega = index.domain.d1.group_gen;
        let evaluation_point_omega = evaluation_point * omega;

        let evaluation_points = [evaluation_point, evaluation_point_omega];

        let evaluation_point_to_domain_size = evaluation_point.pow([index.domain.d1.size() as u64]);

        // Clone for opening proof
        let fq_sponge_before_evaluations = fq_sponge.clone();

        // Create sponge
        let mut fr_sponge = EFrSponge::new(G::sponge_params());

        // Initialize sponge
        fr_sponge.absorb(&fq_sponge.digest());

        let evaluation_point_evals =
            LagrangeBasisEvaluations::new(index.domain.d1, evaluation_point);
        let evaluation_point_omega_evals =
            LagrangeBasisEvaluations::new(index.domain.d1, evaluation_point_omega);

        let evaluate = |evals| PointEvaluations {
            zeta: evaluation_point_evals.evaluate(evals),
            zeta_omega: evaluation_point_omega_evals.evaluate(evals),
        };

        let mut absorb_point_evaluation = |eval: &PointEvaluations<_>| {
            fr_sponge.absorb(&eval.zeta);
            fr_sponge.absorb(&eval.zeta_omega);
        };

        // Fixed column evaluations
        let fixed_column_evals = index.fixed_columns.as_ref().map(evaluate);

        for eval in fixed_column_evals.as_ref().into_iter() {
            absorb_point_evaluation(eval);
        }

        // Memory evaluations
        let initial_memory_evals = initial_memory
            .iter()
            .map(|initial_memory| {
                let eval = evaluate(&initial_memory);
                absorb_point_evaluation(&eval);
                eval
            })
            .collect::<Vec<_>>();
        let final_memory_evals = final_memory
            .iter()
            .map(|final_memory| {
                let eval = evaluate(&final_memory);
                absorb_point_evaluation(&eval);
                eval
            })
            .collect::<Vec<_>>();
        let final_memory_write_index_evals = final_memory_write_index
            .iter()
            .map(|final_memory_write_index| {
                let eval = evaluate(&final_memory_write_index);
                absorb_point_evaluation(&eval);
                eval
            })
            .collect::<Vec<_>>();

        // Register evaluations
        let initial_registers_eval = evaluate(&initial_registers);
        absorb_point_evaluation(&initial_registers_eval);
        let final_registers_eval = evaluate(&final_registers);
        absorb_point_evaluation(&final_registers_eval);
        let final_registers_write_index_eval = evaluate(&final_registers_write_index);
        absorb_point_evaluation(&final_registers_write_index_eval);

        // Instruction decoding evaluations

        let parts_evals = instruction_parts.as_ref().map(evaluate);

        for eval in parts_evals.as_ref().into_iter() {
            absorb_point_evaluation(eval);
        }

        // Selector evaluations
        let selector_evals = instruction_selectors.as_ref().map(evaluate);

        for eval in selector_evals.as_ref().into_iter() {
            absorb_point_evaluation(eval);
        }

        // Instruction_pointer
        let instruction_pointer_evals = evaluate(&instruction_pointer);
        absorb_point_evaluation(&instruction_pointer_evals);

        // Scratch state
        let scratch_state_evals = array::from_fn(|i| evaluate(&scratch_state[i]));
        for eval in scratch_state_evals.iter() {
            absorb_point_evaluation(eval);
        }

        // Halt
        let halt_eval = evaluate(&halt);
        absorb_point_evaluation(&halt_eval);

        // Lookup counters
        let lookup_counters_evals = lookup_counters.as_ref().map(evaluate);
        for eval in lookup_counters_evals.as_ref().into_iter() {
            absorb_point_evaluation(eval);
        }

        // Lookup terms
        let lookup_terms_evals: [_; NUM_LOOKUP_TERMS] =
            array::from_fn(|i| evaluate(&lookup_terms[i]));

        for eval in lookup_terms_evals.iter() {
            absorb_point_evaluation(eval);
        }

        // Lookup aggregation
        let lookup_aggregation_eval = evaluate(&lookup_aggregation);
        absorb_point_evaluation(&lookup_aggregation_eval);

        let ft: DensePolynomial<G::ScalarField> = {
            let t_chunked = quotient_poly
                .to_chunked_polynomial(d1_size)
                .linearize(evaluation_point_to_domain_size);
            t_chunked.scale(G::ScalarField::one() - evaluation_point_to_domain_size)
        };

        let ft_eval1 = ft.evaluate(&evaluation_point_omega);

        // Absorb evaluations
        fr_sponge.absorb(&ft_eval1);

        let polyscale_chal = fr_sponge.challenge();
        let polyscale = polyscale_chal.to_field(endo_r);

        let evalscale_chal = fr_sponge.challenge();
        let evalscale = evalscale_chal.to_field(endo_r);

        let non_hiding = |d1_size: usize| PolyComm {
            unshifted: vec![G::ScalarField::zero(); d1_size],
            shifted: None,
        };
        let coefficients_form = DensePolynomialOrEvaluations::DensePolynomial;
        let evaluation_form = |e| DensePolynomialOrEvaluations::Evaluations(e, index.domain.d1);

        let mut polynomials: Vec<_> = instruction_parts
            .as_ref()
            .into_iter()
            .chain(instruction_selectors.as_ref().into_iter())
            .chain(index.fixed_columns.as_ref().into_iter())
            .chain(initial_memory.iter())
            .chain(final_memory.iter())
            .chain(final_memory_write_index.iter())
            .chain([
                &initial_registers,
                &final_registers,
                &final_registers_write_index,
            ])
            .chain([&instruction_pointer])
            .chain(scratch_state.iter())
            .chain([&halt])
            .chain(lookup_counters.as_ref().into_iter())
            .chain(lookup_terms.iter())
            .chain([&lookup_aggregation])
            .map(|evals| (evaluation_form(evals), None, non_hiding(1)))
            .collect();
        polynomials.push((coefficients_form(&ft), None, non_hiding(1)));

        let opening_proof = index.srs.open(
            group_map,
            &polynomials,
            &evaluation_points,
            polyscale,
            evalscale,
            fq_sponge_before_evaluations,
            rng,
        );
        Ok(Proof {
            opening_proof,
            ft_eval1,
            t_comm,
            commitments: ProofCommitments {
                instruction_parts: parts_comms,
                instruction_selectors: selector_comms,
                initial_memory: initial_memory_comms,
                final_memory: final_memory_comms,
                final_memory_write_index: final_memory_write_index_comms,
                initial_registers: initial_registers_comm,
                final_registers: final_registers_comm,
                final_registers_write_index: final_registers_write_index_comm,
                lookup_terms: lookup_terms_comms,
                lookup_aggregation: lookup_aggregation_comm,
                instruction_pointer: instruction_pointer_comm,
                scratch_state: scratch_state_comms,
                lookup_counters: lookup_counters_comms,
                halt: halt_comm,
            },
            evaluations: ProofEvaluations {
                instruction_parts: parts_evals,
                instruction_selectors: selector_evals,
                fixed_columns: fixed_column_evals,
                initial_memory: initial_memory_evals,
                final_memory: final_memory_evals,
                final_memory_write_index: final_memory_write_index_evals,
                initial_registers: initial_registers_eval,
                final_registers: final_registers_eval,
                final_registers_write_index: final_registers_write_index_eval,
                lookup_terms: lookup_terms_evals,
                lookup_aggregation: lookup_aggregation_eval,
                instruction_pointer: instruction_pointer_evals,
                scratch_state: scratch_state_evals,
                lookup_counters: lookup_counters_evals,
                halt: halt_eval,
            },
        })
    }
}
