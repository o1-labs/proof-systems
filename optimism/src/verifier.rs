use crate::{proof::Proof, verifier_index::VerifierIndex};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::EvaluationDomain;
use kimchi::{
    circuits::expr::{Constants, PolishToken},
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
    proof::PointEvaluations,
};
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use poly_commitment::commitment::{
    absorb_commitment, combined_inner_product, BatchEvaluationProof, Evaluation,
};
use rand::thread_rng;

impl<G: KimchiCurve> Proof<G>
where
    G::BaseField: PrimeField,
{
    pub fn verify<
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
        EFrSponge: FrSponge<G::ScalarField>,
    >(
        &self,
        group_map: &G::Map,
        index: &VerifierIndex<G>,
    ) -> Result<(), &'static str> {
        let d1_size = index.domain.d1.size();

        let (_, endo_r) = G::endos();

        // Create sponge
        let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());

        // Absorb commitments

        // Fixed column commitments
        for comm in index.fixed_columns.as_ref().into_iter() {
            absorb_commitment(&mut fq_sponge, &comm);
        }

        // Memory commitments
        for comm in self.commitments.initial_memory.iter() {
            absorb_commitment(&mut fq_sponge, &comm);
        }
        for comm in self.commitments.final_memory.iter() {
            absorb_commitment(&mut fq_sponge, &comm);
        }
        for comm in self.commitments.final_memory_write_index.iter() {
            absorb_commitment(&mut fq_sponge, &comm);
        }

        // Register commitments
        absorb_commitment(&mut fq_sponge, &self.commitments.initial_registers);
        absorb_commitment(&mut fq_sponge, &self.commitments.final_registers);
        absorb_commitment(
            &mut fq_sponge,
            &self.commitments.final_registers_write_index,
        );

        for comm in self.commitments.instruction_parts.as_ref().into_iter() {
            absorb_commitment(&mut fq_sponge, &comm);
        }

        for comm in self.commitments.instruction_selectors.as_ref().into_iter() {
            absorb_commitment(&mut fq_sponge, &comm);
        }

        absorb_commitment(&mut fq_sponge, &self.commitments.instruction_pointer);

        for comm in self.commitments.scratch_state.iter() {
            absorb_commitment(&mut fq_sponge, &comm);
        }

        absorb_commitment(&mut fq_sponge, &self.commitments.halt);

        for comm in self.commitments.lookup_counters.as_ref().into_iter() {
            absorb_commitment(&mut fq_sponge, comm);
        }

        let vector_lookup_value_combiner = fq_sponge.challenge();

        let beta = fq_sponge.challenge();

        for comm in self.commitments.lookup_terms.iter() {
            absorb_commitment(&mut fq_sponge, &comm);
        }

        absorb_commitment(&mut fq_sponge, &self.commitments.lookup_aggregation);

        // Squeeze constraint combiner
        let constraint_combiner_chal = ScalarChallenge(fq_sponge.challenge());
        let constraint_combiner: G::ScalarField = constraint_combiner_chal.to_field(endo_r);

        absorb_commitment(&mut fq_sponge, &self.t_comm);

        // Sample evaluation point
        let evaluation_point_chal = ScalarChallenge(fq_sponge.challenge());
        let evaluation_point = evaluation_point_chal.to_field(endo_r);

        let omega = index.domain.d1.group_gen;
        let evaluation_point_omega = evaluation_point * omega;

        let evaluation_points = vec![evaluation_point, evaluation_point_omega];

        let evaluation_point_to_domain_size = evaluation_point.pow([d1_size as u64]);

        // Clone for opening proof
        let fq_sponge_before_evaluations = fq_sponge.clone();

        // Create sponge
        let mut fr_sponge = EFrSponge::new(G::sponge_params());

        // Initialize sponge
        fr_sponge.absorb(&fq_sponge.digest());

        let mut absorb_point_evaluation = |eval: &PointEvaluations<_>| {
            fr_sponge.absorb(&eval.zeta);
            fr_sponge.absorb(&eval.zeta_omega);
        };

        for eval in self.evaluations.fixed_columns.as_ref().into_iter() {
            absorb_point_evaluation(eval);
        }

        for eval in self.evaluations.initial_memory.iter() {
            absorb_point_evaluation(eval);
        }
        for eval in self.evaluations.final_memory.iter() {
            absorb_point_evaluation(eval);
        }
        for eval in self.evaluations.final_memory_write_index.iter() {
            absorb_point_evaluation(eval);
        }

        absorb_point_evaluation(&self.evaluations.initial_registers);
        absorb_point_evaluation(&self.evaluations.final_registers);
        absorb_point_evaluation(&self.evaluations.final_registers_write_index);

        for eval in self.evaluations.instruction_parts.as_ref().into_iter() {
            absorb_point_evaluation(eval);
        }

        for eval in self.evaluations.instruction_selectors.as_ref().into_iter() {
            absorb_point_evaluation(eval);
        }

        absorb_point_evaluation(&self.evaluations.instruction_pointer);

        for eval in self.evaluations.scratch_state.iter() {
            absorb_point_evaluation(eval);
        }

        absorb_point_evaluation(&self.evaluations.halt);

        for eval in self.evaluations.lookup_counters.as_ref().into_iter() {
            absorb_point_evaluation(eval);
        }

        for eval in self.evaluations.lookup_terms.iter() {
            absorb_point_evaluation(eval);
        }

        absorb_point_evaluation(&self.evaluations.lookup_aggregation);

        let ft_comm = {
            let chunked_t_comm = self
                .t_comm
                .chunk_commitment(evaluation_point_to_domain_size);
            chunked_t_comm.scale(G::ScalarField::one() - evaluation_point_to_domain_size)
        };

        let constants = Constants {
            alpha: constraint_combiner,
            beta,
            gamma: G::ScalarField::zero(), /* TODO */
            joint_combiner: Some(vector_lookup_value_combiner),
            endo_coefficient: *endo_r,
            mds: &G::sponge_params().mds,
            // TODO/FIXME(dw): 3 might not be correct. Didn't check more. I just
            // want to have this file compiled
            zk_rows: 3,
        };

        let ft_eval0 = -PolishToken::evaluate(
            // TODO(dw): constraints
            &[],
            // &index.constraints,
            index.domain.d1,
            evaluation_point,
            &self.evaluations,
            &constants,
        )
        .unwrap();

        // Absorb evaluations
        fr_sponge.absorb(&self.ft_eval1);

        let polyscale_chal = fr_sponge.challenge();
        let polyscale = polyscale_chal.to_field(endo_r);

        let evalscale_chal = fr_sponge.challenge();
        let evalscale = evalscale_chal.to_field(endo_r);

        let mut evaluations: Vec<_> = (self
            .commitments
            .instruction_parts
            .as_ref()
            .into_iter()
            .zip(self.evaluations.instruction_parts.as_ref().into_iter()))
        .chain(
            (self.commitments.instruction_selectors.as_ref().into_iter())
                .zip(self.evaluations.instruction_selectors.as_ref().into_iter()),
        )
        .chain(
            (index.fixed_columns.as_ref().into_iter())
                .zip(self.evaluations.fixed_columns.as_ref().into_iter()),
        )
        .chain(
            self.commitments
                .initial_memory
                .iter()
                .zip(self.evaluations.initial_memory.iter()),
        )
        .chain(
            self.commitments
                .final_memory
                .iter()
                .zip(self.evaluations.final_memory.iter()),
        )
        .chain(
            self.commitments
                .final_memory_write_index
                .iter()
                .zip(self.evaluations.final_memory_write_index.iter()),
        )
        .chain([
            (
                &self.commitments.initial_registers,
                &self.evaluations.initial_registers,
            ),
            (
                &self.commitments.final_registers,
                &self.evaluations.final_registers,
            ),
            (
                &self.commitments.final_registers_write_index,
                &self.evaluations.final_registers_write_index,
            ),
        ])
        .chain([(
            &self.commitments.instruction_pointer,
            &self.evaluations.instruction_pointer,
        )])
        .chain((self.commitments.scratch_state.iter()).zip(self.evaluations.scratch_state.iter()))
        .chain([(&self.commitments.halt, &self.evaluations.halt)])
        .chain(
            (self.commitments.lookup_counters.as_ref().into_iter())
                .zip(self.evaluations.lookup_counters.as_ref().into_iter()),
        )
        .chain((self.commitments.lookup_terms.iter()).zip(self.evaluations.lookup_terms.iter()))
        .chain([(
            &self.commitments.lookup_aggregation,
            &self.evaluations.lookup_aggregation,
        )])
        .map(|(commitment, evaluations)| Evaluation {
            commitment: commitment.clone(),
            evaluations: vec![vec![evaluations.zeta], vec![evaluations.zeta_omega]],
            degree_bound: None,
        })
        .collect();
        evaluations.push(Evaluation {
            commitment: ft_comm,
            evaluations: vec![vec![ft_eval0], vec![self.ft_eval1]],
            degree_bound: None,
        });

        // \sum e_i u
        let combined_inner_product = {
            let es: Vec<_> = evaluations
                .iter()
                .map(|eval| (eval.evaluations.clone(), None))
                .collect();
            combined_inner_product(
                &evaluation_points,
                &polyscale,
                &evalscale,
                &es,
                index.srs.g.len(),
            )
        };

        let mut batch = vec![BatchEvaluationProof {
            sponge: fq_sponge_before_evaluations,
            evaluations,
            evaluation_points: evaluation_points,
            polyscale,
            evalscale,
            opening: &self.opening_proof,
            combined_inner_product,
        }];
        if index
            .srs
            .verify::<EFqSponge, _>(group_map, &mut batch, &mut thread_rng())
        {
            Ok(())
        } else {
            Err("Opening proof did not verify")
        }
    }
}
