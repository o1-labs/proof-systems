use ark_ff::{Field, One, Zero};

use kimchi::circuits::domains::EvaluationDomains;
use kimchi::circuits::expr::{Challenges, Constants, Expr, PolishToken};
use kimchi::plonk_sponge::FrSponge;
use kimchi::proof::PointEvaluations;
use kimchi::{curve::KimchiCurve, groupmap::GroupMap};
use mina_poseidon::sponge::ScalarChallenge;
use mina_poseidon::FqSponge;
use poly_commitment::{
    commitment::{absorb_commitment, combined_inner_product, BatchEvaluationProof, Evaluation},
    OpenProof,
};
use rand::thread_rng;

use crate::constraint::MSMExpr;
use crate::proof::Proof;

pub fn verify<
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    constraint_exprs: Vec<MSMExpr<G::ScalarField>>,
    proof: &Proof<G, OpeningProof>,
) -> bool {
    let Proof {
        proof_comms,
        proof_evals,
        opening_proof,
    } = proof;

    // -- Absorbing the commitments
    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());
    proof_comms
        .witness_comms
        .into_iter()
        .for_each(|comm| absorb_commitment(&mut fq_sponge, comm));

    if let Some(mvlookup_comms) = &proof_comms.mvlookup_comms {
        mvlookup_comms
            .into_iter()
            .for_each(|comm| absorb_commitment(&mut fq_sponge, comm));
    }

    //~ 1. Sample $\alpha'$ with the Fq-Sponge.
    let alpha_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let alpha: G::ScalarField = alpha_chal.to_field(endo_r);

    absorb_commitment(&mut fq_sponge, &proof_comms.t_comm);

    // -- Finish absorbing the commitments

    // -- Preparing for opening proof verification
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let zeta: G::ScalarField = zeta_chal.to_field(endo_r);
    let omega = domain.d1.group_gen;
    let zeta_omega = zeta * omega;

    let mut evaluations: Vec<Evaluation<_>> = proof_comms
        .witness_comms
        .into_iter()
        .zip(proof_evals.witness_evals.into_iter())
        .map(|(commitment, point_eval)| Evaluation {
            commitment: commitment.clone(),
            evaluations: vec![vec![point_eval.zeta], vec![point_eval.zeta_omega]],
        })
        .collect();

    if let Some(mvlookup_comms) = &proof_comms.mvlookup_comms {
        evaluations.extend(
            mvlookup_comms
                .into_iter()
                .zip(proof_evals.mvlookup_evals.as_ref().unwrap().into_iter())
                .map(|(commitment, point_eval)| Evaluation {
                    commitment: commitment.clone(),
                    evaluations: vec![vec![point_eval.zeta], vec![point_eval.zeta_omega]],
                })
                .collect::<Vec<_>>(),
        );
    }

    // -- Absorb all evaluations
    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    for PointEvaluations { zeta, zeta_omega } in proof_evals.witness_evals.into_iter() {
        fr_sponge.absorb(zeta);
        fr_sponge.absorb(zeta_omega);
    }
    if proof_comms.mvlookup_comms.is_some() {
        // MVLookup FS
        for PointEvaluations { zeta, zeta_omega } in
            proof_evals.mvlookup_evals.as_ref().unwrap().into_iter()
        {
            fr_sponge.absorb(zeta);
            fr_sponge.absorb(zeta_omega);
        }
    };

    let ft_comm = {
        // TODO zeta or zeta*omega?
        let evaluation_point_to_domain_size = zeta.pow([domain.d1.size]);
        let chunked_t_comm = proof_comms
            .t_comm
            .chunk_commitment(evaluation_point_to_domain_size);
        chunked_t_comm.scale(G::ScalarField::one() - evaluation_point_to_domain_size)
    };

    let challenges = Challenges {
        alpha,
        beta: G::ScalarField::zero(),
        gamma: G::ScalarField::zero(),
        joint_combiner: None,
    };

    let constants = Constants {
        endo_coefficient: *endo_r,
        mds: &G::sponge_params().mds,
        zk_rows: 0,
    };

    let combined_expr =
        Expr::combine_constraints(0..(constraint_exprs.len() as u32), constraint_exprs);
    let ft_eval0 = -PolishToken::evaluate(
        combined_expr.to_polish().as_slice(),
        domain.d1,
        zeta,
        proof_evals,
        &constants,
        &challenges,
    )
    .unwrap();

    evaluations.push(Evaluation {
        commitment: ft_comm,
        evaluations: vec![vec![ft_eval0], vec![proof_evals.ft_eval1]],
    });

    fr_sponge.absorb(&proof_evals.ft_eval1);
    // -- End absorb all evaluations

    let v_chal = fr_sponge.challenge();
    let v = v_chal.to_field(endo_r);
    let u_chal = fr_sponge.challenge();
    let u = u_chal.to_field(endo_r);

    let es: Vec<_> = evaluations
        .iter()
        .map(|Evaluation { evaluations, .. }| evaluations.clone())
        .collect();

    let combined_inner_product = combined_inner_product(&v, &u, es.as_slice());

    let batch = BatchEvaluationProof {
        sponge: fq_sponge_before_evaluations,
        evaluations,
        evaluation_points: vec![zeta, zeta_omega],
        polyscale: v,
        evalscale: u,
        opening: opening_proof,
        combined_inner_product,
    };

    let group_map = G::Map::setup();
    OpeningProof::verify(srs, &group_map, &mut [batch], &mut thread_rng())
}
