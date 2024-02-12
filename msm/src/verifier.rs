use kimchi::circuits::domains::EvaluationDomains;
use kimchi::plonk_sponge::FrSponge;
use kimchi::{curve::KimchiCurve, groupmap::GroupMap};
use mina_poseidon::sponge::ScalarChallenge;
use mina_poseidon::FqSponge;
use poly_commitment::{
    commitment::{absorb_commitment, combined_inner_product, BatchEvaluationProof, Evaluation},
    OpenProof,
};
use rand::thread_rng;

use crate::proof::Proof;

pub fn verify<
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    proof: &Proof<G, OpeningProof>,
) -> bool {
    let Proof {
        commitments,
        zeta_evaluations,
        zeta_omega_evaluations,
        opening_proof,
    } = proof;

    // -- Absorbing the commitments
    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());
    commitments
        .into_iter()
        .for_each(|comm| absorb_commitment(&mut fq_sponge, comm));
    // -- Finish absorbing the commitments

    // -- Preparing for opening proof verification
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let zeta: G::ScalarField = zeta_chal.to_field(endo_r);
    let omega = domain.d1.group_gen;
    let zeta_omega = zeta * omega;

    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    let es: Vec<_> = zeta_evaluations
        .into_iter()
        .zip(zeta_omega_evaluations)
        .map(|(zeta, zeta_omega)| (vec![vec![*zeta], vec![*zeta_omega]], None))
        .collect();

    let evaluations: Vec<_> = commitments
        .into_iter()
        .zip(zeta_evaluations.into_iter().zip(zeta_omega_evaluations))
        .map(|(commitment, (zeta_eval, zeta_omega_eval))| Evaluation {
            commitment: commitment.clone(),
            evaluations: vec![vec![*zeta_eval], vec![*zeta_omega_eval]],
            degree_bound: None,
        })
        .collect();

    // -- Absorb all evaluations
    for (zeta_eval, zeta_omega_eval) in zeta_evaluations.into_iter().zip(zeta_omega_evaluations) {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }
    // -- End absorb all evaluations

    let v_chal = fr_sponge.challenge();
    let v = v_chal.to_field(endo_r);
    let u_chal = fr_sponge.challenge();
    let u = u_chal.to_field(endo_r);

    let combined_inner_product = combined_inner_product(
        &[zeta, zeta_omega],
        &v,
        &u,
        es.as_slice(),
        domain.d1.size as usize,
    );

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
