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
    const N: usize,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    proof: &Proof<N, G, OpeningProof>,
) -> bool {
    let Proof {
        commitments,
        zeta_evaluations,
        zeta_omega_evaluations,
        mvlookup_commitments,
        mvlookup_zeta_evaluations,
        mvlookup_zeta_omega_evaluations,
        opening_proof,
    } = proof;

    // -- Absorbing the commitments
    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());
    commitments
        .into_iter()
        .for_each(|comm| absorb_commitment(&mut fq_sponge, comm));
    if let Some(mvlookup_commitments) = mvlookup_commitments {
        mvlookup_commitments
            .into_iter()
            .for_each(|comm| absorb_commitment(&mut fq_sponge, comm));
    }
    // -- Finish absorbing the commitments

    // -- Preparing for opening proof verification
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let zeta: G::ScalarField = zeta_chal.to_field(endo_r);
    let omega = domain.d1.group_gen;
    let zeta_omega = zeta * omega;

    let mut es: Vec<Vec<Vec<G::ScalarField>>> = zeta_evaluations
        .into_iter()
        .zip(zeta_omega_evaluations)
        .map(|(zeta, zeta_omega)| vec![vec![*zeta], vec![*zeta_omega]])
        .collect::<Vec<Vec<Vec<G::ScalarField>>>>();

    if mvlookup_commitments.is_some() {
        let mvlookup_evals = mvlookup_zeta_evaluations
            .as_ref()
            .unwrap()
            .into_iter()
            .zip(mvlookup_zeta_omega_evaluations.as_ref().unwrap())
            .map(|(zeta, zeta_omega)| vec![vec![*zeta], vec![*zeta_omega]])
            .collect::<Vec<Vec<Vec<G::ScalarField>>>>();
        es.extend(mvlookup_evals);
    }

    let mut evaluations: Vec<Evaluation<_>> = commitments
        .into_iter()
        .zip(zeta_evaluations.into_iter().zip(zeta_omega_evaluations))
        .map(|(commitment, (zeta_eval, zeta_omega_eval))| Evaluation {
            commitment: commitment.clone(),
            evaluations: vec![vec![*zeta_eval], vec![*zeta_omega_eval]],
        })
        .collect();

    if let Some(mvlookup_commitments) = mvlookup_commitments {
        evaluations.extend(
            mvlookup_commitments
                .into_iter()
                .zip(
                    mvlookup_zeta_evaluations
                        .as_ref()
                        .unwrap()
                        .into_iter()
                        .zip(mvlookup_zeta_omega_evaluations.as_ref().unwrap()),
                )
                .map(|(commitment, (zeta_eval, zeta_omega_eval))| Evaluation {
                    commitment: commitment.clone(),
                    evaluations: vec![vec![*zeta_eval], vec![*zeta_omega_eval]],
                })
                .collect::<Vec<_>>(),
        );
    }

    // -- Absorb all evaluations
    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    for (zeta_eval, zeta_omega_eval) in zeta_evaluations.into_iter().zip(zeta_omega_evaluations) {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }
    if mvlookup_commitments.is_some() {
        // MVLookup FS
        for (zeta_eval, zeta_omega_eval) in
            mvlookup_zeta_evaluations.as_ref().unwrap().into_iter().zip(
                mvlookup_zeta_omega_evaluations
                    .as_ref()
                    .unwrap()
                    .into_iter(),
            )
        {
            fr_sponge.absorb(zeta_eval);
            fr_sponge.absorb(zeta_omega_eval);
        }
    };
    // -- End absorb all evaluations

    let v_chal = fr_sponge.challenge();
    let v = v_chal.to_field(endo_r);
    let u_chal = fr_sponge.challenge();
    let u = u_chal.to_field(endo_r);

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
