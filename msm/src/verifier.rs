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

use crate::DOMAIN_SIZE;

use crate::mvlookup::LookupProof;
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
        // FIXME
        lookup_commitments: _,
        opening_proof,
    } = proof;

    // -- Absorbing the commitments
    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());
    for comm in commitments.a.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }
    for comm in commitments.b.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }
    for comm in commitments.c.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }
    // TODO: Lookup
    // absorb_commitment(&mut fq_sponge, lookup_counter);
    // for comm in lookup_terms.iter() {
    //     absorb_commitment(&mut fq_sponge, comm)
    // }
    // absorb_commitment(&mut fq_sponge, lookup_aggregation);

    // -- Finish absorbing the commitments

    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let zeta: G::ScalarField = zeta_chal.to_field(endo_r);
    let omega = domain.d1.group_gen;
    let zeta_omega = zeta * omega;

    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    let mut es: Vec<_> = zeta_evaluations
        .a
        .iter()
        .zip(zeta_omega_evaluations.a.iter())
        .map(|(zeta, zeta_omega)| (vec![vec![*zeta], vec![*zeta_omega]], None))
        .collect();
    es.extend(
        zeta_evaluations
            .b
            .iter()
            .zip(zeta_omega_evaluations.b.iter())
            .map(|(zeta, zeta_omega)| (vec![vec![*zeta], vec![*zeta_omega]], None))
            .collect::<Vec<_>>(),
    );
    es.extend(
        zeta_evaluations
            .c
            .iter()
            .zip(zeta_omega_evaluations.c.iter())
            .map(|(zeta, zeta_omega)| (vec![vec![*zeta], vec![*zeta_omega]], None))
            .collect::<Vec<_>>(),
    );

    let mut evaluations: Vec<_> = commitments
        .a
        .iter()
        .zip(
            zeta_evaluations
                .a
                .iter()
                .zip(zeta_omega_evaluations.a.iter()),
        )
        .map(|(commitment, (zeta_eval, zeta_omega_eval))| Evaluation {
            commitment: commitment.clone(),
            evaluations: vec![vec![*zeta_eval], vec![*zeta_omega_eval]],
            degree_bound: None,
        })
        .collect();
    evaluations.extend(
        commitments
            .b
            .iter()
            .zip(
                zeta_evaluations
                    .b
                    .iter()
                    .zip(zeta_omega_evaluations.b.iter()),
            )
            .map(|(commitment, (zeta_eval, zeta_omega_eval))| Evaluation {
                commitment: commitment.clone(),
                evaluations: vec![vec![*zeta_eval], vec![*zeta_omega_eval]],
                degree_bound: None,
            })
            .collect::<Vec<_>>(),
    );
    evaluations.extend(
        commitments
            .c
            .iter()
            .zip(
                zeta_evaluations
                    .c
                    .iter()
                    .zip(zeta_omega_evaluations.c.iter()),
            )
            .map(|(commitment, (zeta_eval, zeta_omega_eval))| Evaluation {
                commitment: commitment.clone(),
                evaluations: vec![vec![*zeta_eval], vec![*zeta_omega_eval]],
                degree_bound: None,
            })
            .collect::<Vec<_>>(),
    );
    // TODO: add lookup

    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .a
        .iter()
        .zip(zeta_omega_evaluations.a.iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }
    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .b
        .iter()
        .zip(zeta_omega_evaluations.b.iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }
    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .c
        .iter()
        .zip(zeta_omega_evaluations.c.iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }

    let v_chal = fr_sponge.challenge();
    let v = v_chal.to_field(endo_r);
    let u_chal = fr_sponge.challenge();
    let u = u_chal.to_field(endo_r);

    let combined_inner_product =
        combined_inner_product(&[zeta, zeta_omega], &v, &u, es.as_slice(), DOMAIN_SIZE);

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
