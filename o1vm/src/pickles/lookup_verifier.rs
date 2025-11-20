use crate::pickles::lookup_columns::*;
use ark_ff::{Field, One, PrimeField, Zero};
use kimchi::{
    circuits::{
        domains::EvaluationDomains,
        expr::{Constants, PolishToken},
    },
    curve::KimchiCurve,
    groupmap::GroupMap,
    plonk_sponge::FrSponge,
};
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use poly_commitment::{
    commitment::{absorb_commitment, combined_inner_product, BatchEvaluationProof, Evaluation},
    ipa::OpeningProof,
    OpenProof, PolyComm,
};
use rand::thread_rng;

pub fn lookup_verify<
    G: KimchiCurve,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
>(
    // input dependent of main proto
    beta_challenge: G::ScalarField,
    gamma_challenge: G::ScalarField,
    constraint: ELookup<G::ScalarField>,
    mut fq_sponge: EFqSponge,
    // fixed input
    // TODO: we don't need the whole domain
    domain: EvaluationDomains<G::ScalarField>,
    srs: &<OpeningProof<G> as OpenProof<G>>::SRS,
    // proof
    proof: &Proof<G>,
) -> bool
where
    G::BaseField: PrimeField,
{
    let Proof {
        commitments,
        evaluations,
        ipa_proof,
    } = proof;

    ///////
    // Reproduce plonkish FS challenges
    //////

    // absorbing commit
    // TODO don't absorb the wires which already have been
    // when the same TODO is done in the prover
    commitments
        .clone()
        .cols
        .into_iter()
        .for_each(|com| absorb_commitment(&mut fq_sponge, &PolyComm { chunks: vec![com] }));

    let (_, endo_r) = G::endos();

    // Sample α with the Fq-Sponge.
    let alpha = fq_sponge.challenge();

    // absorb quotient polynomial
    // TODO: avoid cloning
    absorb_commitment(
        &mut fq_sponge,
        &PolyComm {
            chunks: commitments.clone().t_shares,
        },
    );

    // squeeze zeta
    // TODO: understand why we use the endo here and for IPA ,
    // but not for alpha
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());

    let zeta: G::ScalarField = zeta_chal.to_field(endo_r);
    let zeta_omega = zeta * domain.d1.group_gen;

    ///////
    // Verify IPA
    //////

    let fq_sponge_before_evaluations = fq_sponge.clone();

    // Creating fr_sponge, absorbing eval to create challenges for IPA
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    // TODO avoid cloning
    evaluations
        .clone()
        .into_iter()
        .for_each(|x| fr_sponge.absorb(&x));
    // Create IPA challenges
    // poly scale
    let polyscale_chal = fr_sponge.challenge();
    let polyscale = polyscale_chal.to_field(endo_r);
    // eval scale
    let evalscale_chal = fr_sponge.challenge();
    let evalscale = evalscale_chal.to_field(endo_r);

    // Pack the evaluations and commitments
    // in the right format for IPA

    // Handling columns without quotient
    let mut eval_for_ipa: Vec<_> = evaluations
        .clone()
        .zeta
        .cols
        .into_iter()
        .zip(evaluations.clone().zeta_omega.cols)
        .zip(commitments.clone().cols)
        .map(|((zeta, zeta_omega), cm)| Evaluation {
            commitment: PolyComm { chunks: vec![cm] },
            evaluations: vec![vec![zeta], vec![zeta_omega]],
        })
        .collect();
    // adding quotient
    // TODO avoid cloning
    eval_for_ipa.push(Evaluation {
        commitment: PolyComm {
            chunks: commitments.clone().t_shares,
        },
        evaluations: vec![
            evaluations.clone().zeta.t_shares,
            evaluations.clone().zeta_omega.t_shares,
        ],
    });

    // Compute combined eval point
    let combined_inner_product = {
        let es: Vec<_> = eval_for_ipa
            .iter()
            .map(|Evaluation { evaluations, .. }| evaluations.clone())
            .collect();

        combined_inner_product(&polyscale, &evalscale, es.as_slice())
    };
    let ipa_input = BatchEvaluationProof {
        sponge: fq_sponge_before_evaluations,
        evaluations: eval_for_ipa,
        evaluation_points: vec![zeta, zeta_omega],
        polyscale,
        evalscale,
        opening: ipa_proof,
        combined_inner_product,
    };
    let group_map = G::Map::setup();
    let ipa_is_correct = OpeningProof::verify(srs, &group_map, &mut [ipa_input], &mut thread_rng());

    ////////
    // Compute numerator zeta
    ///////

    let challenges = LookupChallenges {
        alpha,
        beta: beta_challenge,
        gamma: gamma_challenge,
    };
    // TODO : we should not care about the kimchi constants here
    let constants = Constants {
        endo_coefficient: *endo_r,
        mds: &G::sponge_params().mds,
        zk_rows: 0,
    };
    let numerator_zeta = PolishToken::evaluate(
        constraint.to_polish().as_slice(),
        domain.d1,
        zeta,
        evaluations,
        &constants,
        &challenges,
    )
    .unwrap_or_else(|_| panic!("Could not evaluate quotient polynomial at zeta"));

    ////////
    // Check quotient correctness
    ///////

    let zeta_pow_n = zeta.pow([domain.d1.size]);
    let (quotient_zeta, _) = evaluations.zeta.t_shares.iter().fold(
        (G::ScalarField::zero(), G::ScalarField::one()),
        |(res, zeta_i_n), chunk| {
            let res = res + zeta_i_n * chunk;
            let zeta_i_n = zeta_i_n * zeta_pow_n;
            (res, zeta_i_n)
        },
    );

    let quotient_is_correct =
        quotient_zeta == numerator_zeta / (zeta_pow_n - G::ScalarField::one());
    quotient_is_correct && ipa_is_correct
}
