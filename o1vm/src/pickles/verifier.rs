#![allow(clippy::type_complexity)]
#![allow(clippy::boxed_local)]

use ark_ff::{Field, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain as R2D,
};
use rand::thread_rng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use kimchi::{
    circuits::{
        berkeley_columns::BerkeleyChallenges,
        domains::EvaluationDomains,
        expr::{Constants, Expr, PolishToken},
    },
    curve::KimchiCurve,
    groupmap::GroupMap,
    plonk_sponge::FrSponge,
    proof::PointEvaluations,
};
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use poly_commitment::{
    commitment::{
        absorb_commitment, combined_inner_product, BatchEvaluationProof, Evaluation, PolyComm,
    },
    OpenProof, SRS,
};

use kimchi_msm::{logup::LookupTableID, witness::Witness};
use super::proof::Proof;
use crate::E;

pub fn verify<
    G: KimchiCurve,
    OpeningProof: Proof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &SRS<G>,
    constraints: &Vec<E<G::ScalarField>>,
    proof: &Proof<G>,
) -> bool
where
    SRS<G>: Sync,
{
    let Proof {
        commitments,
        zeta_evaluations,
        zeta_omega_evaluations,
        opening_proof,
    } = proof;

    ////////////////////////////////////////////////////////////////////////////
    // TODO :  public inputs
    ////////////////////////////////////////////////////////////////////////////

    ////////////////////////////////////////////////////////////////////////////
    // Absorbing all the commitments to the columns
    ////////////////////////////////////////////////////////////////////////////

    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());
    for comm in commitments.scratch.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }
    absorb_commitment(&mut fq_sponge, &commitments.instruction_counter);
    absorb_commitment(&mut fq_sponge, &commitments.error);
    for comm in commitments.selectors.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }

    // Sample α with the Fq-Sponge.
    let alpha = fq_sponge.challenge();

    ////////////////////////////////////////////////////////////////////////////
    // Quotient polynomial
    ////////////////////////////////////////////////////////////////////////////

    absorb_commitment(&mut fq_sponge, &commitments.t_comm);

    // -- Preparing for opening proof verification
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let zeta: G::ScalarField = zeta_chal.to_field(endo_r);
    let omega = domain.d1.group_gen;
    let zeta_omega = zeta * omega;

    let mut coms_and_evaluations: Vec<Evaluation<_>> = vec![];

    coms_and_evaluations.extend(
        (&commitments)
            .into_iter()
            .zip(&zeta_evaluations)
            .zip(zeta_omega_evaluations)
            .map(|(commitment, (eval_zeta, eval_zeta_omega))| Evaluation {
                commitment: commitment.clone(),
                evaluations: vec![vec![eval_zeta], vec![eval_zeta_omega]],
            }),
    );

    // -- Absorb all coms_and_evaluations
    let fq_sponge_before_coms_and_evaluations = fq_sponge.clone();
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .scratch
        .iter()
        .zip(zeta_omega_evaluations.scratch.iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }
    fr_sponge.absorb(&zeta_evaluations.instruction_counter);
    fr_sponge.absorb(&zeta_omega_evaluations.instruction_counter);
    fr_sponge.absorb(&zeta_evaluations.error);
    fr_sponge.absorb(&zeta_omega_evaluations.error);

    // Compute [ft(X)] = \
    //   (1 - ζ^n) *
    //    ([t_0(X)] + ζ^n [t_1(X)] + ... + ζ^{kn} [t_{k}(X)])
    let ft_comm = {
        let evaluation_point_to_domain_size = zeta.pow([domain.d1.size]);
        let chunked_t_comm = commitments
            .t_comm
            .chunk_commitment(evaluation_point_to_domain_size);
        // (1 - ζ^n)
        let minus_vanishing_poly_at_zeta = -domain.d1.vanishing_polynomial().evaluate(&zeta);
        chunked_t_comm.scale(minus_vanishing_poly_at_zeta)
    };
    // FIXME: use a proper Challenge structure
    let challenges = BerkeleyChallenges {
        alpha,
        // No permutation argument for the moment
        beta: G::ScalarField::zero(),
        gamma: G::ScalarField::zero(),
        // No lookup for the moment
        joint_combiner: G::ScalarField::zero(),
    };
    let (_, endo_r) = G::endos();

    let constants = Constants {
        endo_coefficient: *endo_r,
        mds: &G::sponge_params().mds,
        zk_rows: 0,
    };

    let combined_expr =
        Expr::combine_constraints(0..(constraints.len() as u32), constraints.clone());
    // Note the minus! ft polynomial at zeta (ft_eval0) is minus evaluation of the expression.
    let ft_eval0 = -PolishToken::evaluate(
        combined_expr.to_polish().as_slice(),
        domain.d1,
        zeta,
        evaluations,
        &constants,
        &challenges,
    )
    .unwrap();

    // Fixme add ft eval to the proof
    coms_and_evaluations.push(Evaluation {
        commitment: ft_comm,
        evaluations: vec![vec![ft_eval0], vec![zeta_omega_evaluations.ft]],
    });

    fr_sponge.absorb(zeta_omega_evaluations.ft_eval1);
    // -- End absorb all coms_and_evaluations

    let v_chal = fr_sponge.challenge();
    let v = v_chal.to_field(endo_r);
    let u_chal = fr_sponge.challenge();
    let u = u_chal.to_field(endo_r);

    let combined_inner_product = {
        let es: Vec<_> = coms_and_evaluations
            .iter()
            .map(|Evaluation { evaluations, .. }| evaluations.clone())
            .collect();

        combined_inner_product(&v, &u, es.as_slice())
    };

    let batch = BatchEvaluationProof {
        sponge: fq_sponge_before_coms_and_evaluations,
        evaluations: coms_and_evaluations,
        evaluation_points: vec![zeta, zeta_omega],
        polyscale: v,
        evalscale: u,
        opening: opening_proof,
        combined_inner_product,
    };

    let group_map = G::Map::setup();
    OpeningProof::verify(srs, &group_map, &mut [batch], &mut thread_rng())
}
