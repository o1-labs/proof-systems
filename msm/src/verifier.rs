#![allow(clippy::type_complexity)]
#![allow(clippy::boxed_local)]

use crate::logup::LookupTableID;
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

use crate::{expr::E, proof::Proof, witness::Witness};

pub fn verify<
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
    const N_WIT: usize,
    const N_REL: usize,
    const N_DSEL: usize,
    const N_FSEL: usize,
    const NPUB: usize,
    ID: LookupTableID,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    constraints: &[E<G::ScalarField>],
    fixed_selectors: Box<[Vec<G::ScalarField>; N_FSEL]>,
    proof: &Proof<N_WIT, N_REL, N_DSEL, N_FSEL, G, OpeningProof, ID>,
    public_inputs: Witness<NPUB, Vec<G::ScalarField>>,
) -> bool
where
    OpeningProof::SRS: Sync,
{
    let Proof {
        proof_comms,
        proof_evals,
        opening_proof,
    } = proof;

    ////////////////////////////////////////////////////////////////////////////
    // Re-evaluating public inputs
    ////////////////////////////////////////////////////////////////////////////

    let fixed_selectors_evals_d1: Box<[Evaluations<G::ScalarField, R2D<G::ScalarField>>; N_FSEL]> = {
        o1_utils::array::vec_to_boxed_array(
            fixed_selectors
                .into_par_iter()
                .map(|evals| Evaluations::from_vec_and_domain(evals, domain.d1))
                .collect(),
        )
    };

    let fixed_selectors_polys: Box<[DensePolynomial<G::ScalarField>; N_FSEL]> = {
        o1_utils::array::vec_to_boxed_array(
            fixed_selectors_evals_d1
                .into_par_iter()
                .map(|evals| evals.interpolate())
                .collect(),
        )
    };

    let fixed_selectors_comms: Box<[PolyComm<G>; N_FSEL]> = {
        let comm = |poly: &DensePolynomial<G::ScalarField>| srs.commit_non_hiding(poly, 1);
        o1_utils::array::vec_to_boxed_array(
            fixed_selectors_polys
                .as_ref()
                .into_par_iter()
                .map(comm)
                .collect(),
        )
    };

    // Interpolate public input columns on d1, using trait Into.
    let public_input_evals_d1: Witness<NPUB, Evaluations<G::ScalarField, R2D<G::ScalarField>>> =
        public_inputs
            .into_par_iter()
            .map(|evals| {
                Evaluations::<G::ScalarField, R2D<G::ScalarField>>::from_vec_and_domain(
                    evals, domain.d1,
                )
            })
            .collect::<Witness<NPUB, Evaluations<G::ScalarField, R2D<G::ScalarField>>>>();

    let public_input_polys: Witness<NPUB, DensePolynomial<G::ScalarField>> = {
        let interpolate =
            |evals: Evaluations<G::ScalarField, R2D<G::ScalarField>>| evals.interpolate();
        public_input_evals_d1
            .into_par_iter()
            .map(interpolate)
            .collect::<Witness<NPUB, DensePolynomial<G::ScalarField>>>()
    };

    let public_input_comms: Witness<NPUB, PolyComm<G>> = {
        let comm = |poly: &DensePolynomial<G::ScalarField>| srs.commit_non_hiding(poly, 1);
        (&public_input_polys)
            .into_par_iter()
            .map(comm)
            .collect::<Witness<NPUB, PolyComm<G>>>()
    };

    assert!(
        NPUB <= N_WIT,
        "Number of public inputs exceeds number of witness columns"
    );
    for i in 0..NPUB {
        assert!(public_input_comms.cols[i] == proof_comms.witness_comms.cols[i]);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Absorbing all the commitments to the columns
    ////////////////////////////////////////////////////////////////////////////

    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());

    fixed_selectors_comms
        .as_ref()
        .iter()
        .chain(&proof_comms.witness_comms)
        .for_each(|comm| absorb_commitment(&mut fq_sponge, comm));

    ////////////////////////////////////////////////////////////////////////////
    // Logup
    ////////////////////////////////////////////////////////////////////////////

    let (joint_combiner, beta) = {
        if let Some(logup_comms) = &proof_comms.logup_comms {
            // First, we absorb the multiplicity polynomials
            logup_comms.m.values().for_each(|comms| {
                comms
                    .iter()
                    .for_each(|comm| absorb_commitment(&mut fq_sponge, comm))
            });

            // FIXME @volhovm it seems that the verifier does not
            // actually check that the fixed tables used in the proof
            // are the fixed tables defined in the code. In other
            // words, all the currently used "fixed" tables are
            // runtime and can be chosen freely by the prover.

            // To generate the challenges
            let joint_combiner = fq_sponge.challenge();
            let beta = fq_sponge.challenge();

            // And now, we absorb the commitments to the other polynomials
            logup_comms.h.values().for_each(|comms| {
                comms
                    .iter()
                    .for_each(|comm| absorb_commitment(&mut fq_sponge, comm))
            });

            logup_comms
                .fixed_tables
                .values()
                .for_each(|comm| absorb_commitment(&mut fq_sponge, comm));

            // And at the end, the aggregation
            absorb_commitment(&mut fq_sponge, &logup_comms.sum);
            (Some(joint_combiner), beta)
        } else {
            (None, G::ScalarField::zero())
        }
    };

    // Sample α with the Fq-Sponge.
    let alpha = fq_sponge.challenge();

    ////////////////////////////////////////////////////////////////////////////
    // Quotient polynomial
    ////////////////////////////////////////////////////////////////////////////

    absorb_commitment(&mut fq_sponge, &proof_comms.t_comm);

    // -- Preparing for opening proof verification
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let zeta: G::ScalarField = zeta_chal.to_field(endo_r);
    let omega = domain.d1.group_gen;
    let zeta_omega = zeta * omega;

    let mut coms_and_evaluations: Vec<Evaluation<_>> = vec![];

    coms_and_evaluations.extend(
        (&proof_comms.witness_comms)
            .into_iter()
            .zip(&proof_evals.witness_evals)
            .map(|(commitment, point_eval)| Evaluation {
                commitment: commitment.clone(),
                evaluations: vec![vec![point_eval.zeta], vec![point_eval.zeta_omega]],
            }),
    );

    coms_and_evaluations.extend(
        (fixed_selectors_comms)
            .into_iter()
            .zip(proof_evals.fixed_selectors_evals.iter())
            .map(|(commitment, point_eval)| Evaluation {
                commitment: commitment.clone(),
                evaluations: vec![vec![point_eval.zeta], vec![point_eval.zeta_omega]],
            }),
    );

    if let Some(logup_comms) = &proof_comms.logup_comms {
        coms_and_evaluations.extend(
            logup_comms
                .into_iter()
                .zip(proof_evals.logup_evals.as_ref().unwrap())
                .map(|(commitment, point_eval)| Evaluation {
                    commitment: commitment.clone(),
                    evaluations: vec![vec![point_eval.zeta], vec![point_eval.zeta_omega]],
                })
                .collect::<Vec<_>>(),
        );
    }

    // -- Absorb all coms_and_evaluations
    let fq_sponge_before_coms_and_evaluations = fq_sponge.clone();
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    for PointEvaluations { zeta, zeta_omega } in (&proof_evals.witness_evals).into_iter() {
        fr_sponge.absorb(zeta);
        fr_sponge.absorb(zeta_omega);
    }

    for PointEvaluations { zeta, zeta_omega } in proof_evals.fixed_selectors_evals.as_ref().iter() {
        fr_sponge.absorb(zeta);
        fr_sponge.absorb(zeta_omega);
    }

    if proof_comms.logup_comms.is_some() {
        // Logup FS
        for PointEvaluations { zeta, zeta_omega } in
            proof_evals.logup_evals.as_ref().unwrap().into_iter()
        {
            fr_sponge.absorb(zeta);
            fr_sponge.absorb(zeta_omega);
        }
    };

    // Compute [ft(X)] = \
    //   (1 - ζ^n) \
    //    ([t_0(X)] + ζ^n [t_1(X)] + ... + ζ^{kn} [t_{k}(X)])
    let ft_comm = {
        let evaluation_point_to_domain_size = zeta.pow([domain.d1.size]);
        let chunked_t_comm = proof_comms
            .t_comm
            .chunk_commitment(evaluation_point_to_domain_size);
        // (1 - ζ^n)
        let minus_vanishing_poly_at_zeta = -domain.d1.vanishing_polynomial().evaluate(&zeta);
        chunked_t_comm.scale(minus_vanishing_poly_at_zeta)
    };

    let challenges = BerkeleyChallenges::<G::ScalarField> {
        alpha,
        beta,
        gamma: G::ScalarField::zero(),
        joint_combiner: joint_combiner.unwrap_or(G::ScalarField::zero()),
    };

    let constants = Constants {
        endo_coefficient: *endo_r,
        mds: &G::sponge_params().mds,
        zk_rows: 0,
    };

    let combined_expr =
        Expr::combine_constraints(0..(constraints.len() as u32), constraints.to_vec());
    // Note the minus! ft polynomial at zeta (ft_eval0) is minus evaluation of the expression.
    let ft_eval0 = -PolishToken::evaluate(
        combined_expr.to_polish().as_slice(),
        domain.d1,
        zeta,
        proof_evals,
        &constants,
        &challenges,
    )
    .unwrap();

    coms_and_evaluations.push(Evaluation {
        commitment: ft_comm,
        evaluations: vec![vec![ft_eval0], vec![proof_evals.ft_eval1]],
    });

    fr_sponge.absorb(&proof_evals.ft_eval1);
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
