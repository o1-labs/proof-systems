use crate::mvlookup::LookupTableID;
use ark_ff::{Field, One, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain as R2D};
use rand::thread_rng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use kimchi::{
    circuits::{
        domains::EvaluationDomains,
        expr::{Challenges, Constants, Expr, PolishToken},
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
    const N: usize,
    const NPUB: usize,
    ID: LookupTableID,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    constraints: &Vec<E<G::ScalarField>>,
    proof: &Proof<N, G, OpeningProof, ID>,
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

    // Interpolate public input columns on d1, using trait Into.
    let public_input_evals: Witness<NPUB, Evaluations<G::ScalarField, R2D<G::ScalarField>>> =
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
        public_input_evals
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
        NPUB <= N,
        "Number of public inputs exceeds number of witness columns"
    );
    for i in 0..NPUB {
        assert!(public_input_comms.cols[i] == proof_comms.witness_comms.cols[i]);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Absorbing all the commitments to the columns
    ////////////////////////////////////////////////////////////////////////////

    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());
    (&proof_comms.witness_comms)
        .into_iter()
        .for_each(|comm| absorb_commitment(&mut fq_sponge, comm));

    ////////////////////////////////////////////////////////////////////////////
    // MVLookup
    ////////////////////////////////////////////////////////////////////////////

    let (joint_combiner, beta) = {
        if let Some(mvlookup_comms) = &proof_comms.mvlookup_comms {
            // First, we absorb the multiplicity polynomials
            mvlookup_comms
                .m
                .values()
                .for_each(|comm| absorb_commitment(&mut fq_sponge, comm));

            // To generate the challenges
            let joint_combiner = fq_sponge.challenge();
            let beta = fq_sponge.challenge();

            // And now, we absorb the commitments to the other polynomials
            mvlookup_comms
                .h
                .iter()
                .for_each(|comm| absorb_commitment(&mut fq_sponge, comm));

            mvlookup_comms
                .fixed_tables
                .values()
                .for_each(|comm| absorb_commitment(&mut fq_sponge, comm));

            // And at the end, the aggregation
            absorb_commitment(&mut fq_sponge, &mvlookup_comms.sum);
            (Some(joint_combiner), beta)
        } else {
            (None, G::ScalarField::zero())
        }
    };

    //~ 1. Sample $\alpha'$ with the Fq-Sponge.
    let alpha_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let alpha: G::ScalarField = alpha_chal.to_field(endo_r);

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

    if let Some(mvlookup_comms) = &proof_comms.mvlookup_comms {
        coms_and_evaluations.extend(
            mvlookup_comms
                .into_iter()
                .zip(proof_evals.mvlookup_evals.as_ref().unwrap())
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
    if proof_comms.mvlookup_comms.is_some() {
        // MVLookup FS
        for PointEvaluations { zeta, zeta_omega } in
            proof_evals.mvlookup_evals.as_ref().unwrap().into_iter()
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
        chunked_t_comm.scale(G::ScalarField::one() - evaluation_point_to_domain_size)
    };

    let challenges = Challenges {
        alpha,
        beta,
        gamma: G::ScalarField::zero(),
        joint_combiner,
    };

    let constants = Constants {
        endo_coefficient: *endo_r,
        mds: &G::sponge_params().mds,
        zk_rows: 0,
    };

    let combined_expr =
        Expr::combine_constraints(0..(constraints.len() as u32), constraints.clone());
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
