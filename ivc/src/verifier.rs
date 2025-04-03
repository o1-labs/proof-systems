use crate::{
    expr_eval::GenericEvalEnv,
    plonkish_lang::{PlonkishChallenge, PlonkishWitnessGeneric},
    prover::Proof,
};
use ark_ff::Field;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain as R2D,
};
use folding::{
    eval_leaf::EvalLeaf, instance_witness::ExtendedWitness, FoldingCompatibleExpr, FoldingConfig,
};
use kimchi::{
    self, circuits::domains::EvaluationDomains, curve::KimchiCurve, groupmap::GroupMap,
    plonk_sponge::FrSponge, proof::PointEvaluations,
};
use kimchi_msm::columns::Column as GenericColumn;
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use poly_commitment::{
    commitment::{
        absorb_commitment, combined_inner_product, BatchEvaluationProof, CommitmentCurve,
        Evaluation, PolyComm,
    },
    kzg::{KZGProof, PairingSRS},
    OpenProof, SRS,
};
use rand::thread_rng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

pub type Pairing = kimchi_msm::BN254;
/// The curve we commit into
pub type G = kimchi_msm::BN254G1Affine;
/// Scalar field of the curve.
pub type Fp = kimchi_msm::Fp;
/// The base field of the curve
/// Used to encode the polynomial commitments
pub type Fq = ark_bn254::Fq;

pub fn verify<
    EFqSponge: Clone + FqSponge<Fq, G, Fp>,
    EFrSponge: FrSponge<Fp>,
    FC: FoldingConfig<Column = GenericColumn<usize>, Curve = G, Challenge = PlonkishChallenge>,
    const N_WIT: usize,
    const N_REL: usize,
    const N_DSEL: usize,
    const N_FSEL: usize,
    const NPUB: usize,
>(
    domain: EvaluationDomains<Fp>,
    srs: &PairingSRS<Pairing>,
    combined_expr: &FoldingCompatibleExpr<FC>,
    fixed_selectors: Box<[Evaluations<Fp, R2D<Fp>>; N_FSEL]>,
    proof: &Proof<N_WIT, N_REL, N_DSEL, N_FSEL, G, KZGProof<Pairing>>,
) -> bool {
    assert!(N_WIT == N_REL + N_DSEL);

    let Proof {
        proof_comms,
        proof_evals,
        opening_proof,
        ..
    } = proof;

    ////////////////////////////////////////////////////////////////////////////
    // Re-evaluating public inputs
    ////////////////////////////////////////////////////////////////////////////

    let fixed_selectors_evals_d1: Box<[Evaluations<Fp, R2D<Fp>>; N_FSEL]> = fixed_selectors;

    let fixed_selectors_polys: Box<[DensePolynomial<Fp>; N_FSEL]> = {
        o1_utils::array::vec_to_boxed_array(
            fixed_selectors_evals_d1
                .into_par_iter()
                .map(|evals| evals.interpolate())
                .collect(),
        )
    };

    let fixed_selectors_comms: Box<[PolyComm<G>; N_FSEL]> = {
        let comm = |poly: &DensePolynomial<Fp>| srs.commit_non_hiding(poly, 1);
        o1_utils::array::vec_to_boxed_array(
            fixed_selectors_polys
                .as_ref()
                .into_par_iter()
                .map(comm)
                .collect(),
        )
    };

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
    // Quotient polynomial
    ////////////////////////////////////////////////////////////////////////////

    absorb_commitment(&mut fq_sponge, &proof_comms.t_comm);

    // -- Preparing for opening proof verification
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let zeta: Fp = zeta_chal.to_field(endo_r);
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
                commitment,
                evaluations: vec![vec![point_eval.zeta], vec![point_eval.zeta_omega]],
            }),
    );

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

    // Compute [ft(X)] = \
    //   (1 - ζ^n) \
    //    ([t_0(X)] + ζ^n [t_1(X)] + ... + ζ^{kn} [t_{k}(X)])
    let ft_comm = {
        let evaluation_point_to_domain_size = zeta.pow([domain.d1.size]);
        let chunked_t_comm = proof_comms
            .t_comm
            .chunk_commitment(evaluation_point_to_domain_size);

        // (1 - ζ^n)
        let minus_vanishing_poly_at_zeta: Fp = -domain.d1.vanishing_polynomial().evaluate(&zeta);
        chunked_t_comm.scale(minus_vanishing_poly_at_zeta)
    };

    let ft_eval0 = {
        let witness_evals_vecs = (&proof_evals.witness_evals)
            .into_iter()
            .map(|x| vec![x.zeta])
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let fixed_selectors_evals_vecs = proof_evals
            .fixed_selectors_evals
            .into_iter()
            .map(|x| vec![x.zeta])
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let error_vec = vec![proof_evals.error_vec.zeta];

        let alphas = proof.alphas.clone();
        let challenges = proof.challenges;
        let u = proof.u;

        let eval_env: GenericEvalEnv<G, N_WIT, N_FSEL, Vec<Fp>> = {
            let ext_witness = ExtendedWitness {
                witness: PlonkishWitnessGeneric {
                    witness: witness_evals_vecs,
                    fixed_selectors: fixed_selectors_evals_vecs,
                    phantom: core::marker::PhantomData,
                },
                extended: Default::default(),
            };

            GenericEvalEnv {
                ext_witness,
                alphas,
                challenges,
                error_vec,
                u,
            }
        };

        let eval_res: Vec<_> = match eval_env.eval_naive_fcompat(combined_expr) {
            EvalLeaf::Result(x) => x,
            EvalLeaf::Col(x) => x.to_vec(),
            _ => panic!("eval_leaf is not Result"),
        };

        // Note the minus! ft polynomial at zeta (ft_eval0) is minus evaluation of the expression.
        -eval_res[0]
    };

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

    let group_map = <G as CommitmentCurve>::Map::setup();
    OpenProof::verify(srs, &group_map, &mut [batch], &mut thread_rng())
}
