use ark_ec::AffineRepr;
use ark_ff::{Field, One, PrimeField, Zero};
use rand::thread_rng;

use kimchi::{
    circuits::{
        berkeley_columns::BerkeleyChallenges,
        domains::EvaluationDomains,
        expr::{ColumnEvaluations, Constants, Expr, ExprError, PolishToken},
        gate::CurrOrNext,
    },
    curve::KimchiCurve,
    groupmap::GroupMap,
    plonk_sponge::FrSponge,
    proof::PointEvaluations,
};
use mina_poseidon::{poseidon::ArithmeticSpongeParams, sponge::ScalarChallenge, FqSponge};
use poly_commitment::{
    commitment::{
        absorb_commitment, combined_inner_product, BatchEvaluationProof, Evaluation, PolyComm,
    },
    ipa::OpeningProof,
    OpenProof,
};

use super::{
    column_env::{get_all_columns, RelationColumnType},
    proof::{Proof, WitnessColumns},
};
use crate::{interpreters::mips::column::N_MIPS_SEL_COLS, E};
use kimchi_msm::columns::Column;

type CommitmentColumns<G> = WitnessColumns<PolyComm<G>, [PolyComm<G>; N_MIPS_SEL_COLS]>;
type EvaluationColumns<F> = WitnessColumns<F, [F; N_MIPS_SEL_COLS]>;

struct ColumnEval<'a, G: AffineRepr> {
    commitment: &'a CommitmentColumns<G>,
    zeta_eval: &'a EvaluationColumns<G::ScalarField>,
    zeta_omega_eval: &'a EvaluationColumns<G::ScalarField>,
}

impl<G: AffineRepr> ColumnEvaluations<G::ScalarField> for ColumnEval<'_, G> {
    type Column = Column<RelationColumnType>;
    fn evaluate(
        &self,
        col: Self::Column,
    ) -> Result<PointEvaluations<G::ScalarField>, ExprError<Self::Column>> {
        let ColumnEval {
            commitment: _,
            zeta_eval,
            zeta_omega_eval,
        } = self;
        if let Some(&zeta) = zeta_eval.get_column(&col) {
            if let Some(&zeta_omega) = zeta_omega_eval.get_column(&col) {
                Ok(PointEvaluations { zeta, zeta_omega })
            } else {
                Err(ExprError::MissingEvaluation(col, CurrOrNext::Next))
            }
        } else {
            Err(ExprError::MissingEvaluation(col, CurrOrNext::Curr))
        }
    }
}

pub fn verify<const FULL_ROUNDS: usize, G, EFqSponge, EFrSponge>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &<OpeningProof<G, FULL_ROUNDS> as OpenProof<G, FULL_ROUNDS>>::SRS,
    constraints: &[E<G::ScalarField>],
    proof: &Proof<FULL_ROUNDS, G>,
) -> bool
where
    G: KimchiCurve<FULL_ROUNDS>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField, FULL_ROUNDS>,
    EFrSponge: FrSponge<G::ScalarField>,
    EFrSponge: From<&'static ArithmeticSpongeParams<G::ScalarField, FULL_ROUNDS>>,
    <G as AffineRepr>::BaseField: PrimeField,
{
    let Proof {
        commitments,
        zeta_evaluations,
        zeta_omega_evaluations,
        quotient_commitment,
        quotient_evaluations,
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
    for comm in commitments.scratch_inverse.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }
    for comm in commitments.lookup_state.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }
    absorb_commitment(&mut fq_sponge, &commitments.instruction_counter);
    absorb_commitment(&mut fq_sponge, &commitments.error);
    for comm in commitments.selector.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }

    // Sample α with the Fq-Sponge.
    let alpha = fq_sponge.challenge();

    ////////////////////////////////////////////////////////////////////////////
    // Quotient polynomial
    ////////////////////////////////////////////////////////////////////////////

    absorb_commitment(&mut fq_sponge, quotient_commitment);

    // -- Preparing for opening proof verification
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let zeta = zeta_chal.to_field(endo_r);
    let omega = domain.d1.group_gen;
    let zeta_omega = zeta * omega;

    let column_eval = ColumnEval {
        commitment: commitments,
        zeta_eval: zeta_evaluations,
        zeta_omega_eval: zeta_omega_evaluations,
    };

    // -- Absorb all commitments_and_evaluations
    let fq_sponge_before_commitments_and_evaluations = fq_sponge.clone();
    let mut fr_sponge = EFrSponge::from(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .scratch
        .iter()
        .zip(zeta_omega_evaluations.scratch.iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }
    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .scratch_inverse
        .iter()
        .zip(zeta_omega_evaluations.scratch_inverse.iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }
    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .lookup_state
        .iter()
        .zip(zeta_omega_evaluations.lookup_state.iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }
    fr_sponge.absorb(&zeta_evaluations.instruction_counter);
    fr_sponge.absorb(&zeta_omega_evaluations.instruction_counter);
    fr_sponge.absorb(&zeta_evaluations.error);
    fr_sponge.absorb(&zeta_omega_evaluations.error);
    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .selector
        .iter()
        .zip(zeta_omega_evaluations.selector.iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }
    for (quotient_zeta_eval, quotient_zeta_omega_eval) in quotient_evaluations
        .zeta
        .iter()
        .zip(quotient_evaluations.zeta_omega.iter())
    {
        fr_sponge.absorb(quotient_zeta_eval);
        fr_sponge.absorb(quotient_zeta_omega_eval);
    }

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
        Expr::combine_constraints(0..(constraints.len() as u32), constraints.to_vec());

    let numerator_zeta = PolishToken::evaluate(
        combined_expr.to_polish().as_slice(),
        domain.d1,
        zeta,
        &column_eval,
        &constants,
        &challenges,
    )
    .unwrap_or_else(|_| panic!("Could not evaluate quotient polynomial at zeta"));

    let v_chal = fr_sponge.challenge();
    let v = v_chal.to_field(endo_r);
    let u_chal = fr_sponge.challenge();
    let u = u_chal.to_field(endo_r);

    let mut evaluations: Vec<_> = get_all_columns(column_eval.commitment.lookup_state.len())
        .into_iter()
        .map(|column| {
            let commitment = column_eval
                .commitment
                .get_column(&column)
                .unwrap_or_else(|| panic!("Could not get `commitment` for `Evaluation`"))
                .clone();

            let evaluations = column_eval
                .evaluate(column)
                .unwrap_or_else(|_| panic!("Could not get `evaluations` for `Evaluation`"));

            Evaluation {
                commitment,
                evaluations: vec![vec![evaluations.zeta], vec![evaluations.zeta_omega]],
            }
        })
        .collect();

    evaluations.push(Evaluation {
        commitment: proof.quotient_commitment.clone(),
        evaluations: vec![
            quotient_evaluations.zeta.clone(),
            quotient_evaluations.zeta_omega.clone(),
        ],
    });

    let combined_inner_product = {
        let es: Vec<_> = evaluations
            .iter()
            .map(|Evaluation { evaluations, .. }| evaluations.clone())
            .collect();

        combined_inner_product(&v, &u, es.as_slice())
    };

    let batch = BatchEvaluationProof {
        sponge: fq_sponge_before_commitments_and_evaluations,
        evaluations,
        evaluation_points: vec![zeta, zeta_omega],
        polyscale: v,
        evalscale: u,
        opening: opening_proof,
        combined_inner_product,
    };

    let group_map = G::Map::setup();

    // Check the actual quotient works.
    let (quotient_zeta, _) = quotient_evaluations.zeta.iter().fold(
        (G::ScalarField::zero(), G::ScalarField::one()),
        |(res, zeta_i_n), chunk| {
            let res = res + zeta_i_n * chunk;
            let zeta_i_n = zeta_i_n * zeta.pow([domain.d1.size]);
            (res, zeta_i_n)
        },
    );
    (quotient_zeta == numerator_zeta / (zeta.pow([domain.d1.size]) - G::ScalarField::one()))
        && OpeningProof::verify(srs, &group_map, &mut [batch], &mut thread_rng())
}
