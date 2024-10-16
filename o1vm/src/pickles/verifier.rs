#![allow(clippy::type_complexity)]
#![allow(clippy::boxed_local)]

use ark_ec::{AffineRepr, Group};
use ark_ff::{PrimeField, Zero};
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
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use poly_commitment::{
    commitment::{
        absorb_commitment, combined_inner_product, BatchEvaluationProof, Evaluation, PolyComm,
    },
    ipa::OpeningProof,
    OpenProof
};

use super::{
    column_env::get_all_columns,
    proof::{Proof, WitnessColumns},
};
use crate::{interpreters::mips::column::N_MIPS_SEL_COLS, E};
use kimchi_msm::columns::Column;

type CommitmentColumns<G> = WitnessColumns<PolyComm<G>, [PolyComm<G>; N_MIPS_SEL_COLS]>;
type EvaluationColumns<G> = WitnessColumns<
    <<G as AffineRepr>::Group as Group>::ScalarField,
    [<<G as AffineRepr>::Group as Group>::ScalarField; N_MIPS_SEL_COLS],
>;

// TODO: Move and perhaps derive some traits for these
struct ColumnEval<'a, G: AffineRepr> {
    commitment: &'a CommitmentColumns<G>,
    zeta_eval: &'a EvaluationColumns<G>,
    zeta_omega_eval: &'a EvaluationColumns<G>,
}

impl<G: AffineRepr> ColumnEvaluations<<G as AffineRepr>::ScalarField> for ColumnEval<'_, G> {
    type Column = Column;
    fn evaluate(
        &self,
        col: Self::Column,
    ) -> Result<PointEvaluations<<G as AffineRepr>::ScalarField>, ExprError<Self::Column>> {
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

pub fn verify<
    G: KimchiCurve,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &<OpeningProof<G> as OpenProof<G>>::SRS,
    constraints: &Vec<E<G::ScalarField>>,
    proof: &Proof<G>,
) -> bool
where
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
    let zeta: G::ScalarField = zeta_chal.to_field(endo_r);
    let omega = domain.d1.group_gen;
    let zeta_omega = zeta * omega;

    let column_eval = ColumnEval {
        commitment: commitments,
        zeta_eval: zeta_evaluations,
        zeta_omega_eval: zeta_omega_evaluations,
    };

    // -- Absorb all commitments_and_evaluations
    let fq_sponge_before_commitments_and_evaluations = fq_sponge.clone();
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
    fr_sponge.absorb_multiple(&zeta_evaluations.selector);
    fr_sponge.absorb_multiple(&zeta_omega_evaluations.selector);
    fr_sponge.absorb(&quotient_evaluations.zeta);
    fr_sponge.absorb(&quotient_evaluations.zeta_omega);
    // FIXME: Add selector evaluations (DONE) and quotient evaluations

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

    // FIXME: Add these to the final check!!!!!

    // FIXME: Fixup absorbs so they match in prover.rs

    let quotient_eval_zeta = PolishToken::evaluate(
        combined_expr.to_polish().as_slice(),
        domain.d1,
        zeta,
        &column_eval,
        &constants,
        &challenges,
    )
    .unwrap_or_else(|_| panic!("Could not evaluate quotient polynomial at zeta"));

    let quotient_eval_zeta_omega = PolishToken::evaluate(
        combined_expr.to_polish().as_slice(),
        domain.d1,
        zeta_omega,
        &column_eval,
        &constants,
        &challenges,
    )
    .unwrap_or_else(|_| panic!("Could not evaluate quotient polynomial at zeta_omega"));

    // Check the actual quotient works. combined_expr(eval) [ == quotient_eval_*] = quotient(eval) [== Given by prover (new field) -- chunked] * vanishing_poly(eval) [== x^n - 1 == zeta^(d1.size()) - 1]

    // Fixme add ft eval to the proof
    /*     coms_and_evaluations.push(Evaluation {
           commitment: ft_comm,
           evaluations: vec![vec![ft_eval0], vec![zeta_omega_evaluations.ft]],
       });
    */
    fr_sponge.absorb(&quotient_eval_zeta);
    fr_sponge.absorb(&quotient_eval_zeta_omega);
    // fr_sponge.absorb(zeta_omega_evaluations.ft_eval1);
    // -- End absorb all coms_and_evaluations

    let v_chal = fr_sponge.challenge();
    let v = v_chal.to_field(endo_r);
    let u_chal = fr_sponge.challenge();
    let u = u_chal.to_field(endo_r);

    let evaluations = {
        let all_columns = get_all_columns();

        let mut evaluations = Vec::with_capacity(all_columns.len());

        all_columns.into_iter()
            .for_each(
                |column| {
                    let point_evaluations = column_eval
                        .evaluate(column)
                        .unwrap_or_else(|_| panic!("Could not get `evaluations` for `Evaluation`")); // FIXME: Finish message (DONE)

                    let commitment = column_eval
                        .commitment
                        .get_column(&column)
                        .unwrap_or_else(|| panic!("Could not get `commitment` for `Evaluation`")) // FIXME: Finish message (DONE)
                        .clone();

                    evaluations.push(Evaluation {
                        commitment,
                        evaluations: vec![vec![point_evaluations.zeta], vec![point_evaluations.zeta_omega]],
                    })
        });

        evaluations
    };

    let combined_inner_product = {
        let es: Vec<_> = evaluations
            .iter()
            .map(|Evaluation { evaluations, .. }| evaluations.clone())
            .collect();

        combined_inner_product(&v, &u, es.as_slice())
    };

    let batch = BatchEvaluationProof {
        sponge: fq_sponge_before_commitments_and_evaluations,
        evaluations: evaluations,
        evaluation_points: vec![zeta, zeta_omega],
        polyscale: v,
        evalscale: u,
        opening: opening_proof,
        combined_inner_product,
    };

    let group_map = G::Map::setup();
    OpeningProof::verify(srs, &group_map, &mut [batch], &mut thread_rng())
}
