use super::lookup_columns::{ELookup, LookupChallenges, LookupEvalEnvironment};
use crate::pickles::lookup_columns::*;
use ark_ff::{One, PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Polynomial, Radix2EvaluationDomain};
use kimchi::{
    circuits::{
        domains::{Domain, EvaluationDomains},
        expr::{l0_1, Constants},
    },
    curve::KimchiCurve,
    groupmap::GroupMap,
    plonk_sponge::FrSponge,
};
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use o1_utils::ExtendedDensePolynomial;
use poly_commitment::{commitment::absorb_commitment, ipa::SRS, OpenProof, SRS as _};
use std::ops::{AddAssign, Mul};

use poly_commitment::{ipa::OpeningProof, utils::DensePolynomialOrEvaluations, PolyComm};
use rand::{CryptoRng, RngCore};

///The prover is split in two parts.
/// We define the following structure to pass state
/// from the first prover to the second
pub struct LookupProverState<F: PrimeField> {
    acc: Vec<F>,
    inverses: Vec<Vec<F>>,
}

/// This prover takes one Public Input and one Public Output
/// It then proves that the sum 1/(beta + table) = PI - PO
/// where the table term are term from fixed lookup or RAMLookup
/// It is split in two part, one computes the inverses and accumulator.
/// It outputs the final accumulator and a state for the second part.
/// It is needed as we use the final accumulator for the constraint.
/// TODO : parralelize
pub fn lookup_prove_fst_part<G: KimchiCurve>(
    input: &LookupProofInput<G::ScalarField>,
    acc_init: G::ScalarField,
    domain: EvaluationDomains<G::ScalarField>,
) -> (G::ScalarField, LookupProverState<G::ScalarField>)
where
    G::BaseField: PrimeField,
{
    // TODO check that
    let LookupProofInput {
        wires,
        arity,
        dynamicselectors: _,
        beta_challenge,
        gamma_challenge,
    } = input;
    //Compute how many inverse wires we need
    let nb_inv_wires = arity
        .iter()
        .max_by(|a, b| a.len().cmp(&b.len()))
        .unwrap()
        .len();

    // Init inverses
    let mut inverses = Vec::with_capacity(nb_inv_wires);
    for _ in 0..nb_inv_wires {
        inverses.push(vec![G::ScalarField::zero(); domain.d1.size as usize])
    }

    // Compute powers of gamma once
    // FIXME: Arbitrary constant of 30 should be enough
    let mut gamma_vec = [G::ScalarField::one(); 30];
    let mut gamma_pow = G::ScalarField::one();
    for gamma_i in &mut gamma_vec {
        *gamma_i = gamma_pow;
        gamma_pow *= gamma_challenge
    }

    // Fill inverses without doing the inversion
    for (j, arity_j) in arity.iter().enumerate() {
        let mut wire_idx = 0;
        for (k, arit) in arity_j.iter().enumerate() {
            let mut res = *beta_challenge;
            for i in 0..*arit {
                res += gamma_vec[i] * wires[wire_idx + i][j]
            }
            inverses[k][j] = res;
            wire_idx += arit;
        }
    }

    //perform the inversion
    inverses
        .iter_mut()
        .for_each(|inner_vec| ark_ff::batch_inversion(inner_vec));
    // compute the accumulator
    // init at acc_init
    let mut partial_sum = acc_init;
    let mut acc = vec![];
    acc.push(partial_sum);

    for j in 0..((domain.d1.size - 1) as usize) {
        for inverse_i in inverses.iter() {
            partial_sum += inverse_i[j]
        }
        acc.push(partial_sum)
    }

    let acc_final = acc[acc.len() - 1];
    let state = LookupProverState { acc, inverses };
    (acc_final, state)
}

/// Second part of the lookup prover.
pub fn lookup_prove_snd_part<
    G: KimchiCurve,
    EFqSponge: FqSponge<G::BaseField, G, G::ScalarField> + Clone,
    EFrSponge: FrSponge<G::ScalarField>,
    RNG,
>(
    input: LookupProofInput<G::ScalarField>,
    srs: &SRS<G>,
    domain: EvaluationDomains<G::ScalarField>,
    mut fq_sponge: EFqSponge,
    constraints: &[ELookup<G::ScalarField>],
    rng: &mut RNG,
    // some commitments are already computed
    // we give them as auxiliary input
    cm_wires: Vec<PolyComm<G>>,
    state: LookupProverState<G::ScalarField>,
) -> Proof<G>
where
    G::BaseField: PrimeField,
    RNG: RngCore + CryptoRng,
{
    let LookupProverState { inverses, acc } = state;
    let LookupProofInput {
        wires,
        arity: _,
        dynamicselectors,
        beta_challenge,
        gamma_challenge,
    } = input;

    let columns = ColumnEnv {
        wires,
        inverses,
        acc,
        dynamicselectors,
    };

    ////// Commit and squeeze the constraint combiner alpha
    //interpolating
    let interpolate_col = |evals: Vec<G::ScalarField>| {
        Evaluations::<G::ScalarField, Radix2EvaluationDomain<G::ScalarField>>::from_vec_and_domain(
            evals, domain.d1,
        )
        .interpolate()
    };
    let columns_poly = columns.map(interpolate_col);
    // commiting. Note that we do not commit to the wires, it is already done.
    // TODO avoid cloning
    let columns_com = ColumnEnv {
        wires: cm_wires.into_iter().map(|x| x.chunks[0]).collect(),
        inverses: columns_poly
            .inverses
            .clone()
            .into_iter()
            .map(|poly| srs.commit_non_hiding(&poly, 1).chunks[0])
            .collect(),
        acc: srs.commit_non_hiding(&columns_poly.acc.clone(), 1).chunks[0],
        dynamicselectors: columns_poly
            .dynamicselectors
            .clone()
            .into_iter()
            .map(|poly| srs.commit_non_hiding(&poly, 1).chunks[0])
            .collect(),
    };

    // abosrbing commit
    // TODO don't absorb the wires which already have been
    // TODO avoid cloning
    columns_com
        .clone()
        .into_iter()
        .for_each(|com| absorb_commitment(&mut fq_sponge, &PolyComm { chunks: vec![com] }));

    // Constraints combiner
    let alpha: G::ScalarField = fq_sponge.challenge();

    ////// Compute the quotient polynomial T

    // eval on d4
    // TODO: avoid cloning
    let columns_eval_d4 = columns_poly
        .clone()
        .map(|poly| poly.evaluate_over_domain_by_ref(domain.d4));
    let challenges = LookupChallenges {
        alpha,
        beta: beta_challenge,
        gamma: gamma_challenge,
    };

    let eval_env = LookupEvalEnvironment {
        challenges,
        columns: &columns_eval_d4,
        domain: &domain,
        constants: Constants {
            endo_coefficient: G::ScalarField::zero(),
            mds: &G::sponge_params().mds,
            zk_rows: 0,
        },

        l0_1: l0_1(domain.d1),
    };

    let (t_numerator_evaluation, _) = constraints.iter().fold(
        (
            Evaluations::from_vec_and_domain(
                vec![G::ScalarField::zero(); domain.d4.size as usize],
                domain.d4,
            ),
            G::ScalarField::one(),
        ),
        |(mut acc, alpha_pow), cst| {
            acc.add_assign(
                &cst.evaluations_with_domain(&eval_env, Domain::D4)
                    .mul(alpha_pow),
            );
            (acc, alpha_pow * alpha)
        },
    );
    let t_numerator_poly = t_numerator_evaluation.interpolate();
    let (t, rem) = t_numerator_poly
        .divide_by_vanishing_poly(domain.d1)
        .unwrap();
    assert!(rem.is_zero());

    //////// Squeeze the evaluation point zeta
    // The constraint is of degree 3
    let num_chunk = 2;
    let t_commitment = srs.commit_non_hiding(&t, num_chunk);
    // TODO avoid cloning
    let commitments = AllColumns {
        cols: columns_com,
        quotient_chunks: t_commitment.chunks.clone(),
    };
    // Absorb t
    absorb_commitment(&mut fq_sponge, &t_commitment);
    let t_chunks = t.to_chunked_polynomial(num_chunk, srs.size());
    // squeeze zeta
    // TODO: understand why we use the endo here and for IPA ,
    // but not for alpha
    let (_, endo_r) = G::endos();
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let zeta: G::ScalarField = zeta_chal.to_field(endo_r);
    let zeta_omega = zeta * domain.d1.group_gen;

    /////// evaluate create the IPA proof
    let eval =
        |x,
         cols_poly: ColumnEnv<DensePolynomial<_>>,
         t_chunks: o1_utils::chunked_polynomial::ChunkedPolynomial<_>| AllColumns {
            cols: cols_poly.map(|poly| poly.evaluate(&x)),
            quotient_chunks: t_chunks
                .polys
                .into_iter()
                .map(|poly| poly.evaluate(&x))
                .collect(),
        };
    // TODO avoid cloning
    let evaluations = Eval {
        zeta: eval(zeta, columns_poly.clone(), t_chunks.clone()),
        zeta_omega: eval(zeta_omega, columns_poly.clone(), t_chunks.clone()),
    };
    let fq_sponge_before_evaluations = fq_sponge.clone();
    // Creating fr_sponge, absorbing eval to create challenges for IPA
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());
    // TODO avoid cloning
    evaluations
        .clone()
        .into_iter()
        .for_each(|x| fr_sponge.absorb(&x));
    // poly scale
    let poly_scale_chal = fr_sponge.challenge();
    let poly_scale = poly_scale_chal.to_field(endo_r);
    // eval scale
    let eval_scale_chal = fr_sponge.challenge();
    let eval_scale = eval_scale_chal.to_field(endo_r);
    let group_map = G::Map::setup();
    // prepare polynomials for IPA proof
    let all_columns_poly = AllColumns {
        cols: columns_poly,
        quotient_chunks: t_chunks.polys,
    };
    let polynomials: Vec<_> = all_columns_poly.into_iter().collect();
    let polynomials : Vec<_> = polynomials.iter().map(|poly| {
        (
            DensePolynomialOrEvaluations::<_,Radix2EvaluationDomain<G::ScalarField>>::DensePolynomial(poly),
            // We do not have any blinder, therefore we set to 0.
            PolyComm::new(vec![G::ScalarField::zero()]),
        )
    }).collect();
    let ipa_proof = OpeningProof::open(
        srs,
        &group_map,
        polynomials.as_slice(),
        &[zeta, zeta_omega],
        poly_scale,
        eval_scale,
        fq_sponge_before_evaluations,
        rng,
    );

    Proof {
        commitments,
        evaluations,
        ipa_proof,
    }
}
