use crate::{lookups::FixedLookup, pickles::multiplicities_columns::*};
use ark_ff::{batch_inversion, One, PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Polynomial, Radix2EvaluationDomain};
use kimchi::{
    circuits::{
        domains::EvaluationDomains,
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
pub struct MultiplicitiesProverState<F: PrimeField> {
    acc: Vec<F>,
    inverses: FixedLookup<Vec<F>>,
}

/// This prover takes one Public Input and one Public Output
/// It then proves that the sum multiplicities/(beta + fixed_table) = PI - PO
/// It is split in two part, one computes the inverses and accumulator.
/// It outputs the final accumulator and a state for the second part.
/// It is needed as we use the final accumulator for the constraint.
/// TODO : parralelize
pub fn multiplicitie_prove_fst_part<G: KimchiCurve>(
    input: &MultiplicitiesProofInput<G>,
    acc_init: G::ScalarField,
    domain: EvaluationDomains<G::ScalarField>,
) -> (G::ScalarField, MultiplicitiesProverState<G::ScalarField>)
where
    G::BaseField: PrimeField,
{
    let MultiplicitiesProofInput {
        fixedlookup: _,
        multiplicities,
        beta_challenge,
        gamma_challenge,
        fixedlookupcommitment: _,
        fixedlookup_transposed,
    } = input;

    // Compute the inverses
    let len = domain.d1.size as usize;
    // Init result
    let mut inverses_vec = Vec::new();

    (fixedlookup_transposed)
        .into_iter()
        .zip(multiplicities)
        .for_each(|(table, mul)| {
            // Init individual table
            let mut inv: Vec<_> = Vec::with_capacity(len);
            for table_i in table.iter() {
                let mut res_i = G::ScalarField::zero();
                // Compute sum_i gamma^i val^i using Horner
                for j in 0..table_i.len() {
                    res_i = (res_i * *gamma_challenge) + table_i[table_i.len() - 1 - j]
                }
                //  sum_i gamma^i val^i + beta
                res_i += *beta_challenge;
                inv.push(res_i);
            }
            // 1/(sum_i gamma^i val^i + beta)
            batch_inversion(&mut inv);
            for i in 0..(len) {
                // m/(sum_i gamma^i val^i + beta)
                inv[i] *= mul[i]
            }
            inverses_vec.push(inv);
        });

    // Transform in the correct type
    let inverses: FixedLookup<Vec<_>> = inverses_vec.into_iter().collect();

    // Compute the accumulator

    // Init at acc_init
    let mut partial_sum = acc_init;
    let mut acc = vec![];
    acc.push(partial_sum);

    // Fill with partial sums
    for j in 0..((domain.d1.size - 1) as usize) {
        for inverse_i in (&inverses).into_iter() {
            partial_sum += inverse_i[j]
        }
        acc.push(partial_sum)
    }

    let acc_final = acc[acc.len() - 1];
    let state = MultiplicitiesProverState { acc, inverses };
    (acc_final, state)
}

/// Second part of the lookup prover.
pub fn multiplicities_prove_snd_part<
    G: KimchiCurve,
    EFqSponge: FqSponge<G::BaseField, G, G::ScalarField> + Clone,
    EFrSponge: FrSponge<G::ScalarField>,
    RNG,
>(
    input: MultiplicitiesProofInput<G>,
    srs: &SRS<G>,
    domain: EvaluationDomains<G::ScalarField>,
    mut fq_sponge: EFqSponge,
    constraints: &[EMultiplicities<G::ScalarField>],
    rng: &mut RNG,
    state: MultiplicitiesProverState<G::ScalarField>,
) -> Proof<G>
where
    G::BaseField: PrimeField,
    RNG: RngCore + CryptoRng,
{
    let MultiplicitiesProverState { inverses, acc } = state;

    // TODO change that
    let num_chunk = 8;
    let MultiplicitiesProofInput {
        fixedlookup,
        fixedlookup_transposed: _,
        multiplicities,
        beta_challenge,
        gamma_challenge,
        fixedlookupcommitment: _,
    } = input;

    let columns = ColumnEnv {
        fixedlookup,
        inverses,
        acc,
        multiplicities,
    };

    // Interpolating
    let interpolate_col = |evals: Vec<G::ScalarField>| {
        Evaluations::<G::ScalarField, Radix2EvaluationDomain<G::ScalarField>>::from_vec_and_domain(
            evals, domain.d1,
        )
        .interpolate()
    };
    let columns_poly = columns.map(interpolate_col);

    // TODO avoid cloning
    // TODO don't commit to fixedlookup
    let columns_com = columns_poly.clone().map(|poly| {
        let PolyComm { chunks } = srs.commit_non_hiding(&poly, 1);
        chunks[0]
    });

    // eval on d8
    // TODO: avoid cloning
    // TODO don't eval fixedlookup
    let columns_eval_d8 = columns_poly
        .clone()
        .map(|poly| poly.evaluate_over_domain_by_ref(domain.d8));
    // absorbing commit
    // TODO don't absorb the wires which already have been
    // TODO avoid cloning
    columns_com
        .clone()
        .into_iter()
        .for_each(|com| absorb_commitment(&mut fq_sponge, &PolyComm { chunks: vec![com] }));

    // Constraints combiner
    let alpha: G::ScalarField = fq_sponge.challenge();

    let challenges = MultiplicitiesChallenges {
        alpha,
        beta: beta_challenge,
        gamma: gamma_challenge,
    };
    let eval_env = MultiplicitiesEvalEnvironment {
        challenges,
        columns: &columns_eval_d8,
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
                vec![G::ScalarField::zero(); domain.d8.size as usize],
                domain.d8,
            ),
            G::ScalarField::one(),
        ),
        |(mut acc, alpha_pow), cst| {
            acc.add_assign(&cst.evaluations_d8(&eval_env).mul(alpha_pow));
            (acc, alpha_pow * alpha)
        },
    );
    let t_numerator_poly = t_numerator_evaluation.interpolate();
    let (t, rem) = t_numerator_poly
        .divide_by_vanishing_poly(domain.d1)
        .unwrap();
    assert!(rem.is_zero());
    let t_commitment = srs.commit_non_hiding(
        // TODO: change the nb of chunks later
        &t, num_chunk,
    );
    // TODO avoid cloning
    let commitments = AllColumns {
        cols: columns_com,
        quotient_chunks: t_commitment.chunks.clone(),
    };
    // Absorb t
    absorb_commitment(&mut fq_sponge, &t_commitment);
    // evaluate and prepare for IPA proof
    // TODO check num_chunks and srs length
    let t_chunks = t.to_chunked_polynomial(num_chunk, srs.size());
    // squeeze zeta
    // TODO: understand why we use the endo here and for IPA ,
    // but not for alpha
    let (_, endo_r) = G::endos();
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let zeta: G::ScalarField = zeta_chal.to_field(endo_r);
    let zeta_omega = zeta * domain.d1.group_gen;
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
