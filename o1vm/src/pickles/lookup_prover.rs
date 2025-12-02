use ark_ff::{One, PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Polynomial, Radix2EvaluationDomain};
use kimchi::{circuits::domains::EvaluationDomains, curve::KimchiCurve, plonk_sponge::FrSponge};
use mina_poseidon::FqSponge;
use o1_utils::ExtendedDensePolynomial;
use poly_commitment::{commitment::absorb_commitment, ipa::SRS, OpenProof, SRS as _};
//TODO Parallelize
//use rayon::prelude::*;
use super::lookup_columns::{ELookup, LookupChallenges, LookupEvalEnvironment};
use crate::pickles::lookup_columns::*;
use kimchi::{circuits::expr::l0_1, groupmap::GroupMap};
use poly_commitment::{ipa::OpeningProof, utils::DensePolynomialOrEvaluations, PolyComm};
use rand::{CryptoRng, RngCore};

/// This prover takes one Public Input and one Public Output
/// It then proves that the sum 1/(beta + table) = PI - PO
/// where the table term are term from fixed lookup or RAMLookup

pub fn lookup_prove<
    G: KimchiCurve,
    EFqSponge: FqSponge<G::BaseField, G, G::ScalarField> + Clone,
    EFrSponge: FrSponge<G::ScalarField>,
    RNG,
>(
    input: LookupProofInput<G::ScalarField>,
    acc_init: G::ScalarField,
    srs: &SRS<G>,
    domain: EvaluationDomains<G::ScalarField>,
    mut fq_sponge: EFqSponge,
    constraint: &ELookup<G::ScalarField>,
    rng: &mut RNG,
) -> (Proof<G>, G::ScalarField)
where
    G::BaseField: PrimeField,
    RNG: RngCore + CryptoRng,
{
    // TODO check that
    let num_chunk = 8;
    let LookupProofInput {
        wires,
        arity,
        beta_challenge,
        gamma_challenge,
    } = input;
    // Compute how many inverse wires we need to define pad function accordingly
    let nb_inv_wires = arity
        .iter()
        .max_by(|a, b| a.len().cmp(&b.len()))
        .unwrap()
        .len();
    let pad = |mut vec: Vec<G::ScalarField>| {
        vec.append(&mut vec![G::ScalarField::zero(); nb_inv_wires]);
        vec
    };

    // Compute the 1/beta+sum_i gamma^i value_i for each lookup term
    // The inversions is computed in batch in the end
    let mut inverses: Vec<Vec<G::ScalarField>> = wires
        .iter()
        .zip(arity)
        .map(|(inner_vec, arity)| {
            arity
                .into_iter()
                .map(|arity| {
                    // TODO don't recompute gamma powers everytime
                    let (res, _) = inner_vec.iter().take(arity).fold(
                        (beta_challenge, G::ScalarField::one()),
                        |(acc, gamma_i), x| (acc + gamma_i * x, gamma_i * gamma_challenge),
                    );
                    res
                })
                .collect()
        })
        .map(pad)
        .collect();
    // Perform the inversion
    inverses
        .iter_mut()
        .for_each(|inner_vec| ark_ff::batch_inversion(inner_vec));
    // Compute the accumulator
    // Init at acc_init
    let mut partial_sum = acc_init;
    let mut acc = vec![];
    for inner in inverses.iter_mut() {
        for x in inner.iter_mut() {
            partial_sum += *x;
            acc.push(partial_sum)
        }
    }
    let acc_final = acc[acc.len()];
    let columns = ColumnEnv {
        wires,
        inverses,
        acc,
    };
    // Interpolating
    let interpolate_col = |evals: Vec<G::ScalarField>| {
        Evaluations::<G::ScalarField, Radix2EvaluationDomain<G::ScalarField>>::from_vec_and_domain(
            evals, domain.d1,
        )
        .interpolate()
    };
    let columns_poly = columns.my_map(interpolate_col);
    // Committing
    // TODO avoid cloning
    let columns_com = columns_poly
        .clone()
        .my_map(|poly| srs.commit_non_hiding(&poly, 1).chunks[0]);

    // eval on d8
    // TODO: check the degree
    // TODO: avoid cloning
    let columns_eval_d8 = columns_poly
        .clone()
        .my_map(|poly| poly.evaluate_over_domain_by_ref(domain.d8));
    // absorbing commit
    // TODO don't absorb the wires which already have been
    // TODO avoid cloning
    columns_com
        .clone()
        .into_iter()
        .for_each(|com| absorb_commitment(&mut fq_sponge, &PolyComm { chunks: vec![com] }));

    // Constraints combiner
    let alpha: G::ScalarField = fq_sponge.challenge();

    let challenges = LookupChallenges {
        alpha,
        beta: beta_challenge,
        gamma: gamma_challenge,
    };
    let eval_env = LookupEvalEnvironment {
        challenges,
        columns: &columns_eval_d8,
        domain: &domain,
        l0_1: l0_1(domain.d1),
    };
    let t_numerator_evaluation: Evaluations<
        G::ScalarField,
        Radix2EvaluationDomain<G::ScalarField>,
    > = constraint.evaluations(&eval_env);
    let t_numerator_poly = t_numerator_evaluation.interpolate();
    let (t, rem) = t_numerator_poly.divide_by_vanishing_poly(domain.d1);
    assert!(!rem.is_zero());
    let t_commitment = srs.commit_non_hiding(
        &t, 8, //TODO: check the degree,
    );
    // TODO avoid cloning
    let commitments = AllColumns {
        cols: columns_com,
        t_shares: t_commitment.chunks.clone(),
    };
    // Absorb t
    absorb_commitment(&mut fq_sponge, &t_commitment);
    // evaluate and prepare for IPA proof
    // TODO check num_chunks and srs length
    let t_chunks = t.to_chunked_polynomial(num_chunk, srs.size());
    let zeta = fq_sponge.challenge();
    let zeta_omega = zeta * domain.d1.group_gen;
    let eval =
        |x,
         cols_poly: ColumnEnv<DensePolynomial<_>>,
         t_chunks: o1_utils::chunked_polynomial::ChunkedPolynomial<_>| AllColumns {
            cols: cols_poly.my_map(|poly| poly.evaluate(&x)),
            t_shares: t_chunks
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
    let (_, endo_r) = G::endos();
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
        t_shares: t_chunks.polys,
    };
    let polynomials: Vec<_> = all_columns_poly.into_iter().collect();
    let polynomials : Vec<_> = polynomials.iter().map(|poly| {
        (
            DensePolynomialOrEvaluations::<_,Radix2EvaluationDomain<G::ScalarField>>::DensePolynomial(poly),
            // We do not have any blinder, therefore we set to 1.
            PolyComm::new(vec![G::ScalarField::one()]),
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
    (
        Proof {
            commitments,
            evaluations,
            ipa_proof,
        },
        acc_final,
    )
}
