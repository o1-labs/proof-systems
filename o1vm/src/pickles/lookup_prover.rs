use ark_ff::{One, PrimeField, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{Evaluations, Polynomial, Radix2EvaluationDomain};
use kimchi::{circuits::domains::EvaluationDomains, curve::KimchiCurve};
use mina_poseidon::FqSponge;
use o1_utils::ExtendedDensePolynomial;
use poly_commitment::OpenProof;
use poly_commitment::{commitment::absorb_commitment, ipa::SRS, SRS as _};
//TODO Parralelize
//use rayon::prelude::*;
use super::lookup_columns::ELookup;
use super::lookup_columns::{LookupChallenges, LookupEvalEnvironment};
use crate::pickles::lookup_columns::ColumnEnv;
use kimchi::circuits::expr::l0_1;
use poly_commitment::ipa::OpeningProof;
use std::iter::Chain;
use std::iter::Once;
use std::vec::IntoIter;
/// This prover takes one Public Input and one Public Output
/// It then proves that the sum 1/(beta + table) = PI - PO
/// where the table term are term from fixed lookup or RAMLookup

pub struct LookupProofInput<F: PrimeField> {
    wires: Vec<Vec<F>>,
    arity: Vec<Vec<usize>>,
    beta_challenge: F,
    gamma_challenge: F,
}

pub struct AllColumns<X> {
    pub cols: ColumnEnv<X>,
    pub t_shares: Vec<X>,
}

impl<X> IntoIterator for AllColumns<X> {
    type Item = X;
    type IntoIter =
        Chain<<ColumnEnv<X> as IntoIterator>::IntoIter, <Vec<X> as IntoIterator>::IntoIter>;
    fn into_iter(self) -> Self::IntoIter {
        self.cols.into_iter().chain(self.t_shares)
    }
}

pub struct Eval<F: PrimeField> {
    pub zeta: AllColumns<F>,
    pub zeta_omega: AllColumns<F>,
}

impl<F: PrimeField> IntoIterator for Eval<F> {
    type Item = F;
    type IntoIter =
        Chain<<AllColumns<F> as IntoIterator>::IntoIter, <AllColumns<F> as IntoIterator>::IntoIter>;
    fn into_iter(self) -> Self::IntoIter {
        self.zeta.into_iter().chain(self.zeta_omega)
    }
}

pub struct Proof<G: KimchiCurve> {
    pub commitments: AllColumns<G>,
    pub evaluations: Eval<G::ScalarField>,
    pub ipa_proof: OpeningProof<G>,
}

pub fn lookup_prove<
    G: KimchiCurve,
    EFqSponge: FqSponge<G::BaseField, G, G::ScalarField> + Clone,
>(
    input: LookupProofInput<G::ScalarField>,
    srs: &SRS<G>,
    domain: EvaluationDomains<G::ScalarField>,
    mut fq_sponge: EFqSponge,
    constraint: &ELookup<G::ScalarField>,
) {
    // TODO check that
    let num_chunk = 8;
    let LookupProofInput {
        wires,
        arity,
        beta_challenge,
        gamma_challenge,
    } = input;
    //Compute how many inverse wires we need to define pad function accordingly
    let nb_inv_wires = arity
        .iter()
        .max_by(|a, b| a.len().cmp(&b.len()))
        .unwrap()
        .len();
    let pad = |mut vec: Vec<G::ScalarField>| {
        vec.append(&mut vec![G::ScalarField::zero(); nb_inv_wires]);
        vec
    };

    // compute the 1/beta+sum_i gamma^i value_i for each lookup term
    // The inversions is commputed in batch in the end
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
    //perform the inversion
    inverses
        .iter_mut()
        .for_each(|inner_vec| ark_ff::batch_inversion(inner_vec));
    // compute the accumulator
    let mut partial_sum = G::ScalarField::zero();
    let mut acc = vec![];
    for inner in inverses.iter_mut() {
        for x in inner.iter_mut() {
            partial_sum += *x;
            acc.push(partial_sum)
        }
    }
    let columns = ColumnEnv {
        wires,
        inverses,
        acc,
    };
    //interpolating
    let interpolate_col = |evals: Vec<G::ScalarField>| {
        Evaluations::<G::ScalarField, Radix2EvaluationDomain<G::ScalarField>>::from_vec_and_domain(
            evals, domain.d1,
        )
        .interpolate()
    };
    let columns_poly = columns.my_map(interpolate_col);
    // commiting
    let columns_com = columns_poly
        .clone()
        .my_map(|poly| srs.commit_non_hiding(&poly, 1).chunks[0]);

    // eval on d8
    //TODO: check the degree
    let columns_eval_d8 = columns_poly.my_map(|poly| poly.evaluate_over_domain_by_ref(domain.d8));
    // abosrbing commit
    // TODO don't absorb the wires which already have been
    columns_com
        .into_iter()
        .for_each(|com| absorb_commitment(&mut fq_sponge, &com));

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
    let (t, rem) = t_numerator_poly
        .divide_by_vanishing_poly(domain.d1)
        .unwrap();
    assert!(!rem.is_zero());
    let t_commitment = srs.commit_non_hiding(
        &t, 8, //TODO: check the degree,
    );
    let commitments = AllColumns {
        cols: columns_com,
        t_shares: t_commitment.chunks,
    };
    // Absorb t
    absorb_commitment(&mut fq_sponge, &t_commitment);
    // TODO check num_chunks and srs
    let t_chunks = t.to_chunked_polynomial(num_chunk, srs.size());
    let zeta = fq_sponge.challenge();
    let zeta_omega = zeta * domain.d1.group_gen;
    let eval = |x| AllColumns {
        cols: columns_poly.my_map(|poly| poly.evaluate(&x)),
        t_shares: t_chunks
            .polys
            .into_iter()
            .map(|poly| poly.evaluate(&x))
            .collect(),
    };
    let eval = Eval {
        zeta: eval(zeta),
        zeta_omega: eval(zeta_omega),
    };
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());
    //    let openingProof = OpeningProof::open(srs, group_map, plnms, elm, polyscale, evalscale, sponge, rng)
}
