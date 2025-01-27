use crate::E;
use ark_ff::{One, PrimeField, Zero};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use core::iter::Once;
use kimchi::{circuits::domains::EvaluationDomains, curve::KimchiCurve};
use mina_poseidon::FqSponge;
use poly_commitment::{commitment::absorb_commitment, ipa::SRS, SRS as _};
//TODO Parralelize
//use rayon::prelude::*;
use std::iter::Chain;

/// This prover takes one Public Input and one Public Output
/// It then proves that the sum 1/(beta + table) = PI - PO
/// where the table term are term from fixed lookup or RAMLookup

pub struct AuxiliaryProofInput<F: PrimeField> {
    wires: Vec<Vec<F>>,
    arity: Vec<Vec<usize>>,
    beta_challenge: F,
    gamma_challenge: F,
}
pub struct ColumnEnv<X> {
    wires: Vec<X>,
    inverses: Vec<X>,
    acc: X,
}

impl<X> IntoIterator for ColumnEnv<X> {
    type Item = X;
    type IntoIter = Chain<
        Chain<<Vec<X> as IntoIterator>::IntoIter, <Vec<X> as IntoIterator>::IntoIter>,
        <Once<X> as IntoIterator>::IntoIter,
    >;
    fn into_iter(self) -> Self::IntoIter {
        self.wires
            .into_iter()
            .chain(self.inverses)
            .chain(std::iter::once(self.acc))
    }
}

pub struct AllColumns<X> {
    cols: ColumnEnv<X>,
    t_1: X,
    t_2: X,
}
pub struct Eval<F: PrimeField> {
    zeta: AllColumns<F>,
    zeta_omega: AllColumns<F>,
}

pub struct Proof<G: KimchiCurve> {
    //placeholder
    a: G::ScalarField,
}

pub fn aux_prove<G: KimchiCurve, EFqSponge: FqSponge<G::BaseField, G, G::ScalarField> + Clone>(
    input: AuxiliaryProofInput<G::ScalarField>,
    srs: &SRS<G>,
    domain: EvaluationDomains<G::ScalarField>,
    mut fq_sponge: EFqSponge,
    constraints: &[E<G::ScalarField>],
) ->  {
    let AuxiliaryProofInput {
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
    let eval_col = |evals: Vec<G::ScalarField>| {
        Evaluations::<G::ScalarField, Radix2EvaluationDomain<G::ScalarField>>::from_vec_and_domain(
            evals, domain.d1,
        )
        .interpolate()
    };
    let columns_poly = columns.into_iter().map(eval_col);
    // commiting
    let columns_com = columns_poly
        .into_iter()
        .map(|poly| srs.commit_non_hiding(&poly, 1));

    // abosrbing commit
    // TODO don't absorb the wires which already have been
    columns_com
        .into_iter()
        .for_each(|com| absorb_commitment(&mut fq_sponge, &com));

    // Constraints combiner
    let alpha: G::ScalarField = fq_sponge.challenge();
}
