use crate::E;
use ark_ff::{One, PrimeField, Zero};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use core::iter::Once;
use kimchi::circuits::domains::EvaluationDomains;
use kimchi::curve::KimchiCurve;
use mina_poseidon::FqSponge;
use poly_commitment::commitment::absorb_commitment;
use poly_commitment::ipa::SRS;
use poly_commitment::SRS as _;
//TODO Parralelize
//use rayon::prelude::*;
use std::iter::Chain;

/// This 'auxiliary' prover is intended to be used in a streaming
/// fashion. It will receive a chunk of wire to be looked-up,
/// and output their corresponding contribution to the accumulator.
/// Once the proof is produced, these wires are no longer needed
/// for the rest of the protocol

pub struct AuxiliaryProofInput<F: PrimeField> {
    wires: Vec<Vec<F>>,
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
    //    Chain<<Vec<X> as IntoIterator>::IntoIter, <Vec<X> as IntoIterator>::IntoIter>
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
) -> () {
    let AuxiliaryProofInput {
        wires,
        beta_challenge,
        gamma_challenge,
    } = input;
    // compute the 1/beta+value for each individual wires
    let mut to_inv_wires: Vec<Vec<G::ScalarField>> = wires
        .iter()
        .map(|inner_vec| inner_vec.iter().map(|x| *x + beta_challenge).collect())
        .collect();
    to_inv_wires
        .iter_mut()
        .for_each(|inner_vec| ark_ff::batch_inversion(inner_vec));
    // compute the accumulator
    let mut to_inv_acc: Vec<G::ScalarField> = wires
        .iter()
        .map(|inner_vec| {
            let (res, _) = inner_vec.iter().fold(
                (beta_challenge, G::ScalarField::one()),
                |(acc, gamma_i), x| (acc + gamma_i * x, gamma_i * gamma_challenge),
            );
            res
        })
        .collect();
    ark_ff::batch_inversion(&mut to_inv_acc);
    let mut partial_sum = G::ScalarField::zero();
    for x in to_inv_acc.iter_mut() {
        partial_sum += *x;
        *x = partial_sum;
    }
    let columns = ColumnEnv {
        wires,
        inverses: to_inv_wires,
        acc: to_inv_acc,
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
