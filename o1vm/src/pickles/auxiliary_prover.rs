use ark_ff::{One, PrimeField, Zero};
use kimchi::curve::KimchiCurve;

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
            .chain(self.inverses.into_iter())
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
    evaluations_zeta: ColumnEnv<G::ScalarField>,
}
pub fn aux_prove<G: KimchiCurve>(
    input: AuxiliaryProofInput<G::ScalarField>,
) -> Vec<G::ScalarField> {
    let AuxiliaryProofInput {
        wires,
        beta_challenge,
        gamma_challenge,
    } = input;
    let mut to_inv: Vec<G::ScalarField> = wires
        .iter()
        .map(|inner_vec| {
            let (res, _) = inner_vec.iter().fold(
                (beta_challenge, G::ScalarField::one()),
                |(acc, gamma_i), x| (acc + gamma_i * x, gamma_i * gamma_challenge),
            );
            res
        })
        .collect();
    ark_ff::batch_inversion(&mut to_inv);
    let mut partial_sum = G::ScalarField::zero();
    for x in to_inv.iter_mut() {
        partial_sum += x.clone();
        *x = partial_sum;
    }
    to_inv
}
