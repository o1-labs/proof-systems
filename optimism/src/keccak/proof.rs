use super::column::KeccakColumns;
use crate::DOMAIN_SIZE;
use ark_ff::{One, Zero};
use ark_poly::{Evaluations, Radix2EvaluationDomain as D};
use kimchi::{circuits::domains::EvaluationDomains, curve::KimchiCurve, plonk_sponge::FrSponge};
use mina_poseidon::sponge::ScalarChallenge;
use mina_poseidon::FqSponge;
use poly_commitment::OpenProof;
use poly_commitment::{
    commitment::{absorb_commitment, PolyComm},
    SRS as _,
};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};

#[derive(Debug)]
pub struct KeccakProofInputs<G: KimchiCurve> {
    evaluations: KeccakColumns<Vec<G::ScalarField>>,
}

impl<G: KimchiCurve> Default for KeccakProofInputs<G> {
    fn default() -> Self {
        KeccakProofInputs {
            evaluations: KeccakColumns {
                hash_index: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
                step_index: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
                flag_round: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
                flag_absorb: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
                flag_squeeze: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
                flag_root: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
                flag_pad: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
                flag_length: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
                two_to_pad: (0..DOMAIN_SIZE).map(|_| G::ScalarField::one()).collect(),
                inverse_round: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
                flags_bytes: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
                pad_suffix: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
                round_constants: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
                curr: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
                next: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
            },
        }
    }
}

#[derive(Debug)]
pub struct KeccakProof<G: KimchiCurve, OpeningProof: OpenProof<G>> {
    _commitments: KeccakColumns<PolyComm<G>>,
    _zeta_evaluations: KeccakColumns<G::ScalarField>,
    _zeta_omega_evaluations: KeccakColumns<G::ScalarField>,
    _opening_proof: OpeningProof,
}

pub fn fold<
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    accumulator: &mut KeccakProofInputs<G>,
    inputs: &KeccakColumns<Vec<G::ScalarField>>,
) where
    <OpeningProof as poly_commitment::OpenProof<G>>::SRS: std::marker::Sync,
{
    let commitments = {
        inputs
            .par_iter()
            .map(|evals: &Vec<G::ScalarField>| {
                let evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                    evals.clone(),
                    domain.d1,
                );
                srs.commit_evaluations_non_hiding(domain.d1, &evals)
            })
            .collect::<KeccakColumns<_>>()
    };
    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());

    for column in commitments.into_iter() {
        absorb_commitment(&mut fq_sponge, &column);
    }
    let scaling_challenge = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let scaling_challenge = scaling_challenge.to_field(endo_r);
    accumulator
        .evaluations
        .par_iter_mut()
        .zip(inputs.par_iter())
        .for_each(|(accumulator, inputs)| {
            accumulator
                .par_iter_mut()
                .zip(inputs.par_iter())
                .for_each(|(accumulator, input)| {
                    *accumulator = *input + scaling_challenge * *accumulator
                });
        });
}
