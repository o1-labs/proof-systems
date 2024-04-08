use crate::lookups::LookupTableIDs;
use ark_poly::{Evaluations, Radix2EvaluationDomain as D};
use kimchi::{circuits::domains::EvaluationDomains, curve::KimchiCurve, plonk_sponge::FrSponge};
use kimchi_msm::{proof::ProofInputs, witness::Witness};
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use poly_commitment::{commitment::absorb_commitment, OpenProof, SRS as _};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};

/// This function folds the witness of the current circuit with the accumulated Keccak instance
/// with a random combination using a scaling challenge
pub fn fold<
    const N: usize,
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    accumulator: &mut ProofInputs<N, G, LookupTableIDs>,
    inputs: &Witness<N, Vec<G::ScalarField>>,
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
            .collect::<Witness<N, _>>()
    };
    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());

    commitments.into_iter().for_each(|comm| {
        absorb_commitment(&mut fq_sponge, &comm);
    });

    let scaling_challenge = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let scaling_challenge = scaling_challenge.to_field(endo_r);
    // TODO: fold mvlookups as well
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
