use crate::lookups::LookupTableIDs;
use ark_ff::Zero;
use ark_poly::{Evaluations, Radix2EvaluationDomain as D};
use folding::{decomposable_folding::DecomposableFoldingScheme, FoldingConfig};
use kimchi::{circuits::domains::EvaluationDomains, curve::KimchiCurve, plonk_sponge::FrSponge};
use kimchi_msm::{proof::ProofInputs, witness::Witness};
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use poly_commitment::{commitment::absorb_commitment, OpenProof, SRS as _};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};

/// FIXME: DUMMY FOLD FUNCTION THAT ONLY KEEPS THE LAST INSTANCE
// FIXME: we must pass an instance of the sponge.
// Or maybe it is already in the folding scheme?
pub fn fold<
    const N: usize,
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
    FC: FoldingConfig,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    // Left instance
    accumulator: &mut ProofInputs<N, G::ScalarField, LookupTableIDs>,
    // Right instance
    inputs: &Witness<N, Vec<G::ScalarField>>,
    _folding_scheme: Option<DecomposableFoldingScheme<FC>>,
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
    // FIXME: it must be passed as an argument or given in the folding scheme.
    // The folding scheme should keep track of a sponge state.
    // For the moment, leaving it like this. I only want to use the folding
    // scheme.
    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());

    commitments.into_iter().for_each(|comm| {
        absorb_commitment(&mut fq_sponge, &comm);
    });

    // -----
    // Generating the challenges.
    // FIXME: check twice if the challenges are generated correctly.

    // // For lookups.
    // // Can be none atm.
    let beta: G::ScalarField = fq_sponge.challenge();
    let joint_combiner: G::ScalarField = fq_sponge.challenge();
    // // FIXME: Set to zero for now
    let beta: G::ScalarField = G::ScalarField::zero();

    // // For combining the constraints
    let alpha: G::ScalarField = fq_sponge.challenge();

    // let instance: FC::Instance = FC::Instance::new();
    // FIXME: here relax + fold instance + witness + generate challenges + call
    // folding scheme

    // TODO: fold mvlookups as well
    accumulator
        .evaluations
        .par_iter_mut()
        .zip(inputs.par_iter())
        .for_each(|(accumulator, inputs)| {
            accumulator
                .par_iter_mut()
                .zip(inputs.par_iter())
                .for_each(|(accumulator, input)| *accumulator = *input);
        });
}

#[allow(dead_code)]
/// This function folds the witness of the current circuit with the accumulated Keccak instance
/// with a random combination using a scaling challenge
// FIXME: This will have to be adapted when the folding library is available
fn old_fold<
    const N: usize,
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    accumulator: &mut ProofInputs<N, G::ScalarField, LookupTableIDs>,
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
