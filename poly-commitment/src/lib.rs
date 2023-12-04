pub mod chunked;
mod combine;
pub mod commitment;
pub mod error;
pub mod evaluation_proof;
pub mod pairing_proof;
pub mod srs;

#[cfg(test)]
mod tests;

pub use commitment::PolyComm;

use crate::commitment::{BatchEvaluationProof, BlindedCommitment, CommitmentCurve};
use crate::error::CommitmentError;
use crate::evaluation_proof::DensePolynomialOrEvaluations;
use ark_ec::AffineCurve;
use ark_ff::UniformRand;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain as D,
};
use mina_poseidon::FqSponge;
use rand_core::{CryptoRng, RngCore};

pub trait SRS<G: CommitmentCurve> {
    /// The maximum polynomial degree that can be committed to
    fn max_poly_size(&self) -> usize;

    /// Retrieve the precomputed Lagrange basis for the given domain size
    fn get_lagrange_basis(&self, domain_size: usize) -> Option<&Vec<PolyComm<G>>>;

    /// Get the group element used for blinding commitments
    fn blinding_commitment(&self) -> G;

    /// Commits a polynomial, potentially splitting the result in multiple commitments.
    fn commit(
        &self,
        plnm: &DensePolynomial<G::ScalarField>,
        num_chunks: usize,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<G>;

    /// Same as [SRS::mask] except that you can pass the blinders manually.
    fn mask_custom(
        &self,
        com: PolyComm<G>,
        blinders: &PolyComm<G::ScalarField>,
    ) -> Result<BlindedCommitment<G>, CommitmentError>;

    /// Turns a non-hiding polynomial commitment into a hidding polynomial commitment. Transforms each given `<a, G>` into `(<a, G> + wH, w)` with a random `w` per commitment.
    fn mask(
        &self,
        comm: PolyComm<G>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<G> {
        let blinders = comm.map(|_| G::ScalarField::rand(rng));
        self.mask_custom(comm, &blinders).unwrap()
    }

    /// This function commits a polynomial using the SRS' basis of size `n`.
    /// - `plnm`: polynomial to commit to with max size of sections
    /// - `num_chunks`: the number of commitments to be included in the output polynomial commitment
    /// The function returns an unbounded commitment vector
    /// (which splits the commitment into several commitments of size at most `n`).
    fn commit_non_hiding(
        &self,
        plnm: &DensePolynomial<G::ScalarField>,
        num_chunks: usize,
    ) -> PolyComm<G>;

    fn commit_evaluations_non_hiding(
        &self,
        domain: D<G::ScalarField>,
        plnm: &Evaluations<G::ScalarField, D<G::ScalarField>>,
    ) -> PolyComm<G>;

    fn commit_evaluations(
        &self,
        domain: D<G::ScalarField>,
        plnm: &Evaluations<G::ScalarField, D<G::ScalarField>>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<G>;
}

#[allow(type_alias_bounds)]
/// Vector of triples (polynomial itself, degree bound, omegas).
type PolynomialsToCombine<'a, G: CommitmentCurve, D: EvaluationDomain<G::ScalarField>> = &'a [(
    DensePolynomialOrEvaluations<'a, G::ScalarField, D>,
    PolyComm<G::ScalarField>,
)];

pub trait OpenProof<G: CommitmentCurve>: Sized {
    type SRS: SRS<G>;

    #[allow(clippy::too_many_arguments)]
    fn open<EFqSponge, RNG, D: EvaluationDomain<<G as AffineCurve>::ScalarField>>(
        srs: &Self::SRS,
        group_map: &<G as CommitmentCurve>::Map,
        plnms: PolynomialsToCombine<G, D>, // vector of polynomial with optional degree bound and commitment randomness
        elm: &[<G as AffineCurve>::ScalarField], // vector of evaluation points
        polyscale: <G as AffineCurve>::ScalarField, // scaling factor for polynoms
        evalscale: <G as AffineCurve>::ScalarField, // scaling factor for evaluation point powers
        sponge: EFqSponge,                 // sponge
        rng: &mut RNG,
    ) -> Self
    where
        EFqSponge:
            Clone + FqSponge<<G as AffineCurve>::BaseField, G, <G as AffineCurve>::ScalarField>,
        RNG: RngCore + CryptoRng;

    fn verify<EFqSponge, RNG>(
        srs: &Self::SRS,
        group_map: &G::Map,
        batch: &mut [BatchEvaluationProof<G, EFqSponge, Self>],
        rng: &mut RNG,
    ) -> bool
    where
        EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>,
        RNG: RngCore + CryptoRng;
}
