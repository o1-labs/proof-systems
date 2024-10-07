mod combine;
pub mod commitment;
pub mod error;

/// Inner product argument
pub mod ipa;
/// KZG polynomial commitment scheme
pub mod kzg;

// Exposing property based tests for the SRS trait
pub mod pbt_srs;

pub use commitment::PolyComm;

use crate::{
    commitment::{BatchEvaluationProof, BlindedCommitment, CommitmentCurve},
    error::CommitmentError,
    ipa::DensePolynomialOrEvaluations,
};
use ark_ec::AffineRepr;
use ark_ff::UniformRand;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain as D,
};
use mina_poseidon::FqSponge;
use rand_core::{CryptoRng, RngCore};

pub trait SRS<G: CommitmentCurve>: Clone + Sized {
    /// The maximum polynomial degree that can be committed to
    fn max_poly_size(&self) -> usize;

    /// Retrieve the precomputed Lagrange basis for the given domain size
    fn get_lagrange_basis(&self, domain_size: usize) -> Option<&Vec<PolyComm<G>>>;

    /// Get the group element used for blinding commitments
    fn blinding_commitment(&self) -> G;

    /// Same as [SRS::mask] except that you can pass the blinders manually.
    /// A [BlindedCommitment] object is returned instead of a PolyComm object to
    /// keep the blinding factors and the commitment together. The blinded
    /// commitment is saved in the commitment field of the output.
    /// The output is wrapped into a [Result] to handle the case the blinders
    /// are not the same length than the number of chunks commitments have.
    fn mask_custom(
        &self,
        com: PolyComm<G>,
        blinders: &PolyComm<G::ScalarField>,
    ) -> Result<BlindedCommitment<G>, CommitmentError>;

    /// Turns a non-hiding polynomial commitment into a hidding polynomial
    /// commitment. Transforms each given `<a, G>` into `(<a, G> + wH, w)` with
    /// a random `w` per commitment.
    /// A [BlindedCommitment] object is returned instead of a PolyComm object to
    /// keep the blinding factors and the commitment together. The blinded
    /// commitment is saved in the commitment field of the output.
    fn mask(
        &self,
        comm: PolyComm<G>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<G> {
        let blinders = comm.map(|_| G::ScalarField::rand(rng));
        self.mask_custom(comm, &blinders).unwrap()
    }

    /// This function commits a polynomial using the SRS' basis of size `n`.
    /// - `plnm`: polynomial to commit to. The polynomial can be of any degree,
    /// including higher than `n`.
    /// - `num_chunks`: the minimal number of commitments to be included in the
    /// output polynomial commitment.
    ///
    /// The function returns the commitments to the chunks (of size at most `n`) of
    /// the polynomials.
    ///
    /// The function will also pad with zeroes if the polynomial has a degree
    /// smaller than `n * num_chunks`.
    ///
    /// Note that if the polynomial has a degree higher than `n * num_chunks`,
    /// the output will contain more than `num_chunks` commitments as it will
    /// also contain the additional chunks.
    ///
    /// See the test
    /// [crate::pbt_srs::test_regression_commit_non_hiding_expected_number_of_chunks]
    /// for an example of the number of chunks returned.
    fn commit_non_hiding(
        &self,
        plnm: &DensePolynomial<G::ScalarField>,
        num_chunks: usize,
    ) -> PolyComm<G>;

    /// Commits a polynomial, potentially splitting the result in multiple
    /// commitments.
    /// It is analogous to [SRS::commit_evaluations] but for polynomials.
    /// A [BlindedCommitment] object is returned instead of a PolyComm object to
    /// keep the blinding factors and the commitment together. The blinded
    /// commitment is saved in the commitment field of the output.
    fn commit(
        &self,
        plnm: &DensePolynomial<G::ScalarField>,
        num_chunks: usize,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<G>;

    /// Commit to a polynomial, with custom blinding factors.
    /// It is a combination of [SRS::commit] and [SRS::mask_custom].
    /// It is analogous to [SRS::commit_evaluations_custom] but for polynomials.
    /// A [BlindedCommitment] object is returned instead of a PolyComm object to
    /// keep the blinding factors and the commitment together. The blinded
    /// commitment is saved in the commitment field of the output.
    /// The output is wrapped into a [Result] to handle the case the blinders
    /// are not the same length than the number of chunks commitments have.
    fn commit_custom(
        &self,
        plnm: &DensePolynomial<G::ScalarField>,
        num_chunks: usize,
        blinders: &PolyComm<G::ScalarField>,
    ) -> Result<BlindedCommitment<G>, CommitmentError>;

    /// Commit to evaluations, without blinding factors.
    /// It is analogous to [SRS::commit_non_hiding] but for evaluations.
    fn commit_evaluations_non_hiding(
        &self,
        domain: D<G::ScalarField>,
        plnm: &Evaluations<G::ScalarField, D<G::ScalarField>>,
    ) -> PolyComm<G>;

    /// Commit to evaluations with blinding factors, generated using the random
    /// number generator `rng`.
    /// It is analogous to [SRS::commit] but for evaluations.
    /// A [BlindedCommitment] object is returned instead of a PolyComm object to
    /// keep the blinding factors and the commitment together. The blinded
    /// commitment is saved in the commitment field of the output.
    fn commit_evaluations(
        &self,
        domain: D<G::ScalarField>,
        plnm: &Evaluations<G::ScalarField, D<G::ScalarField>>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<G>;

    /// Commit to evaluations with custom blinding factors.
    /// It is a combination of [SRS::commit_evaluations] and [SRS::mask_custom].
    /// It is analogous to [SRS::commit_custom] but for evaluations.
    /// A [BlindedCommitment] object is returned instead of a PolyComm object to
    /// keep the blinding factors and the commitment together. The blinded
    /// commitment is saved in the commitment field of the output.
    /// The output is wrapped into a [Result] to handle the case the blinders
    /// are not the same length than the number of chunks commitments have.
    fn commit_evaluations_custom(
        &self,
        domain: D<G::ScalarField>,
        plnm: &Evaluations<G::ScalarField, D<G::ScalarField>>,
        blinders: &PolyComm<G::ScalarField>,
    ) -> Result<BlindedCommitment<G>, CommitmentError>;

    fn create(depth: usize) -> Self;

    fn add_lagrange_basis(&mut self, domain: D<G::ScalarField>);

    fn size(&self) -> usize;
}

#[allow(type_alias_bounds)]
/// Simply an alias to represent a polynomial with its commitment, possibly with
/// a blinder.
// TODO: add a string to name the polynomial
type PolynomialsToCombine<'a, G: CommitmentCurve, D: EvaluationDomain<G::ScalarField>> = &'a [(
    DensePolynomialOrEvaluations<'a, G::ScalarField, D>,
    PolyComm<G::ScalarField>,
)];

pub trait OpenProof<G: CommitmentCurve>: Sized + Clone {
    type SRS: SRS<G>;

    /// Parameters:
    /// - `srs`: the structured reference string
    /// - `group_map`: the group map
    /// - `plnms`: vector of polynomials with optional degree bound and
    /// commitment randomness
    /// - `elm`: vector of evaluation points
    /// - `polyscale`: scaling factor for polynoms
    /// - `evalscale`: scaling factor for evaluation point powers
    /// - `sponge`: Sponge used to coin and absorb values
    /// - `rng`: The RNG to use to generate random elements in the open
    #[allow(clippy::too_many_arguments)]
    fn open<EFqSponge, RNG, D: EvaluationDomain<<G as AffineRepr>::ScalarField>>(
        srs: &Self::SRS,
        group_map: &<G as CommitmentCurve>::Map,
        plnms: PolynomialsToCombine<G, D>,
        elm: &[<G as AffineRepr>::ScalarField],
        polyscale: <G as AffineRepr>::ScalarField,
        evalscale: <G as AffineRepr>::ScalarField,
        sponge: EFqSponge, // sponge
        rng: &mut RNG,
    ) -> Self
    where
        EFqSponge:
            Clone + FqSponge<<G as AffineRepr>::BaseField, G, <G as AffineRepr>::ScalarField>,
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
