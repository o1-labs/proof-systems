//! This module implements the KZG protocol described in the paper
//! [Constant-Size Commitments to Polynomials and Their
//! Applications](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf)
//! by Kate, Zaverucha and Goldberg, often referred to as the KZG10 paper.
//!
//! The protocol requires a structured reference string (SRS) that contains
//! powers of a generator of a group, and a pairing friendly curve.
//!
//! The pairing friendly curve requirement is hidden in the Pairing trait
//! parameter.

use crate::{
    commitment::*, ipa::SRS, utils::combine_polys, CommitmentError, PolynomialsToCombine,
    SRS as SRSTrait,
};

use ark_ec::{pairing::Pairing, AffineRepr, VariableBaseMSM};
use ark_ff::{One, PrimeField, Zero};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain as D,
};
use mina_poseidon::FqSponge;
use rand::thread_rng;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::ops::Neg;

/// Combine the (chunked) evaluations of multiple polynomials.
/// This function returns the accumulation of the evaluations, scaled by
/// `polyscale`.
/// If no evaluation is given, the function returns an empty vector.
/// It does also suppose that for each evaluation, the number of evaluations is
/// the same. It is not constrained yet in the interface, but it should be. If
/// one list has not the same size, it will be shrunk to the size of the first
/// element of the list.
/// For instance, if we have 3 polynomials P1, P2, P3 evaluated at the points
/// ζ and ζω (like in vanilla PlonK), and for each polynomial, we have two
/// chunks, i.e. we have
/// ```text
///         2 chunks of P1
///        /---------------\
/// E1 = [(P1_1(ζ), P1_2(ζ)), (P1_1(ζω), P1_2(ζω))]
/// E2 = [(P2_1(ζ), P2_2(ζ)), (P2_1(ζω), P2_2(ζω))]
/// E3 = [(P3_1(ζ), P3_2(ζ)), (P3_1(ζω), P3_2(ζω))]
/// ```
/// The output will be a list of 3 elements, equal to:
/// ```text
/// P1_1(ζ) + P1_2(ζ) * polyscale + P1_1(ζω) polyscale^2 + P1_2(ζω) * polyscale^3
/// P2_1(ζ) + P2_2(ζ) * polyscale + P2_1(ζω) polyscale^2 + P2_2(ζω) * polyscale^3
/// ```
pub fn combine_evaluations<G: CommitmentCurve>(
    evaluations: &[Evaluation<G>],
    polyscale: G::ScalarField,
) -> Vec<G::ScalarField> {
    let mut polyscale_i = G::ScalarField::one();
    let mut acc = {
        let num_evals = if !evaluations.is_empty() {
            evaluations[0].evaluations.len()
        } else {
            0
        };
        vec![G::ScalarField::zero(); num_evals]
    };

    for Evaluation { evaluations, .. } in evaluations.iter().filter(|x| !x.commitment.is_empty()) {
        // IMPROVEME: we could have a flat array that would contain all the
        // evaluations and all the chunks. It would avoid fetching the memory
        // and avoid indirection into RAM.
        // We could have a single flat array.
        // iterating over the polynomial segments
        for chunk_idx in 0..evaluations[0].len() {
            // supposes that all evaluations are of the same size
            for eval_pt_idx in 0..evaluations.len() {
                acc[eval_pt_idx] += evaluations[eval_pt_idx][chunk_idx] * polyscale_i;
            }
            polyscale_i *= polyscale;
        }
    }

    acc
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(
    bound = "Pair::G1Affine: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize"
)]
pub struct KZGProof<Pair: Pairing> {
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub quotient: Pair::G1Affine,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    /// A blinding factor used to hide the polynomial, if necessary
    pub blinding: <Pair::G1Affine as AffineRepr>::ScalarField,
}

impl<Pair: Pairing> Default for KZGProof<Pair> {
    fn default() -> Self {
        Self {
            quotient: Pair::G1Affine::generator(),
            blinding: <Pair::G1Affine as AffineRepr>::ScalarField::zero(),
        }
    }
}

impl<Pair: Pairing> Clone for KZGProof<Pair> {
    fn clone(&self) -> Self {
        Self {
            quotient: self.quotient,
            blinding: self.blinding,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
/// Define a structured reference string (i.e. SRS) for the KZG protocol.
/// The SRS consists of powers of an element `g^x` for some toxic waste `x`.
///
/// The SRS is formed using what we call a "trusted setup". For now, the setup
/// is created using the method `create_trusted_setup`.
pub struct PairingSRS<Pair: Pairing> {
    /// The full SRS is the one used by the prover. Can be seen as the "proving
    /// key"/"secret key"
    pub full_srs: SRS<Pair::G1Affine>,
    /// SRS to be used by the verifier. Can be seen as the "verification
    /// key"/"public key".
    pub verifier_srs: SRS<Pair::G2Affine>,
}

impl<
        F: PrimeField,
        G: CommitmentCurve<ScalarField = F>,
        G2: CommitmentCurve<ScalarField = F>,
        Pair: Pairing<G1Affine = G, G2Affine = G2>,
    > PairingSRS<Pair>
{
    /// Create a trusted setup for the KZG protocol.
    /// The setup is created using a toxic waste `toxic_waste` and a depth
    /// `depth`.
    pub fn create_trusted_setup(toxic_waste: F, depth: usize) -> Self {
        let full_srs = unsafe { SRS::create_trusted_setup(toxic_waste, depth) };
        let verifier_srs = unsafe { SRS::create_trusted_setup(toxic_waste, 3) };
        Self {
            full_srs,
            verifier_srs,
        }
    }
}

impl<Pair: Pairing> Default for PairingSRS<Pair> {
    fn default() -> Self {
        Self {
            full_srs: SRS::default(),
            verifier_srs: SRS::default(),
        }
    }
}

impl<Pair: Pairing> Clone for PairingSRS<Pair> {
    fn clone(&self) -> Self {
        Self {
            full_srs: self.full_srs.clone(),
            verifier_srs: self.verifier_srs.clone(),
        }
    }
}

impl<
        F: PrimeField,
        G: CommitmentCurve<ScalarField = F>,
        G2: CommitmentCurve<ScalarField = F>,
        Pair: Pairing<G1Affine = G, G2Affine = G2>,
    > crate::OpenProof<G> for KZGProof<Pair>
{
    type SRS = PairingSRS<Pair>;

    /// Parameters:
    /// - `srs`: the structured reference string
    /// - `plnms`: vector of polynomials with optional degree bound and
    ///   commitment randomness
    /// - `elm`: vector of evaluation points
    /// - `polyscale`: scaling factor for polynoms
    ///   group_maps, sponge, rng and evalscale are not used. The parameters are
    ///   kept to fit the trait and to be used generically.
    fn open<EFqSponge, RNG, D: EvaluationDomain<F>>(
        srs: &Self::SRS,
        _group_map: &<G as CommitmentCurve>::Map,
        plnms: PolynomialsToCombine<G, D>,
        elm: &[<G as AffineRepr>::ScalarField],
        polyscale: <G as AffineRepr>::ScalarField,
        _evalscale: <G as AffineRepr>::ScalarField,
        _sponge: EFqSponge,
        _rng: &mut RNG,
    ) -> Self
    where
        EFqSponge: Clone + FqSponge<<G as AffineRepr>::BaseField, G, F>,
        RNG: RngCore + CryptoRng,
    {
        KZGProof::create(srs, plnms, elm, polyscale).unwrap()
    }

    fn verify<EFqSponge, RNG>(
        srs: &Self::SRS,
        _group_map: &G::Map,
        batch: &mut [BatchEvaluationProof<G, EFqSponge, Self>],
        _rng: &mut RNG,
    ) -> bool
    where
        EFqSponge: FqSponge<G::BaseField, G, F>,
        RNG: RngCore + CryptoRng,
    {
        for BatchEvaluationProof {
            sponge: _,
            evaluations,
            evaluation_points,
            polyscale,
            evalscale: _,
            opening,
            combined_inner_product: _,
        } in batch.iter()
        {
            if !opening.verify(srs, evaluations, *polyscale, evaluation_points) {
                return false;
            }
        }
        true
    }
}

impl<
        F: PrimeField,
        G: CommitmentCurve<ScalarField = F>,
        G2: CommitmentCurve<ScalarField = F>,
        Pair: Pairing<G1Affine = G, G2Affine = G2>,
    > SRSTrait<G> for PairingSRS<Pair>
{
    fn max_poly_size(&self) -> usize {
        self.full_srs.max_poly_size()
    }

    fn get_lagrange_basis(&self, domain: D<G::ScalarField>) -> &Vec<PolyComm<G>> {
        self.full_srs.get_lagrange_basis(domain)
    }

    fn get_lagrange_basis_from_domain_size(&self, domain_size: usize) -> &Vec<PolyComm<G>> {
        self.full_srs
            .get_lagrange_basis_from_domain_size(domain_size)
    }

    fn blinding_commitment(&self) -> G {
        self.full_srs.blinding_commitment()
    }

    fn mask_custom(
        &self,
        com: PolyComm<G>,
        blinders: &PolyComm<G::ScalarField>,
    ) -> Result<BlindedCommitment<G>, CommitmentError> {
        self.full_srs.mask_custom(com, blinders)
    }

    fn mask(
        &self,
        comm: PolyComm<G>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<G> {
        self.full_srs.mask(comm, rng)
    }

    fn commit(
        &self,
        plnm: &DensePolynomial<F>,
        num_chunks: usize,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<G> {
        self.full_srs.commit(plnm, num_chunks, rng)
    }

    fn commit_non_hiding(
        &self,
        plnm: &DensePolynomial<G::ScalarField>,
        num_chunks: usize,
    ) -> PolyComm<G> {
        self.full_srs.commit_non_hiding(plnm, num_chunks)
    }

    fn commit_custom(
        &self,
        plnm: &DensePolynomial<<G>::ScalarField>,
        num_chunks: usize,
        blinders: &PolyComm<<G>::ScalarField>,
    ) -> Result<BlindedCommitment<G>, CommitmentError> {
        self.full_srs.commit_custom(plnm, num_chunks, blinders)
    }

    fn commit_evaluations_non_hiding(
        &self,
        domain: D<G::ScalarField>,
        plnm: &Evaluations<G::ScalarField, D<G::ScalarField>>,
    ) -> PolyComm<G> {
        self.full_srs.commit_evaluations_non_hiding(domain, plnm)
    }

    fn commit_evaluations(
        &self,
        domain: D<G::ScalarField>,
        plnm: &Evaluations<G::ScalarField, D<G::ScalarField>>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<G> {
        self.full_srs.commit_evaluations(domain, plnm, rng)
    }

    fn commit_evaluations_custom(
        &self,
        domain: D<<G>::ScalarField>,
        plnm: &Evaluations<<G>::ScalarField, D<<G>::ScalarField>>,
        blinders: &PolyComm<<G>::ScalarField>,
    ) -> Result<BlindedCommitment<G>, CommitmentError> {
        self.full_srs
            .commit_evaluations_custom(domain, plnm, blinders)
    }

    fn create(depth: usize) -> Self {
        let mut rng = thread_rng();
        let toxic_waste = G::ScalarField::rand(&mut rng);
        Self::create_trusted_setup(toxic_waste, depth)
    }

    fn size(&self) -> usize {
        self.full_srs.g.len()
    }
}

/// The polynomial that evaluates to each of `evals` for the respective `elm`s.
/// For now, only works for 2 evaluations points.
/// `elm` is the vector of evaluation points and `evals` is the vector of
/// evaluations at those points.
fn eval_polynomial<F: PrimeField>(elm: &[F], evals: &[F]) -> DensePolynomial<F> {
    assert_eq!(elm.len(), evals.len());
    let (zeta, zeta_omega) = if elm.len() == 2 {
        (elm[0], elm[1])
    } else {
        todo!()
    };
    let (eval_zeta, eval_zeta_omega) = if evals.len() == 2 {
        (evals[0], evals[1])
    } else {
        todo!()
    };

    // The polynomial that evaluates to `p(ζ)` at `ζ` and `p(ζω)` at
    // `ζω`.
    // We write `p(x) = a + bx`, which gives
    // ```text
    // p(ζ) = a + b * ζ
    // p(ζω) = a + b * ζω
    // ```
    // and so
    // ```text
    // b = (p(ζω) - p(ζ)) / (ζω - ζ)
    // a = p(ζ) - b * ζ
    // ```
    let b = (eval_zeta_omega - eval_zeta) / (zeta_omega - zeta);
    let a = eval_zeta - b * zeta;
    DensePolynomial::from_coefficients_slice(&[a, b])
}

/// The polynomial that evaluates to `0` at the evaluation points.
fn divisor_polynomial<F: PrimeField>(elm: &[F]) -> DensePolynomial<F> {
    elm.iter()
        .map(|value| DensePolynomial::from_coefficients_slice(&[-(*value), F::one()]))
        .reduce(|poly1, poly2| &poly1 * &poly2)
        .unwrap()
}

impl<
        F: PrimeField,
        G: CommitmentCurve<ScalarField = F>,
        G2: CommitmentCurve<ScalarField = F>,
        Pair: Pairing<G1Affine = G, G2Affine = G2>,
    > KZGProof<Pair>
{
    /// Create a KZG proof.
    /// Parameters:
    /// - `srs`: the structured reference string used to commit
    ///   to the polynomials
    /// - `plnms`: the list of polynomials to open.
    ///   The type is simply an alias to handle the polynomials in evaluations or
    ///   coefficients forms.
    /// - `elm`: vector of evaluation points. Note that it only works for two
    ///   elements for now.
    /// - `polyscale`: a challenge to batch the polynomials.
    pub fn create<D: EvaluationDomain<F>>(
        srs: &PairingSRS<Pair>,
        plnms: PolynomialsToCombine<G, D>,
        elm: &[F],
        polyscale: F,
    ) -> Option<Self> {
        let (p, blinding_factor) = combine_polys::<G, D>(plnms, polyscale, srs.full_srs.g.len());
        let evals: Vec<_> = elm.iter().map(|pt| p.evaluate(pt)).collect();

        let quotient_poly = {
            // This is where the condition on two points is enforced.
            let eval_polynomial = eval_polynomial(elm, &evals);
            let divisor_polynomial = divisor_polynomial(elm);
            let numerator_polynomial = &p - &eval_polynomial;
            let (quotient, remainder) = DenseOrSparsePolynomial::divide_with_q_and_r(
                &numerator_polynomial.into(),
                &divisor_polynomial.into(),
            )?;
            if !remainder.is_zero() {
                return None;
            }
            quotient
        };

        let quotient = srs
            .full_srs
            .commit_non_hiding(&quotient_poly, 1)
            .get_first_chunk();

        Some(KZGProof {
            quotient,
            blinding: blinding_factor,
        })
    }

    /// Verify a proof. Note that it only works for two elements for now, i.e.
    /// elm must be of size 2.
    /// Also, chunking is not supported.
    pub fn verify(
        &self,
        srs: &PairingSRS<Pair>,        // SRS
        evaluations: &[Evaluation<G>], // commitments to the polynomials
        polyscale: F,                  // scaling factor for polynoms
        elm: &[F],                     // vector of evaluation points
    ) -> bool {
        let poly_commitment: G::Group = {
            let mut scalars: Vec<F> = Vec::new();
            let mut points = Vec::new();
            combine_commitments(
                evaluations,
                &mut scalars,
                &mut points,
                polyscale,
                F::one(), /* TODO: This is inefficient */
            );
            let scalars: Vec<_> = scalars.iter().map(|x| x.into_bigint()).collect();

            G::Group::msm_bigint(&points, &scalars)
        };

        // IMPROVEME: we could have a single flat array for all evaluations, see
        // same comment in combine_evaluations
        let evals = combine_evaluations(evaluations, polyscale);
        let blinding_commitment = srs.full_srs.h.mul(self.blinding);
        // Taking the first element of the commitment, i.e. no support for chunking.
        let divisor_commitment = srs
            .verifier_srs
            .commit_non_hiding(&divisor_polynomial(elm), 1)
            .get_first_chunk();
        // Taking the first element of the commitment, i.e. no support for chunking.
        let eval_commitment = srs
            .full_srs
            .commit_non_hiding(&eval_polynomial(elm, &evals), 1)
            .get_first_chunk()
            .into_group();
        let numerator_commitment = { poly_commitment - eval_commitment - blinding_commitment };
        // We compute the result of the multiplication of two miller loop,
        // to apply only one final exponentiation
        let to_loop_left = [
            ark_ec::pairing::prepare_g1::<Pair>(numerator_commitment),
            // Note that we do a neagtion here, to put everything on the same side
            ark_ec::pairing::prepare_g1::<Pair>(self.quotient.into_group().neg()),
        ];
        let to_loop_right = [
            ark_ec::pairing::prepare_g2::<Pair>(Pair::G2Affine::generator()),
            ark_ec::pairing::prepare_g2::<Pair>(divisor_commitment),
        ];
        // the result here is numerator_commitment * 1 - quotient * divisor_commitment
        // Note that the unwrap cannot fail as the output of a miller loop is non zero
        let res = Pair::multi_pairing(to_loop_left, to_loop_right);

        res.is_zero()
    }
}
