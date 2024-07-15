use crate::{
    commitment::*, evaluation_proof::combine_polys, srs::SRS, CommitmentError,
    PolynomialsToCombine, SRS as SRSTrait,
};

use ark_ec::{msm::VariableBaseMSM, AffineCurve, PairingEngine};
use ark_ff::{One, PrimeField, Zero};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain as D, UVPolynomial,
};
use mina_poseidon::FqSponge;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(
    bound = "Pair::G1Affine: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize"
)]
pub struct PairingProof<Pair: PairingEngine> {
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub quotient: Pair::G1Affine,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub blinding: <Pair::G1Affine as AffineCurve>::ScalarField,
}

impl<Pair: PairingEngine> Default for PairingProof<Pair> {
    fn default() -> Self {
        Self {
            quotient: Pair::G1Affine::prime_subgroup_generator(),
            blinding: <Pair::G1Affine as AffineCurve>::ScalarField::zero(),
        }
    }
}

impl<Pair: PairingEngine> Clone for PairingProof<Pair> {
    fn clone(&self) -> Self {
        Self {
            quotient: self.quotient,
            blinding: self.blinding,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingSRS<Pair: PairingEngine> {
    /// The full SRS is the one used by the prover. Can be seen as the "proving
    /// key"/"secret key"
    pub full_srs: SRS<Pair::G1Affine>,
    /// SRS to be used by the verifier. Can be seen as the "verification
    /// key"/"public key".
    pub verifier_srs: SRS<Pair::G2Affine>,
}

impl<Pair: PairingEngine> Default for PairingSRS<Pair> {
    fn default() -> Self {
        Self {
            full_srs: SRS::default(),
            verifier_srs: SRS::default(),
        }
    }
}

impl<Pair: PairingEngine> Clone for PairingSRS<Pair> {
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
        Pair: PairingEngine<G1Affine = G, G2Affine = G2>,
    > PairingSRS<Pair>
{
    pub fn create(x: F, n: usize) -> Self {
        PairingSRS {
            full_srs: SRS::create_trusted_setup(x, n),
            verifier_srs: SRS::create_trusted_setup(x, 3),
        }
    }
}

impl<
        F: PrimeField,
        G: CommitmentCurve<ScalarField = F>,
        G2: CommitmentCurve<ScalarField = F>,
        Pair: PairingEngine<G1Affine = G, G2Affine = G2>,
    > crate::OpenProof<G> for PairingProof<Pair>
{
    type SRS = PairingSRS<Pair>;

    /// Parameters:
    /// - `srs`: the structured reference string
    /// - `plnms`: vector of polynomials with optional degree bound and
    /// commitment randomness
    /// - `elm`: vector of evaluation points
    /// - `polyscale`: scaling factor for polynoms
    /// group_maps, sponge, rng and evalscale are not used. The parameters are
    /// kept to fit the trait and to be used generically.
    fn open<EFqSponge, RNG, D: EvaluationDomain<F>>(
        srs: &Self::SRS,
        _group_map: &<G as CommitmentCurve>::Map,
        plnms: PolynomialsToCombine<G, D>,
        elm: &[<G as AffineCurve>::ScalarField],
        polyscale: <G as AffineCurve>::ScalarField,
        _evalscale: <G as AffineCurve>::ScalarField,
        _sponge: EFqSponge,
        _rng: &mut RNG,
    ) -> Self
    where
        EFqSponge: Clone + FqSponge<<G as AffineCurve>::BaseField, G, F>,
        RNG: RngCore + CryptoRng,
    {
        PairingProof::create(srs, plnms, elm, polyscale).unwrap()
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
        Pair: PairingEngine<G1Affine = G, G2Affine = G2>,
    > SRSTrait<G> for PairingSRS<Pair>
{
    fn max_poly_size(&self) -> usize {
        self.full_srs.max_poly_size()
    }

    fn get_lagrange_basis(&self, domain_size: usize) -> Option<&Vec<PolyComm<G>>> {
        self.full_srs.get_lagrange_basis(domain_size)
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

    fn create(_depth: usize) -> Self {
        todo!()
    }

    fn add_lagrange_basis(&mut self, domain: D<<G>::ScalarField>) {
        self.full_srs.add_lagrange_basis(domain);
    }

    fn size(&self) -> usize {
        self.full_srs.g.len()
    }
}

/// The polynomial that evaluates to each of `evals` for the respective `elm`s.
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
        Pair: PairingEngine<G1Affine = G, G2Affine = G2>,
    > PairingProof<Pair>
{
    /// Create a pairing proof.
    /// Parameters:
    /// - `srs`: the structured reference string
    /// - `plnms`: vector of polynomials with optional degree bound and
    /// commitment randomness
    /// - `elm`: vector of evaluation points
    /// - `polyscale`: scaling factor
    pub fn create<D: EvaluationDomain<F>>(
        srs: &PairingSRS<Pair>,
        plnms: PolynomialsToCombine<G, D>,
        elm: &[F],
        polyscale: F,
    ) -> Option<Self> {
        let (p, blinding_factor) = combine_polys::<G, D>(plnms, polyscale, srs.full_srs.g.len());
        let evals: Vec<_> = elm.iter().map(|pt| p.evaluate(pt)).collect();

        let quotient_poly = {
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

        let quotient = srs.full_srs.commit_non_hiding(&quotient_poly, 1).elems[0];

        Some(PairingProof {
            quotient,
            blinding: blinding_factor,
        })
    }

    pub fn verify(
        &self,
        srs: &PairingSRS<Pair>,           // SRS
        evaluations: &Vec<Evaluation<G>>, // commitments to the polynomials
        polyscale: F,                     // scaling factor for polynoms
        elm: &[F],                        // vector of evaluation points
    ) -> bool {
        let poly_commitment = {
            let mut scalars: Vec<F> = Vec::new();
            let mut points = Vec::new();
            combine_commitments(
                evaluations,
                &mut scalars,
                &mut points,
                polyscale,
                F::one(), /* TODO: This is inefficient */
            );
            let scalars: Vec<_> = scalars.iter().map(|x| x.into_repr()).collect();

            VariableBaseMSM::multi_scalar_mul(&points, &scalars)
        };

        // IMPROVEME: we could have a single flat array for all evaluations, see
        // same comment in combine_evaluations
        let evals = combine_evaluations(evaluations, polyscale);
        let blinding_commitment = srs.full_srs.h.mul(self.blinding);
        let divisor_commitment = srs
            .verifier_srs
            .commit_non_hiding(&divisor_polynomial(elm), 1)
            .elems[0];
        let eval_commitment = srs
            .full_srs
            .commit_non_hiding(&eval_polynomial(elm, &evals), 1)
            .elems[0]
            .into_projective();
        let numerator_commitment = { poly_commitment - eval_commitment - blinding_commitment };
        // We compute the result of the multiplication of two miller loop,
        // to apply only one final exponentation
        let to_loop = [
            (
                ark_ec::prepare_g1::<Pair>(numerator_commitment),
                ark_ec::prepare_g2::<Pair>(Pair::G2Affine::prime_subgroup_generator()),
            ),
            (
                // Note that we do a neagtion here, to put everything on the same side
                (self.quotient).neg().into(),
                ark_ec::prepare_g2::<Pair>(divisor_commitment),
            ),
        ];
        // the result here is numerator_commitment * 1 - quotient * divisor_commitment
        // Note that the unwrap cannot fail as the output of a miller loop is non zero
        let res = Pair::final_exponentiation(&(Pair::miller_loop(&to_loop))).unwrap();

        res == Pair::Fqk::one()
    }
}

#[cfg(test)]
mod tests {
    use super::{PairingProof, PairingSRS};
    use crate::{
        commitment::Evaluation, evaluation_proof::DensePolynomialOrEvaluations, srs::SRS, SRS as _,
    };
    use ark_bn254::{Fr as ScalarField, G1Affine as G1, G2Affine as G2, Parameters};
    use ark_ec::bn::Bn;
    use ark_ff::{UniformRand, Zero};
    use ark_poly::{
        univariate::DensePolynomial, EvaluationDomain, Polynomial, Radix2EvaluationDomain as D,
        UVPolynomial,
    };
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_pairing_proof() {
        let n = 64;
        let domain = D::<ScalarField>::new(n).unwrap();

        let rng = &mut StdRng::from_seed([0u8; 32]);

        let x = ScalarField::rand(rng);

        let mut srs = SRS::<G1>::create_trusted_setup(x, n);
        let verifier_srs = SRS::<G2>::create_trusted_setup(x, 3);
        srs.add_lagrange_basis(domain);

        let srs = PairingSRS {
            full_srs: srs,
            verifier_srs,
        };

        let polynomials: Vec<_> = (0..4)
            .map(|_| {
                let coeffs = (0..63).map(|_| ScalarField::rand(rng)).collect();
                DensePolynomial::from_coefficients_vec(coeffs)
            })
            .collect();

        let comms: Vec<_> = polynomials
            .iter()
            .map(|p| srs.full_srs.commit(p, 1, rng))
            .collect();

        let polynomials_and_blinders: Vec<(DensePolynomialOrEvaluations<_, D<_>>, _)> = polynomials
            .iter()
            .zip(comms.iter())
            .map(|(p, comm)| {
                let p = DensePolynomialOrEvaluations::DensePolynomial(p);
                (p, comm.blinders.clone())
            })
            .collect();

        let evaluation_points = vec![ScalarField::rand(rng), ScalarField::rand(rng)];

        let evaluations: Vec<_> = polynomials
            .iter()
            .zip(comms)
            .map(|(p, commitment)| {
                let evaluations = evaluation_points
                    .iter()
                    .map(|x| {
                        // Inputs are chosen to use only 1 chunk
                        vec![p.evaluate(x)]
                    })
                    .collect();
                Evaluation {
                    commitment: commitment.commitment,
                    evaluations,
                }
            })
            .collect();

        let polyscale = ScalarField::rand(rng);

        let pairing_proof = PairingProof::<Bn<Parameters>>::create(
            &srs,
            polynomials_and_blinders.as_slice(),
            &evaluation_points,
            polyscale,
        )
        .unwrap();

        let res = pairing_proof.verify(&srs, &evaluations, polyscale, &evaluation_points);
        assert!(res);
    }

    /// Our points in G2 are not actually in the correct subgroup and serialize well.
    #[test]
    fn check_srs_g2_valid_and_serializes() {
        type BN254 = ark_ec::bn::Bn<ark_bn254::Parameters>;
        type BN254G2BaseField = <BN254 as ark_ec::PairingEngine>::Fqe;
        type Fp = ark_bn254::Fr;

        let x = Fp::rand(&mut rand::rngs::OsRng);
        let srs: PairingSRS<BN254> = PairingSRS::create(x, 1 << 5);

        let mut vec: Vec<u8> = vec![0u8; 1024];

        for actual in [
            srs.verifier_srs.h,
            srs.verifier_srs.g[0],
            srs.verifier_srs.g[1],
        ] {
            // Check it's valid
            assert!(!actual.is_zero());
            assert!(actual.is_on_curve());
            assert!(actual.is_in_correct_subgroup_assuming_on_curve());

            // Check it serializes well
            let actual_y: BN254G2BaseField = actual.y;
            let res = actual_y.serialize(vec.as_mut_slice());
            assert!(res.is_ok());
            let expected: BN254G2BaseField =
                CanonicalDeserialize::deserialize(vec.as_slice()).unwrap();
            assert!(expected == actual_y, "serialization failed");
        }
    }
}
