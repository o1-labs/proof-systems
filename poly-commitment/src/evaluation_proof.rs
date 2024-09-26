//! This module contains the implementation of the polynomial commitment scheme
//! called the Inner Product Argument (IPA) as described in [Efficient
//! Zero-Knowledge Arguments for Arithmetic Circuits in the Discrete Log
//! Setting](https://eprint.iacr.org/2016/263)

use crate::{commitment::*, srs::SRS, PolynomialsToCombine};
use ark_ec::AffineRepr;
use ark_ff::{FftField, Field, One, PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations};
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use o1_utils::ExtendedDensePolynomial;
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::iter::Iterator;

// A formal sum of the form
// `s_0 * p_0 + ... s_n * p_n`
// where each `s_i` is a scalar and each `p_i` is a polynomial.
#[derive(Default)]
struct ScaledChunkedPolynomial<F, P>(Vec<(F, P)>);

pub enum DensePolynomialOrEvaluations<'a, F: FftField, D: EvaluationDomain<F>> {
    DensePolynomial(&'a DensePolynomial<F>),
    Evaluations(&'a Evaluations<F, D>, D),
}

impl<F, P> ScaledChunkedPolynomial<F, P> {
    fn add_poly(&mut self, scale: F, p: P) {
        self.0.push((scale, p))
    }
}

impl<'a, F: Field> ScaledChunkedPolynomial<F, &'a [F]> {
    fn to_dense_polynomial(&self) -> DensePolynomial<F> {
        let mut res = DensePolynomial::<F>::zero();

        let scaled: Vec<_> = self
            .0
            .par_iter()
            .map(|(scale, segment)| {
                let scale = *scale;
                let v = segment.par_iter().map(|x| scale * *x).collect();
                DensePolynomial::from_coefficients_vec(v)
            })
            .collect();

        for p in scaled {
            res += &p;
        }

        res
    }
}

/// Combine the polynomials using `polyscale`, creating a single unified
/// polynomial to open.
/// Parameters:
/// - plnms: vector of polynomial with optional degree bound and commitment randomness
/// - polyscale: scaling factor for polynomials
pub fn combine_polys<G: CommitmentCurve, D: EvaluationDomain<G::ScalarField>>(
    plnms: PolynomialsToCombine<G, D>,
    polyscale: G::ScalarField,
    srs_length: usize,
) -> (DensePolynomial<G::ScalarField>, G::ScalarField) {
    let mut plnm = ScaledChunkedPolynomial::<G::ScalarField, &[G::ScalarField]>::default();
    let mut plnm_evals_part = {
        // For now just check that all the evaluation polynomials are the same
        // degree so that we can do just a single FFT.
        // Furthermore we check they have size less than the SRS size so we
        // don't have to do chunking.
        // If/when we change this, we can add more complicated code to handle
        // different degrees.
        let degree = plnms
            .iter()
            .fold(None, |acc, (p, _)| match p {
                DensePolynomialOrEvaluations::DensePolynomial(_) => acc,
                DensePolynomialOrEvaluations::Evaluations(_, d) => {
                    if let Some(n) = acc {
                        assert_eq!(n, d.size());
                    }
                    Some(d.size())
                }
            })
            .unwrap_or(0);
        vec![G::ScalarField::zero(); degree]
    };

    let mut omega = G::ScalarField::zero();
    let mut scale = G::ScalarField::one();

    // iterating over polynomials in the batch
    for (p_i, omegas) in plnms {
        match p_i {
            DensePolynomialOrEvaluations::Evaluations(evals_i, sub_domain) => {
                let stride = evals_i.evals.len() / sub_domain.size();
                let evals = &evals_i.evals;
                plnm_evals_part
                    .par_iter_mut()
                    .enumerate()
                    .for_each(|(i, x)| {
                        *x += scale * evals[i * stride];
                    });
                for j in 0..omegas.elems.len() {
                    omega += &(omegas.elems[j] * scale);
                    scale *= &polyscale;
                }
            }

            DensePolynomialOrEvaluations::DensePolynomial(p_i) => {
                let mut offset = 0;
                // iterating over chunks of the polynomial
                for j in 0..omegas.elems.len() {
                    let segment = &p_i.coeffs[std::cmp::min(offset, p_i.coeffs.len())
                        ..std::cmp::min(offset + srs_length, p_i.coeffs.len())];
                    plnm.add_poly(scale, segment);

                    omega += &(omegas.elems[j] * scale);
                    scale *= &polyscale;
                    offset += srs_length;
                }
            }
        }
    }

    let mut plnm = plnm.to_dense_polynomial();
    if !plnm_evals_part.is_empty() {
        let n = plnm_evals_part.len();
        let max_poly_size = srs_length;
        let num_chunks = if n == 0 {
            1
        } else {
            n / max_poly_size + if n % max_poly_size == 0 { 0 } else { 1 }
        };
        plnm += &Evaluations::from_vec_and_domain(plnm_evals_part, D::new(n).unwrap())
            .interpolate()
            .to_chunked_polynomial(num_chunks, max_poly_size)
            .linearize(polyscale);
    }

    (plnm, omega)
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(bound = "G: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize")]
pub struct OpeningProof<G: AffineRepr> {
    /// Vector of rounds of L & R commitments
    #[serde_as(as = "Vec<(o1_utils::serialization::SerdeAs, o1_utils::serialization::SerdeAs)>")]
    pub lr: Vec<(G, G)>,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub delta: G,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub z1: G::ScalarField,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub z2: G::ScalarField,
    /// A final folded commitment base
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub sg: G,
}

impl<BaseField: PrimeField, G: AffineRepr<BaseField = BaseField> + CommitmentCurve + EndoCurve>
    crate::OpenProof<G> for OpeningProof<G>
{
    type SRS = SRS<G>;

    fn open<EFqSponge, RNG, D: EvaluationDomain<<G as AffineRepr>::ScalarField>>(
        srs: &Self::SRS,
        group_map: &<G as CommitmentCurve>::Map,
        plnms: PolynomialsToCombine<G, D>,
        elm: &[<G as AffineRepr>::ScalarField], // vector of evaluation points
        polyscale: <G as AffineRepr>::ScalarField, // scaling factor for polynoms
        evalscale: <G as AffineRepr>::ScalarField, // scaling factor for evaluation point powers
        sponge: EFqSponge,                      // sponge
        rng: &mut RNG,
    ) -> Self
    where
        EFqSponge:
            Clone + FqSponge<<G as AffineRepr>::BaseField, G, <G as AffineRepr>::ScalarField>,
        RNG: RngCore + CryptoRng,
    {
        srs.open(group_map, plnms, elm, polyscale, evalscale, sponge, rng)
    }

    fn verify<EFqSponge, RNG>(
        srs: &Self::SRS,
        group_map: &G::Map,
        batch: &mut [BatchEvaluationProof<G, EFqSponge, Self>],
        rng: &mut RNG,
    ) -> bool
    where
        EFqSponge: FqSponge<<G as AffineRepr>::BaseField, G, <G as AffineRepr>::ScalarField>,
        RNG: RngCore + CryptoRng,
    {
        srs.verify(group_map, batch, rng)
    }
}

/// Commitment round challenges (endo mapped) and their inverses.
pub struct Challenges<F> {
    pub chal: Vec<F>,
    pub chal_inv: Vec<F>,
}

impl<G: AffineRepr> OpeningProof<G> {
    /// Computes a log-sized vector of scalar challenges for
    /// recombining elements inside the IPA.
    pub fn prechallenges<EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>>(
        &self,
        sponge: &mut EFqSponge,
    ) -> Vec<ScalarChallenge<G::ScalarField>> {
        let _t = sponge.challenge_fq();
        self.lr
            .iter()
            .map(|(l, r)| {
                sponge.absorb_g(&[*l]);
                sponge.absorb_g(&[*r]);
                squeeze_prechallenge(sponge)
            })
            .collect()
    }

    /// Same as `prechallenges`, but maps scalar challenges using the
    /// provided endomorphism, and computes their inverses.
    pub fn challenges<EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>>(
        &self,
        endo_r: &G::ScalarField,
        sponge: &mut EFqSponge,
    ) -> Challenges<G::ScalarField> {
        let chal: Vec<_> = self
            .lr
            .iter()
            .map(|(l, r)| {
                sponge.absorb_g(&[*l]);
                sponge.absorb_g(&[*r]);
                squeeze_challenge(endo_r, sponge)
            })
            .collect();

        let chal_inv = {
            let mut cs = chal.clone();
            ark_ff::batch_inversion(&mut cs);
            cs
        };

        Challenges { chal, chal_inv }
    }
}

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::OpeningProof;
    use ark_ec::AffineRepr;
    use ocaml;

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlOpeningProof<G, F> {
        /// vector of rounds of L & R commitments
        pub lr: Vec<(G, G)>,
        pub delta: G,
        pub z1: F,
        pub z2: F,
        pub sg: G,
    }

    impl<G, CamlF, CamlG> From<OpeningProof<G>> for CamlOpeningProof<CamlG, CamlF>
    where
        G: AffineRepr,
        CamlG: From<G>,
        CamlF: From<G::ScalarField>,
    {
        fn from(opening_proof: OpeningProof<G>) -> Self {
            Self {
                lr: opening_proof
                    .lr
                    .into_iter()
                    .map(|(g1, g2)| (CamlG::from(g1), CamlG::from(g2)))
                    .collect(),
                delta: CamlG::from(opening_proof.delta),
                z1: opening_proof.z1.into(),
                z2: opening_proof.z2.into(),
                sg: CamlG::from(opening_proof.sg),
            }
        }
    }

    impl<G, CamlF, CamlG> From<CamlOpeningProof<CamlG, CamlF>> for OpeningProof<G>
    where
        G: AffineRepr,
        CamlG: Into<G>,
        CamlF: Into<G::ScalarField>,
    {
        fn from(caml: CamlOpeningProof<CamlG, CamlF>) -> Self {
            Self {
                lr: caml
                    .lr
                    .into_iter()
                    .map(|(g1, g2)| (g1.into(), g2.into()))
                    .collect(),
                delta: caml.delta.into(),
                z1: caml.z1.into(),
                z2: caml.z2.into(),
                sg: caml.sg.into(),
            }
        }
    }
}
