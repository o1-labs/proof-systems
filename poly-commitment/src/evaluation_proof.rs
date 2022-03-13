use crate::commitment::*;
use crate::srs::SRS;
use ark_ec::{msm::VariableBaseMSM, AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_poly::univariate::DensePolynomial;
use oracle::{sponge::ScalarChallenge, FqSponge};
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;
use std::iter::Iterator;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

/// This function opens polynomial commitments in batch
///     plnms: batch of polynomials to open commitments for with, optionally, max degrees
///     elm: evaluation point vector to open the commitments at
///     polyscale: polynomial scaling factor for opening commitments in batch
///     evalscale: eval scaling factor for opening commitments in batch
///     oracle_params: parameters for the random oracle argument
///     RETURN: commitment opening proof
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
#[allow(clippy::many_single_char_names)]
impl<G: CommitmentCurve> SRS<G> {
    pub fn open<EFqSponge, RNG>(
        &self,
        group_map: &G::Map,
        // TODO(mimoo): create a type for that entry
        plnms: &[(&DensePolynomial<Fr<G>>, Option<usize>, PolyComm<Fr<G>>)], // vector of polynomial with optional degree bound and commitment randomness
        elm: &[Fr<G>],         // vector of evaluation points
        polyscale: Fr<G>,      // scaling factor for polynoms
        evalscale: Fr<G>,      // scaling factor for evaluation point powers
        mut sponge: EFqSponge, // sponge
        rng: &mut RNG,
    ) -> OpeningProof<G>
    where
        EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>,
        RNG: RngCore + CryptoRng,
        G::BaseField: PrimeField,
    {
        let rounds = ceil_log2(self.g.len());
        let padded_length = 1 << rounds;

        // TODO: Trim this to the degree of the largest polynomial
        let padding = padded_length - self.g.len();
        let mut g = self.g.clone();
        g.extend(vec![G::zero(); padding]);

        let (p, blinding_factor) = {
            let mut plnm = ChunkedPolynomial::<Fr<G>, &[Fr<G>]>::default();
            // let mut plnm_chunks: Vec<(Fr<G>, OptShiftedPolynomial<_>)> = vec![];

            let mut omega = Fr::<G>::zero();
            let mut scale = Fr::<G>::one();

            // iterating over polynomials in the batch
            for (p_i, degree_bound, omegas) in plnms.iter().filter(|p| !p.0.is_zero()) {
                let mut offset = 0;
                let mut j = 0;
                // iterating over chunks of the polynomial
                if let Some(m) = degree_bound {
                    assert!(p_i.coeffs.len() <= m + 1);
                    while j < omegas.unshifted.len() {
                        let segment = &p_i.coeffs[offset
                            ..if offset + self.g.len() > p_i.coeffs.len() {
                                p_i.coeffs.len()
                            } else {
                                offset + self.g.len()
                            }];
                        // always mixing in the unshifted segments
                        plnm.add_unshifted(scale, segment);

                        omega += &(omegas.unshifted[j] * scale);
                        j += 1;
                        scale *= &polyscale;
                        offset += self.g.len();
                        if offset > *m {
                            // mixing in the shifted segment since degree is bounded
                            plnm.add_shifted(scale, self.g.len() - m % self.g.len(), segment);
                            omega += &(omegas.shifted.unwrap() * scale);
                            scale *= &polyscale;
                        }
                    }
                } else {
                    assert!(omegas.shifted.is_none());
                    while j < omegas.unshifted.len() {
                        let segment = &p_i.coeffs[offset
                            ..if offset + self.g.len() > p_i.coeffs.len() {
                                p_i.coeffs.len()
                            } else {
                                offset + self.g.len()
                            }];

                        // always mixing in the unshifted segments
                        plnm.add_unshifted(scale, segment);
                        omega += &(omegas.unshifted[j] * scale);
                        j += 1;
                        scale *= &polyscale;
                        offset += self.g.len();
                    }
                }
                assert_eq!(j, omegas.unshifted.len());
            }

            (plnm.to_dense_polynomial(), omega)
        };

        let rounds = ceil_log2(self.g.len());

        // b_j = sum_i r^i elm_i^j
        let b_init = {
            // randomise/scale the eval powers
            let mut scale = Fr::<G>::one();
            let mut res: Vec<Fr<G>> = (0..padded_length).map(|_| Fr::<G>::zero()).collect();
            for e in elm {
                for (i, t) in pows(padded_length, *e).iter().enumerate() {
                    res[i] += &(scale * t);
                }
                scale *= &evalscale;
            }
            res
        };

        let combined_inner_product = p
            .coeffs
            .iter()
            .zip(b_init.iter())
            .map(|(a, b)| *a * b)
            .fold(Fr::<G>::zero(), |acc, x| acc + x);

        sponge.absorb_fr(&[shift_scalar::<G>(combined_inner_product)]);

        let t = sponge.challenge_fq();
        let u: G = to_group(group_map, t);

        let mut a = p.coeffs;
        assert!(padded_length >= a.len());
        a.extend(vec![Fr::<G>::zero(); padded_length - a.len()]);

        let mut b = b_init;

        let mut lr = vec![];

        let mut blinders = vec![];

        let mut chals = vec![];
        let mut chal_invs = vec![];

        for _ in 0..rounds {
            let n = g.len() / 2;
            let (g_lo, g_hi) = (g[0..n].to_vec(), g[n..].to_vec());
            let (a_lo, a_hi) = (&a[0..n], &a[n..]);
            let (b_lo, b_hi) = (&b[0..n], &b[n..]);

            let rand_l = Fr::<G>::rand(rng);
            let rand_r = Fr::<G>::rand(rng);

            let l = VariableBaseMSM::multi_scalar_mul(
                &[&g[0..n], &[self.h, u]].concat(),
                &[&a[n..], &[rand_l, inner_prod(a_hi, b_lo)]]
                    .concat()
                    .iter()
                    .map(|x| x.into_repr())
                    .collect::<Vec<_>>(),
            )
            .into_affine();

            let r = VariableBaseMSM::multi_scalar_mul(
                &[&g[n..], &[self.h, u]].concat(),
                &[&a[0..n], &[rand_r, inner_prod(a_lo, b_hi)]]
                    .concat()
                    .iter()
                    .map(|x| x.into_repr())
                    .collect::<Vec<_>>(),
            )
            .into_affine();

            lr.push((l, r));
            blinders.push((rand_l, rand_r));

            sponge.absorb_g(&[l]);
            sponge.absorb_g(&[r]);

            let u_pre = squeeze_prechallenge(&mut sponge);
            let u = u_pre.to_field(&self.endo_r);
            let u_inv = u.inverse().unwrap();

            chals.push(u);
            chal_invs.push(u_inv);

            a = a_hi
                .par_iter()
                .zip(a_lo)
                .map(|(&hi, &lo)| {
                    // lo + u_inv * hi
                    let mut res = hi;
                    res *= u_inv;
                    res += &lo;
                    res
                })
                .collect();

            b = b_lo
                .par_iter()
                .zip(b_hi)
                .map(|(&lo, &hi)| {
                    // lo + u * hi
                    let mut res = hi;
                    res *= u;
                    res += &lo;
                    res
                })
                .collect();

            g = G::combine_one_endo(self.endo_r, self.endo_q, &g_lo, &g_hi, u_pre);
        }

        assert!(g.len() == 1);
        let a0 = a[0];
        let b0 = b[0];
        let g0 = g[0];

        let r_prime = blinders
            .iter()
            .zip(chals.iter().zip(chal_invs.iter()))
            .map(|((l, r), (u, u_inv))| ((*l) * u_inv) + (*r * u))
            .fold(blinding_factor, |acc, x| acc + x);

        let d = Fr::<G>::rand(rng);
        let r_delta = Fr::<G>::rand(rng);

        let delta = ((g0.into_projective() + (u.mul(b0))).into_affine().mul(d)
            + self.h.mul(r_delta))
        .into_affine();

        sponge.absorb_g(&[delta]);
        let c = ScalarChallenge(sponge.challenge()).to_field(&self.endo_r);

        let z1 = a0 * c + d;
        let z2 = c * r_prime + r_delta;

        OpeningProof {
            delta,
            lr,
            z1,
            z2,
            sg: g0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct OpeningProof<G: AffineCurve> {
    /// vector of rounds of L & R commitments
    pub lr: Vec<(G, G)>,
    pub delta: G,
    pub z1: G::ScalarField,
    pub z2: G::ScalarField,
    pub sg: G,
}

pub struct Challenges<F> {
    pub chal: Vec<F>,
    pub chal_inv: Vec<F>,
}

impl<G: AffineCurve> OpeningProof<G> {
    pub fn prechallenges<EFqSponge: FqSponge<Fq<G>, G, Fr<G>>>(
        &self,
        sponge: &mut EFqSponge,
    ) -> Vec<ScalarChallenge<Fr<G>>> {
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

    pub fn challenges<EFqSponge: FqSponge<Fq<G>, G, Fr<G>>>(
        &self,
        endo_r: &Fr<G>,
        sponge: &mut EFqSponge,
    ) -> Challenges<Fr<G>> {
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
