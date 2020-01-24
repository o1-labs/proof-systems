/*****************************************************************************************************************

This source file implements Dlog-based polynomial commitment schema.
The folowing functionality is implemented

1. Commit to polynomial with its max degree
2. Open polynomial commitment batch at the given evaluation point and scaling factor scalar
    producing the batched opening proof
3. Verify batch of batched opening proofs

*****************************************************************************************************************/

use super::srs::SRS;
use algebra::{
    AffineCurve, BitIterator, Field, LegendreSymbol, PrimeField, ProjectiveCurve, SquareRootField,
    UniformRand, VariableBaseMSM,
};
use ff_fft::DensePolynomial;
use oracle::rndoracle::{ArithmeticSpongeParams, ProofError};
use oracle::FqSponge;
use rand_core::RngCore;
use rayon::prelude::*;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

#[derive(Clone)]
pub struct OpeningProof<G: AffineCurve> {
    pub lr: Vec<(G, G)>, // vector of rounds of L & R commitments
    pub delta: G,
    pub z1: G::ScalarField,
    pub z2: G::ScalarField,
}

fn product<F: Field>(xs: impl Iterator<Item = F>) -> F {
    let mut res = F::one();
    for x in xs {
        res *= &x;
    }
    res
}

fn b_poly<F: Field>(chals: &Vec<F>, chal_invs: &Vec<F>, x: F) -> F {
    let k = chals.len();

    let mut pow_twos = vec![x];

    for i in 1..k {
        pow_twos.push(pow_twos[i - 1].square());
    }

    product((0..k).map(|i| (chal_invs[i] + &(chals[i] * &pow_twos[k - 1 - i]))))
}

fn ceil_log2(d: usize) -> usize {
    let mut pow2 = 1;
    let mut ceil_log2 = 0;
    while d > pow2 {
        ceil_log2 += 1;
        pow2 *= 2;
    }
    ceil_log2
}

fn pows<F: Field>(d: usize, x: F) -> Vec<F> {
    let mut acc = F::one();
    (0..d)
        .map(|_| {
            let r = acc;
            acc *= &x;
            r
        })
        .collect()
}

fn squeeze_square_challenge<Fq: Field, G, Fr: SquareRootField, EFqSponge: FqSponge<Fq, G, Fr>>(
    sponge: &mut EFqSponge,
) -> Fr {
    // TODO: Make this a parameter
    let nonresidue: Fr = (7 as u64).into();
    let mut pre = sponge.challenge();
    match pre.legendre() {
        LegendreSymbol::Zero => (),
        LegendreSymbol::QuadraticResidue => (),
        LegendreSymbol::QuadraticNonResidue => {
            pre *= &nonresidue;
        }
    };
    pre
}

fn squeeze_sqrt_challenge<Fq: Field, G, Fr: SquareRootField, EFqSponge: FqSponge<Fq, G, Fr>>(
    sponge: &mut EFqSponge,
) -> Fr {
    squeeze_square_challenge(sponge).sqrt().unwrap()
}

fn shamir_sum<G: AffineCurve>(
    x1: G::ScalarField,
    g1: G,
    x2: G::ScalarField,
    g2: G,
) -> G::Projective {
    let mut g1g2: G::Projective = g1.into_projective();
    g1g2.add_assign_mixed(&g2);
    let g1g2 = g1g2.into_affine();

    let bits1 = BitIterator::new(x1.into_repr());
    let bits2 = BitIterator::new(x2.into_repr());

    let mut res = G::Projective::zero();

    for (b1, b2) in bits1.zip(bits2) {
        res.double_in_place();

        match (b1, b2) {
            (true, true) => res.add_assign_mixed(&g1g2),
            (false, true) => res.add_assign_mixed(&g2),
            (true, false) => res.add_assign_mixed(&g1),
            (false, false) => (),
        }
    }

    res
}

impl<G: AffineCurve> SRS<G> {
    // This function commits the polynomial against SRS instance with degree bound
    //     plnm: polynomial to commit
    //     max: maximal degree of the polynomial
    //     RETURN: commitment group elements: unshifted, shifted
    pub fn commit_with_degree_bound(
        &self,
        plnm: &DensePolynomial<Fr<G>>,
        max: usize,
    ) -> Result<(G, G), ProofError> {
        let d = self.g.len();
        if d < max || plnm.coeffs.len() > max {
            return Err(ProofError::PolyCommit);
        }

        Ok((
            self.commit_no_degree_bound(&plnm)?,
            VariableBaseMSM::multi_scalar_mul(
                &self.g[d - max..plnm.len() + d - max],
                &plnm
                    .coeffs
                    .iter()
                    .map(|s| s.into_repr())
                    .collect::<Vec<_>>(),
            )
            .into_affine(),
        ))
    }

    // This function commits the polynomial against SRS instance without degree bound
    //     plnm: polynomial to commit
    //     RETURN: commitment group element
    pub fn commit_no_degree_bound(&self, plnm: &DensePolynomial<Fr<G>>) -> Result<G, ProofError> {
        if self.g.len() < plnm.coeffs.len() {
            return Err(ProofError::PolyCommit);
        }

        Ok(VariableBaseMSM::multi_scalar_mul(
            &self.g[0..plnm.coeffs.len()],
            &plnm
                .coeffs
                .iter()
                .map(|s| s.into_repr())
                .collect::<Vec<_>>(),
        )
        .into_affine())
    }

    // This function opens polynomial commitments in batch
    //     plnms: batch of polynomials to open commitments for with, optionally, max degrees
    //     elm: evaluation point vector to open the commitments at
    //     polyscale: polynomial scaling factor for opening commitments in batch
    //     evalscale: eval scaling factor for opening commitments in batch
    //     oracle_params: parameters for the random oracle argument
    //     RETURN: commitment opening proof
    pub fn open<EFqSponge: FqSponge<Fq<G>, G, Fr<G>>>(
        &self,
        plnms: &Vec<(DensePolynomial<Fr<G>>, Option<usize>)>, // vector of polynomial with optional degree bound
        elm: &Vec<Fr<G>>,                                     // vector of evaluation points
        polyscale: Fr<G>,                                     // scaling factor for polynoms
        evalscale: Fr<G>, // scaling factor for evaluation point powers
        oracle_params: &ArithmeticSpongeParams<Fq<G>>, // parameters for the random oracle argument
        rng: &mut dyn RngCore,
    ) -> Result<OpeningProof<G>, ProofError> {
        let u: G = G::prime_subgroup_generator(); // TODO: Should make this a random group element after the group map is implemented.
        let rounds = ceil_log2(self.g.len());

        // scale the polynoms in accumulator shifted, if bounded, to the end of SRS
        // let mut p_comm = G::Projective::zero();
        let p = {
            let mut p = DensePolynomial::<Fr<G>>::zero();
            let mut scale = Fr::<G>::one();
            for (p_i, degree_bound) in plnms.iter() {
                // always mixing in the unshifted polynom
                p += &(p_i.scale(scale));
                // p_comm += &(comm_i.mul(scale));
                scale *= &polyscale;

                match degree_bound {
                    Some(m) => {
                        // mixing in the shifted polynom since degree is bounded
                        p += &(p_i.shiftr(self.g.len() - m).scale(scale));
                        // p_comm += &(shifted_comm_i.mul(scale));
                        scale *= &polyscale;
                    }
                    _ => {}
                }
            }
            p
        };

        // TODO: Add blindings to the commitments. Opening will require knowing the blinding factor
        // for each commitment in the batch.
        let blinding_factor = Fr::<G>::zero();

        let padded_length = 1 << rounds;

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

        let padding = padded_length - self.g.len();
        let mut g = self.g.clone();
        g.extend(vec![G::zero(); padding]);

        let mut a = p.coeffs;
        a.extend(vec![Fr::<G>::zero(); padded_length - a.len()]);

        let mut b = b_init.clone();

        let mut sponge = EFqSponge::new(oracle_params.clone());

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
                &[&g[n..], &[self.h, u]].concat(),
                &[&a[0..n], &[rand_l, inner_prod(a_lo, b_hi)]].concat()
                    .iter().map(|x| x.into_repr()).collect::<Vec<_>>()
            ).into_affine();

            let r = VariableBaseMSM::multi_scalar_mul(
                &[&g[0..n], &[self.h, u]].concat(),
                &[&a[n..], &[rand_r, inner_prod(a_hi, b_lo)]].concat()
                    .iter().map(|x| x.into_repr()).collect::<Vec<_>>()
            ).into_affine();

            lr.push((l, r));
            blinders.push((rand_l, rand_r));

            sponge.absorb_g(&l);
            sponge.absorb_g(&r);

            let u = squeeze_sqrt_challenge(&mut sponge);
            let u_inv = u.inverse().unwrap();

            chals.push(u);
            chal_invs.push(u_inv);

            a = a_hi
                .iter()
                .zip(a_lo)
                .map(|(&hi, &lo)| {
                    let mut res = hi * &u_inv;
                    res += &(lo * &u);
                    res
                })
                .collect();

            b = b_lo
                .iter()
                .zip(b_hi)
                .map(|(&lo, &hi)| {
                    let mut res = lo * &u_inv;
                    res += &(hi * &u);
                    res
                })
                .collect();

            // TODO: Make this more efficient
            g = {
                let mut g_proj: Vec<G::Projective> = {
                    let pairs: Vec<_> = g_lo.iter().zip(g_hi).collect();
                    pairs
                        .into_par_iter()
                        .map(|(lo, hi)| shamir_sum::<G>(u_inv, *lo, u, hi))
                        .collect()
                };
                G::Projective::batch_normalization(g_proj.as_mut_slice());
                g_proj.par_iter().map(|g| g.into_affine()).collect()
            };
        }

        assert!(g.len() == 1);
        let a0 = a[0];
        let b0 = b[0];
        let g0 = g[0];

        let r_prime = blinders
            .iter()
            .zip(chals.iter().zip(chal_invs.iter()))
            .map(|((l, r), (u, u_inv))| ((*l) * &u.square()) + &(*r * &u_inv.square()))
            .fold(blinding_factor, |acc, x| acc + &x);

        let d = Fr::<G>::rand(rng);
        let r_delta = Fr::<G>::rand(rng);

        let delta = ((g0.into_projective() + &(u.mul(b0))).into_affine().mul(d)
            + &self.h.mul(r_delta))
            .into_affine();

        sponge.absorb_g(&delta);
        let c = sponge.challenge();

        let z1 = a0 * &c + &d;
        let z2 = c * &r_prime + &r_delta;

        Ok(OpeningProof { delta, lr, z1, z2 })
    }

    // This function verifies batch of batched polynomial commitment opening proofs
    //     batch: batch of batched polynomial commitment opening proofs
    //          vector of evaluation points
    //          polynomial scaling factor for this batched openinig proof
    //          eval scaling factor for this batched openinig proof
    //          batch/vector of polycommitments (opened in this batch), evaluation vectors and, optionally, max degrees
    //          opening proof for this batched opening
    //     oracle_params: parameters for the random oracle argument
    //     randomness source context
    //     RETURN: verification status
    pub fn verify<EFqSponge: FqSponge<Fq<G>, G, Fr<G>>>(
        &self,
        batch: &Vec<(
            Vec<Fr<G>>, // vector of evaluation points
            Fr<G>,      // scaling factor for polynoms
            Fr<G>,      // scaling factor for evaluation point powers
            Vec<(
                G,                  // unshifted polycommitment
                Vec<Fr<G>>,         // vector of evaluations
                Option<(G, usize)>, // shifted polycommitment and degree bound
            )>,
            OpeningProof<G>, // batched opening proof
        )>,
        oracle_params: &ArithmeticSpongeParams<Fq<G>>,
        rng: &mut dyn RngCore,
    ) -> bool {
        // Verifier checks for all i,
        // c_i Q_i + delta_i = z1_i (G_i + b_i U_i) + z2_i H
        //
        // if we sample r at random, it suffices to check
        //
        // 0 == sum_i r^i (c_i Q_i + delta_i - ( z1_i (G_i + b_i U_i) + z2_i H ))
        //
        // and because each G_i is a multiexp on the same array self.g, we
        // can batch the multiexp across proofs.
        //
        // So for each proof in the batch, we add onto our big multiexp the following terms
        // r^i c_i Q_i
        // r^i delta_i
        // - (r^i z1_i) G_i
        // - (r^i z2_i) H
        // - (r^i z1_i b_i) U_i
        let max_rounds = ceil_log2(self.g.len());

        let padded_length = 1 << max_rounds;

        let padding = padded_length - self.g.len();
        let mut points = self.g.clone();
        points.extend(vec![G::zero(); padding]);

        points.push(self.h);
        let mut scalars = vec![Fr::<G>::zero(); padded_length + 1];

        // sample randomiser to scale the proofs with
        let rand_base = Fr::<G>::rand(rng);
        let mut rand_base_i = Fr::<G>::one();

        for (evaluation_points, xi, r, polys, opening) in batch.iter() {
            let rounds = opening.lr.len();
            let s_length = 1 << rounds;

            let u: G = G::prime_subgroup_generator(); // TODO: Should make this a random group element after the group map is implemented.

            let sponge = &mut EFqSponge::new(oracle_params.clone());

            let chal_squareds: Vec<_> = opening
                .lr
                .iter()
                .map(|(l, r)| {
                    sponge.absorb_g(l);
                    sponge.absorb_g(r);
                    squeeze_square_challenge(sponge)
                })
                .collect();

            let chal_squared_invs = {
                let mut cs = chal_squareds.clone();
                algebra::fields::batch_inversion(&mut cs);
                cs
            };

            let chals: Vec<Fr<G>> = chal_squareds.iter().map(|x| x.sqrt().unwrap()).collect();
            let chal_invs = {
                let mut cs = chals.clone();
                algebra::fields::batch_inversion(&mut cs);
                cs
            };

            sponge.absorb_g(&opening.delta);
            let c = sponge.challenge();

            // < s, sum_i r^i pows(evaluation_point[i]) >
            // ==
            // sum_i r^i < s, pows(evaluation_point[i]) >
            let b0 = {
                let mut scale = Fr::<G>::one();
                let mut res = Fr::<G>::zero();
                for &e in evaluation_points {
                    res += &(scale * &b_poly(&chals, &chal_invs, e));
                    scale *= r;
                }
                res
            };

            let s = {
                let mut s = vec![Fr::<G>::one(); s_length];
                s[0] = chal_invs.iter().fold(Fr::<G>::one(), |x, y| x * &y);
                let mut k: usize = 0;
                let mut pow: usize = 1;
                for i in 1..s_length {
                    k += if i == pow { 1 } else { 0 };
                    pow <<= if i == pow { 1 } else { 0 };
                    s[i] = s[i - (pow >> 1)] * &chal_squareds[rounds - 1 - (k - 1)];
                }
                s
            };

            let neg_rand_base_i = -rand_base_i;

            // TERM
            // - rand_base_i z1 G
            // =
            // rand_base_i * ( - z1 * < s, self.g > )
            // =
            // - rand_base_i * (z1 * < s, self.g > )
            {
                let terms: Vec<_> = s
                    .par_iter()
                    .map(|s| {
                        let mut term = opening.z1;
                        term *= s;
                        term *= &rand_base_i;
                        term
                    })
                    .collect();

                for (i, term) in terms.iter().enumerate() {
                    scalars[i] -= term;
                }
            }

            // TERM
            // - rand_base_i * z2 * H
            scalars[padded_length] -= &(rand_base_i * &opening.z2);

            // TERM
            // -rand_base_i * (z1 * b0 * U)
            scalars.push(neg_rand_base_i * &(opening.z1 * &b0));
            points.push(u);

            // TERM
            // rand_base_i c_i Q_i
            // = rand_base_i c_i
            //   (sum_j (chal_squareds[j] L_j + chal_squared_invs[j] R_j) + P_prime)
            // where P_prime = combined commitment + combined_inner_product * U
            let rand_base_i_c_i = c * &rand_base_i;
            for ((l, r), (u, u_inv)) in opening
                .lr
                .iter()
                .zip(chal_squareds.iter().zip(chal_squared_invs.iter()))
            {
                points.push(*l);
                scalars.push(rand_base_i_c_i * u);

                points.push(*r);
                scalars.push(rand_base_i_c_i * u_inv);
            }

            // TERM
            // sum_j r^j (sum_i xi^i f_i) (elm_j)
            // == sum_j sum_i r^j xi^i f_i(elm_j)
            // == sum_i xi^i sum_j r^j f_i(elm_j)
            let combined_inner_product = {
                let mut res = Fr::<G>::zero();
                let mut xi_i = Fr::<G>::one();

                for (comm, evals, shifted) in polys {
                    let term = eval_polynomial(evals, *r);

                    res += &(xi_i * &term);

                    scalars.push(rand_base_i_c_i * &xi_i);
                    points.push(*comm);

                    xi_i *= xi;

                    match shifted {
                        Some((shifted_comm_i, m)) => {
                            // xi^i sum_j r^j elm_j^{N - m} f(elm_j)
                            let shifted_evals: Vec<_> = evaluation_points
                                .iter()
                                .zip(evals)
                                .map(|(elm, f_elm)| elm.pow(&[(self.g.len() - m) as u64]) * f_elm)
                                .collect();

                            scalars.push(rand_base_i_c_i * &xi_i);
                            points.push(*shifted_comm_i);

                            res += &(xi_i * &eval_polynomial(&shifted_evals, *r));

                            xi_i *= xi;
                        }
                        None => (),
                    }
                }
                res
            };

            scalars.push(rand_base_i_c_i * &combined_inner_product);
            points.push(u);

            scalars.push(rand_base_i);
            points.push(opening.delta);

            rand_base_i *= &rand_base;
        }
        // verify the equation
        let scalars: Vec<_> = scalars.iter().map(|x| x.into_repr()).collect();
        assert!(VariableBaseMSM::multi_scalar_mul(&points, &scalars) == G::Projective::zero());
        true
    }
}

fn inner_prod<F: Field>(xs: &[F], ys: &[F]) -> F {
    let mut res = F::zero();
    for (&x, y) in xs.iter().zip(ys) {
        res += &(x * y);
    }
    res
}

fn eval_polynomial<F: Field>(coeffs: &[F], x: F) -> F {
    let mut res = F::zero();
    for c in coeffs.iter().rev() {
        res *= &x;
        res += c;
    }
    res
}

pub trait Utils<F: Field> {
    fn scale(&self, elm: F) -> Self;
    fn shiftr(&self, size: usize) -> Self;
}

impl<F: Field> Utils<F> for DensePolynomial<F> {
    // This function "scales" (multiplies) polynomaial with a scalar
    // It is implemented to have the desired functionality for DensePolynomial
    fn scale(&self, elm: F) -> Self {
        let mut result = self.clone();
        for coeff in &mut result.coeffs {
            *coeff *= &elm
        }
        result
    }

    fn shiftr(&self, size: usize) -> Self {
        let mut result = vec![F::zero(); size];
        result.extend(self.coeffs.clone());
        DensePolynomial::<F>::from_coefficients_vec(result)
    }
}
