//! This module implements permutation constraint polynomials.

//~ The permutation constraints are the following 4 constraints:
//~
//~ The two sides of the coin (with $\text{shift}_0 = 1$):
//~
//~ $$\begin{align}
//~     & z(x) \cdot zkpm(x) \cdot \alpha^{PERM0} \cdot \\
//~     & (w_0(x) + \beta \cdot \text{shift}_0 x + \gamma) \cdot \\
//~     & (w_1(x) + \beta \cdot \text{shift}_1 x + \gamma) \cdot \\
//~     & (w_2(x) + \beta \cdot \text{shift}_2 x + \gamma) \cdot \\
//~     & (w_3(x) + \beta \cdot \text{shift}_3 x + \gamma) \cdot \\
//~     & (w_4(x) + \beta \cdot \text{shift}_4 x + \gamma) \cdot \\
//~     & (w_5(x) + \beta \cdot \text{shift}_5 x + \gamma) \cdot \\
//~     & (w_6(x) + \beta \cdot \text{shift}_6 x + \gamma)
//~ \end{align}$$
//~
//~ and
//~
//~ $$\begin{align}
//~ & -1 \cdot z(x \omega) \cdot zkpm(x) \cdot \alpha^{PERM0} \cdot \\
//~ & (w_0(x) + \beta \cdot \sigma_0(x) + \gamma) \cdot \\
//~ & (w_1(x) + \beta \cdot \sigma_1(x) + \gamma) \cdot \\
//~ & (w_2(x) + \beta \cdot \sigma_2(x) + \gamma) \cdot \\
//~ & (w_3(x) + \beta \cdot \sigma_3(x) + \gamma) \cdot \\
//~ & (w_4(x) + \beta \cdot \sigma_4(x) + \gamma) \cdot \\
//~ & (w_5(x) + \beta \cdot \sigma_5(x) + \gamma) \cdot \\
//~ & (w_6(x) + \beta \cdot \sigma_6(x) + \gamma) \cdot
//~ \end{align}$$
//~
//~ the initialization of the accumulator:
//~
//~ $$(z(x) - 1) L_1(x) \alpha^{PERM1}$$
//~
//~ and the accumulator's final value:
//~
//~ $$(z(x) - 1) L_{n-k}(x) \alpha^{PERM2}$$
//~
//~ You can read more about why it looks like that in [this post](https://minaprotocol.com/blog/a-more-efficient-approach-to-zero-knowledge-for-plonk).
//~
use crate::{
    circuits::{
        constraints::ConstraintSystem,
        polynomial::WitnessOverDomains,
        wires::{Wire, COLUMNS, PERMUTS},
    },
    curve::KimchiCurve,
    error::ProverError,
    proof::{PointEvaluations, ProofEvaluations},
    prover_index::ProverIndex,
};
use ark_ff::{FftField, PrimeField, Zero};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain as D,
};
use blake2::{Blake2b512, Digest};
use core::array;
use o1_utils::{ExtendedDensePolynomial, ExtendedEvaluations};
use rand::{CryptoRng, RngCore};
use rayon::prelude::*;

/// Number of constraints produced by the argument.
pub const CONSTRAINTS: u32 = 3;

/// Evaluates the polynomial
/// (x - w^{n - i}) * (x - w^{n - i + 1}) * ... * (x - w^{n - 1})
pub fn eval_vanishes_on_last_n_rows<F: FftField>(domain: D<F>, i: u64, x: F) -> F {
    if i == 0 {
        return F::one();
    }
    let mut term = domain.group_gen.pow([domain.size - i]);
    let mut acc = x - term;
    for _ in 0..i - 1 {
        term *= domain.group_gen;
        acc *= x - term;
    }
    acc
}

/// The polynomial
/// (x - w^{n - i}) * (x - w^{n - i + 1}) * ... * (x - w^{n - 1})
pub fn vanishes_on_last_n_rows<F: FftField>(domain: D<F>, i: u64) -> DensePolynomial<F> {
    let constant = |a: F| DensePolynomial::from_coefficients_slice(&[a]);
    if i == 0 {
        return constant(F::one());
    }
    let x = DensePolynomial::from_coefficients_slice(&[F::zero(), F::one()]);
    let mut term = domain.group_gen.pow([domain.size - i]);
    let mut acc = &x - &constant(term);
    for _ in 0..i - 1 {
        term *= domain.group_gen;
        acc = &acc * &(&x - &constant(term));
    }
    acc
}

/// Returns the end of the circuit, which is used for introducing zero-knowledge in the permutation polynomial
pub fn zk_w<F: FftField>(domain: D<F>, zk_rows: u64) -> F {
    domain.group_gen.pow([domain.size - zk_rows])
}

/// Evaluates the polynomial
/// (x - w^{n - zk_rows}) * (x - w^{n - zk_rows + 1}) * (x - w^{n - 1})
pub fn eval_permutation_vanishing_polynomial<F: FftField>(domain: D<F>, zk_rows: u64, x: F) -> F {
    let term = domain.group_gen.pow([domain.size - zk_rows]);
    (x - term) * (x - term * domain.group_gen) * (x - domain.group_gen.pow([domain.size - 1]))
}

/// The polynomial
/// (x - w^{n - zk_rows}) * (x - w^{n - zk_rows + 1}) * (x - w^{n - 1})
pub fn permutation_vanishing_polynomial<F: FftField>(
    domain: D<F>,
    zk_rows: u64,
) -> DensePolynomial<F> {
    let constant = |a: F| DensePolynomial::from_coefficients_slice(&[a]);
    let x = DensePolynomial::from_coefficients_slice(&[F::zero(), F::one()]);
    let term = domain.group_gen.pow([domain.size - zk_rows]);
    &(&(&x - &constant(term)) * &(&x - &constant(term * domain.group_gen)))
        * &(&x - &constant(domain.group_gen.pow([domain.size - 1])))
}

/// Shifts represent the shifts required in the permutation argument of PLONK.
/// It also caches the shifted powers of omega for optimization purposes.
pub struct Shifts<F> {
    /// The coefficients `k` (in the Plonk paper) that create a coset when multiplied with the generator of our domain.
    pub(crate) shifts: [F; PERMUTS],
    /// A matrix that maps all cells coordinates `{col, row}` to their shifted field element.
    /// For example the cell `{col:2, row:1}` will map to `omega * k2`,
    /// which lives in `map[2][1]`
    pub(crate) map: [Vec<F>; PERMUTS],
}

impl<F> Shifts<F>
where
    F: FftField,
{
    /// Generates the shifts for a given domain
    pub fn new(domain: &D<F>) -> Self {
        let mut shifts = [F::zero(); PERMUTS];

        // first shift is the identity
        shifts[0] = F::one();

        // sample the other shifts
        let mut i: u32 = 7;
        for idx in 1..(PERMUTS) {
            let mut shift = Self::sample(domain, &mut i);
            // they have to be distincts
            while shifts.contains(&shift) {
                shift = Self::sample(domain, &mut i);
            }
            shifts[idx] = shift;
        }

        // create a map of cells to their shifted value
        let map: [Vec<F>; PERMUTS] =
            array::from_fn(|i| domain.elements().map(|elm| shifts[i] * elm).collect());

        //
        Self { shifts, map }
    }

    /// retrieve the shifts
    pub fn shifts(&self) -> &[F; PERMUTS] {
        &self.shifts
    }

    /// sample coordinate shifts deterministically
    fn sample(domain: &D<F>, input: &mut u32) -> F {
        let mut h = Blake2b512::new();

        *input += 1;
        h.update(input.to_be_bytes());

        let mut shift = F::from_random_bytes(&h.finalize()[..31])
            .expect("our field elements fit in more than 31 bytes");

        while !shift.legendre().is_qnr() || domain.evaluate_vanishing_polynomial(shift).is_zero() {
            let mut h = Blake2b512::new();
            *input += 1;
            h.update(input.to_be_bytes());
            shift = F::from_random_bytes(&h.finalize()[..31])
                .expect("our field elements fit in more than 31 bytes");
        }
        shift
    }

    /// Returns the field element that represents a position
    pub(crate) fn cell_to_field(&self, &Wire { row, col }: &Wire) -> F {
        self.map[col][row]
    }
}

impl<const ROUNDS: usize, F, G, Srs> ProverIndex<ROUNDS, G, Srs>
where
    F: PrimeField,
    G: KimchiCurve<ROUNDS, ScalarField = F>,
    Srs: poly_commitment::SRS<G>,
{
    /// permutation quotient poly contribution computation
    ///
    /// # Errors
    ///
    /// Will give error if `polynomial division` fails.
    ///
    /// # Panics
    ///
    /// Will panic if `power of alpha` is missing.
    #[allow(clippy::type_complexity)]
    pub fn perm_quot(
        &self,
        lagrange: &WitnessOverDomains<F>,
        beta: F,
        gamma: F,
        z: &DensePolynomial<F>,
        mut alphas: impl Iterator<Item = F>,
    ) -> Result<(Evaluations<F, D<F>>, DensePolynomial<F>), ProverError> {
        let alpha0 = alphas.next().expect("missing power of alpha");
        let alpha1 = alphas.next().expect("missing power of alpha");
        let alpha2 = alphas.next().expect("missing power of alpha");

        let zk_rows = self.cs.zk_rows as usize;

        // constant gamma in evaluation form (in domain d8)
        let gamma = &self.cs.precomputations().constant_1_d8.scale(gamma);

        //~ The quotient contribution of the permutation is split into two parts $perm$ and $bnd$.
        //~ They will be used by the prover.
        //~
        //~ $$
        //~ \begin{align}
        //~ perm(x) =
        //~     & \; a^{PERM0} \cdot zkpl(x) \cdot [ \\
        //~     & \;\;   z(x) \cdot \\
        //~     & \;\;   (w_0(x) + \gamma + x \cdot \beta \cdot \text{shift}_0) \cdot \\
        //~     & \;\;   (w_1(x) + \gamma + x \cdot \beta \cdot \text{shift}_1) \cdot \\
        //~     & \;\;   (w_2(x) + \gamma + x \cdot \beta \cdot \text{shift}_2) \cdot \\
        //~     & \;\;   (w_3(x) + \gamma + x \cdot \beta \cdot \text{shift}_3) \cdot \\
        //~     & \;\;   (w_4(x) + \gamma + x \cdot \beta \cdot \text{shift}_4) \cdot \\
        //~     & \;\;   (w_5(x) + \gamma + x \cdot \beta \cdot \text{shift}_5) \cdot \\
        //~     & \;\;   (w_6(x) + \gamma + x \cdot \beta \cdot \text{shift}_6) \cdot \\
        //~     & \;   - \\
        //~     & \;\;   z(x \cdot w) \cdot \\
        //~     & \;\;   (w_0(x) + \gamma + \sigma_0 \cdot \beta) \cdot \\
        //~     & \;\;   (w_1(x) + \gamma + \sigma_1 \cdot \beta) \cdot \\
        //~     & \;\;   (w_2(x) + \gamma + \sigma_2 \cdot \beta) \cdot \\
        //~     & \;\;   (w_3(x) + \gamma + \sigma_3 \cdot \beta) \cdot \\
        //~     & \;\;   (w_4(x) + \gamma + \sigma_4 \cdot \beta) \cdot \\
        //~     & \;\;   (w_5(x) + \gamma + \sigma_5 \cdot \beta) \cdot \\
        //~     & \;\;   (w_6(x) + \gamma + \sigma_6 \cdot \beta) \cdot \\
        //~     &]
        //~ \end{align}
        //~ $$
        //~
        let perm = {
            // shifts = z(x) *
            // (w[0](x) + gamma + x * beta * shift[0]) *
            // (w[1](x) + gamma + x * beta * shift[1]) * ...
            // (w[6](x) + gamma + x * beta * shift[6])
            // in evaluation form in d8
            let shifts: Evaluations<F, D<F>> = &lagrange
                .d8
                .this
                .w
                .par_iter()
                .zip(self.cs.shift.par_iter())
                .map(|(witness, shift)| {
                    &(witness + gamma) + &self.cs.precomputations().poly_x_d1.scale(beta * shift)
                })
                .reduce_with(|mut l, r| {
                    l *= &r;
                    l
                })
                .unwrap()
                * &lagrange.d8.this.z.clone();

            // sigmas = z(x * w) *
            // (w8[0] + gamma + sigma[0] * beta) *
            // (w8[1] + gamma + sigma[1] * beta) * ...
            // (w8[6] + gamma + sigma[6] * beta)
            // in evaluation form in d8
            let sigmas = &lagrange
                .d8
                .this
                .w
                .par_iter()
                .zip(
                    self.column_evaluations
                        .get()
                        .permutation_coefficients8
                        .par_iter(),
                )
                .map(|(witness, sigma)| witness + &(gamma + &sigma.scale(beta)))
                .reduce_with(|mut l, r| {
                    l *= &r;
                    l
                })
                .unwrap()
                * &lagrange.d8.next.z.clone();

            &(&shifts - &sigmas).scale(alpha0)
                * &self.cs.precomputations().permutation_vanishing_polynomial_l
        };

        //~ and `bnd`:
        //~
        //~ $$bnd(x) =
        //~     a^{PERM1} \cdot \frac{z(x) - 1}{x - 1}
        //~     +
        //~     a^{PERM2} \cdot \frac{z(x) - 1}{x - sid[n-k]}
        //~ $$
        let bnd = {
            let one_poly = DensePolynomial::from_coefficients_slice(&[F::one()]);
            let z_minus_1 = z - &one_poly;

            // TODO(mimoo): use self.sid[0] instead of 1
            // accumulator init := (z(x) - 1) / (x - 1)
            let x_minus_1 = DensePolynomial::from_coefficients_slice(&[-F::one(), F::one()]);
            let (bnd1, res) = DenseOrSparsePolynomial::divide_with_q_and_r(
                &z_minus_1.clone().into(),
                &x_minus_1.into(),
            )
            .ok_or(ProverError::Permutation("first division"))?;
            if !res.is_zero() {
                return Err(ProverError::Permutation("first division rest"));
            }

            // accumulator end := (z(x) - 1) / (x - sid[n-zk_rows])
            let denominator = DensePolynomial::from_coefficients_slice(&[
                -self.cs.sid[self.cs.domain.d1.size() - zk_rows],
                F::one(),
            ]);
            let (bnd2, res) = DenseOrSparsePolynomial::divide_with_q_and_r(
                &z_minus_1.into(),
                &denominator.into(),
            )
            .ok_or(ProverError::Permutation("second division"))?;
            if !res.is_zero() {
                return Err(ProverError::Permutation("second division rest"));
            }

            &bnd1.scale(alpha1) + &bnd2.scale(alpha2)
        };
        Ok((perm, bnd))
    }

    /// permutation linearization poly contribution computation
    pub fn perm_lnrz(
        &self,
        e: &ProofEvaluations<PointEvaluations<F>>,
        zeta: F,
        beta: F,
        gamma: F,
        alphas: impl Iterator<Item = F>,
    ) -> Evaluations<F, D<F>> {
        //~
        //~ The linearization:
        //~
        //~ $\text{scalar} \cdot \sigma_6(x)$
        //~
        let zkpm_zeta = self
            .cs
            .precomputations()
            .permutation_vanishing_polynomial_m
            .evaluate(&zeta);
        let scalar = ConstraintSystem::<F>::perm_scalars(e, beta, gamma, alphas, zkpm_zeta);
        let evals8 = &self.column_evaluations.get().permutation_coefficients8[PERMUTS - 1].evals;
        const STRIDE: usize = 8;
        let n = evals8.len() / STRIDE;
        let evals = (0..n)
            .into_par_iter()
            .map(|i| scalar * evals8[STRIDE * i])
            .collect();
        Evaluations::from_vec_and_domain(evals, D::new(n).unwrap())
    }
}

impl<F: PrimeField> ConstraintSystem<F> {
    pub fn perm_scalars(
        e: &ProofEvaluations<PointEvaluations<F>>,
        beta: F,
        gamma: F,
        mut alphas: impl Iterator<Item = F>,
        zkp_zeta: F,
    ) -> F {
        let alpha0 = alphas
            .next()
            .expect("not enough powers of alpha for permutation");
        let _alpha1 = alphas
            .next()
            .expect("not enough powers of alpha for permutation");
        let _alpha2 = alphas
            .next()
            .expect("not enough powers of alpha for permutation");

        //~ where $\text{scalar}$ is computed as:
        //~
        //~ $$
        //~ \begin{align}
        //~ z(\zeta \omega) \beta \alpha^{PERM0} zkpl(\zeta) \cdot \\
        //~ (\gamma + \beta \sigma_0(\zeta) + w_0(\zeta)) \cdot \\
        //~ (\gamma + \beta \sigma_1(\zeta) + w_1(\zeta)) \cdot \\
        //~ (\gamma + \beta \sigma_2(\zeta) + w_2(\zeta)) \cdot \\
        //~ (\gamma + \beta \sigma_3(\zeta) + w_3(\zeta)) \cdot \\
        //~ (\gamma + \beta \sigma_4(\zeta) + w_4(\zeta)) \cdot \\
        //~ (\gamma + \beta \sigma_5(\zeta) + w_5(\zeta)) \cdot \\
        //~ \end{align}
        //~$$
        //~
        let init = e.z.zeta_omega * beta * alpha0 * zkp_zeta;
        let res =
            e.w.iter()
                .zip(e.s.iter())
                .map(|(w, s)| gamma + (beta * s.zeta) + w.zeta)
                .fold(init, |x, y| x * y);
        -res
    }
}

impl<const ROUNDS: usize, F, G, Srs> ProverIndex<ROUNDS, G, Srs>
where
    F: PrimeField,
    G: KimchiCurve<ROUNDS, ScalarField = F>,
    Srs: poly_commitment::SRS<G>,
{
    /// permutation aggregation polynomial computation
    ///
    /// # Errors
    ///
    /// Will give error if permutation result is not correct.
    ///
    /// # Panics
    ///
    /// Will panic if `first element` is not 1.
    pub fn perm_aggreg(
        &self,
        witness: &[Vec<F>; COLUMNS],
        beta: &F,
        gamma: &F,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<DensePolynomial<F>, ProverError> {
        let n = self.cs.domain.d1.size();

        let zk_rows = self.cs.zk_rows as usize;

        // only works if first element is 1
        assert_eq!(self.cs.domain.d1.elements().next(), Some(F::one()));

        //~ To compute the permutation aggregation polynomial,
        //~ the prover interpolates the polynomial that has the following evaluations.

        //~ The first evaluation represents the initial value of the accumulator:
        //~ $$z(g^0) = 1$$

        //~ For $i = 0, \cdot, n - 4$, where $n$ is the size of the domain,
        //~ evaluations are computed as:
        //~
        //~ $$z(g^{i+1}) = z_1 / z_2$$
        //~
        //~ with
        //~
        //~ $$
        //~ \begin{align}
        //~ z_1 = &\ (w_0(g^i + sid(g^i) \cdot beta \cdot shift_0 + \gamma) \cdot \\
        //~ &\ (w_1(g^i) + sid(g^i) \cdot beta \cdot shift_1 + \gamma) \cdot \\
        //~ &\ (w_2(g^i) + sid(g^i) \cdot beta \cdot shift_2 + \gamma) \cdot \\
        //~ &\ (w_3(g^i) + sid(g^i) \cdot beta \cdot shift_3 + \gamma) \cdot \\
        //~ &\ (w_4(g^i) + sid(g^i) \cdot beta \cdot shift_4 + \gamma) \cdot \\
        //~ &\ (w_5(g^i) + sid(g^i) \cdot beta \cdot shift_5 + \gamma) \cdot \\
        //~ &\ (w_6(g^i) + sid(g^i) \cdot beta \cdot shift_6 + \gamma)
        //~ \end{align}
        //~ $$
        //~
        //~ and
        //~
        //~ $$
        //~ \begin{align}
        //~ z_2 = &\ (w_0(g^i) + \sigma_0 \cdot beta + \gamma) \cdot \\
        //~ &\ (w_1(g^i) + \sigma_1 \cdot beta + \gamma) \cdot \\
        //~ &\ (w_2(g^i) + \sigma_2 \cdot beta + \gamma) \cdot \\
        //~ &\ (w_3(g^i) + \sigma_3 \cdot beta + \gamma) \cdot \\
        //~ &\ (w_4(g^i) + \sigma_4 \cdot beta + \gamma) \cdot \\
        //~ &\ (w_5(g^i) + \sigma_5 \cdot beta + \gamma) \cdot \\
        //~ &\ (w_6(g^i) + \sigma_6 \cdot beta + \gamma)
        //~ \end{align}
        //~ $$
        //~

        // We compute z such that:
        // z[0] = 1
        // z[j+1] = \Prod_{i=0}^{PERMUTS}(wit[i][j] + (s[i][8*j] * beta) + gamma)     for j ∈ 0..n-1
        //
        // We compute every product batch separately first (one batch
        // per i∈[COLUMNS]), and then multiply all batches together.
        //
        // Note that we zip array of COLUMNS with array of PERMUTS;
        // Since PERMUTS < COLUMNS, that's what's actually used.
        let mut z: Vec<F> = witness
            .par_iter()
            .zip(
                self.column_evaluations
                    .get()
                    .permutation_coefficients8
                    .par_iter(),
            )
            .map(|(w_i, perm_coeffs8_i)| {
                let mut output_vec: Vec<_> = vec![F::one(); 1];
                for (j, w_i_j) in w_i.iter().enumerate().take(n - 1) {
                    output_vec.push(*w_i_j + (perm_coeffs8_i[8 * j] * beta) + gamma);
                }
                output_vec
            })
            .reduce_with(|mut l, r| {
                for i in 0..n {
                    l[i] *= &r[i];
                }
                l
            })
            .unwrap();

        ark_ff::fields::batch_inversion::<F>(&mut z[1..n]);

        let z_prefolded: Vec<F> = witness
            .par_iter()
            .zip(self.cs.shift.par_iter())
            .map(|(w_i, shift_i)| {
                let mut output_vec: Vec<_> = vec![F::one(); 1];
                for (j, w_i_j) in w_i.iter().enumerate().take(n - 1) {
                    output_vec.push(*w_i_j + (self.cs.sid[j] * beta * shift_i) + gamma);
                }
                output_vec
            })
            .reduce_with(|mut l, r| {
                for i in 0..n {
                    l[i] *= &r[i];
                }
                l
            })
            .unwrap();

        //~ We randomize the evaluations at `n - zk_rows + 1` and `n - zk_rows + 2` in order to add
        //~ zero-knowledge to the protocol.
        //~
        for j in 0..n - 1 {
            if j != n - zk_rows && j != n - zk_rows + 1 {
                let x = z[j];
                z[j + 1] *= z_prefolded[j + 1] * x;
            } else {
                z[j + 1] = F::rand(rng);
            }
        }

        //~ For a valid witness, we then have have $z(g^{n-zk_rows}) = 1$.
        //~
        if z[n - zk_rows] != F::one() {
            return Err(ProverError::Permutation("final value"));
        };

        let res = Evaluations::<F, D<F>>::from_vec_and_domain(z, self.cs.domain.d1).interpolate();

        Ok(res)
    }
}
