//! This module implements permutation constraint polynomials.

//~
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
    circuits::{constraints::ConstraintSystem, polynomial::WitnessOverDomains, wires::*},
    error::ProverError,
    proof::ProofEvaluations,
};
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    EvaluationDomain, Evaluations, Radix2EvaluationDomain as D,
};
use ark_poly::{Polynomial, UVPolynomial};
use o1_utils::{ExtendedDensePolynomial, ExtendedEvaluations};
use rand::{CryptoRng, RngCore};

/// Number of constraints produced by the argument.
pub const CONSTRAINTS: u32 = 3;
pub const ZK_ROWS: u64 = 3;
/// Evaluates the polynomial
/// (x - w^{n - 4}) (x - w^{n - 3}) * (x - w^{n - 2}) * (x - w^{n - 1})
pub fn eval_vanishes_on_last_4_rows<F: FftField>(domain: D<F>, x: F) -> F {
    let w4 = domain.group_gen.pow(&[domain.size - (ZK_ROWS + 1)]);
    let w3 = domain.group_gen * w4;
    let w2 = domain.group_gen * w3;
    let w1 = domain.group_gen * w2;
    (x - w1) * (x - w2) * (x - w3) * (x - w4)
}

/// The polynomial
/// (x - w^{n - 4}) (x - w^{n - 3}) * (x - w^{n - 2}) * (x - w^{n - 1})
pub fn vanishes_on_last_4_rows<F: FftField>(domain: D<F>) -> DensePolynomial<F> {
    let x = DensePolynomial::from_coefficients_slice(&[F::zero(), F::one()]);
    let c = |a: F| DensePolynomial::from_coefficients_slice(&[a]);
    let w4 = domain.group_gen.pow(&[domain.size - (ZK_ROWS + 1)]);
    let w3 = domain.group_gen * w4;
    let w2 = domain.group_gen * w3;
    let w1 = domain.group_gen * w2;
    &(&(&x - &c(w1)) * &(&x - &c(w2))) * &(&(&x - &c(w3)) * &(&x - &c(w4)))
}

/// Returns the end of the circuit, which is used for introducing zero-knowledge in the permutation polynomial
pub fn zk_w3<F: FftField>(domain: D<F>) -> F {
    domain.group_gen.pow(&[domain.size - (ZK_ROWS)])
}

/// Evaluates the polynomial
/// (x - w^{n - 3}) * (x - w^{n - 2}) * (x - w^{n - 1})
pub fn eval_zk_polynomial<F: FftField>(domain: D<F>, x: F) -> F {
    let w3 = zk_w3(domain);
    let w2 = domain.group_gen * w3;
    let w1 = domain.group_gen * w2;
    (x - w1) * (x - w2) * (x - w3)
}

/// Computes the zero-knowledge polynomial for blinding the permutation polynomial: `(x-w^{n-k})(x-w^{n-k-1})...(x-w^n)`.
/// Currently, we use k = 3 for 2 blinding factors,
/// see <https://www.plonk.cafe/t/noob-questions-plonk-paper/73>
pub fn zk_polynomial<F: FftField>(domain: D<F>) -> DensePolynomial<F> {
    let w3 = zk_w3(domain);
    let w2 = domain.group_gen * w3;
    let w1 = domain.group_gen * w2;

    // (x-w3)(x-w2)(x-w1) =
    // x^3 - x^2(w1+w2+w3) + x(w1w2+w1w3+w2w3) - w1w2w3
    let w1w2 = w1 * w2;
    DensePolynomial::from_coefficients_slice(&[
        -w1w2 * w3,                   // 1
        w1w2 + (w1 * w3) + (w3 * w2), // x
        -w1 - w2 - w3,                // x^2
        F::one(),                     // x^3
    ])
}

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    /// permutation quotient poly contribution computation
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

        // constant gamma in evaluation form (in domain d8)
        let gamma = &self.precomputations().constant_1_d8.scale(gamma);

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
            let mut shifts = lagrange.d8.this.z.clone();
            for (witness, shift) in lagrange.d8.this.w.iter().zip(self.shift.iter()) {
                let term =
                    &(witness + gamma) + &self.precomputations().poly_x_d1.scale(beta * shift);
                shifts = &shifts * &term;
            }

            // sigmas = z(x * w) *
            // (w8[0] + gamma + sigma[0] * beta) *
            // (w8[1] + gamma + sigma[1] * beta) * ...
            // (w8[6] + gamma + sigma[6] * beta)
            // in evaluation form in d8
            let mut sigmas = lagrange.d8.next.z.clone();
            for (witness, sigma) in lagrange.d8.this.w.iter().zip(self.sigmal8.iter()) {
                let term = witness + &(gamma + &sigma.scale(beta));
                sigmas = &sigmas * &term;
            }

            &(&shifts - &sigmas).scale(alpha0) * &self.precomputations().zkpl
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
            .map_or(Err(ProverError::Permutation("first division")), Ok)?;
            if !res.is_zero() {
                return Err(ProverError::Permutation("first division rest"));
            }

            // accumulator end := (z(x) - 1) / (x - sid[n-3])
            let denominator = DensePolynomial::from_coefficients_slice(&[
                -self.sid[self.domain.d1.size() - 3],
                F::one(),
            ]);
            let (bnd2, res) = DenseOrSparsePolynomial::divide_with_q_and_r(
                &z_minus_1.into(),
                &denominator.into(),
            )
            .map_or(Err(ProverError::Permutation("second division")), Ok)?;
            if !res.is_zero() {
                return Err(ProverError::Permutation("second division rest"));
            }

            &bnd1.scale(alpha1) + &bnd2.scale(alpha2)
        };

        //
        Ok((perm, bnd))
    }

    /// permutation linearization poly contribution computation
    pub fn perm_lnrz(
        &self,
        e: &[ProofEvaluations<F>],
        zeta: F,
        beta: F,
        gamma: F,
        alphas: impl Iterator<Item = F>,
    ) -> DensePolynomial<F> {
        //~
        //~ The linearization:
        //~
        //~ $\text{scalar} \cdot \sigma_6(x)$
        //~
        let zkpm_zeta = self.precomputations().zkpm.evaluate(&zeta);
        let scalar = Self::perm_scalars(e, beta, gamma, alphas, zkpm_zeta);
        self.sigmam[PERMUTS - 1].scale(scalar)
    }

    pub fn perm_scalars(
        e: &[ProofEvaluations<F>],
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
        let init = e[1].z * beta * alpha0 * zkp_zeta;
        let res = e[0]
            .w
            .iter()
            .zip(e[0].s.iter())
            .map(|(w, s)| gamma + (beta * s) + w)
            .fold(init, |x, y| x * y);
        -res
    }

    /// permutation aggregation polynomial computation
    pub fn perm_aggreg(
        &self,
        witness: &[Vec<F>; COLUMNS],
        beta: &F,
        gamma: &F,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<DensePolynomial<F>, ProverError> {
        let n = self.domain.d1.size();

        // only works if first element is 1
        assert_eq!(self.domain.d1.elements().next(), Some(F::one()));

        //~ To compute the permutation aggregation polynomial,
        //~ the prover interpolates the polynomial that has the following evaluations.

        //~ The first evaluation represents the initial value of the accumulator:
        //~ $$z(g^0) = 1$$

        let mut z = vec![F::one(); n];

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
        //~
        for j in 0..n - 3 {
            z[j + 1] = witness
                .iter()
                .zip(self.sigmal1.iter())
                .map(|(w, s)| w[j] + (s[j] * beta) + gamma)
                .fold(F::one(), |x, y| x * y)
        }

        ark_ff::fields::batch_inversion::<F>(&mut z[1..=n - 3]);

        for j in 0..n - 3 {
            let x = z[j];
            z[j + 1] *= witness
                .iter()
                .zip(self.shift.iter())
                .map(|(w, s)| w[j] + (self.sid[j] * beta * s) + gamma)
                .fold(x, |z, y| z * y)
        }

        //~ If computed correctly, we should have $z(g^{n-3}) = 1$.
        //~
        if z[n - 3] != F::one() {
            return Err(ProverError::Permutation("final value"));
        };

        //~ Finally, randomize the last `EVAL_POINTS` evaluations $z(g^{n-2})$ and $z(g^{n-1})$,
        //~ in order to add zero-knowledge to the protocol.
        z[n - 2] = F::rand(rng);
        z[n - 1] = F::rand(rng);

        let res = Evaluations::<F, D<F>>::from_vec_and_domain(z, self.domain.d1).interpolate();
        Ok(res)
    }
}
