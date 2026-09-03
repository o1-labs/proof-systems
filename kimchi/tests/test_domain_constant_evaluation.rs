//! [`DomainConstantEvaluations`] builds its d8 evaluations in closed form
//! rather than by interpolating and running an FFT. These tests pin that the
//! closed forms agree exactly with the polynomials they stand in for, so the
//! cheaper construction cannot silently drift from the definitions the prover
//! and verifier rely on.

use ark_ff::{FftField, Field, One, Zero};
use ark_poly::{
    univariate::DensePolynomial as DP, DenseUVPolynomial, Evaluations as E, Polynomial,
    Radix2EvaluationDomain as D,
};
use kimchi::circuits::{
    domain_constant_evaluation::DomainConstantEvaluations,
    domains::EvaluationDomains,
    polynomials::permutation::{permutation_vanishing_polynomial, vanishes_on_last_n_rows},
};
use mina_curves::pasta::Fp;

/// The construction each field used before it was given a closed form: build
/// the polynomial in coefficient form and evaluate it over d8 by FFT.
fn reference<F: FftField>(poly: &DP<F>, d8: D<F>) -> E<F, D<F>> {
    poly.evaluate_over_domain_by_ref(d8)
}

/// Domain sizes and zk_rows worth exercising: small domains (where d8 is close
/// to the number of zk rows) and larger ones, against every zk_rows the
/// constraint system builds in practice.
fn cases() -> impl Iterator<Item = (usize, u64)> {
    (3u32..=10)
        .flat_map(|log_n| [3u64, 5, 7].map(move |zk_rows| (1usize << log_n, zk_rows)))
        // `create` requires only `n > zk_rows`; include that boundary, where
        // the vanishing polynomial's roots reach the start of the domain.
        .filter(|(n, zk_rows)| *n as u64 > *zk_rows)
}

#[test]
fn poly_x_d1_is_the_d8_domain_points() {
    for (n, zk_rows) in cases() {
        let domain = EvaluationDomains::<Fp>::create(n).unwrap();
        let dce = DomainConstantEvaluations::create(domain, zk_rows).unwrap();

        // `poly_x_d1` holds the polynomial `x` over d8, i.e. the d8 domain
        // points; it is read back as a plain slice by the permutation argument.
        let expected = reference(
            &DP::from_coefficients_slice(&[Fp::zero(), Fp::one()]),
            domain.d8,
        );
        assert_eq!(
            dce.poly_x_d1, expected,
            "poly_x_d1 mismatch at n={n} zk_rows={zk_rows}"
        );

        // Equivalently: the i-th entry is g8^i.
        let mut x = Fp::one();
        for (i, point) in dce.poly_x_d1.evals.iter().enumerate() {
            assert_eq!(*point, x, "poly_x_d1[{i}] mismatch at n={n}");
            x *= domain.d8.group_gen;
        }
    }
}

#[test]
fn vanishing_polynomials_match_their_interpolations() {
    for (n, zk_rows) in cases() {
        let domain = EvaluationDomains::<Fp>::create(n).unwrap();
        let dce = DomainConstantEvaluations::create(domain, zk_rows).unwrap();

        // Vanishes on the last zk_rows + 1 rows.
        let expected = reference(&vanishes_on_last_n_rows(domain.d1, zk_rows + 1), domain.d8);
        assert_eq!(
            dce.vanishes_on_zero_knowledge_and_previous_rows, expected,
            "vanishes_on_zero_knowledge_and_previous_rows mismatch at n={n} zk_rows={zk_rows}"
        );

        // The permutation vanishing polynomial, and its d8 evaluations.
        let m = permutation_vanishing_polynomial(domain.d1, zk_rows);
        assert_eq!(
            dce.permutation_vanishing_polynomial_m, m,
            "permutation_vanishing_polynomial_m mismatch at n={n} zk_rows={zk_rows}"
        );
        assert_eq!(
            dce.permutation_vanishing_polynomial_l,
            reference(&m, domain.d8),
            "permutation_vanishing_polynomial_l mismatch at n={n} zk_rows={zk_rows}"
        );
    }
}

#[test]
fn vanishing_polynomials_vanish_on_their_roots() {
    for (n, zk_rows) in cases() {
        let domain = EvaluationDomains::<Fp>::create(n).unwrap();
        let dce = DomainConstantEvaluations::create(domain, zk_rows).unwrap();
        let omega = domain.d1.group_gen;

        // d1 row `i` sits at index `8 * i` of a d8 evaluation.
        let at_row = |evals: &E<Fp, D<Fp>>, row: u64| evals.evals[8 * (row as usize)];

        for i in (n as u64 - (zk_rows + 1))..(n as u64) {
            assert!(
                at_row(&dce.vanishes_on_zero_knowledge_and_previous_rows, i).is_zero(),
                "vanishes_on_zero_knowledge_and_previous_rows nonzero at row {i} (n={n} zk_rows={zk_rows})"
            );
        }
        // The row before the zk rows must *not* vanish, or the polynomial would
        // be zeroing more of the domain than intended. (When the roots reach the
        // start of the domain there is no such row.)
        if let Some(row) = (n as u64).checked_sub(zk_rows + 2) {
            assert!(
                !at_row(&dce.vanishes_on_zero_knowledge_and_previous_rows, row).is_zero(),
                "vanishes_on_zero_knowledge_and_previous_rows vanishes too early (n={n} zk_rows={zk_rows})"
            );
        }

        for root in [
            omega.pow([n as u64 - zk_rows]),
            omega.pow([n as u64 - zk_rows + 1]),
            omega.pow([n as u64 - 1]),
        ] {
            assert!(
                dce.permutation_vanishing_polynomial_m
                    .evaluate(&root)
                    .is_zero(),
                "permutation_vanishing_polynomial_m nonzero at a root (n={n} zk_rows={zk_rows})"
            );
        }
    }
}
