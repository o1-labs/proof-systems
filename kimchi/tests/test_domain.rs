#![cfg(feature = "prover")]

use ark_ff::{Field, UniformRand};
use ark_poly::{
    univariate::DensePolynomial as DP, DenseUVPolynomial, EvaluationDomain, Evaluations,
};
use kimchi::circuits::domains::EvaluationDomains;
use mina_curves::pasta::Fp;

#[test]
fn test_create_domain() {
    if let Ok(d) = EvaluationDomains::<Fp>::create(usize::MAX) {
        assert!(d.d4.group_gen.pow([4]) == d.d1.group_gen);
        assert!(d.d8.group_gen.pow([2]) == d.d4.group_gen);
        println!("d8 = {:?}", d.d8.group_gen);
        println!("d8^2 = {:?}", d.d8.group_gen.pow([2]));
        println!("d4 = {:?}", d.d4.group_gen);
        println!("d4 = {:?}", d.d4.group_gen.pow([4]));
        println!("d1 = {:?}", d.d1.group_gen);
    }
}

/// d1 is a subgroup of d8 (d8 = 8 * d1, both Radix2), so the d1 domain points
/// are exactly every 8th d8 domain point.
#[test]
fn d1_is_the_8_stride_subgroup_of_d8() {
    for log_n in 3..=10u32 {
        let d = EvaluationDomains::<Fp>::create(1 << log_n).unwrap();
        assert_eq!(d.d8.size(), 8 * d.d1.size());
        for (j, x) in d.d1.elements().enumerate() {
            assert_eq!(
                x,
                d.d8.element(8 * j),
                "d1[{j}] != d8[8*{j}] at n=1<<{log_n}"
            );
        }
    }
}

/// The prover recovers the joint lookup table's coefficient form by subsampling
/// its d8 evaluations to d1 and running a d1-sized iFFT, rather than a full d8
/// iFFT. That is exact for any polynomial of degree < d1 -- which the joint
/// table is, being a fixed linear combination of the table columns. Pin the
/// identity here so the prover's shortcut cannot silently stop being valid.
#[test]
fn subsampling_d8_evals_to_d1_recovers_the_polynomial() {
    let mut rng = o1_utils::tests::make_test_rng(None);

    for log_n in 3..=10u32 {
        let d = EvaluationDomains::<Fp>::create(1 << log_n).unwrap();

        // Any polynomial of degree < d1 -- the bound the joint lookup table meets.
        let coeffs: Vec<Fp> = (0..d.d1.size()).map(|_| Fp::rand(&mut rng)).collect();
        let poly = DP::from_coefficients_vec(coeffs);

        let evals_d8 = poly.evaluate_over_domain_by_ref(d.d8);

        let subsampled: Vec<Fp> = evals_d8.evals.iter().step_by(8).copied().collect();
        let recovered = Evaluations::from_vec_and_domain(subsampled, d.d1).interpolate();

        assert_eq!(
            recovered, poly,
            "subsampling failed to recover the polynomial at n=1<<{log_n}"
        );
        // ...and it agrees with the full d8 iFFT it replaces.
        assert_eq!(
            recovered,
            evals_d8.interpolate_by_ref(),
            "subsampling disagrees with the d8 interpolation at n=1<<{log_n}"
        );
    }
}
