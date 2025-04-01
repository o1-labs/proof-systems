#![allow(clippy::unit_arg)]
use ark_ff::UniformRand;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations,
    Radix2EvaluationDomain,
};
use criterion::{criterion_group, criterion_main, Criterion};
use mina_curves::pasta::Fp;
use rand_core::OsRng;
use std::ops::Mul;

static SRS_SIZE: usize = 1 << 16;

/// Given a polynomial f in evaluation `evals` form over a `domain`,
/// - Interpolate f to get the polynomial
/// - Enlarge the domain
/// - Evaluate the polynomial over the enlarged domain
/// - Divide the evaluations of the polynomial by the vanishing polynomial of the original domain

fn arkworks_impl(
    vanishing_domain: Radix2EvaluationDomain<Fp>,
    evals: Evaluations<Fp, Radix2EvaluationDomain<Fp>>,
) -> DensePolynomial<Fp> {
    let p: DensePolynomial<Fp> = evals.interpolate();
    let d8 = Radix2EvaluationDomain::new(SRS_SIZE * 8).unwrap();
    let p_evals = p.evaluate_over_domain(d8);
    let p_d8 = p_evals.interpolate();
    let (q, _) = p_d8.divide_by_vanishing_poly(vanishing_domain).unwrap();
    q
}

/// Given a polynomial f in evaluation `evals` form over a `domain`,
/// - Interpolate f to get the polynomial
/// - Enlarge the domain and take a coset
/// - Evaluate the polynomial over the coset domain
/// - Evaluate and invert the vanishing polynomial of `domian` over the coset domain
/// - Multiply the evaluations of the polynomial and the inverted vanishing polynomial
fn o1_impl(
    rng: &mut OsRng,
    vanishing_domain: Radix2EvaluationDomain<Fp>,
    evals: Evaluations<Fp, Radix2EvaluationDomain<Fp>>,
) -> Evaluations<Fp, Radix2EvaluationDomain<Fp>> {
    let offset = Fp::rand(rng);
    let d8_coset_domain = Radix2EvaluationDomain::new_coset(SRS_SIZE * 8, offset).unwrap();
    let numerator = {
        let f: DensePolynomial<Fp> = evals.interpolate();
        f.evaluate_over_domain(d8_coset_domain)
    };
    //eprintln!("numerator: {:?}", numerator);
    let denominator_inv = {
        let vp: DensePolynomial<Fp> = vanishing_domain.vanishing_polynomial().into();
        let mut vp_evals = vp.evaluate_over_domain(d8_coset_domain).evals;
        ark_ff::batch_inversion(&mut vp_evals);
        Evaluations::from_vec_and_domain(vp_evals, d8_coset_domain)
    };
    numerator.mul(&denominator_inv)
}

fn rand_poly(n: usize, rng: &mut OsRng) -> DensePolynomial<Fp> {
    DensePolynomial::<Fp>::rand(n, rng)
}

// this should act like a test, you can use it as main
pub fn sanity_check() {
    let mut rng = &mut OsRng;
    let domain = Radix2EvaluationDomain::<Fp>::new(SRS_SIZE).unwrap();
    let p: DensePolynomial<Fp> = {
        let p = rand_poly(SRS_SIZE * 3, &mut rng);
        let vp = domain.vanishing_polynomial().into();
        p.mul(&vp)
    };
    let evals = p.evaluate_over_domain(domain);
    let arkworks_result = arkworks_impl(domain, evals.clone());
    let o1_result = o1_impl(rng, domain, evals.clone());
    assert_eq!(
        arkworks_result,
        o1_result.interpolate_by_ref(),
        "polynomials are unequal"
    );
    assert_eq!(
        arkworks_result.evaluate_over_domain(o1_result.domain()),
        o1_result,
        "evaluations are unequal"
    );
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("polynomial_division");
    let mut rng = OsRng;

    let sizes = [SRS_SIZE];

    for &size in &sizes {
        let domain = Radix2EvaluationDomain::<Fp>::new(size).unwrap();

        let p: DensePolynomial<Fp> = {
            let p = rand_poly(size * 3, &mut rng);
            let vp = domain.vanishing_polynomial().into();
            p.mul(&vp)
        };

        let evals = p.evaluate_over_domain(domain);

        group.bench_function(format!("arkworks_impl_size_{}", size), |b| {
            b.iter_batched(
                || evals.clone(),
                |e| {
                    for _ in 0..10 {
                        criterion::black_box({
                            let res = arkworks_impl(domain, e.clone());
                            res.evaluate_over_domain(domain)
                    });
                    }
                },
                criterion::BatchSize::SmallInput,
            )
        });

        group.bench_function(format!("o1_impl_size_{}", size), |b| {
            b.iter_batched(
                || evals.clone(),
                |e| {
                    for _ in 0..10 {
                        let mut iter_rng = OsRng;
                        criterion::black_box(o1_impl(&mut iter_rng, domain, e.clone()));
                    }
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
