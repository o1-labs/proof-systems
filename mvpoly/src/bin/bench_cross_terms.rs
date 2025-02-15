use ark_ff::UniformRand;
use mina_curves::pasta::Fp;
use mvpoly::{monomials::Sparse, MVPoly};
use std::time::Instant;

fn bench_sparse_cross_terms_computation_scaled() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1: Sparse<Fp, 10, 7> = unsafe { Sparse::random(&mut rng, None) };
    let eval_left: [Fp; 10] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let eval_right: [Fp; 10] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let u1 = Fp::rand(&mut rng);
    let u2 = Fp::rand(&mut rng);
    let a1 = Fp::rand(&mut rng);
    let a2 = Fp::rand(&mut rng);
    let start_timer = Instant::now();
    p1.compute_cross_terms_scaled(&eval_left, &eval_right, u1, u2, a1, a2);
    let elapsed = start_timer.elapsed();
    println!("sparse cross terms computation scaled: {:?}", elapsed);
}

fn main() {
    bench_sparse_cross_terms_computation_scaled();
}
