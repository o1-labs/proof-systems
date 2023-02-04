use ark_ec::ProjectiveCurve;
use ark_std::{test_rng, UniformRand};
use mina_curves::pasta::Vesta;
use o1_utils::fast_msm::msm::MultiScalarMultiplication;

fn create_scalars_and_points<G: MultiScalarMultiplication>(
    len: usize,
) -> (Vec<G::ScalarField>, Vec<G>) {
    let mut scalars = Vec::with_capacity(len);
    let mut points = Vec::with_capacity(len);
    for _ in 0..len {
        scalars.push(G::ScalarField::rand(&mut test_rng()));
        points.push(G::Projective::rand(&mut test_rng()).into_affine());
    }
    (scalars, points)
}

fn main() {
    let (scalars, points) = create_scalars_and_points::<Vesta>(1 << 18);

    for _ in 0..100 {
        let _ = Vesta::msm(&points, &scalars);
    }
}
