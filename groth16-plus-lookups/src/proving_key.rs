use crate::verification_key::VerificationKey;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{FftField, PrimeField, UniformRand};
use ark_poly::{EvaluationDomain, Polynomial, Radix2EvaluationDomain as D};

pub struct TrustedSetupProverOutputs<G1, G2> {
    pub left_fixed_randomizer: G1,
    pub right_fixed_randomizer: (G1, G2),
    pub output_fixed_randomizer: (G1, G2),
    pub left_commitments: Box<[G1]>,
    pub right_commitments: Box<[G2]>,
    pub out_commitments: Box<[G1]>,
    pub quotient_commitments: Box<[G1]>,
}

pub struct CircuitLayout<F: FftField> {
    pub public_input_size: usize,
    pub a_contributions: Box<[Box<[(usize, F)]>]>,
    pub b_contributions: Box<[Box<[(usize, F)]>]>,
    pub c_contributions: Box<[Box<[(usize, F)]>]>,
    pub domain: D<F>,
    pub domain_d2: D<F>,
}

pub fn trusted_setup<F: PrimeField, Rng: rand::RngCore, Pair: PairingEngine<Fr = F>>(
    layout: &CircuitLayout<F>,
    rng: &mut Rng,
) -> (
    TrustedSetupProverOutputs<Pair::G1Affine, Pair::G2Affine>,
    VerificationKey<Pair::G1Affine, Pair::G2Affine>,
) {
    let left_randomizer: F = <F as UniformRand>::rand(rng);
    let right_randomizer: F = <F as UniformRand>::rand(rng);
    let output_randomizer: F = <F as UniformRand>::rand(rng);
    let public_input_randomizer_: F = <F as UniformRand>::rand(rng);

    let left_fixed_randomizer = Pair::G1Affine::prime_subgroup_generator()
        .mul(left_randomizer)
        .into_affine();
    let right_fixed_randomizer = (
        Pair::G1Affine::prime_subgroup_generator()
            .mul(right_randomizer)
            .into_affine(),
        Pair::G2Affine::prime_subgroup_generator()
            .mul(right_randomizer)
            .into_affine(),
    );
    let output_fixed_randomizer = (
        Pair::G1Affine::prime_subgroup_generator()
            .mul(output_randomizer)
            .into_affine(),
        Pair::G2Affine::prime_subgroup_generator()
            .mul(output_randomizer)
            .into_affine(),
    );
    let public_input_randomizer = Pair::G2Affine::prime_subgroup_generator()
        .mul(public_input_randomizer_)
        .into_affine();

    let evaluation_point: F = <F as UniformRand>::rand(rng);

    let left_commitments = {
        let mut x_pow = F::one();
        let comms: Vec<_> = (0..layout.domain.size())
            .map(|_| {
                let res = Pair::G1Affine::prime_subgroup_generator().mul(x_pow);
                x_pow *= evaluation_point;
                res.into_affine()
            })
            .collect();
        comms.into_boxed_slice()
    };

    let right_commitments = {
        let mut x_pow = F::one();
        let comms: Vec<_> = (0..layout.domain.size())
            .map(|_| {
                let res = Pair::G2Affine::prime_subgroup_generator().mul(x_pow);
                x_pow *= evaluation_point;
                res.into_affine()
            })
            .collect();
        comms.into_boxed_slice()
    };

    let quotient_commitments = {
        let vanishing_poly_eval = layout
            .domain
            .vanishing_polynomial()
            .evaluate(&evaluation_point);

        let mut x_pow = vanishing_poly_eval / output_randomizer;
        let comms: Vec<_> = (0..layout.domain.size())
            .map(|_| {
                let res = Pair::G1Affine::prime_subgroup_generator().mul(x_pow);
                x_pow *= evaluation_point;
                res.into_affine()
            })
            .collect();
        comms.into_boxed_slice()
    };

    let (public_input_commitments, out_commitments) = {
        let lagrange_basis = kimchi::lagrange_basis_evaluations::LagrangeBasisEvaluations::new(
            layout.domain.size(),
            layout.domain,
            evaluation_point,
        )
        .evaluations();
        let comm_evals = |i: usize, scalar: F| {
            let mut left_eval = F::zero();
            for (idx, scalar) in layout.a_contributions[i].iter() {
                left_eval += lagrange_basis[0][*idx] * *scalar;
            }
            let mut right_eval = F::zero();
            for (idx, scalar) in layout.b_contributions[i].iter() {
                right_eval += lagrange_basis[0][*idx] * *scalar;
            }
            let mut eval = left_eval * right_randomizer + right_eval * left_randomizer;
            for (idx, scalar) in layout.c_contributions[i].iter() {
                eval += lagrange_basis[0][*idx] * *scalar;
            }
            eval *= scalar;
            Pair::G1Affine::prime_subgroup_generator()
                .mul(eval)
                .into_affine()
        };
        let public_comms: Vec<_> = {
            let inv_randomizer = public_input_randomizer_.inverse().unwrap();
            (0..layout.public_input_size)
                .map(|i| comm_evals(i, inv_randomizer))
                .collect()
        };
        let out_comms: Vec<_> = {
            let inv_randomizer = output_randomizer.inverse().unwrap();
            (layout.public_input_size..layout.a_contributions.len())
                .map(|i| comm_evals(i, inv_randomizer))
                .collect()
        };
        (
            public_comms.into_boxed_slice(),
            out_comms.into_boxed_slice(),
        )
    };

    (
        TrustedSetupProverOutputs {
            left_fixed_randomizer,
            right_fixed_randomizer,
            output_fixed_randomizer,
            left_commitments,
            right_commitments,
            out_commitments,
            quotient_commitments,
        },
        VerificationKey {
            left_fixed_randomizer,
            right_fixed_randomizer: right_fixed_randomizer.1,
            output_fixed_randomizer: output_fixed_randomizer.1,
            public_input_randomizer,
            public_input_commitments,
        },
    )
}
