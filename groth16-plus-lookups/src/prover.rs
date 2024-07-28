use crate::proof::Proof;
use crate::proving_key::{CircuitLayout, TrustedSetupProverOutputs};
use ark_ec::{group::Group, msm::VariableBaseMSM, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{FftField, PrimeField, UniformRand, Zero};
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain as D};

fn compute_contributions<F: FftField>(
    domain: D<F>,
    witness: &[F],
    contributions: &[Box<[(usize, F)]>],
) -> Evaluations<F, D<F>> {
    let mut values = vec![F::zero(); domain.size()];
    for (witness_value, contributions) in witness.iter().zip(contributions.iter()) {
        for (idx, scalar) in contributions.iter() {
            values[*idx] += *witness_value * *scalar;
        }
    }
    Evaluations::<F, D<F>>::from_vec_and_domain(values, domain)
}

pub fn prove<F: PrimeField, Rng: rand::RngCore, Pair: PairingEngine<Fr = F>>(
    witness: &[<Pair::G1Projective as Group>::ScalarField],
    trusted_setup_outputs: &TrustedSetupProverOutputs<Pair::G1Affine, Pair::G2Affine>,
    circuit_layout: &CircuitLayout<<Pair::G1Projective as Group>::ScalarField>,
    rng: &mut Rng,
) -> Proof<Pair::G1Affine, Pair::G2Affine> {
    let r = <F as UniformRand>::rand(rng);
    let r_delayed = <F as UniformRand>::rand(rng);
    let r_sum = r + r_delayed;
    let s = <F as UniformRand>::rand(rng);

    let a_poly = compute_contributions(
        circuit_layout.domain,
        &witness,
        &circuit_layout.a_contributions,
    )
    .interpolate();
    let a = {
        let initial = trusted_setup_outputs
            .output_fixed_randomizer
            .0
            .mul(r)
            .into_affine()
            + trusted_setup_outputs.left_fixed_randomizer;
        let coefficients: Vec<_> = a_poly.iter().map(|x| x.into_repr()).collect();
        VariableBaseMSM::multi_scalar_mul(
            &trusted_setup_outputs.left_commitments,
            coefficients.as_slice(),
        )
        .into_affine()
            + initial
    };
    let neg_a = -a;

    let a_delayed_poly = compute_contributions(
        circuit_layout.domain,
        &witness,
        &circuit_layout.a_delayed_contributions,
    )
    .interpolate();
    let a_delayed = {
        let initial = trusted_setup_outputs
            .output_fixed_randomizer
            .0
            .mul(r_delayed)
            .into_affine();
        let coefficients: Vec<_> = a_delayed_poly.iter().map(|x| x.into_repr()).collect();
        VariableBaseMSM::multi_scalar_mul(
            &trusted_setup_outputs.left_commitments,
            coefficients.as_slice(),
        )
        .into_affine()
            + initial
    };
    let neg_a_delayed = -a_delayed;

    let b_poly = compute_contributions(
        circuit_layout.domain,
        &witness,
        &circuit_layout.b_contributions,
    )
    .interpolate();
    let b = {
        let initial = trusted_setup_outputs.right_fixed_randomizer.1
            + trusted_setup_outputs
                .output_fixed_randomizer
                .1
                .mul(s)
                .into_affine();
        let values_commitment = {
            let coefficients: Vec<_> = b_poly.iter().map(|x| x.into_repr()).collect();
            VariableBaseMSM::multi_scalar_mul(
                &trusted_setup_outputs.right_commitments,
                coefficients.as_slice(),
            )
            .into_affine()
        };
        initial + values_commitment
    };

    let c = {
        let witness_commitment = {
            let private_witness: Vec<_> = witness[circuit_layout.public_input_size..]
                .iter()
                .map(|x| x.into_repr())
                .collect();
            VariableBaseMSM::multi_scalar_mul(
                &trusted_setup_outputs.out_commitments,
                private_witness.as_slice(),
            )
            .into_affine()
        };
        let quotient_commitment = {
            let quotient_poly = {
                let mut a_values_d2 =
                    (a_poly + a_delayed_poly).evaluate_over_domain_by_ref(circuit_layout.domain_d2);
                let b_values_d2 = b_poly.evaluate_over_domain_by_ref(circuit_layout.domain_d2);
                // TODO: Wasteful
                let c_values_d2 = compute_contributions(
                    circuit_layout.domain,
                    &witness,
                    &circuit_layout.c_contributions,
                )
                .interpolate()
                .evaluate_over_domain_by_ref(circuit_layout.domain_d2);
                for (a, (b, c)) in a_values_d2.evals.iter_mut().zip(
                    b_values_d2
                        .evals
                        .into_iter()
                        .zip(c_values_d2.evals.into_iter()),
                ) {
                    *a *= b;
                    *a -= c;
                }
                let (quotient, res) = a_values_d2
                    .interpolate()
                    .divide_by_vanishing_poly(circuit_layout.domain)
                    .unwrap();
                if !res.is_zero() {
                    panic!("Division wasn't zero :'(");
                }
                quotient
            };

            let coefficients: Vec<_> = quotient_poly.iter().map(|x| x.into_repr()).collect();
            VariableBaseMSM::multi_scalar_mul(
                &trusted_setup_outputs.quotient_commitments,
                coefficients.as_slice(),
            )
            .into_affine()
        };
        let scaled_a_values_commitment = (a + a_delayed).mul(s).into_affine();
        let scaled_b_values_commitment = {
            let witness: Vec<_> = b_poly.iter().map(|x| (r_sum * *x).into_repr()).collect();
            VariableBaseMSM::multi_scalar_mul(
                &trusted_setup_outputs.left_commitments,
                witness.as_slice(),
            )
            .into_affine()
                + trusted_setup_outputs
                    .right_fixed_randomizer
                    .0
                    .mul(r_sum)
                    .into_affine()
        };
        let delayed_equality_correction_commitment = trusted_setup_outputs
            .output_delayed_fixed_randomizer
            .mul(r_delayed)
            .into_affine();
        witness_commitment
            + quotient_commitment
            + scaled_a_values_commitment
            + scaled_b_values_commitment
            + delayed_equality_correction_commitment
    };
    Proof {
        neg_a,
        neg_a_delayed,
        b,
        c,
    }
}
