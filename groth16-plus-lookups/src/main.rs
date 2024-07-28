use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
use groth16_plus_lookups::{
    prover::prove,
    proving_key::{trusted_setup, CircuitLayout},
    verifier::verify,
};

type BN254 = ark_ec::bn::Bn<ark_bn254::Parameters>;

pub fn main() {
    let size = 1 << 5;
    let domain = D::new(size).unwrap();
    let domain_d2 = D::new(size << 1).unwrap();
    let public_input_size = 1;
    let witness = vec![Fr::from(1u64), Fr::from(4u64), Fr::from(16u64)];
    let layout = CircuitLayout {
        public_input_size,
        a_contributions: vec![
            vec![(1, Fr::from(1u64))].into_boxed_slice(),
            vec![(2, Fr::from(1u64))].into_boxed_slice(),
            vec![].into_boxed_slice(),
        ]
        .into_boxed_slice(),
        a_delayed_contributions: vec![
            vec![(1, Fr::from(1u64))].into_boxed_slice(),
            vec![].into_boxed_slice(),
            vec![].into_boxed_slice(),
        ]
        .into_boxed_slice(),
        b_contributions: vec![
            vec![(1, Fr::from(2u64))].into_boxed_slice(),
            vec![(2, Fr::from(1u64))].into_boxed_slice(),
            vec![].into_boxed_slice(),
        ]
        .into_boxed_slice(),
        c_contributions: vec![
            vec![].into_boxed_slice(),
            vec![(1, Fr::from(1u64))].into_boxed_slice(),
            vec![(2, Fr::from(1u64))].into_boxed_slice(),
        ]
        .into_boxed_slice(),
        c_delayed_equality_contributions: vec![
            vec![(1, Fr::from(1u64))].into_boxed_slice(),
            vec![].into_boxed_slice(),
            vec![].into_boxed_slice(),
        ]
        .into_boxed_slice(),
        domain,
        domain_d2,
    };

    let (prover_setup, vk) = trusted_setup::<_, _, BN254>(&layout, &mut rand::rngs::OsRng);

    let proof = prove::<_, _, BN254>(
        witness.as_slice(),
        &prover_setup,
        &layout,
        &mut rand::rngs::OsRng,
    );

    let verifies = verify::<BN254>(vec![Fr::from(1u64).into_repr()].as_slice(), &proof, &vk);

    println!("verifies? {}", verifies);
}
