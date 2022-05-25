use crate::circuits::{
    gate::{CircuitGate, GateType},
    polynomials::varbasemul,
    wires::*,
};
use crate::tests::framework::TestFramework;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{BigInteger, BitIteratorLE, Field, One, PrimeField, UniformRand, Zero};
use array_init::array_init;
use colored::Colorize;
use mina_curves::pasta::{fp::Fp as F, pallas::Affine as Other};
use rand::{rngs::StdRng, SeedableRng};
use std::time::Instant;

#[test]
fn varbase_mul_test() {
    let num_bits = F::size_in_bits();
    let chunks = num_bits / 5;

    let num_scalars = 10;
    let rows_per_scalar = 2 * (255 / 5);

    assert_eq!(num_bits % 5, 0);

    let mut gates = vec![];

    for i in 0..(chunks * num_scalars) {
        let row = 2 * i;
        gates.push(CircuitGate {
            typ: GateType::VarBaseMul,
            wires: Wire::new(row),
            coeffs: vec![],
        });
        gates.push(CircuitGate {
            typ: GateType::Zero,
            wires: Wire::new(row + 1),
            coeffs: vec![],
        });
    }

    let mut witness: [Vec<F>; COLUMNS] =
        array_init(|_| vec![F::zero(); rows_per_scalar * num_scalars]);

    let rng = &mut StdRng::from_seed([0; 32]);

    let start = Instant::now();
    for i in 0..num_scalars {
        let x = F::rand(rng);
        let bits_lsb: Vec<_> = BitIteratorLE::new(x.into_repr()).take(num_bits).collect();
        let x_ = <Other as AffineCurve>::ScalarField::from_repr(
            <F as PrimeField>::BigInt::from_bits_le(&bits_lsb[..]),
        )
        .unwrap();

        let base = Other::prime_subgroup_generator();
        let g = Other::prime_subgroup_generator().into_projective();
        let acc = (g + g).into_affine();
        let acc = (acc.x, acc.y);

        let bits_msb: Vec<_> = bits_lsb.iter().take(num_bits).copied().rev().collect();

        let res = varbasemul::witness(
            &mut witness,
            i * rows_per_scalar,
            (base.x, base.y),
            &bits_msb,
            acc,
        );

        let shift = <Other as AffineCurve>::ScalarField::from(2).pow(&[(bits_msb.len()) as u64]);
        let expected = g
            .mul((<Other as AffineCurve>::ScalarField::one() + shift + x_.double()).into_repr())
            .into_affine();

        assert_eq!(x_.into_repr(), res.n.into_repr());
        assert_eq!((expected.x, expected.y), res.acc);
    }
    println!(
        "{}{:?}",
        "Witness generation time: ".yellow(),
        start.elapsed()
    );

    TestFramework::default()
        .gates(gates)
        .witness(witness)
        .setup()
        .prove_and_verify();
}
