use crate::{
    circuits::{
        gate::{CircuitGate, GateType},
        polynomials::endomul_scalar,
        wires::*,
    },
    tests::framework::TestFramework,
};
use ark_ff::{BigInteger, BitIteratorLE, PrimeField, UniformRand};
use core::array;
use mina_curves::pasta::{Fp as F, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge, ScalarChallenge},
};
use poly_commitment::ipa::endos;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams, 55>;
type ScalarSponge = DefaultFrSponge<F, SpongeParams, 55>;

#[test]
fn endomul_scalar_test() {
    let bits_per_row = 2 * 8;
    let num_bits = 128;
    let rows_per_scalar = num_bits / bits_per_row;

    let num_scalars = 100;

    assert_eq!(num_bits % bits_per_row, 0);

    let mut gates = vec![];

    for s in 0..num_scalars {
        for i in 0..rows_per_scalar {
            let row = rows_per_scalar * s + i;
            gates.push(CircuitGate::new(
                GateType::EndoMulScalar,
                Wire::for_row(row),
                vec![],
            ));
        }
    }

    let (_, endo_scalar_coeff) = endos::<Vesta>();

    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![]);

    let rng = &mut o1_utils::tests::make_test_rng(None);

    //let start = Instant::now();
    for _ in 0..num_scalars {
        let x = {
            let bits_lsb: Vec<_> = BitIteratorLE::new(F::rand(rng).into_bigint())
                .take(num_bits)
                .collect();
            F::from_bigint(<F as PrimeField>::BigInt::from_bits_le(&bits_lsb[..])).unwrap()
        };

        assert_eq!(
            ScalarChallenge(x).to_field(&endo_scalar_coeff),
            endomul_scalar::gen_witness(&mut witness, x, endo_scalar_coeff, num_bits)
        );
    }

    TestFramework::<55, Vesta>::default()
        .gates(gates)
        .witness(witness)
        .setup()
        .prove_and_verify::<BaseSponge, ScalarSponge>()
        .unwrap();
}
