use crate::{
    circuits::{
        gate::{CircuitGate, GateType},
        polynomials::endosclmul,
        wires::*,
    },
    tests::framework::TestFramework,
};
use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup};
use ark_ff::{BigInteger, BitIteratorLE, One, PrimeField, UniformRand, Zero};
use core::{array, ops::Mul};
use mina_curves::pasta::{Fp as F, Pallas as Other, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    pasta::FULL_ROUNDS,
    sponge::{DefaultFqSponge, DefaultFrSponge, ScalarChallenge},
};
use poly_commitment::ipa::endos;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams, FULL_ROUNDS>;
type ScalarSponge = DefaultFrSponge<F, SpongeParams, FULL_ROUNDS>;

#[test]
fn endomul_test() {
    let bits_per_chunk = 4;
    let num_bits = 128;
    let chunks = num_bits / bits_per_chunk;

    let num_scalars = 100;

    assert_eq!(num_bits % bits_per_chunk, 0);

    let mut gates = vec![];

    let rows_per_scalar = 1 + chunks;

    for s in 0..num_scalars {
        for i in 0..chunks {
            let row = rows_per_scalar * s + i;
            gates.push(CircuitGate::new(
                GateType::EndoMul,
                Wire::for_row(row),
                vec![],
            ));
        }

        let row = rows_per_scalar * s + chunks;
        gates.push(CircuitGate::new(GateType::Zero, Wire::for_row(row), vec![]));
    }

    let (endo_q, endo_r) = endos::<Other>();

    let mut witness: [Vec<F>; COLUMNS] =
        array::from_fn(|_| vec![F::zero(); rows_per_scalar * num_scalars]);

    let rng = &mut o1_utils::tests::make_test_rng(None);

    // let start = Instant::now();
    for i in 0..num_scalars {
        let bits_lsb: Vec<_> = BitIteratorLE::new(F::rand(rng).into_bigint())
            .take(num_bits)
            .collect();
        let x = <Other as AffineRepr>::ScalarField::from_bigint(
            <F as PrimeField>::BigInt::from_bits_le(&bits_lsb[..]),
        )
        .unwrap();

        let x_scalar = ScalarChallenge::new(x).to_field(&endo_r);

        let base = Other::generator();
        // let g = Other::generator().into_group();
        let acc0 = {
            let t = Other::new_unchecked(endo_q * base.x, base.y);
            // Ensuring we use affine coordinates
            let p = t + base;
            let acc: Other = (p + p).into();
            (acc.x, acc.y)
        };

        let bits_msb: Vec<_> = bits_lsb.iter().take(num_bits).copied().rev().collect();

        let res = endosclmul::gen_witness(
            &mut witness,
            i * rows_per_scalar,
            endo_q,
            (base.x, base.y),
            &bits_msb,
            acc0,
        );

        let expected = {
            let t = Other::generator();
            let mut acc = Other::new_unchecked(acc0.0, acc0.1).into_group();
            for i in (0..(num_bits / 2)).rev() {
                let b2i = F::from(bits_lsb[2 * i] as u64);
                let b2i1 = F::from(bits_lsb[2 * i + 1] as u64);
                let xq = (F::one() + ((endo_q - F::one()) * b2i1)) * t.x;
                let yq = (b2i.double() - F::one()) * t.y;
                acc = acc + (acc + Other::new_unchecked(xq, yq));
            }
            acc.into_affine()
        };
        assert_eq!(
            expected,
            Other::generator().into_group().mul(x_scalar).into_affine()
        );

        assert_eq!((expected.x, expected.y), res.acc);
        assert_eq!(x.into_bigint(), res.n.into_bigint());
    }

    TestFramework::<FULL_ROUNDS, Vesta>::default()
        .gates(gates)
        .witness(witness)
        .setup()
        .prove_and_verify::<BaseSponge, ScalarSponge>()
        .unwrap();
}

/// Regression test for EndoMul gate with fixed scalar values.
/// This test uses hardcoded expected outputs to detect any changes in the
/// gate's behavior.
#[test]
fn test_endomul_regression() {
    use std::str::FromStr;

    let num_bits = 16; // Small scalar for readable test
    let chunks = num_bits / 4;

    let (endo_q, _) = endos::<Other>();
    let base = Other::generator();

    // Initial accumulator: acc0 = 2 * (base + phi(base))
    let acc0 = {
        let phi_base = Other::new_unchecked(endo_q * base.x, base.y);
        let p = phi_base + base;
        let acc: Other = (p + p).into();
        (acc.x, acc.y)
    };

    // Fixed 16-bit scalar in MSB-first order: 0b1010_0011_1100_0101 = 41925
    let bits_msb: Vec<bool> = vec![
        true, false, true, false, // 0xA
        false, false, true, true, // 0x3
        true, true, false, false, // 0xC
        false, true, false, true, // 0x5
    ];

    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); chunks + 1]);

    let res = endosclmul::gen_witness(&mut witness, 0, endo_q, (base.x, base.y), &bits_msb, acc0);

    // Expected values (computed once and hardcoded for regression testing)
    let expected_acc_x = F::from_str(
        "13451015727828487409105090745067382573284440950068981965830848908350988424768",
    )
    .unwrap();
    let expected_acc_y =
        F::from_str("9969116504129436059100105870338261105816321160161624462757629802673790029360")
            .unwrap();
    let expected_n = F::from(41925u64);

    assert_eq!(
        res.acc.0, expected_acc_x,
        "Accumulated x-coordinate mismatch"
    );
    assert_eq!(
        res.acc.1, expected_acc_y,
        "Accumulated y-coordinate mismatch"
    );
    assert_eq!(res.n, expected_n, "Accumulated scalar mismatch");

    // Also verify intermediate witness values for first row
    // Row 0: processes bits [1,0,1,0] -> b1=1, b2=0, b3=1, b4=0
    assert_eq!(witness[11][0], F::one(), "b1 should be 1");
    assert_eq!(witness[12][0], F::zero(), "b2 should be 0");
    assert_eq!(witness[13][0], F::one(), "b3 should be 1");
    assert_eq!(witness[14][0], F::zero(), "b4 should be 0");

    // Verify scalar accumulation: after row 0, n = 8*1 + 4*0 + 2*1 + 0 = 10
    assert_eq!(witness[6][1], F::from(10u64), "n after row 0 should be 10");
}
