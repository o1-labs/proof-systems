use crate::circuits::{
    gate::{CircuitGate, GateType},
    polynomials::endosclmul,
    wires::*,
};
use crate::tests::framework::TestFramework;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{BigInteger, BitIteratorLE, Field, One, PrimeField, UniformRand, Zero};
use array_init::array_init;
use commitment_dlog::srs::endos;
use mina_curves::pasta::{fp::Fp as F, pallas::Affine as Other};
use oracle::sponge::ScalarChallenge;
use rand::{rngs::StdRng, SeedableRng};

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
            gates.push(CircuitGate {
                typ: GateType::EndoMul,
                wires: Wire::new(row),
                coeffs: vec![],
            });
        }

        let row = rows_per_scalar * s + chunks;
        gates.push(CircuitGate {
            typ: GateType::Zero,
            wires: Wire::new(row),
            coeffs: vec![],
        });
    }

    let (endo_q, endo_r) = endos::<Other>();

    let mut witness: [Vec<F>; COLUMNS] =
        array_init(|_| vec![F::zero(); rows_per_scalar * num_scalars]);

    let rng = &mut StdRng::from_seed([0; 32]);

    // let start = Instant::now();
    for i in 0..num_scalars {
        let bits_lsb: Vec<_> = BitIteratorLE::new(F::rand(rng).into_repr())
            .take(num_bits)
            .collect();
        let x = <Other as AffineCurve>::ScalarField::from_repr(
            <F as PrimeField>::BigInt::from_bits_le(&bits_lsb[..]),
        )
        .unwrap();

        let x_scalar = ScalarChallenge(x).to_field(&endo_r);

        let base = Other::prime_subgroup_generator();
        // let g = Other::prime_subgroup_generator().into_projective();
        let acc0 = {
            let t = Other::new(endo_q * base.x, base.y, false);
            let p = t + base;
            let acc = p + p;
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
            let t = Other::prime_subgroup_generator();
            let mut acc = Other::new(acc0.0, acc0.1, false);
            for i in (0..(num_bits / 2)).rev() {
                let b2i = F::from(bits_lsb[2 * i] as u64);
                let b2i1 = F::from(bits_lsb[2 * i + 1] as u64);
                let xq = (F::one() + ((endo_q - F::one()) * b2i1)) * t.x;
                let yq = (b2i.double() - F::one()) * t.y;
                acc = acc + (acc + Other::new(xq, yq, false));
            }
            acc
        };
        assert_eq!(
            expected,
            Other::prime_subgroup_generator()
                .into_projective()
                .mul(x_scalar.into_repr())
                .into_affine()
        );

        assert_eq!((expected.x, expected.y), res.acc);
        assert_eq!(x.into_repr(), res.n.into_repr());
    }

    TestFramework::default()
        .gates(gates)
        .witness(witness)
        .setup()
        .prove_and_verify();
}
