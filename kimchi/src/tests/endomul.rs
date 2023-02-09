use crate::circuits::{
    gate::{CircuitGate, GateType},
    polynomials::endosclmul,
    wires::*,
};
use crate::tests::framework::TestFramework;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, BitIteratorLE, Field, One, PrimeField, UniformRand, Zero};
use mina_curves::pasta::{Fp as F, Pallas as Other, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge, ScalarChallenge},
};
use poly_commitment::srs::endos;
use rand::{rngs::StdRng, SeedableRng};
use std::array;
use std::ops::Mul;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<F, SpongeParams>;

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

    let rng = &mut StdRng::from_seed([0; 32]);

    // let start = Instant::now();
    for i in 0..num_scalars {
        let bits_lsb: Vec<_> = BitIteratorLE::new(F::rand(rng).into_bigint())
            .take(num_bits)
            .collect();
        let x = <Other as AffineRepr>::ScalarField::from_bigint(
            <F as PrimeField>::BigInt::from_bits_le(&bits_lsb[..]),
        )
        .unwrap();

        let x_scalar = ScalarChallenge(x).to_field(&endo_r);

        let base = Other::generator();
        // let g = Other::prime_subgroup_generator().into_projective();
        let acc0 = {
            let t = Other::new(endo_q * base.x, base.y);
            let p = t + base;
            let acc = (p + p).into_affine();
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
            let mut acc = Other::new(acc0.0, acc0.1);
            for i in (0..(num_bits / 2)).rev() {
                let b2i = F::from(bits_lsb[2 * i] as u64);
                let b2i1 = F::from(bits_lsb[2 * i + 1] as u64);
                let xq = (F::one() + ((endo_q - F::one()) * b2i1)) * t.x;
                let yq = (b2i.double() - F::one()) * t.y;
                acc = (acc + (acc + Other::new(xq, yq))).into();
            }
            acc
        };
        assert_eq!(
            expected,
            Other::generator().into_group().mul(x_scalar).into_affine()
        );

        assert_eq!((expected.x, expected.y), res.acc);
        assert_eq!(x.into_bigint(), res.n.into_bigint());
    }

    assert!(TestFramework::<Vesta>::default()
        .gates(gates)
        .witness(witness)
        .setup()
        .prove_and_verify::<BaseSponge, ScalarSponge>()
        .is_ok());
}
