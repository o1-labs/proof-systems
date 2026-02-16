use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, GateType},
        polynomials::endomul_scalar,
        wires::{Wire, COLUMNS},
    },
    tests::framework::TestFramework,
};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, BitIteratorLE, Field, One, PrimeField, UniformRand, Zero};
use core::array;
use mina_curves::pasta::{Fp as F, Fp, Pallas as Other, Vesta, VestaParameters};
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
            ScalarChallenge::new(x).to_field(&endo_scalar_coeff),
            endomul_scalar::gen_witness(&mut witness, x, endo_scalar_coeff, num_bits)
        );
    }

    TestFramework::<FULL_ROUNDS, Vesta>::default()
        .gates(gates)
        .witness(witness)
        .setup()
        .prove_and_verify::<BaseSponge, ScalarSponge>()
        .unwrap();
}

#[test]
fn test_degenerate_case() {
    let gate = CircuitGate::new(GateType::EndoMul, Wire::for_row(0), vec![]);
    let zero_gate = CircuitGate::new(GateType::Zero, Wire::for_row(1), vec![]);
    let gates = vec![gate.clone(), zero_gate];
    let cs = ConstraintSystem::<Fp>::create(gates).build().unwrap();

    let b1 = Fp::zero();
    let b2 = Fp::one();
    let b3 = Fp::one();
    let b4 = Fp::one();

    // this is Pallas base point
    let base = Other::generator();
    let (xt, yt) = (base.x, base.y);

    let (xp, yp) = (xt, yt);

    let xr = xp;
    let yr = -yp;
    let s1 = Fp::from(1337u64);

    let xs = xr;
    let ys = -yr;

    let endo = cs.endo;
    let xq2 = endo * xt;
    let yq2 = yt;

    let s3_denom = xq2 - xr;
    let s3 = (yq2 - yr) * s3_denom.inverse().unwrap();

    let n = Fp::zero();
    let n_next = Fp::from(7u64);

    let mut witness: [Vec<Fp>; COLUMNS] = core::array::from_fn(|_| vec![Fp::zero(); 2]);

    witness[0][0] = xt;
    witness[1][0] = yt;
    witness[4][0] = xp;
    witness[5][0] = yp;
    witness[6][0] = n;
    witness[7][0] = xr;
    witness[8][0] = yr;
    witness[9][0] = s1;
    witness[10][0] = s3;
    witness[11][0] = b1;
    witness[12][0] = b2;
    witness[13][0] = b3;
    witness[14][0] = b4;

    witness[4][1] = xs;
    witness[5][1] = ys;
    witness[6][1] = n_next;

    assert_eq!(xr, xp); // mid state change as expected
    assert_eq!(yr, -yp);
    assert_eq!(xs, xp); // end state change as expected
    assert_eq!(ys, yp);

    assert_eq!(witness[6][1], Fp::from(7u64)); // n consumed
                                               // so these asserts show it verifies P * 7 = P

    // Degenerate case P = -R should fail to verify
    let result = gate.verify_endomul::<FULL_ROUNDS, Vesta>(0, &witness, &cs);
    assert!(result.is_err());
}
