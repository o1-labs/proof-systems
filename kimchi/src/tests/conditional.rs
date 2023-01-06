use std::array;

use ark_ec::AffineCurve;
use ark_ff::{PrimeField, Zero};
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use num_bigint::RandBigInt;
use o1_utils::{BigUintFieldHelpers, FieldHelpers};
use rand::{rngs::StdRng, SeedableRng};

use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, GateType},
        polynomial::COLUMNS,
        polynomials::conditional,
        wires::Wire,
    },
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
};

type BaseSponge = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
type ScalarSponge = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;
type ScalarField = <Vesta as AffineCurve>::ScalarField;

use super::framework::TestFramework;

const RNG_SEED: [u8; 32] = [1; 32];

fn run_test<G: KimchiCurve, EFqSponge, EFrSponge>(
    full: bool,
    x: &[G::ScalarField; 2],
    y: &[G::ScalarField; 2],
    b: &[bool; 2],
    invalidations: Vec<((usize, usize), G::ScalarField)>,
) -> (Result<(), String>, [Vec<G::ScalarField>; COLUMNS])
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    let (next_row, mut gates) = CircuitGate::<G::ScalarField>::create_conditional(0);
    let mut witness = conditional::create(x, y, b);

    // Pad with a zero gate (kimchi requires at least two)
    gates.push(CircuitGate {
        typ: GateType::Zero,
        wires: Wire::for_row(next_row),
        coeffs: vec![],
    });
    for col in &mut witness {
        col.push(G::ScalarField::zero())
    }

    let runner = if full {
        // Create prover index with test framework
        Some(
            TestFramework::<G>::default()
                .gates(gates.clone())
                .witness(witness.clone())
                .setup(),
        )
    } else {
        None
    };

    let cs = if let Some(runner) = runner.as_ref() {
        runner.prover_index().cs.clone()
    } else {
        // If not full mode, just create constraint system (this is much faster)
        ConstraintSystem::create(gates.clone()).build().unwrap()
    };

    // Perform witness verification that everything is ok before invalidation (quick checks)
    for (row, gate) in gates.iter().enumerate().take(witness[0].len()) {
        let result = gate.verify_witness::<G>(row, &witness, &cs, &witness[0][0..cs.public]);
        if result.is_err() {
            return (result.map_err(|e| e.to_string()), witness);
        }
    }

    if let Some(runner) = runner {
        // Perform full test that everything is ok before invalidation
        assert_eq!(runner.prove_and_verify::<EFqSponge, EFrSponge>(), Ok(()));
    }

    if !invalidations.is_empty() {
        for ((row, col), value) in invalidations {
            // Invalidate witness
            assert_ne!(witness[col][row], value);
            witness[col][row] = value;
        }

        if full {
            return (
                TestFramework::<G>::default()
                    .gates(gates.clone())
                    .witness(witness.clone())
                    .setup()
                    .prove_and_verify::<EFqSponge, EFrSponge>(),
                witness,
            );
        }
    }

    (Ok(()), witness)
}

#[test]
fn test_conditional() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    let x: [ScalarField; 2] = array::from_fn(|_| {
        rng.gen_biguint_below(&ScalarField::modulus_biguint())
            .to_field()
            .expect("failed to convert to field")
    });
    let y: [ScalarField; 2] = array::from_fn(|_| {
        rng.gen_biguint_below(&ScalarField::modulus_biguint())
            .to_field()
            .expect("failed to convert to field")
    });

    // Assert all test values are unique
    assert_ne!(x[0], x[1]);
    assert_ne!(y[0], y[1]);
    for x_val in x {
        for y_val in y {
            assert_ne!(x_val, y_val);
        }
    }

    // Positive test case 1
    let (result, witness) =
        run_test::<Vesta, BaseSponge, ScalarSponge>(true, &x, &y, &[true, false], vec![]);
    assert_eq!(witness[0][0], witness[1][0]);
    assert_eq!(witness[3][0], witness[5][0]);
    assert_eq!(result, Ok(()));

    // Positive test case 2
    let (result, witness) =
        run_test::<Vesta, BaseSponge, ScalarSponge>(true, &x, &y, &[false, true], vec![]);
    assert_eq!(witness[0][0], witness[2][0]);
    assert_eq!(witness[3][0], witness[4][0]);
    assert_eq!(result, Ok(()));

    // Positive test case 3
    let (result, witness) =
        run_test::<Vesta, BaseSponge, ScalarSponge>(true, &x, &y, &[true, true], vec![]);
    assert_eq!(witness[0][0], witness[1][0]);
    assert_eq!(witness[3][0], witness[4][0]);
    assert_eq!(result, Ok(()));

    // Positive test case 4
    let (result, witness) =
        run_test::<Vesta, BaseSponge, ScalarSponge>(true, &x, &y, &[false, false], vec![]);
    assert_eq!(witness[0][0], witness[2][0]);
    assert_eq!(witness[3][0], witness[5][0]);
    assert_eq!(result, Ok(()));

    // Negative test case 1
    let (result, _) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        true,
        &x,
        &y,
        &[true, false],
        vec![((0, 6), ScalarField::from(4u64))], // Invalidate b
    );
    assert_eq!(
        result,
        Err(String::from(
            "Custom { row: 0, err: \"Invalid Conditional constraint: 1\" }"
        ))
    );

    // Negative test case 2 a
    let (result, _) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        true,
        &x,
        &y,
        &[true, false],
        vec![((0, 7), ScalarField::from(2u64))], // Invalidate b1
    );
    assert_eq!(
        result,
        Err(String::from(
            "Custom { row: 0, err: \"Invalid Conditional constraint: 2\" }"
        ))
    );

    // Negative test case 2 b
    let (result, _) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        true,
        &x,
        &y,
        &[true, false],
        vec![((0, 8), ScalarField::from(2u64))], // Invalidate b2
    );
    assert_eq!(
        result,
        Err(String::from(
            "Custom { row: 0, err: \"Invalid Conditional constraint: 2\" }"
        ))
    );

    // Negative test case 3
    let (result, witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        true,
        &x,
        &y,
        &[true, false],
        vec![((0, 0), y[0])], // Invalidate r1
    );
    assert_ne!(witness[0][0], witness[1][0]);
    assert_eq!(
        result,
        Err(String::from(
            "Custom { row: 0, err: \"Invalid Conditional constraint: 3\" }"
        ))
    );

    // Negative test case 4
    let (result, witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        true,
        &x,
        &y,
        &[true, false],
        vec![((0, 3), x[1])], // Invalidate r2
    );
    assert_ne!(witness[3][0], witness[5][0]);
    assert_eq!(
        result,
        Err(String::from(
            "Custom { row: 0, err: \"Invalid Conditional constraint: 4\" }"
        ))
    );
}
