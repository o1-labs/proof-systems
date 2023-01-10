use std::array;

use ark_ec::AffineCurve;
use ark_ff::{One, PrimeField, Zero};
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use num_bigint::{BigUint, RandBigInt};
use o1_utils::BigUintFieldHelpers;
use rand::{rngs::StdRng, SeedableRng};

use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, GateType},
        polynomial::COLUMNS,
        polynomials::boolean_op,
        wires::Wire,
    },
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
};

type BaseSponge = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
type ScalarSponge = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;
type ScalarField = <Vesta as AffineCurve>::ScalarField;

use super::framework::TestFramework;

const RNG_SEED: [u8; 32] = [2; 32];

fn run_test<G: KimchiCurve, EFqSponge, EFrSponge>(
    full: bool,
    left_inputs: &[G::ScalarField; 2],
    right_inputs: &[G::ScalarField; 2],
    coeffs: &[G::ScalarField; 4],
    invalidations: Vec<((usize, usize), G::ScalarField)>,
) -> (Result<(), String>, [Vec<G::ScalarField>; COLUMNS])
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    let (next_row, mut gates) = CircuitGate::<G::ScalarField>::create_boolean_op(0, coeffs);
    let mut witness = boolean_op::create(
        &left_inputs[0],
        &right_inputs[0],
        &left_inputs[1],
        &right_inputs[1],
        coeffs,
    );

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

fn and_op(left_input: ScalarField, right_input: ScalarField) -> ScalarField {
    if left_input.is_one() && right_input.is_one() {
        ScalarField::one()
    } else {
        ScalarField::zero()
    }
}

fn or_op(left_input: ScalarField, right_input: ScalarField) -> ScalarField {
    if left_input.is_one() || right_input.is_one() {
        ScalarField::one()
    } else {
        ScalarField::zero()
    }
}

fn xor_op(left_input: ScalarField, right_input: ScalarField) -> ScalarField {
    if (left_input.is_one() || right_input.is_one())
        && !(left_input.is_one() && right_input.is_one())
    {
        ScalarField::one()
    } else {
        ScalarField::zero()
    }
}

fn not_op(value: ScalarField) -> ScalarField {
    if value.is_one() {
        ScalarField::zero()
    } else {
        ScalarField::one()
    }
}

#[test]
fn test_boolean_op() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    for _ in 0..4 {
        // Deterministically generate some random inputs
        let left_inputs: [ScalarField; 2] = array::from_fn(|_| {
            rng.gen_biguint_below(&BigUint::from(2u64))
                .to_field()
                .expect("failed to convert to field")
        });
        let right_inputs: [ScalarField; 2] = array::from_fn(|_| {
            rng.gen_biguint_below(&BigUint::from(2u64))
                .to_field()
                .expect("failed to convert to field")
        });

        // Positive test case 1 (a pair of AND operations)
        let coeffs = [
            ScalarField::one(),
            ScalarField::zero(),
            ScalarField::one(),
            ScalarField::zero(),
        ];
        let (result, witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(
            true,
            &left_inputs,
            &right_inputs,
            &coeffs,
            vec![],
        );
        assert_eq!(witness[2][0], and_op(witness[0][0], witness[1][0]));
        assert_eq!(witness[5][0], and_op(witness[3][0], witness[4][0]));
        assert_eq!(result, Ok(()));

        // Positive test case 2 (a pair of OR operations)
        let coeffs = [
            -ScalarField::one(),
            ScalarField::one(),
            -ScalarField::one(),
            ScalarField::one(),
        ];
        let (result, witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(
            true,
            &left_inputs,
            &right_inputs,
            &coeffs,
            vec![],
        );
        assert_eq!(witness[2][0], or_op(witness[0][0], witness[1][0]));
        assert_eq!(witness[5][0], or_op(witness[3][0], witness[4][0]));
        assert_eq!(result, Ok(()));

        // Positive test case 3 (an AND and an OR operation)
        let coeffs = [
            ScalarField::one(),
            ScalarField::zero(),
            -ScalarField::one(),
            ScalarField::one(),
        ];
        let (result, witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(
            true,
            &left_inputs,
            &right_inputs,
            &coeffs,
            vec![],
        );
        assert_eq!(witness[2][0], and_op(witness[0][0], witness[1][0]));
        assert_eq!(witness[5][0], or_op(witness[3][0], witness[4][0]));
        assert_eq!(result, Ok(()));

        // Positive test case 4 (an OR and an AND operation)
        let coeffs = [
            -ScalarField::one(),
            ScalarField::one(),
            ScalarField::one(),
            ScalarField::zero(),
        ];
        let (result, witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(
            true,
            &left_inputs,
            &right_inputs,
            &coeffs,
            vec![],
        );
        assert_eq!(witness[2][0], or_op(witness[0][0], witness[1][0]));
        assert_eq!(witness[5][0], and_op(witness[3][0], witness[4][0]));
        assert_eq!(result, Ok(()));

        // Positive test case 5 (a pair of XORs)
        let coeffs = [
            -ScalarField::from(2u64),
            ScalarField::one(),
            -ScalarField::from(2u64),
            ScalarField::one(),
        ];
        let (result, witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(
            true,
            &left_inputs,
            &right_inputs,
            &coeffs,
            vec![],
        );
        assert_eq!(witness[2][0], xor_op(witness[0][0], witness[1][0]));
        assert_eq!(witness[5][0], xor_op(witness[3][0], witness[4][0]));
        assert_eq!(result, Ok(()));

        // Negative test case 1
        let coeffs = [
            ScalarField::one(), // AND
            ScalarField::zero(),
            -ScalarField::one(), // OR
            ScalarField::one(),
        ];
        let (result, _) = run_test::<Vesta, BaseSponge, ScalarSponge>(
            true,
            &left_inputs,
            &right_inputs,
            &coeffs,
            vec![((0, 0), ScalarField::from(3u64))], // Invalidate left_input0
        );
        assert_eq!(
            result,
            Err(String::from(
                "Custom { row: 0, err: \"Invalid BooleanOp constraint: 1\" }"
            ))
        );

        // Negative test case 2
        let coeffs = [
            ScalarField::one(), // AND
            ScalarField::zero(),
            -ScalarField::one(), // OR
            ScalarField::one(),
        ];
        let (result, _) = run_test::<Vesta, BaseSponge, ScalarSponge>(
            true,
            &left_inputs,
            &right_inputs,
            &coeffs,
            vec![((0, 3), ScalarField::from(3u64))], // Invalidate left_input1
        );
        assert_eq!(
            result,
            Err(String::from(
                "Custom { row: 0, err: \"Invalid BooleanOp constraint: 2\" }"
            ))
        );

        // Negative test case 3
        let coeffs = [
            ScalarField::one(), // AND
            ScalarField::zero(),
            -ScalarField::one(), // OR
            ScalarField::one(),
        ];
        let (result, _) = run_test::<Vesta, BaseSponge, ScalarSponge>(
            true,
            &left_inputs,
            &right_inputs,
            &coeffs,
            vec![((0, 1), ScalarField::from(3u64))], // Invalidate right_input0
        );
        assert_eq!(
            result,
            Err(String::from(
                "Custom { row: 0, err: \"Invalid BooleanOp constraint: 3\" }"
            ))
        );

        // Negative test case 4
        let coeffs = [
            ScalarField::one(), // AND
            ScalarField::zero(),
            -ScalarField::one(), // OR
            ScalarField::one(),
        ];
        let (result, _) = run_test::<Vesta, BaseSponge, ScalarSponge>(
            true,
            &left_inputs,
            &right_inputs,
            &coeffs,
            vec![((0, 4), ScalarField::from(3u64))], // Invalidate right_input1
        );
        assert_eq!(
            result,
            Err(String::from(
                "Custom { row: 0, err: \"Invalid BooleanOp constraint: 4\" }"
            ))
        );

        // Negative test case 5
        let coeffs = [
            ScalarField::one(), // AND
            ScalarField::zero(),
            -ScalarField::one(), // OR
            ScalarField::one(),
        ];
        let (result, _) = run_test::<Vesta, BaseSponge, ScalarSponge>(
            true,
            &left_inputs,
            &right_inputs,
            &coeffs,
            vec![((0, 2), ScalarField::from(3u64))], // Invalidate output0
        );
        assert_eq!(
            result,
            Err(String::from(
                "Custom { row: 0, err: \"Invalid BooleanOp constraint: 5\" }"
            ))
        );

        // Negative test case 6
        let coeffs = [
            ScalarField::one(), // AND
            ScalarField::zero(),
            -ScalarField::one(), // OR
            ScalarField::one(),
        ];
        let (result, _) = run_test::<Vesta, BaseSponge, ScalarSponge>(
            true,
            &left_inputs,
            &right_inputs,
            &coeffs,
            vec![((0, 5), ScalarField::from(3u64))], // Invalidate output1
        );
        assert_eq!(
            result,
            Err(String::from(
                "Custom { row: 0, err: \"Invalid BooleanOp constraint: 6\" }"
            ))
        );

        // Negative test case 7
        let coeffs = [
            ScalarField::one(), // AND
            ScalarField::zero(),
            -ScalarField::one(), // OR
            ScalarField::one(),
        ];
        let (result, _) = run_test::<Vesta, BaseSponge, ScalarSponge>(
            true,
            &left_inputs,
            &right_inputs,
            &coeffs,
            vec![((0, 2), not_op(and_op(left_inputs[0], right_inputs[0])))], // Negate output0
        );
        assert_eq!(
            result,
            Err(String::from(
                "Custom { row: 0, err: \"Invalid BooleanOp constraint: 5\" }"
            ))
        );

        // Negative test case 8
        let coeffs = [
            ScalarField::one(), // AND
            ScalarField::zero(),
            -ScalarField::one(), // OR
            ScalarField::one(),
        ];
        let (result, _) = run_test::<Vesta, BaseSponge, ScalarSponge>(
            true,
            &left_inputs,
            &right_inputs,
            &coeffs,
            vec![((0, 5), not_op(and_op(left_inputs[1], right_inputs[1])))], // Negate output1
        );
        assert_eq!(
            result,
            Err(String::from(
                "Custom { row: 0, err: \"Invalid BooleanOp constraint: 6\" }"
            ))
        );
    }
}

#[test]
fn test_boolean_op_and() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    // Deterministically generate some random inputs
    let left_inputs: [ScalarField; 2] = array::from_fn(|_| {
        rng.gen_biguint_below(&BigUint::from(2u64))
            .to_field()
            .expect("failed to convert to field")
    });
    let right_inputs: [ScalarField; 2] = array::from_fn(|_| {
        rng.gen_biguint_below(&BigUint::from(2u64))
            .to_field()
            .expect("failed to convert to field")
    });

    let (next_row, mut gates) = CircuitGate::<ScalarField>::create_boolean_and(0);
    let mut witness = boolean_op::create_and(
        &left_inputs[0],
        &right_inputs[0],
        &left_inputs[1],
        &right_inputs[1],
    );

    assert_eq!(witness[2][0], and_op(witness[0][0], witness[1][0]));
    assert_eq!(witness[5][0], and_op(witness[3][0], witness[4][0]));

    // Pad with a zero gate (kimchi requires at least two)
    gates.push(CircuitGate {
        typ: GateType::Zero,
        wires: Wire::for_row(next_row),
        coeffs: vec![],
    });
    for col in &mut witness {
        col.push(ScalarField::zero())
    }

    let cs = ConstraintSystem::<Fp>::create(gates.clone())
        .build()
        .unwrap();

    // Perform witness verification
    for (row, gate) in gates.iter().enumerate().take(witness[0].len()) {
        assert_eq!(
            gate.verify_witness::<Vesta>(row, &witness, &cs, &witness[0][0..cs.public]),
            Ok(())
        );
    }
}

#[test]
fn test_boolean_op_or() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    // Deterministically generate some random inputs
    let left_inputs: [ScalarField; 2] = array::from_fn(|_| {
        rng.gen_biguint_below(&BigUint::from(2u64))
            .to_field()
            .expect("failed to convert to field")
    });
    let right_inputs: [ScalarField; 2] = array::from_fn(|_| {
        rng.gen_biguint_below(&BigUint::from(2u64))
            .to_field()
            .expect("failed to convert to field")
    });

    let (next_row, mut gates) = CircuitGate::<ScalarField>::create_boolean_or(0);
    let mut witness = boolean_op::create_or(
        &left_inputs[0],
        &right_inputs[0],
        &left_inputs[1],
        &right_inputs[1],
    );

    assert_eq!(witness[2][0], or_op(witness[0][0], witness[1][0]));
    assert_eq!(witness[5][0], or_op(witness[3][0], witness[4][0]));

    // Pad with a zero gate (kimchi requires at least two)
    gates.push(CircuitGate {
        typ: GateType::Zero,
        wires: Wire::for_row(next_row),
        coeffs: vec![],
    });
    for col in &mut witness {
        col.push(ScalarField::zero())
    }

    let cs = ConstraintSystem::<Fp>::create(gates.clone())
        .build()
        .unwrap();

    // Perform witness verification
    for (row, gate) in gates.iter().enumerate().take(witness[0].len()) {
        assert_eq!(
            gate.verify_witness::<Vesta>(row, &witness, &cs, &witness[0][0..cs.public]),
            Ok(())
        );
    }
}

#[test]
fn test_boolean_op_xor() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    // Deterministically generate some random inputs
    let left_inputs: [ScalarField; 2] = array::from_fn(|_| {
        rng.gen_biguint_below(&BigUint::from(2u64))
            .to_field()
            .expect("failed to convert to field")
    });
    let right_inputs: [ScalarField; 2] = array::from_fn(|_| {
        rng.gen_biguint_below(&BigUint::from(2u64))
            .to_field()
            .expect("failed to convert to field")
    });

    let (next_row, mut gates) = CircuitGate::<ScalarField>::create_boolean_xor(0);
    let mut witness = boolean_op::create_xor(
        &left_inputs[0],
        &right_inputs[0],
        &left_inputs[1],
        &right_inputs[1],
    );

    assert_eq!(witness[2][0], xor_op(witness[0][0], witness[1][0]));
    assert_eq!(witness[5][0], xor_op(witness[3][0], witness[4][0]));

    // Pad with a zero gate (kimchi requires at least two)
    gates.push(CircuitGate {
        typ: GateType::Zero,
        wires: Wire::for_row(next_row),
        coeffs: vec![],
    });
    for col in &mut witness {
        col.push(ScalarField::zero())
    }

    let cs = ConstraintSystem::<Fp>::create(gates.clone())
        .build()
        .unwrap();

    // Perform witness verification
    for (row, gate) in gates.iter().enumerate().take(witness[0].len()) {
        assert_eq!(
            gate.verify_witness::<Vesta>(row, &witness, &cs, &witness[0][0..cs.public]),
            Ok(())
        );
    }
}
