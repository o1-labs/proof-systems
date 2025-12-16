use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, CircuitGateError, CircuitGateResult, Connect, GateType},
        polynomial::COLUMNS,
        polynomials::{
            foreign_field_common::{
                BigUintArrayCompose, BigUintForeignFieldHelpers, FieldArrayCompose,
            },
            foreign_field_mul,
        },
    },
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
    tests::framework::TestFramework,
};
use ark_ec::AffineRepr;
use ark_ff::{Field, One, PrimeField, Zero};
use mina_curves::pasta::{Fp, Fq, Pallas, PallasParameters, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    poseidon::ArithmeticSpongeParams,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use num_bigint::{BigUint, RandBigInt};
use o1_utils::{FieldHelpers, Two};
use std::sync::Arc;

type PallasField = <Pallas as AffineRepr>::BaseField;
type VestaField = <Vesta as AffineRepr>::BaseField;

type SpongeParams = PlonkSpongeConstantsKimchi;
type VestaBaseSponge = DefaultFqSponge<VestaParameters, SpongeParams, 55>;
type VestaScalarSponge = DefaultFrSponge<Fp, SpongeParams, 55>;
type PallasBaseSponge = DefaultFqSponge<PallasParameters, SpongeParams, 55>;
type PallasScalarSponge = DefaultFrSponge<Fq, SpongeParams, 55>;

// The secp256k1 base field modulus
fn secp256k1_modulus() -> BigUint {
    BigUint::from_bytes_be(&secp256k1::constants::FIELD_SIZE)
}

// Maximum value in the secp256k1 base field
fn secp256k1_max() -> BigUint {
    secp256k1_modulus() - BigUint::from(1u32)
}

// Maximum value whose square fits in secp256k1 base field
fn secp256k1_sqrt() -> BigUint {
    secp256k1_max().sqrt()
}

// Maximum value in the pallas base field
fn pallas_max() -> BigUint {
    PallasField::modulus_biguint() - BigUint::from(1u32)
}

// Maximum value whose square fits in the pallas base field
fn pallas_sqrt() -> BigUint {
    pallas_max().sqrt()
}

// Boilerplate for tests
fn run_test<const FULL_ROUNDS: usize, G: KimchiCurve<FULL_ROUNDS>, EFqSponge, EFrSponge>(
    full: bool,
    external_gates: bool,
    disable_gates_checks: bool,
    left_input: &BigUint,
    right_input: &BigUint,
    foreign_field_modulus: &BigUint,
    invalidations: Vec<((usize, usize), G::ScalarField)>,
) -> (CircuitGateResult<()>, [Vec<G::ScalarField>; COLUMNS])
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField, FULL_ROUNDS>,
    EFrSponge: FrSponge<G::ScalarField>,
    EFrSponge: From<&'static ArithmeticSpongeParams<G::ScalarField, FULL_ROUNDS>>,
{
    // Create foreign field multiplication gates
    let (mut next_row, mut gates) =
        CircuitGate::<G::ScalarField>::create_foreign_field_mul(0, foreign_field_modulus);

    // Compute multiplication witness
    let (mut witness, mut external_checks) =
        foreign_field_mul::witness::create(left_input, right_input, foreign_field_modulus);

    // Optionally also add external gate checks to circuit
    if external_gates {
        // Layout for this test (just an example, circuit designer has complete flexibility where to put the checks)
        //    BASIC:
        //      0-1  ForeignFieldMul | Zero
        // EXTERNAL:
        //      2-5  compact-multi-range-check (result range check)
        //        6  "single" Generic (result bound)
        //      7-10 multi-range-check (quotient range check)
        //     11-14 multi-range-check (quotient_bound, product1_lo, product1_hi_0)
        //     later limb-check result bound
        // DESIGNER:
        //        15 Generic (left and right bounds)
        //     16-19 multi-range-check (left multiplicand)
        //     20-23 multi-range-check (right multiplicand)
        //     24-27 multi-range-check (result bound, left bound, right bound)

        // Result compact-multi-range-check
        CircuitGate::extend_compact_multi_range_check(&mut gates, &mut next_row);
        gates.connect_cell_pair((1, 0), (4, 1)); // remainder01
        gates.connect_cell_pair((1, 1), (2, 0)); // remainder2
        external_checks.extend_witness_compact_multi_range_checks(&mut witness);
        // These are the coordinates (row, col) of the remainder limbs in the witness
        // remainder0 -> (3, 0), remainder1 -> (4, 0), remainder2 -> (2,0)

        // Constant single Generic gate for result bound
        CircuitGate::extend_high_bounds(&mut gates, &mut next_row, foreign_field_modulus);
        gates.connect_cell_pair((6, 0), (1, 1)); // remainder2
        external_checks.extend_witness_high_bounds_computation(&mut witness, foreign_field_modulus);

        // Quotient multi-range-check
        CircuitGate::extend_multi_range_check(&mut gates, &mut next_row);
        gates.connect_cell_pair((1, 2), (7, 0)); // quotient0
        gates.connect_cell_pair((1, 3), (8, 0)); // quotient1
        gates.connect_cell_pair((1, 4), (9, 0)); // quotient2
                                                 // Witness updated below

        // Multiplication witness value quotient_bound, product1_lo, product1_hi_0 multi-range-check
        CircuitGate::extend_multi_range_check(&mut gates, &mut next_row);
        gates.connect_cell_pair((1, 5), (11, 0)); // quotient_bound
        gates.connect_cell_pair((0, 6), (12, 0)); // product1_lo
        gates.connect_cell_pair((1, 6), (13, 0)); // product1_hi_0
                                                  // Witness updated below

        // Add witness for external multi-range checks:
        // [quotient0, quotient1, quotient2]
        // [quotient_bound, product1_lo, product1_hi_0]
        external_checks.extend_witness_multi_range_checks(&mut witness);

        // DESIGNER CHOICE: left and right (and result bound from before)
        let left_limbs = left_input.to_field_limbs();
        let right_limbs = right_input.to_field_limbs();
        // Constant Double Generic gate for result and quotient bounds
        external_checks.add_high_bound_computation(&left_limbs[2]);
        external_checks.add_high_bound_computation(&right_limbs[2]);
        CircuitGate::extend_high_bounds(&mut gates, &mut next_row, foreign_field_modulus);
        gates.connect_cell_pair((15, 0), (0, 2)); // left2
        gates.connect_cell_pair((15, 3), (0, 5)); // right2
        external_checks.extend_witness_high_bounds_computation(&mut witness, foreign_field_modulus);

        // Left input multi-range-check
        external_checks.add_multi_range_check(&left_limbs);
        CircuitGate::extend_multi_range_check(&mut gates, &mut next_row);
        gates.connect_cell_pair((0, 0), (16, 0)); // left_input0
        gates.connect_cell_pair((0, 1), (17, 0)); // left_input1
        gates.connect_cell_pair((0, 2), (18, 0)); // left_input2
                                                  // Witness updated below

        // Right input multi-range-check
        external_checks.add_multi_range_check(&right_limbs);
        CircuitGate::extend_multi_range_check(&mut gates, &mut next_row);
        gates.connect_cell_pair((0, 3), (20, 0)); // right_input0
        gates.connect_cell_pair((0, 4), (21, 0)); // right_input1
        gates.connect_cell_pair((0, 5), (22, 0)); // right_input2
                                                  // Witness updated below

        // Add witness for external multi-range checks:
        // left and right limbs
        external_checks.extend_witness_multi_range_checks(&mut witness);

        // [result_bound, 0, 0]
        // Bounds for result limb range checks
        CircuitGate::extend_multi_range_check(&mut gates, &mut next_row);
        gates.connect_cell_pair((6, 2), (24, 0)); // result_bound
                                                  // Witness updated below

        // Multi-range check bounds for left and right inputs
        let left_hi_bound =
            foreign_field_mul::witness::compute_high_bound(left_input, foreign_field_modulus);
        let right_hi_bound =
            foreign_field_mul::witness::compute_high_bound(right_input, foreign_field_modulus);
        external_checks.add_limb_check(&left_hi_bound.into());
        external_checks.add_limb_check(&right_hi_bound.into());
        gates.connect_cell_pair((15, 2), (25, 0)); // left_bound
        gates.connect_cell_pair((15, 5), (26, 0)); // right_bound

        external_checks.extend_witness_limb_checks(&mut witness);
    }

    let runner = if full {
        // Create prover index with test framework
        Some(
            TestFramework::<FULL_ROUNDS, G>::default()
                .disable_gates_checks(disable_gates_checks)
                .gates(gates.clone())
                .setup(),
        )
    } else {
        None
    };

    let cs = if let Some(runner) = runner.as_ref() {
        runner.clone().prover_index().cs.clone()
    } else {
        // If not full mode, just create constraint system (this is much faster)
        Arc::new(ConstraintSystem::create(gates.clone()).build().unwrap())
    };

    // Perform witness verification that everything is ok before invalidation (quick checks)
    for (row, gate) in gates.iter().enumerate().take(witness[0].len()) {
        let result =
            gate.verify_witness::<FULL_ROUNDS, G>(row, &witness, &cs, &witness[0][0..cs.public]);
        if result.is_err() {
            return (result, witness);
        }
    }

    if let Some(runner) = runner.as_ref() {
        // Perform full test that everything is ok before invalidation
        assert_eq!(
            runner
                .clone()
                .witness(witness.clone())
                .prove_and_verify::<EFqSponge, EFrSponge>(),
            Ok(())
        );
    }

    if !invalidations.is_empty() {
        for ((row, col), mut value) in invalidations {
            // Invalidate witness
            if witness[col][row] == value {
                // If the invalidation would be the same value choose a different one
                // Don't let it wrap around
                assert_ne!(value, G::ScalarField::zero());
                value -= G::ScalarField::one();
            }
            witness[col][row] = value;
        }

        if !disable_gates_checks {
            // Check witness verification fails
            // When targeting the plookup constraints the invalidated values would cause custom constraint
            // failures, so we want to suppress these witness verification checks when doing plookup tests.
            for (row, gate) in gates.iter().enumerate().take(witness[0].len()) {
                let result = gate.verify_witness::<FULL_ROUNDS, G>(
                    row,
                    &witness,
                    &cs,
                    &witness[0][0..cs.public],
                );
                if result.is_err() {
                    return (result, witness);
                }
            }
        }

        // Run test on invalid witness
        if let Some(runner) = runner.as_ref() {
            match runner
                .clone()
                .witness(witness.clone())
                .prove_and_verify::<EFqSponge, EFrSponge>()
            {
                Err(err_msg) => {
                    if err_msg[..46] == *"the lookup failed to find a match in the table" {
                        return (
                            Err(CircuitGateError::InvalidLookupConstraint(
                                GateType::ForeignFieldMul,
                            )),
                            witness,
                        );
                    } else {
                        return (
                            Err(CircuitGateError::InvalidConstraint(
                                GateType::ForeignFieldMul,
                            )),
                            witness,
                        );
                    }
                }
                Ok(()) => return (Ok(()), witness),
            }
        }
    }

    (Ok(()), witness)
}

// Test targeting each custom constraint (positive and negative tests for each)
fn test_custom_constraints<
    const FULL_ROUNDS: usize,
    G: KimchiCurve<FULL_ROUNDS>,
    EFqSponge,
    EFrSponge,
>(
    foreign_field_modulus: &BigUint,
) where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField, FULL_ROUNDS>,
    EFrSponge: FrSponge<G::ScalarField>,
    EFrSponge: From<&'static ArithmeticSpongeParams<G::ScalarField, FULL_ROUNDS>>,
{
    let rng = &mut o1_utils::tests::make_test_rng(None);

    for _ in 0..3 {
        let left_input = rng.gen_biguint_range(&BigUint::zero(), foreign_field_modulus);
        let right_input = rng.gen_biguint_range(&BigUint::zero(), foreign_field_modulus);

        // Test constraint (C1): invalidate product1_hi_1 is in [0, 2^2)
        let (result, witness) = run_test::<FULL_ROUNDS, G, EFqSponge, EFrSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            foreign_field_modulus,
            vec![((1, 7), G::ScalarField::from(4u32))], // Invalidate product1_hi_1
        );
        assert_eq!(
            (&left_input * &right_input) % foreign_field_modulus,
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 1)),
        );

        // Test constraint (C2): invalidate carry0 in [0, 2^2)
        let (result, witness) = run_test::<FULL_ROUNDS, G, EFqSponge, EFrSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            foreign_field_modulus,
            vec![((1, 11), G::ScalarField::from(4u32))], // Invalidate carry0
        );
        assert_eq!(
            (&left_input * &right_input) % foreign_field_modulus,
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 2)),
        );

        // Test constraint (C3): invalidate middle intermediate product p1 decomposition
        let (result, witness) = run_test::<FULL_ROUNDS, G, EFqSponge, EFrSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            foreign_field_modulus,
            vec![((0, 6), G::ScalarField::one())], // Invalidate product1_lo
        );
        assert_eq!(
            (&left_input * &right_input) % foreign_field_modulus,
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 3)),
        );

        // Test constraint (C4): invalidate carry0
        let (result, witness) = run_test::<FULL_ROUNDS, G, EFqSponge, EFrSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            foreign_field_modulus,
            vec![((1, 11), G::ScalarField::from(3u32))], // Invalidate carry0
        );
        assert_eq!(
            (&left_input * &right_input) % foreign_field_modulus,
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 4)),
        );

        // Test constraint (C5): invalid native modulus check but binary modulus checks ok
        //     Triggering constraint C4 is challenging, so this is done with
        //     the test_native_modulus_constraint() test below

        // Test constraint (C6): invalidate carry1_crumb0
        let (result, witness) = run_test::<FULL_ROUNDS, G, EFqSponge, EFrSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            foreign_field_modulus,
            vec![((0, 11), G::ScalarField::from(8u32))], // Invalidate carry1_crumb0
        );
        assert_eq!(
            (&left_input * &right_input) % foreign_field_modulus,
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 6)),
        );
        // Test constraint (C7): invalidate carry1_crumb1
        let (result, witness) = run_test::<FULL_ROUNDS, G, EFqSponge, EFrSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            foreign_field_modulus,
            vec![((0, 12), G::ScalarField::from(8u32))], // Invalidate carry1_crumb0
        );
        assert_eq!(
            (&left_input * &right_input) % foreign_field_modulus,
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 7)),
        );
        // Test constraint (C8): invalidate carry1_crumb2
        let (result, witness) = run_test::<FULL_ROUNDS, G, EFqSponge, EFrSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            foreign_field_modulus,
            vec![((0, 13), G::ScalarField::from(8u32))], // Invalidate carry1_crumb0
        );
        assert_eq!(
            (&left_input * &right_input) % foreign_field_modulus,
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 8)),
        );

        // Test constraint (C9): invalidate carry1_bit
        let (result, witness) = run_test::<FULL_ROUNDS, G, EFqSponge, EFrSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            foreign_field_modulus,
            vec![((0, 14), G::ScalarField::from(3u32))], // Invalidate carry1_crumb0
        );
        assert_eq!(
            (&left_input * &right_input) % foreign_field_modulus,
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 9)),
        );

        // Test constraint (C10): invalidate zero check
        let (result, witness) = run_test::<FULL_ROUNDS, G, EFqSponge, EFrSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            foreign_field_modulus,
            vec![((0, 7), G::ScalarField::one())], // Invalidate carry1_0_11
        );
        assert_eq!(
            (&left_input * &right_input) % foreign_field_modulus,
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 10)),
        );

        // Test constraint (C11): invalidate quotient high bound
        let (result, witness) = run_test::<FULL_ROUNDS, G, EFqSponge, EFrSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            foreign_field_modulus,
            vec![((1, 5), G::ScalarField::one())], // Invalidate quotient_bound
        );
        assert_eq!(
            (&left_input * &right_input) % foreign_field_modulus,
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 11)),
        );
    }
}

#[test]
// Test the multiplication of two zeros.
// This checks that small amounts get packed into limbs
fn test_zero_mul() {
    let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        true,
        true,
        false,
        &BigUint::zero(),
        &BigUint::zero(),
        &secp256k1_modulus(),
        vec![],
    );
    assert_eq!(result, Ok(()));

    // Check remainder is zero
    assert_eq!(witness[0][1], PallasField::zero()); // remainder01
    assert_eq!(witness[1][1], PallasField::zero()); // remainder2

    // Check quotient is zero
    assert_eq!(witness[2][1], PallasField::zero());
    assert_eq!(witness[3][1], PallasField::zero());
    assert_eq!(witness[4][1], PallasField::zero());
}

#[test]
// Test the multiplication of largest foreign element and 1
fn test_one_mul() {
    let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        true,
        true,
        false,
        &secp256k1_max(),
        &One::one(),
        &secp256k1_modulus(),
        vec![],
    );
    assert_eq!(result, Ok(()));

    // Check remainder is secp256k1_max()
    let target = secp256k1_max().to_compact_field_limbs();
    assert_eq!(witness[0][1], target[0]);
    assert_eq!(witness[1][1], target[1]);

    // Check quotient is zero
    assert_eq!(witness[2][1], PallasField::zero());
    assert_eq!(witness[3][1], PallasField::zero());
    assert_eq!(witness[4][1], PallasField::zero());
}

#[test]
// Test the maximum value m whose square fits in the native field
//    m^2 = q * f + r -> q should be 0 and r should be m^2 < n < f
fn test_max_native_square() {
    let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        true,
        true,
        false,
        &pallas_sqrt(),
        &pallas_sqrt(),
        &secp256k1_modulus(),
        vec![],
    );
    assert_eq!(result, Ok(()));

    // Check remainder is the square
    let multiplicand = pallas_sqrt();
    let square = multiplicand.pow(2u32);
    let product = square.to_compact_field_limbs();
    assert_eq!(witness[0][1], product[0]);
    assert_eq!(witness[1][1], product[1]);

    // Check quotient is zero
    assert_eq!(witness[2][1], PallasField::zero());
    assert_eq!(witness[3][1], PallasField::zero());
    assert_eq!(witness[4][1], PallasField::zero());
}

#[test]
// Test the maximum value g whose square fits in the foreign field
//     g^2 = q * f + r -> q should be 0 and r should be g^2 < f
fn test_max_foreign_square() {
    let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        true,
        true,
        false,
        &secp256k1_sqrt(),
        &secp256k1_sqrt(),
        &secp256k1_modulus(),
        vec![],
    );
    assert_eq!(result, Ok(()));

    // Check remainder is the square
    let multiplicand = secp256k1_sqrt();
    let square = multiplicand.pow(2u32);
    let product = square.to_compact_field_limbs();
    assert_eq!(witness[0][1], product[0]);
    assert_eq!(witness[1][1], product[1]);

    // Check quotient is zero
    assert_eq!(witness[2][1], PallasField::zero());
    assert_eq!(witness[3][1], PallasField::zero());
    assert_eq!(witness[4][1], PallasField::zero());
}

#[test]
// Test squaring the maximum native field elements
//     (n - 1) * (n - 1) = q * f + r
fn test_max_native_multiplicands() {
    let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        true,
        true,
        false,
        &pallas_max(),
        &pallas_max(),
        &secp256k1_modulus(),
        vec![],
    );
    assert_eq!(result, Ok(()));
    assert_eq!(
        pallas_max() * pallas_max() % secp256k1_modulus(),
        [witness[0][1], witness[1][1]].compose()
    );
}

#[test]
// Test squaring the maximum foreign field elements
//     (f - 1) * (f - 1) = f^2 - 2f + 1 = f * (f - 2) + 1
fn test_max_foreign_multiplicands() {
    let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        true,
        true,
        false,
        &secp256k1_max(),
        &secp256k1_max(),
        &secp256k1_modulus(),
        vec![],
    );
    assert_eq!(result, Ok(()));
    assert_eq!(
        secp256k1_max() * secp256k1_max() % secp256k1_modulus(),
        [witness[0][1], witness[1][1]].compose()
    );
}

#[test]
// Test with nonzero carry0 bits
fn test_nonzero_carry0() {
    let rng = &mut o1_utils::tests::make_test_rng(None);

    for _ in 0..4 {
        let mut a = rng.gen_biguint_below(&secp256k1_modulus()).to_limbs();
        let mut b = rng.gen_biguint_below(&secp256k1_modulus()).to_limbs();

        // Adjust lowest limb to trigger carry bits into carry0
        a[0] = BigUint::two_to_limb() - BigUint::one();
        let a = a.compose();
        assert!(a < secp256k1_modulus());
        b[0] = BigUint::two_to_limb() - BigUint::one();
        let b = b.compose();
        assert!(b < secp256k1_modulus());

        // Valid witness test
        let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
            false,
            true,
            false,
            &a,
            &b,
            &secp256k1_modulus(),
            vec![],
        );
        assert_eq!(result, Ok(()));
        assert_ne!(witness[11][1], PallasField::zero()); // carry0 is not zero
        assert_eq!(
            &a * &b % secp256k1_modulus(),
            [witness[0][1], witness[1][1]].compose()
        );

        // Invalid carry0 witness test
        let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
            false,
            true,
            false,
            &a,
            &b,
            &secp256k1_modulus(),
            vec![((1, 11), PallasField::zero())], // Invalidate carry0
        );
        // The constraint (C4) should fail
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 4))
        );
        assert_eq!(
            a * b % secp256k1_modulus(),
            [witness[0][1], witness[1][1]].compose()
        );
    }
}

#[test]
// Test with nonzero carry10 (this targets only the limbs and the first crumb of carry1)
fn test_nonzero_carry10() {
    // Max modulus
    // Actually this is larger than max_foreign_field_modulus, but it's fine because
    // we can still hold larger than 2^259-1. This is just for the test to produce nonzero carry10.
    let foreign_field_modulus = BigUint::two().pow(259u32);

    // Maximum quotient
    let q = &foreign_field_modulus - BigUint::one();

    // Compute operands
    let a = &foreign_field_modulus / BigUint::two().pow(5);
    let b = ((&q * &foreign_field_modulus) / &a) % &foreign_field_modulus;

    // Valid witness test
    let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        true,
        false,
        &a,
        &b,
        &foreign_field_modulus,
        vec![],
    );
    assert_eq!(result, Ok(()));
    let carry10 = witness[7][0]
        + witness[8][0] * PallasField::two_pow(12)
        + witness[9][0] * PallasField::two_pow(24)
        + witness[10][0] * PallasField::two_pow(36)
        + witness[8][1] * PallasField::two_pow(48)
        + witness[9][1] * PallasField::two_pow(60)
        + witness[10][1] * PallasField::two_pow(72)
        + witness[11][0] * PallasField::two_pow(84)
        + witness[12][0] * PallasField::two_pow(86);
    assert_ne!(carry10, PallasField::zero()); // carry10 is definitely not zero
    assert_eq!(
        &a * &b % &foreign_field_modulus,
        [witness[0][1], witness[1][1]].compose()
    );

    // Invalid carry0 witness test
    let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        false, // Disable copy constraints so we can catch carry10 custom constraint failure
        false,
        &a,
        &b,
        &foreign_field_modulus,
        vec![((0, 10), PallasField::zero())], // Invalidate carry10
    );
    // The constraint (C10) should fail
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 10))
    );
    assert_eq!(
        a * b % &foreign_field_modulus,
        [witness[0][1], witness[1][1]].compose()
    );
}

#[test]
// Test with nonzero carry1_hi (this targets only carry1_crumb2 and carry1_bit)
fn test_nonzero_carry1_hi() {
    // Big (rubbish) modulus
    let foreign_field_modulus = BigUint::two().pow(259u32) - BigUint::one();

    // Maximum operands
    let a = &foreign_field_modulus - BigUint::one();

    // Valid witness test
    let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        true,
        false,
        &a,
        &a,
        &foreign_field_modulus,
        vec![],
    );
    assert_eq!(result, Ok(()));
    let carry1_hi = witness[13][0] + witness[14][0] * PallasField::from(4u32);
    assert_ne!(carry1_hi, PallasField::zero()); // carry1_hi is definitely not zero
    assert_eq!(
        &a * &a % &foreign_field_modulus,
        [witness[0][1], witness[1][1]].compose()
    );

    // Invalid carry1_hi witness test
    let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        false, // Disable copy constraints so we can catch carry1_hi custom constraint failure
        false,
        &a,
        &a,
        &foreign_field_modulus,
        vec![((0, 7), PallasField::zero())], // Invalidate carry1_hi
    );
    // The constraint (C5) should fail
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 10))
    );
    assert_eq!(
        &a * &a % &foreign_field_modulus,
        [witness[0][1], witness[1][1]].compose()
    );
}

#[test]
// Test with nonzero second bit of carry1_hi
fn test_nonzero_second_bit_carry1_hi() {
    let rng = &mut o1_utils::tests::make_test_rng(None);
    let a = rng.gen_biguint_range(
        &(secp256k1_modulus() - BigUint::two().pow(64)),
        &secp256k1_modulus(),
    );
    let b = secp256k1_max();

    // Valid witness test
    let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        true,
        false,
        &a,
        &b,
        &secp256k1_modulus(),
        vec![],
    );
    assert_eq!(result, Ok(()));
    let carry1_hi = witness[13][0] + witness[14][0] * PallasField::from(4u32);
    assert_eq!(carry1_hi, PallasField::from(2u32)); // carry1_hi is not zero
    assert_eq!(
        &a * &b % secp256k1_modulus(),
        [witness[0][1], witness[1][1]].compose()
    );

    // Invalid carry1_hi witness test
    let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        false, // Disable copy constraints so we can catch carry1_hi custom constraint failure
        false,
        &a,
        &b,
        &secp256k1_modulus(),
        vec![((0, 13), PallasField::two())], // Invalidate carry1_hi
    );
    // The constraint (C10) should fail
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 10))
    );
    assert_eq!(
        a * b % secp256k1_modulus(),
        [witness[0][1], witness[1][1]].compose()
    );
}

#[test]
// Test invalid carry1_hi range bit
fn test_invalid_carry1_bit() {
    let a = BigUint::zero();
    let b = BigUint::zero();

    // Invalid carry1_hi witness test
    let (result, _) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        true,
        false, // Disable external checks so we can catch carry1_hi plookup failure
        false,
        &a,
        &b,
        &secp256k1_modulus(),
        vec![
            ((0, 14), PallasField::from(2u32)), // carry1_hi > 3 bits (invalid)
        ],
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 9))
    );
}

#[test]
// This is no longer a lookup test since the 3-bit check is now a crumb + a bit
fn test_invalid_wraparound_carry1_hi() {
    let a = BigUint::zero();
    let b = BigUint::zero();

    // Sanity check wraparound values
    let two_to_9 = PallasField::from(2u32).pow([9]);
    // Wraparound (exploit) value x s.t. x >= 2^12 AND 2^9 * x < 2^12
    // (credit to querolita for computing the real instances of this value for these test cases!)
    let wraparound_0 = two_to_9.inverse().expect("failed to get inverse");
    for i in 0..8 {
        let wraparound_i = wraparound_0 + PallasField::from(i);
        assert!(wraparound_i >= PallasField::from(2u32).pow([12u64]));
        assert!(two_to_9 * wraparound_i < PallasField::from(2u32).pow([12u64]));
        // Wraparound!!!
    }
    // edge case: x - 1 is not a wraparound value
    assert!(wraparound_0 - PallasField::one() >= PallasField::from(2u32).pow([12u64]));
    assert!(two_to_9 * (wraparound_0 - PallasField::one()) >= PallasField::from(2u32).pow([12u64]));
    // edge case: x + 8 is not a wraparound value
    assert!(wraparound_0 + PallasField::from(8) >= PallasField::from(2u32).pow([12u64]));
    assert!(
        two_to_9 * (wraparound_0 + PallasField::from(8)) >= PallasField::from(2u32).pow([12u64])
    );

    let value = PallasField::from(512u32) // wraparound_0 + 1
        .inverse()
        .expect("failed to get inverse")
        .to_biguint();

    let carry1_bit = value.clone() / BigUint::from(4u32);

    let carry1_crumb2 = value % BigUint::from(4u32);

    // Invalid carry1_hi witness that causes wrap around to something less than 3-bits
    let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        true,
        false, // Disable external checks so we can catch carry1_hi plookup failure
        false,
        &a,
        &b,
        &secp256k1_modulus(),
        vec![
            // Invalidate carry1_hi by wrapping
            // carry1_hi > 12 bits > 3 bits, but wraps around < 12-bits when scaled by 2^9
            ((0, 14), carry1_bit.into()),
            ((0, 13), carry1_crumb2.into()),
        ],
    );
    // crumb is "1"
    // bit is "7222870800814035139336520183037050892714122003062567151295331946573649149952"
    // carry1_hi is >> 9 bits but
    // carry1_hi * 2^9 is < 12 bits, actually is equal to one
    let carry1_hi = witness[13][0] + witness[14][0] * PallasField::from(4u32);
    assert!(carry1_hi >= PallasField::from(2u32).pow([9u64]));
    assert!(two_to_9 * carry1_hi < PallasField::from(2u32).pow([12u64]));
    // the bit is not a bit
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 9)),
    );
}

#[test]
// Test witness with invalid quotient fails verification
fn test_zero_mul_invalid_quotient() {
    let (result, _) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        true,
        false,
        &BigUint::zero(),
        &BigUint::zero(),
        &secp256k1_modulus(),
        vec![((1, 2), PallasField::one())], // Invalidate q0
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 4)),
    );

    let (result, _) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        true,
        false,
        &BigUint::zero(),
        &BigUint::zero(),
        &secp256k1_modulus(),
        vec![((1, 3), PallasField::one())], // Invalidate q1
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 3)),
    );

    let (result, _) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        true,
        false,
        &BigUint::zero(),
        &BigUint::zero(),
        &secp256k1_modulus(),
        vec![((1, 4), PallasField::one())], // Invalidate q2
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 5))
    );

    let (result, _) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        true,
        false,
        &secp256k1_sqrt(),
        &secp256k1_sqrt(),
        &secp256k1_modulus(),
        vec![((1, 2), PallasField::one())], // Invalidate q0
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 4))
    );

    let (result, _) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        true,
        false,
        &secp256k1_sqrt(),
        &secp256k1_sqrt(),
        &secp256k1_modulus(),
        vec![((1, 3), PallasField::one())], // Invalidate q1
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 3))
    );

    let (result, _) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        true,
        false,
        &secp256k1_sqrt(),
        &secp256k1_sqrt(),
        &secp256k1_modulus(),
        vec![((1, 4), PallasField::one())], // Invalidate q2
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 5))
    );
}

#[test]
// Test witness with invalid remainder fails
fn test_mul_invalid_remainder() {
    let (result, _) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        false,
        false,
        &secp256k1_sqrt(),
        &secp256k1_sqrt(),
        &secp256k1_modulus(),
        vec![((1, 0), PallasField::zero())], // Invalidate r01
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 4))
    );

    let (result, _) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        false,
        false,
        &secp256k1_sqrt(),
        &secp256k1_sqrt(),
        &secp256k1_modulus(),
        vec![((1, 1), PallasField::one())], // Invalidate r2
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 5))
    );
}

#[test]
// Test multiplying some random values and invalidating carry1_lo
fn test_random_multiplicands_carry1_lo() {
    let rng = &mut o1_utils::tests::make_test_rng(None);

    for _ in 0..10 {
        let left_input = rng.gen_biguint_range(&BigUint::zero(), &secp256k1_max());
        let right_input = rng.gen_biguint_range(&BigUint::zero(), &secp256k1_max());

        let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((0, 7), PallasField::one())], // Invalidate carry1_lo
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 10)),
        );
        let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((0, 8), PallasField::one())], // Invalidate carry1_lo
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 10)),
        );
        let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((0, 9), PallasField::one())], // Invalidate carry1_lo
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 10)),
        );
        let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((0, 10), PallasField::one())], // Invalidate carry1_lo
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 10)),
        );
        let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((1, 8), PallasField::one())], // Invalidate carry1_lo
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 10)),
        );
        let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((1, 9), PallasField::one())], // Invalidate carry1_lo
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 10)),
        );
        let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((1, 10), PallasField::one())], // Invalidate carry1_lo
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 10)),
        );
        let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((0, 11), PallasField::one())], // Invalidate carry1_lo
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 10)),
        );
        let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((0, 12), PallasField::one())], // Invalidate carry1_lo
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 10)),
        );
    }
}

#[test]
// Test multiplying some random values with secp256k1 foreign modulus
fn test_random_multiplicands_valid() {
    let rng = &mut o1_utils::tests::make_test_rng(None);

    for _ in 0..10 {
        let left_input = rng.gen_biguint_range(&BigUint::zero(), &secp256k1_max());
        let right_input = rng.gen_biguint_range(&BigUint::zero(), &secp256k1_max());

        let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
            false,
            true,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![],
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(result, Ok(()),);
    }
}

#[test]
// Test multiplying some random values with foreign modulus smaller than native modulus
fn test_smaller_foreign_field_modulus() {
    let foreign_field_modulus = BigUint::two().pow(252u32) - BigUint::one();

    let rng = &mut o1_utils::tests::make_test_rng(None);

    for _ in 0..10 {
        let left_input = rng.gen_biguint_range(&BigUint::zero(), &foreign_field_modulus);
        let right_input = rng.gen_biguint_range(&BigUint::zero(), &foreign_field_modulus);

        let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
            false,
            true,
            false,
            &left_input,
            &right_input,
            &foreign_field_modulus,
            vec![],
        );
        assert_eq!(
            (&left_input * &right_input) % &foreign_field_modulus,
            [witness[0][1], witness[1][1]].compose()
        );
        assert_eq!(result, Ok(()),);
    }
}

#[test]
// Tests targeting each custom constraint with secp256k1 (foreign field modulus)
// on Vesta (native field modulus)
fn test_custom_constraints_secp256k1_on_vesta() {
    test_custom_constraints::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(&secp256k1_modulus());
}

#[test]
// Tests targeting each custom constraint with secp256k1 (foreign field modulus)
// on Pallas (native field modulus)
fn test_custom_constraints_secp256k1_on_pallas() {
    test_custom_constraints::<55, Pallas, PallasBaseSponge, PallasScalarSponge>(
        &secp256k1_modulus(),
    );
}

#[test]
// Tests targeting each custom constraint with Vesta (foreign field modulus) on Pallas (native field modulus)
fn test_custom_constraints_vesta_on_pallas() {
    test_custom_constraints::<55, Pallas, PallasBaseSponge, PallasScalarSponge>(
        &VestaField::modulus_biguint(),
    );
}

#[test]
// Tests targeting each custom constraint with Pallas (foreign field modulus) on Vesta (native field modulus)
fn test_custom_constraints_pallas_on_vesta() {
    test_custom_constraints::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        &PallasField::modulus_biguint(),
    );
}

#[test]
// Tests targeting each custom constraint with Vesta (foreign field modulus) on Vesta (native field modulus)
fn test_custom_constraints_vesta_on_vesta() {
    test_custom_constraints::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        &VestaField::modulus_biguint(),
    );
}

#[test]
// Tests targeting each custom constraint with Pallas (foreign field modulus) on Pallas (native field modulus)
fn test_custom_constraints_pallas_on_pallas() {
    test_custom_constraints::<55, Pallas, PallasBaseSponge, PallasScalarSponge>(
        &PallasField::modulus_biguint(),
    );
}

#[test]
// Tests targeting each custom constraint (foreign modulus smaller than native vesta)
fn test_custom_constraints_small_foreign_field_modulus_on_vesta() {
    test_custom_constraints::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        &(BigUint::two().pow(252u32) - BigUint::one()),
    );
}

#[test]
// Tests targeting each custom constraint (foreign modulus smaller than native pallas)
fn test_custom_constraints_small_foreign_field_modulus_on_pallas() {
    test_custom_constraints::<55, Pallas, PallasBaseSponge, PallasScalarSponge>(
        &(BigUint::two().pow(252u32) - BigUint::one()),
    );
}

#[test]
fn test_native_modulus_constraint() {
    let rng = &mut o1_utils::tests::make_test_rng(None);
    let left_input = rng.gen_biguint_range(
        &(secp256k1_modulus() - BigUint::two().pow(96)),
        &secp256k1_modulus(),
    );
    let right_input = rng.gen_biguint_range(
        &(secp256k1_modulus() - BigUint::two().pow(96)),
        &secp256k1_modulus(),
    );

    let (result, _) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        false,
        false,
        &left_input,
        &right_input,
        &secp256k1_modulus(),
        vec![
            // Targeted attack on constraint 1. Make carry1_hi to be 8
            ((0, 13), PallasField::zero()),
            ((0, 14), PallasField::from(2u32)),
            (
                (1, 1),
                PallasField::from_bytes(&[
                    89, 18, 0, 0, 237, 48, 45, 153, 27, 249, 76, 9, 252, 152, 70, 34, 0, 0, 0, 0,
                    0, 0, 249, 255, 255, 255, 255, 255, 255, 255, 255, 63,
                ])
                .unwrap(),
            ),
        ],
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 5))
    );
}

#[test]
fn test_gates_max_foreign_field_modulus() {
    CircuitGate::<PallasField>::create_foreign_field_mul(
        0,
        &BigUint::max_foreign_field_modulus::<PallasField>(),
    );
}

#[test]
fn test_witness_max_foreign_field_modulus() {
    foreign_field_mul::witness::create::<PallasField>(
        &BigUint::zero(),
        &BigUint::zero(),
        &BigUint::max_foreign_field_modulus::<PallasField>(),
    );
}

#[test]
// Checks that the high bound check includes when q2 is exactly f2 and not just up to f2-1
fn test_q2_exactly_f2() {
    let left_input = secp256k1_max() - BigUint::from(4u32);
    let right_input = secp256k1_max() - BigUint::from(1u32);

    let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        true,
        false,
        &left_input,
        &right_input,
        &secp256k1_modulus(),
        vec![],
    );
    assert_eq!(witness[4][1], secp256k1_max().to_field_limbs()[2]); // q2 is f2
    assert_eq!(
        (&left_input * &right_input) % secp256k1_modulus(),
        [witness[0][1], witness[1][1]].compose()
    );
    assert_eq!(result, Ok(()),);
}

#[test]
fn test_carry_plookups() {
    let left_input = secp256k1_max() - BigUint::from(4u32);
    let right_input = secp256k1_max() - BigUint::from(1u32);
    // Correct execution of this test has the following values in plookup cells
    // carry1_0 = 0xC26
    // carry1_12 = 0xFFF
    // carry1_24 = 0xEFF
    // carry1_36 = 0xFFF
    // product1_1_1 = 0x1
    // carry1_48 = 0xFFF
    // carry1_60 = 0xFFF
    // carry1_72 = 0xFF
    let (result, witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        false,
        false,
        &left_input,
        &right_input,
        &secp256k1_modulus(),
        vec![],
    );
    assert_eq!(
        (&left_input * &right_input) % secp256k1_modulus(),
        [witness[0][1], witness[1][1]].compose()
    );
    assert_eq!(result, Ok(()),);
    // Adds 1 bit to carry1_36 (obtaining 0x1FFF) and removing 1 from carry1_48 (obtaining 0xFFE)
    let (result, _witness) = run_test::<55, Vesta, VestaBaseSponge, VestaScalarSponge>(
        true,
        false,
        false,
        &left_input,
        &right_input,
        &secp256k1_modulus(),
        vec![
            ((0, 10), PallasField::from(0x1FFFu32)),
            ((1, 8), PallasField::from(0xFFEu32)),
        ],
    );
    assert_eq!(
        result,
        Err(CircuitGateError::InvalidLookupConstraint(
            GateType::ForeignFieldMul
        ))
    );
}
