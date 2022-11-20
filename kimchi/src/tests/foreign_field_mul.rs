use crate::{
    auto_clone_array,
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, CircuitGateError, CircuitGateResult, Connect, GateType},
        polynomial::COLUMNS,
        polynomials::{
            foreign_field_mul,
            range_check,
        },
        wires::Wire,
    },
    tests::framework::TestFramework,
};
use ark_ec::AffineCurve;
use ark_ff::{Field, PrimeField, Zero};
use mina_curves::pasta::{Pallas, Vesta};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;
use o1_utils::{
    foreign_field::{
        BigUintArrayCompose, BigUintForeignFieldHelpers,
        FieldArrayCompose, ForeignElement, ForeignFieldHelpers,
    },
    FieldHelpers,
};

use num_bigint::RandBigInt;
use rand::{rngs::StdRng, SeedableRng};

type PallasField = <Pallas as AffineCurve>::BaseField;
type VestaField = <Vesta as AffineCurve>::BaseField;

const RNG_SEED: [u8; 32] = [
    211, 31, 143, 75, 29, 255, 0, 126, 237, 193, 86, 160, 1, 90, 131, 221, 186, 168, 4, 95, 50, 48,
    89, 29, 13, 250, 215, 172, 130, 24, 164, 162,
];

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
fn run_test(
    full: bool,
    external_gates: bool,
    target_plookups: bool,
    left_input: &BigUint,
    right_input: &BigUint,
    foreign_field_modulus: &BigUint,
    invalidations: Vec<((usize, usize), PallasField)>,
) -> (CircuitGateResult<()>, [Vec<PallasField>; COLUMNS]) {
    // Create foreign field multiplication gates
    let (mut next_row, mut gates) = CircuitGate::create_foreign_field_mul(0);

    // Compute multiplication witness
    let (mut witness, external_checks) =
        foreign_field_mul::witness::create(&left_input, &right_input, &foreign_field_modulus);

    // Optionally also add external gate checks to circuit
    if external_gates {
        // Layout for this test (just an example, circuit designer has complete flexibility, where to put the checks)
        //      0-1  ForeignFieldMul
        //      2-3  ForeignFieldAdd (result bound addition)
        //      4-7  multi-range-check (left multiplicand)
        //      8-11 multi-range-check (right multiplicand)
        //     12-15 multi-range-check (product1_lo, product1_hi_0, carry1_lo)
        //     16-19 multi-range-check (result range check)
        //     20-23 multi-range-check (quotient range check)

        // Bound addition for multiplication result
        CircuitGate::<PallasField>::extend_single_foreign_field_add(&mut gates, &mut next_row);
        gates.connect_cell_pair((1, 0), (2, 0));
        gates.connect_cell_pair((1, 1), (2, 1));
        gates.connect_cell_pair((1, 2), (2, 2));
        external_checks
            .extend_witness_bound_addition(&mut witness, &foreign_field_modulus.to_field_limbs());

        // Left input multi-range-check
        CircuitGate::<PallasField>::extend_multi_range_check(&mut gates, &mut next_row);
        gates.connect_cell_pair((0, 0), (4, 0));
        gates.connect_cell_pair((0, 1), (5, 0));
        gates.connect_cell_pair((0, 2), (6, 0));
        range_check::witness::extend_multi_limbs(&mut witness, &left_input.to_field_limbs());

        // Right input multi-range-check
        CircuitGate::<PallasField>::extend_multi_range_check(&mut gates, &mut next_row);
        gates.connect_cell_pair((0, 3), (8, 0));
        gates.connect_cell_pair((0, 4), (9, 0));
        gates.connect_cell_pair((0, 5), (10, 0));
        range_check::witness::extend_multi_limbs(&mut witness, &right_input.to_field_limbs());

        // Multiplication witness value product1_lo, product1_hi_0, carry1_lo multi-range-check
        CircuitGate::<PallasField>::extend_multi_range_check(&mut gates, &mut next_row);
        gates.connect_cell_pair((0, 6), (12, 0)); // carry1_lo
        gates.connect_cell_pair((1, 5), (13, 0)); // product1_lo
        gates.connect_cell_pair((1, 6), (14, 0)); // product1_hi_0
                                                  // Witness updated below

        // Result/remainder bound multi-range-check
        CircuitGate::<PallasField>::extend_multi_range_check(&mut gates, &mut next_row);
        gates.connect_cell_pair((3, 0), (16, 0));
        gates.connect_cell_pair((3, 1), (17, 0));
        gates.connect_cell_pair((3, 2), (18, 0));
        // Witness updated below

        // Add witness for external multi-range checks (product1_lo, product1_hi_0, carry1_lo and result)
        external_checks.extend_witness_multi_range_checks(&mut witness);

        // TODO: (required for soundness) Wire this up once range-check gate is updated to support compact limbs
        // // Quotient bound multi-range-check
        // CircuitGate::<PallasField>::extend_compact_multi_range_check(next_row);
        // gates.connect_cell_pair((1, 3), (TODO1, 0));
        // gates.connect_cell_pair((1, 4), (TODO2, 0));
        // external_checks.extend_witness_compact_multi_range_checks(&mut witness);
    }

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    let runner = if full {
        // Create prover index with test framework
        Some(
            TestFramework::default()
                .gates(gates.clone())
                .witness(witness.clone())
                .lookup_tables(vec![foreign_field_mul::gadget::lookup_table()])
                .foreign_modulus(Some(foreign_field_modulus.clone()))
                .setup(),
        )
    } else {
        None
    };

    let cs = if let Some(runner) = runner.as_ref() {
        runner.prover_index().cs.clone()
    } else {
        // If not full mode, just create constraint system (this is much faster)
        ConstraintSystem::create(gates.clone())
            .foreign_field_modulus(&Some(foreign_field_modulus.clone()))
            .build()
            .unwrap()
    };

    // Perform witness verification that everything is ok before invalidation (quick checks)
    for row in 0..witness[0].len() {
        let result = gates[row].verify_witness::<Vesta>(
            row,
            &witness,
            &cs,
            &witness[0][0..cs.public].to_vec(),
        );
        if result.is_err() {
            return (result, witness);
        }
    }

    if let Some(runner) = runner {
        // Perform full test that everything is ok before invalidation
        runner.prove_and_verify();
    }

    if !invalidations.is_empty() {
        for ((row, col), value) in invalidations {
            // Invalidate witness
            assert_ne!(witness[col][row], value);
            witness[col][row] = value;
        }

        if !target_plookups {
            // Check witness verification fails
            // When targeting the plookup constraints the invalidated values would cause custom constraint
            // failures, so we want to suppress these witness verification checks when doing plookup tests.
            for row in 0..witness[0].len() {
                let result = gates[row].verify_witness::<Vesta>(
                    row,
                    &witness,
                    &cs,
                    &witness[0][0..cs.public].to_vec(),
                );
                if result.is_err() {
                    return (result, witness);
                }
            }
        }

        // Catch plookup failures caused by invalidation of witness
        if full {
            TestFramework::default()
                .gates(gates.clone())
                .witness(witness.clone())
                .lookup_tables(vec![foreign_field_mul::gadget::lookup_table()])
                .foreign_modulus(Some(foreign_field_modulus.clone()))
                .setup()
                .prove_and_verify()
        }
    }

    (Ok(()), witness)
}

/// Generate a random foreign field element x whose addition with the negated foreign field modulus f' = 2^t - f results
/// in an overflow in the lest significant limb x0.  The limbs are in 2 limb compact representation:
///
///     x  = x0  + 2^2L * x1
///     f' = f'0 + 2^2L * f'1
///
/// Note that it is not possible to have an overflow in the most significant limb.  This is because if there were an overflow
/// when adding f'1 to x1, then we'd have a contradiction.  To see this, first note that to get an overflow in the highest limbs,
/// we need
///
///     2^L < x1 + o0 + f'1 <= 2^L - 1 + o0 + f'1
///
/// where 2^L - 1 is the maximum possible size of x1 (before it overflows) and o0 is the overflow bit from the addition of the
/// least significant limbs x0 and f'0.  This means
///
///     2^L - o0 - f'1 < x1 < 2^L
///
/// We cannot allow x to overflow the foreign field, so we also have
///
///     x1 < (f - x0)/2^2L
///
/// Thus,
///
///     2^L - o0  - f'1 < (f - x0)/2^2L = f/2^2L - x0/2^2L
///
/// Since x0/2^2L = o0 we have
///
///     2^L - o0 - f'1 < f/2^2L - o0
///
/// so
///     2^L - f'1 < f/2^2L
///
/// Notice that f/2^2L = f1.  Now we have
///
///     2^L - f'1 < f1
///     <=>
///     f'1 > 2^L - f1
///
/// However, this is a contradiction with the definition of our negated foreign field modulus limb f'1 = 2^L - f1.
///
/// TODO: This proof probably means, since they are never used, we can safely remove the witness for the carry bit of
///       addition of the most significant bound addition limbs and the corresponding constraint.
pub fn rand_foreign_field_element_with_bound_overflows<F: PrimeField>(
    rng: &mut StdRng,
    foreign_field_modulus: &BigUint,
) -> Result<BigUint, &'static str> {
    if *foreign_field_modulus < BigUint::two_to_2limb() {
        return Err("Foreign field modulus too small");
    }

    auto_clone_array!(
        neg_foreign_field_modulus,
        foreign_field_modulus.negate().to_compact_limbs()
    );

    if neg_foreign_field_modulus(0) == BigUint::zero() {
        return Err("Overflow not possible");
    }

    // Compute x0 that will overflow: this means 2^2L - f'0 < x0 < 2^2L
    let (start, stop) = (
        BigUint::two_to_2limb() - neg_foreign_field_modulus(0),
        BigUint::two_to_2limb(),
    );

    let x0 = rng.gen_biguint_range(&start, &stop);

    // Compute overflow bit
    let (o0, _) = (x0.clone() + neg_foreign_field_modulus(0)).div_rem(&BigUint::two_to_2limb());

    // Compute x1: this means x2 < 2^L - o01 - f'1 AND  x2 < (f - x01)/2^2L
    let (start, stop) = (
        BigUint::zero(),
        std::cmp::min(
            BigUint::two_to_limb() - o0 - neg_foreign_field_modulus(1),
            (foreign_field_modulus - x0.clone()) / BigUint::two_to_2limb(),
        ),
    );
    let x1 = rng.gen_biguint_range(&start, &stop);
    return Ok([x0, x1].compose());
}

fn test_rand_foreign_field_element_with_bound_overflows<F: PrimeField>(
    rng: &mut StdRng,
    foreign_field_modulus: &BigUint,
) {
    let neg_foreign_field_modulus = foreign_field_modulus.negate();

    // Select a random x that would overflow on lowest limb
    let x = rand_foreign_field_element_with_bound_overflows::<F>(rng, &foreign_field_modulus)
        .expect("Failed to get element with bound overflow");

    // Check it obeys the modulus
    assert!(x < *foreign_field_modulus);

    // Compute bound directly as BigUint
    let bound = foreign_field_mul::witness::compute_bound(&x, &neg_foreign_field_modulus.clone());

    // Compute bound separately on limbs
    let sums: [F; 2] = foreign_field_mul::circuitgates::compute_intermediate_sums(
        &x.to_field_limbs::<F>(),
        &neg_foreign_field_modulus.to_field_limbs(),
    );

    // Convert bound to field limbs in order to do checks
    let bound = bound.to_compact_field_limbs::<F>();

    // Check there is an overflow
    assert!(sums[0] >= F::two_to_2limb());
    assert!(sums[1] < F::two_to_limb());
    assert!(bound[0] < F::two_to_2limb());
    assert!(bound[1] < F::two_to_limb());

    // Check that limbs don't match sums
    assert_ne!(bound[0], sums[0]);
    assert_ne!(bound[1], sums[1]);
}

#[test]
// Test the multiplication of two zeros.
// This checks that small amounts get packed into limbs
fn test_zero_mul() {
    let (result, witness) = run_test(
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
    assert_eq!(witness[0][1], PallasField::zero());
    assert_eq!(witness[1][1], PallasField::zero());
    assert_eq!(witness[2][1], PallasField::zero());

    // Check quotient is zero
    assert_eq!(witness[10][0], PallasField::zero());
    assert_eq!(witness[11][0], PallasField::zero());
    assert_eq!(witness[12][0], PallasField::zero());
}

#[test]
// Test the multiplication of largest foreign element and 1
fn test_one_mul() {
    let (result, witness) = run_test(
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
    let target = secp256k1_max().to_field_limbs();
    assert_eq!(witness[0][1], target[0]);
    assert_eq!(witness[1][1], target[1]);
    assert_eq!(witness[2][1], target[2]);

    // Check quotient is zero
    assert_eq!(witness[10][0], PallasField::zero());
    assert_eq!(witness[11][0], PallasField::zero());
    assert_eq!(witness[12][0], PallasField::zero());
}

#[test]
// Test the maximum value m whose square fits in the native field
//    m^2 = q * f + r -> q should be 0 and r should be m^2 < n < f
fn test_max_native_square() {
    let (result, witness) = run_test(
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
    let product = ForeignElement::<PallasField, 3>::from_biguint(square);
    assert_eq!(witness[0][1], product[0]);
    assert_eq!(witness[1][1], product[1]);
    assert_eq!(witness[2][1], product[2]);

    // Check quotient is zero
    assert_eq!(witness[10][0], PallasField::zero());
    assert_eq!(witness[11][0], PallasField::zero());
    assert_eq!(witness[12][0], PallasField::zero());
}

#[test]
// Test the maximum value g whose square fits in the foreign field
//     g^2 = q * f + r -> q should be 0 and r should be g^2 < f
fn test_max_foreign_square() {
    let (result, witness) = run_test(
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
    let product = ForeignElement::<PallasField, 3>::from_biguint(square);
    assert_eq!(witness[0][1], product[0]);
    assert_eq!(witness[1][1], product[1]);
    assert_eq!(witness[2][1], product[2]);

    // Check quotient is zero
    assert_eq!(witness[10][0], PallasField::zero());
    assert_eq!(witness[11][0], PallasField::zero());
    assert_eq!(witness[12][0], PallasField::zero());
}

#[test]
// Test squaring the maximum native field elements
//     (n - 1) * (n - 1) = q * f + r
fn test_max_native_multiplicands() {
    let (result, witness) = run_test(
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
        [witness[0][1], witness[1][1], witness[2][1]].compose()
    );
}

#[test]
// Test squaring the maximum foreign field elements
//     (f - 1) * (f - 1) = f^2 - 2f + 1 = f * (f - 2) + 1
fn test_max_foreign_multiplicands() {
    let (result, witness) = run_test(
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
        [witness[0][1], witness[1][1], witness[2][1]].compose()
    );
}

#[test]
// Test with nonzero carry0 bits
fn test_nonzero_carry0() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

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
        let (result, witness) = run_test(false, true, false, &a, &b, &secp256k1_modulus(), vec![]);
        assert_eq!(result, Ok(()));
        assert_ne!(witness[9][0], PallasField::zero()); // carry0 is not zero
        assert_eq!(
            &a * &b % secp256k1_modulus(),
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );

        // Invalid carry0 witness test
        let (result, witness) = run_test(
            false,
            true,
            false,
            &a,
            &b,
            &secp256k1_modulus(),
            vec![((0, 9), PallasField::zero())], // Invalidate carry0
        );
        // The 4th constraint (i.e. C5) should fail
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 4))
        );
        assert_eq!(
            a * b % secp256k1_modulus(),
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
    }
}

#[test]
// Test with nonzero carry10 (this targets only carry10)
fn test_nonzero_carry10() {
    // Max modulus
    let foreign_modulus = BigUint::two().pow(259u32);

    // Maximum quotient
    let q = &foreign_modulus - BigUint::one();

    // Compute operands
    let a = &foreign_modulus / BigUint::two().pow(5);
    let b = (&q * &foreign_modulus) / &a;

    // Valid witness test
    let (result, witness) = run_test(false, true, false, &a, &b, &foreign_modulus, vec![]);
    assert_eq!(result, Ok(()));
    assert_ne!(witness[6][0], PallasField::zero()); // carry10 is definitely not zero
    assert_eq!(
        &a * &b % &foreign_modulus,
        [witness[0][1], witness[1][1], witness[2][1]].compose()
    );

    // Invalid carry0 witness test
    let (result, witness) = run_test(
        false,
        false, // Disable copy constraints so we can catch carry10 custom constraint failure
        false,
        &a,
        &b,
        &foreign_modulus,
        vec![((0, 6), PallasField::zero())], // Invalidate carry10
    );
    // The 6th constraint (i.e. C9) should fail
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 6))
    );
    assert_eq!(
        a * b % &foreign_modulus,
        [witness[0][1], witness[1][1], witness[2][1]].compose()
    );
}

#[test]
// Test with nonzero carry11
fn test_nonzero_carry11() {
    // Big (rubbish) modulus
    let foreign_modulus = BigUint::two().pow(259u32) - BigUint::one();

    // Maximum quotient
    let q = &foreign_modulus - BigUint::one();

    // Compute operands
    let a = &foreign_modulus / BigUint::two().pow(4);
    let b = (&q * &foreign_modulus) / &a;

    // Valid witness test
    let (result, witness) = run_test(false, true, false, &a, &b, &foreign_modulus, vec![]);
    assert_eq!(result, Ok(()));
    assert_ne!(witness[7][0], PallasField::zero()); // carry11 is definitely not zero
    assert_eq!(
        &a * &b % &foreign_modulus,
        [witness[0][1], witness[1][1], witness[2][1]].compose()
    );

    // Invalid carry11 witness test
    let (result, witness) = run_test(
        false,
        false, // Disable copy constraints so we can catch carry11 custom constraint failure
        false,
        &a,
        &b,
        &foreign_modulus,
        vec![((0, 7), PallasField::zero()), ((0, 8), PallasField::zero())], // Invalidate carry11 and make scaled_carry11 match
    );
    // The 6th constraint (i.e. C9) should fail
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 6))
    );
    assert_eq!(
        a * b % &foreign_modulus,
        [witness[0][1], witness[1][1], witness[2][1]].compose()
    );
}

#[test]
// Test with nonzero second bit of carry11
fn test_nonzero_second_bit_carry11() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let a = rng.gen_biguint_range(
        &(secp256k1_modulus() - BigUint::two().pow(64)),
        &secp256k1_modulus(),
    );
    let b = secp256k1_max();

    // Valid witness test
    let (result, witness) = run_test(false, true, false, &a, &b, &secp256k1_modulus(), vec![]);
    assert_eq!(result, Ok(()));
    assert_eq!(witness[7][0], PallasField::from(2u32)); // carry11 is not zero
    assert_eq!(
        &a * &b % secp256k1_modulus(),
        [witness[0][1], witness[1][1], witness[2][1]].compose()
    );

    // Invalid carry11 witness test
    let (result, witness) = run_test(
        false,
        false, // Disable copy constraints so we can catch carry11 custom constraint failure
        false,
        &a,
        &b,
        &secp256k1_modulus(),
        vec![
            ((0, 7), PallasField::one()),
            ((0, 8), PallasField::from(512u32)),
        ], // Invalidate carry11 and make scaled_carry11 match
    );
    // The 6th constraint (i.e. C9) should fail
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 6))
    );
    assert_eq!(
        a * b % secp256k1_modulus(),
        [witness[0][1], witness[1][1], witness[2][1]].compose()
    );
}

#[test]
// Test invalid carry11 scaling
fn test_invalid_carry11_scaling() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let a = rng.gen_biguint_range(
        &(secp256k1_modulus() - BigUint::two().pow(64)),
        &secp256k1_modulus(),
    );
    let b = rng.gen_biguint_range(
        &(secp256k1_modulus() - BigUint::two().pow(128)),
        &secp256k1_modulus(),
    );

    // Valid witness test
    let (result, witness) = run_test(false, true, false, &a, &b, &secp256k1_modulus(), vec![]);
    assert_eq!(result, Ok(()));
    assert_eq!(witness[7][0], PallasField::one()); // carry11 is 1
    assert_eq!(
        &a * &b % secp256k1_modulus(),
        [witness[0][1], witness[1][1], witness[2][1]].compose()
    );

    // Invalid carry11 witness test
    let (result, witness) = run_test(
        false,
        false, // Disable copy constraints so we can catch scaled_carry11 custom constraint failure
        false,
        &a,
        &b,
        &secp256k1_modulus(),
        vec![((0, 8), PallasField::from(2u32))], // Invalidate scaled_carry11
    );
    // The 5th constraint (i.e. C8) should fail
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 5))
    );
    assert_eq!(
        a * b % secp256k1_modulus(),
        [witness[0][1], witness[1][1], witness[2][1]].compose()
    );
}

#[test]
#[should_panic]
// Test invalid carry11 range
fn test_invalid_carry11_plookup() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let a = rng.gen_biguint_range(
        &(secp256k1_modulus() - BigUint::two().pow(96)),
        &secp256k1_modulus(),
    );
    let b = rng.gen_biguint_range(
        &(secp256k1_modulus() - BigUint::two().pow(96)),
        &secp256k1_modulus(),
    );

    // Valid witness test
    let (result, witness) = run_test(
        false, // positive full checks done as part of negative tests below
        false,
        true,
        &a,
        &b,
        &secp256k1_modulus(),
        vec![]
    );
    assert_eq!(result, Ok(()));
    assert_eq!(witness[7][0], PallasField::one()); // carry11 is 1
    assert_eq!(
        &a * &b % secp256k1_modulus(),
        [witness[0][1], witness[1][1], witness[2][1]].compose()
    );

    // Invalid carry11 witness test
    let (_, _) = run_test(
        true,
        false, // Disable copy constraints so we can catch carry11 plookup failure
        true,  // Target tests at lookup constraints
        &a,
        &b,
        &secp256k1_modulus(),
        vec![
            ((0, 7), PallasField::from(2u32).pow(&[12u64])),
        ], // Make carry11 13 bits long
    );
    // Above should panic
}

#[test]
#[should_panic]
// Test invalid scaled_carry11 range
fn test_invalid_scaled_carry11_plookup() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let a = rng.gen_biguint_range(
        &(secp256k1_modulus() - BigUint::two().pow(96)),
        &secp256k1_modulus(),
    );
    let b = rng.gen_biguint_range(
        &(secp256k1_modulus() - BigUint::two().pow(96)),
        &secp256k1_modulus(),
    );

    // Valid witness test
    let (result, witness) = run_test(
        false, // positive full checks done as part of negative tests below
        false,
        true,
        &a,
        &b,
        &secp256k1_modulus(),
        vec![]
    );
    assert_eq!(result, Ok(()));
    assert_eq!(witness[8][0], PallasField::from(512u32)); // scaled_carry11 is 512
    assert_eq!(
        &a * &b % secp256k1_modulus(),
        [witness[0][1], witness[1][1], witness[2][1]].compose()
    );

    // Invalid scaled_carry11 witness test
    let (_, _) = run_test(
        true,
        false, // Disable copy constraints so we can catch carry11 plookup failure
        true,  // Target tests at lookup constraints
        &a,
        &b,
        &secp256k1_modulus(),
        vec![
            ((0, 8), PallasField::from(2u32).pow(&[12u64])),
        ], // Make scaled_carry11 13 bits long
    );
    // Above should panic
}

#[test]
// Test witness with invalid quotient fails verification
fn test_zero_mul_invalid_quotient() {
    let (result, _) = run_test(
        false,
        true,
        false,
        &BigUint::zero(),
        &BigUint::zero(),
        &secp256k1_modulus(),
        vec![((0, 10), PallasField::one())], // Invalidate q0
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 4)),
    );

    let (result, _) = run_test(
        false,
        true,
        false,
        &BigUint::zero(),
        &BigUint::zero(),
        &secp256k1_modulus(),
        vec![((0, 11), PallasField::one())], // Invalidate q1
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 2)),
    );

    let (result, _) = run_test(
        false,
        true,
        false,
        &BigUint::zero(),
        &BigUint::zero(),
        &secp256k1_modulus(),
        vec![((0, 12), PallasField::one())], // Invalidate q2
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 6))
    );

    let (result, _) = run_test(
        false,
        true,
        false,
        &secp256k1_sqrt(),
        &secp256k1_sqrt(),
        &secp256k1_modulus(),
        vec![((0, 10), PallasField::one())], // Invalidate q0
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 4))
    );

    let (result, _) = run_test(
        false,
        true,
        false,
        &secp256k1_sqrt(),
        &secp256k1_sqrt(),
        &secp256k1_modulus(),
        vec![((0, 11), PallasField::one())], // Invalidate q1
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 2))
    );

    let (result, _) = run_test(
        false,
        true,
        false,
        &secp256k1_sqrt(),
        &secp256k1_sqrt(),
        &secp256k1_modulus(),
        vec![((0, 12), PallasField::one())], // Invalidate q2
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 6))
    );
}

#[test]
// Test witness with invalid remainder fails
fn test_mul_invalid_remainder() {
    for col in 0..1 {
        let (result, _) = run_test(
            false,
            false,
            false,
            &secp256k1_sqrt(),
            &secp256k1_sqrt(),
            &secp256k1_modulus(),
            vec![((1, col), PallasField::zero())], // Invalidate ri
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 4))
        );
    }

    let (result, _) = run_test(
        false,
        false,
        false,
        &secp256k1_sqrt(),
        &secp256k1_sqrt(),
        &secp256k1_modulus(),
        vec![((1, 2), PallasField::one())], // Invalidate r2
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 6))
    );
}

#[test]
// Test multiplying some random values and invalidating carry1_lo
fn test_random_multiplicands_1() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    for _ in 0..10 {
        let left_input = rng.gen_biguint_range(&BigUint::zero(), &secp256k1_max());
        let right_input = rng.gen_biguint_range(&BigUint::zero(), &secp256k1_max());

        let (result, witness) = run_test(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((0, 4), PallasField::one())], // Invalidate carry1_lo
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 2)),
        );
    }
}

#[test]
// Tests targeting each custom constraint
fn test_custom_constraints() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    for _ in 0..3 {
        let left_input = rng.gen_biguint_range(&BigUint::zero(), &secp256k1_max());
        let right_input = rng.gen_biguint_range(&BigUint::zero(), &secp256k1_max());

        // Test 1st constraint (C1): invalidate product1_hi_1 is in [0, 2^2)
        let (result, witness) = run_test(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((1, 7), PallasField::from(4u32))], // Invalidate product1_hi_1
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 1)),
        );

        // Test 2nd constraint (C3): invalidate middle intermediate product p1 decomposition
        let (result, witness) = run_test(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((1, 5), PallasField::one())], // Invalidate product1_lo
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 2)),
        );

        // Test 3rd constraint (C4): invalidate carry0 in [0, 2^2)
        let (result, witness) = run_test(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((0, 9), PallasField::from(4u32))], // Invalidate carry0
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 3)),
        );

        // Test 4th constraint (C5): invalidate carry0
        let (result, witness) = run_test(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((0, 9), PallasField::from(3u32))], // Invalidate carry0
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 4)),
        );

        // Test 5th constraint (C8): invalidate scaled_carry1_hi
        let (result, witness) = run_test(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((0, 8), PallasField::one())], // Invalidate scaled_carry1_hi
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 5)),
        );

        // Test 6th constraint (C9): invalidate first zero check
        let (result, witness) = run_test(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((0, 6), PallasField::one())], // Invalidate carry1_lo
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 6)),
        );

        // TODO: Test 7th constraint (C10): invalid native modulus check but binary modulus checks ok

        // Test 8th constraint (C12): invalidate q'_carry01 is boolean
        let (result, witness) = run_test(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((0, 13), PallasField::from(2u32))], // Make q'_carry01 non-boolean
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 8)),
        );

        // Test 9th constraint (C13): invalidate first bound addition zero check
        let (result, witness) = run_test(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((0, 13), PallasField::from(1u32))], // Make q'_carry01 invalid
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 9)),
        );

        // Test 10th constraint (C14): invalidate q'_carry2 is boolean
        let (result, witness) = run_test(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((0, 14), PallasField::from(2u32))], // Make q'_carry2 non-boolean
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 10)),
        );

        // Test 11th constraint (C15): invalidate second bound addition zero check
        let (result, witness) = run_test(
            false,
            false,
            false,
            &left_input,
            &right_input,
            &secp256k1_modulus(),
            vec![((0, 14), PallasField::one())], // invalidate q'_carry2
        );
        assert_eq!(
            (&left_input * &right_input) % secp256k1_modulus(),
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 11)),
        );
    }
}

#[test]
// Test with secp256k1 modulus
fn test_rand_foreign_field_element_with_bound_overflows_1() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    for _ in 0..1000 {
        test_rand_foreign_field_element_with_bound_overflows::<PallasField>(
            rng,
            &secp256k1_modulus(),
        );
    }
}

#[test]
// Modulus where lowest limb is non-zero
fn test_rand_foreign_field_element_with_bound_overflows_2() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    for _ in 0..1000 {
        test_rand_foreign_field_element_with_bound_overflows::<PallasField>(
            rng,
            &(BigUint::from(2u32).pow(259) - BigUint::one()),
        );
    }
}

#[test]
//  Made up modulus where lowest limb is non-zero
fn test_rand_foreign_field_element_with_bound_overflows_3() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    for _ in 0..1000 {
        test_rand_foreign_field_element_with_bound_overflows::<PallasField>(
            rng,
            &(BigUint::from(2u32).pow(259) / BigUint::from(382734983107u64)),
        );
    }
}

#[test]
//  Real modulus where lowest limb is non-zero
fn test_rand_foreign_field_element_with_bound_overflows_4() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    for _ in 0..1000 {
        test_rand_foreign_field_element_with_bound_overflows::<PallasField>(
            rng,
            &(PallasField::modulus_biguint()),
        );
    }
}

#[test]
//  Another real modulus where lowest limb is non-zero
fn test_rand_foreign_field_element_with_bound_overflows_5() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    for _ in 0..1000 {
        test_rand_foreign_field_element_with_bound_overflows::<PallasField>(
            rng,
            &(VestaField::modulus_biguint()),
        );
    }
}

#[test]
#[should_panic]
// Foreign field modulus too small
fn test_rand_foreign_field_element_with_bound_overflows_6() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    test_rand_foreign_field_element_with_bound_overflows::<PallasField>(
        rng,
        &(BigUint::binary_modulus().sqrt()),
    );
}

#[test]
#[should_panic]
// Cannot have overflow when f'0 is zero
fn test_rand_foreign_field_element_with_bound_overflows_7() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    rand_foreign_field_element_with_bound_overflows::<PallasField>(
        rng,
        &BigUint::from(2u32).pow(257),
    )
    .expect("Failed to get element with bound overflow");
}
