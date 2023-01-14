use std::ops::Div;

use crate::{
    auto_clone_array,
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, CircuitGateError, CircuitGateResult, Connect, GateType},
        polynomial::COLUMNS,
        polynomials::{foreign_field_add::witness::FFOps, foreign_field_mul, range_check},
        wires::Wire,
    },
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
    tests::framework::TestFramework,
};
use ark_ec::AffineCurve;
use ark_ff::{Field, PrimeField, Zero};
use mina_curves::pasta::{Fp, Fq, Pallas, PallasParameters, Vesta, VestaParameters};
use num_bigint::BigUint;
use num_traits::One;
use o1_utils::{
    foreign_field::{
        BigUintArrayCompose, BigUintForeignFieldHelpers, FieldArrayCompose, ForeignElement,
        ForeignFieldHelpers,
    },
    FieldHelpers,
};

use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use num_bigint::RandBigInt;
use rand::{rngs::StdRng, SeedableRng};

type PallasField = <Pallas as AffineCurve>::BaseField;
type VestaField = <Vesta as AffineCurve>::BaseField;

type SpongeParams = PlonkSpongeConstantsKimchi;
type VestaBaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type VestaScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
type PallasBaseSponge = DefaultFqSponge<PallasParameters, SpongeParams>;
type PallasScalarSponge = DefaultFrSponge<Fq, SpongeParams>;

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
fn run_test<G: KimchiCurve, EFqSponge, EFrSponge>(
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
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    // Create foreign field multiplication gates
    let (mut next_row, mut gates) =
        CircuitGate::<G::ScalarField>::create_foreign_field_mul(0, foreign_field_modulus);

    // Compute multiplication witness
    let (mut witness, external_checks) =
        foreign_field_mul::witness::create(left_input, right_input, foreign_field_modulus);

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
        CircuitGate::extend_single_ffadd(
            &mut gates,
            &mut next_row,
            FFOps::Add,
            foreign_field_modulus,
        );
        gates.connect_cell_pair((1, 0), (2, 0));
        gates.connect_cell_pair((1, 1), (2, 1));
        gates.connect_cell_pair((1, 2), (2, 2));
        external_checks
            .extend_witness_bound_addition(&mut witness, &foreign_field_modulus.to_field_limbs());

        // Left input multi-range-check
        CircuitGate::extend_multi_range_check(&mut gates, &mut next_row);
        gates.connect_cell_pair((0, 0), (4, 0));
        gates.connect_cell_pair((0, 1), (5, 0));
        gates.connect_cell_pair((0, 2), (6, 0));
        range_check::witness::extend_multi_limbs(&mut witness, &left_input.to_field_limbs());

        // Right input multi-range-check
        CircuitGate::extend_multi_range_check(&mut gates, &mut next_row);
        gates.connect_cell_pair((0, 3), (8, 0));
        gates.connect_cell_pair((0, 4), (9, 0));
        gates.connect_cell_pair((0, 5), (10, 0));
        range_check::witness::extend_multi_limbs(&mut witness, &right_input.to_field_limbs());

        // Multiplication witness value product1_lo, product1_hi_0, carry1_lo multi-range-check
        CircuitGate::extend_multi_range_check(&mut gates, &mut next_row);
        gates.connect_cell_pair((0, 6), (12, 0)); // carry1_lo
        gates.connect_cell_pair((1, 5), (13, 0)); // product1_lo
        gates.connect_cell_pair((1, 6), (14, 0)); // product1_hi_0
                                                  // Witness updated below

        // Result/remainder bound multi-range-check
        CircuitGate::extend_multi_range_check(&mut gates, &mut next_row);
        gates.connect_ffadd_range_checks(2, None, None, 16);
        // Witness updated below

        // Add witness for external multi-range checks (product1_lo, product1_hi_0, carry1_lo and result)
        external_checks.extend_witness_multi_range_checks(&mut witness);

        // Quotient bound multi-range-check
        CircuitGate::extend_compact_multi_range_check(&mut gates, &mut next_row);
        gates.connect_cell_pair((1, 3), (22, 1));
        gates.connect_cell_pair((1, 4), (20, 0));
        external_checks.extend_witness_compact_multi_range_checks(&mut witness);
    }

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    let runner = if full {
        // Create prover index with test framework
        Some(
            TestFramework::<G>::default()
                .disable_gates_checks(disable_gates_checks)
                .gates(gates.clone())
                .witness(witness.clone())
                .lookup_tables(vec![foreign_field_mul::gadget::lookup_table()])
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
            return (result, witness);
        }
    }

    println!("witness[7][0] = {}", witness[7][0].to_biguint());
    if let Some(runner) = runner {
        // Perform full test that everything is ok before invalidation
        assert_eq!(runner.prove_and_verify::<EFqSponge, EFrSponge>(), Ok(()));
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
                let result =
                    gate.verify_witness::<G>(row, &witness, &cs, &witness[0][0..cs.public]);
                if result.is_err() {
                    return (result, witness);
                }
            }
        }

        // Run test on invalid witness
        if full {
            match TestFramework::<G>::default()
                .disable_gates_checks(disable_gates_checks)
                .gates(gates.clone())
                .witness(witness.clone())
                .lookup_tables(vec![foreign_field_mul::gadget::lookup_table()])
                .setup()
                .prove_and_verify::<EFqSponge, EFrSponge>()
            {
                Err(err_msg) => {
                    if err_msg == *"the lookup failed to find a match in the table" {
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
/// This proof means that, since they are never used, we can safely remove the witness for the carry bit of
/// addition of the most significant bound addition limbs and its corresponding boolean constraint.
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
    let o0 = (x0.clone() + neg_foreign_field_modulus(0)).div(&BigUint::two_to_2limb());

    // Compute x1: this means x2 < 2^L - o01 - f'1 AND  x2 < (f - x01)/2^2L
    let (start, stop) = (
        BigUint::zero(),
        std::cmp::min(
            BigUint::two_to_limb() - o0 - neg_foreign_field_modulus(1),
            (foreign_field_modulus - x0.clone()) / BigUint::two_to_2limb(),
        ),
    );
    let x1 = rng.gen_biguint_range(&start, &stop);
    Ok([x0, x1].compose())
}

fn test_rand_foreign_field_element_with_bound_overflows<F: PrimeField>(
    rng: &mut StdRng,
    foreign_field_modulus: &BigUint,
) {
    let neg_foreign_field_modulus = foreign_field_modulus.negate();

    // Select a random x that would overflow on lowest limb
    let x = rand_foreign_field_element_with_bound_overflows::<F>(rng, foreign_field_modulus)
        .expect("Failed to get element with bound overflow");

    // Check it obeys the modulus
    assert!(x < *foreign_field_modulus);

    // Compute bound directly as BigUint
    let bound = foreign_field_mul::witness::compute_bound(&x, &neg_foreign_field_modulus);

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

// Test targeting each custom constraint (positive and negative tests for each)
fn test_custom_constraints<G: KimchiCurve, EFqSponge, EFrSponge>(foreign_field_modulus: &BigUint)
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    let rng = &mut StdRng::from_seed(RNG_SEED);

    for _ in 0..3 {
        let left_input = rng.gen_biguint_range(&BigUint::zero(), foreign_field_modulus);
        let right_input = rng.gen_biguint_range(&BigUint::zero(), foreign_field_modulus);

        // Test 1st constraint (C1): invalidate product1_hi_1 is in [0, 2^2)
        let (result, witness) = run_test::<G, EFqSponge, EFrSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            foreign_field_modulus,
            vec![((0, 13), G::ScalarField::from(4u32))], // Invalidate product1_hi_1
        );
        assert_eq!(
            (&left_input * &right_input) % foreign_field_modulus,
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 1)),
        );

        // Test 2nd constraint (C3): invalidate middle intermediate product p1 decomposition
        let (result, witness) = run_test::<G, EFqSponge, EFrSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            foreign_field_modulus,
            vec![((1, 5), G::ScalarField::one())], // Invalidate product1_lo
        );
        assert_eq!(
            (&left_input * &right_input) % foreign_field_modulus,
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 2)),
        );

        // Test 3rd constraint (C4): invalidate carry0 in [0, 2^2)
        let (result, witness) = run_test::<G, EFqSponge, EFrSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            foreign_field_modulus,
            vec![((0, 8), G::ScalarField::from(4u32))], // Invalidate carry0
        );
        assert_eq!(
            (&left_input * &right_input) % foreign_field_modulus,
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 3)),
        );

        // Test 4th constraint (C5): invalidate carry0
        let (result, witness) = run_test::<G, EFqSponge, EFrSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            foreign_field_modulus,
            vec![((0, 8), G::ScalarField::from(3u32))], // Invalidate carry0
        );
        assert_eq!(
            (&left_input * &right_input) % foreign_field_modulus,
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 4)),
        );

        // Test 5th constraint (C7): invalidate first zero check
        let (result, witness) = run_test::<G, EFqSponge, EFrSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            foreign_field_modulus,
            vec![((0, 6), G::ScalarField::one())], // Invalidate carry1_lo
        );
        assert_eq!(
            (&left_input * &right_input) % foreign_field_modulus,
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 5)),
        );

        // Test 6th constraint (C8): invalid native modulus check but binary modulus checks ok
        //     Triggering constraint C8 is challenging, so this is done with
        //     the test_native_modulus_constraint() test below

        // Test 7th constraint (C10): invalidate q'_carry is boolean
        let (result, witness) = run_test::<G, EFqSponge, EFrSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            foreign_field_modulus,
            vec![((0, 12), G::ScalarField::from(2u32))], // Make q'_carry non-boolean
        );
        assert_eq!(
            (&left_input * &right_input) % foreign_field_modulus,
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 7)),
        );

        // Test 8th constraint (C11): invalidate first bound addition zero check
        let (result, witness) = run_test::<G, EFqSponge, EFrSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            foreign_field_modulus,
            vec![((0, 12), G::ScalarField::one())], // Make q'_carry invalid
        );
        assert_eq!(
            (&left_input * &right_input) % foreign_field_modulus,
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 8)),
        );

        // Test 9th constraint (C12): invalidate second bound addition zero check
        let (result, witness) = run_test::<G, EFqSponge, EFrSponge>(
            false,
            false,
            false,
            &left_input,
            &right_input,
            foreign_field_modulus,
            vec![((1, 4), G::ScalarField::zero())], // Make quotient_bound2 invalid
        );
        assert_eq!(
            (&left_input * &right_input) % foreign_field_modulus,
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(
            result,
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 9)),
        );
    }
}

#[test]
// Test the multiplication of two zeros.
// This checks that small amounts get packed into limbs
fn test_zero_mul() {
    let (result, witness) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
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
    let (result, witness) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
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
    let (result, witness) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
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
    let (result, witness) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
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
    let (result, witness) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
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
    let (result, witness) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        true,
        false,
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
        let (result, witness) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
            false,
            true,
            false,
            &a,
            &b,
            &secp256k1_modulus(),
            vec![],
        );
        assert_eq!(result, Ok(()));
        assert_ne!(witness[9][0], PallasField::zero()); // carry0 is not zero
        assert_eq!(
            &a * &b % secp256k1_modulus(),
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );

        // Invalid carry0 witness test
        let (result, witness) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
            false,
            true,
            false,
            &a,
            &b,
            &secp256k1_modulus(),
            vec![((0, 8), PallasField::zero())], // Invalidate carry0
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
    let foreign_field_modulus = BigUint::two().pow(259u32);

    // Maximum quotient
    let q = &foreign_field_modulus - BigUint::one();

    // Compute operands
    let a = &foreign_field_modulus / BigUint::two().pow(5);
    let b = (&q * &foreign_field_modulus) / &a;

    // Valid witness test
    let (result, witness) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        true,
        false,
        &a,
        &b,
        &foreign_field_modulus,
        vec![],
    );
    assert_eq!(result, Ok(()));
    assert_ne!(witness[6][0], PallasField::zero()); // carry10 is definitely not zero
    assert_eq!(
        &a * &b % &foreign_field_modulus,
        [witness[0][1], witness[1][1], witness[2][1]].compose()
    );

    // Invalid carry0 witness test
    let (result, witness) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        false, // Disable copy constraints so we can catch carry10 custom constraint failure
        false,
        &a,
        &b,
        &foreign_field_modulus,
        vec![((0, 6), PallasField::zero())], // Invalidate carry10
    );
    // The 5th constraint (i.e. C7) should fail
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 5))
    );
    assert_eq!(
        a * b % &foreign_field_modulus,
        [witness[0][1], witness[1][1], witness[2][1]].compose()
    );
}

#[test]
// Test with nonzero carry1_hi
fn test_nonzero_carry1_hi() {
    // Big (rubbish) modulus
    let foreign_field_modulus = BigUint::two().pow(259u32) - BigUint::one();

    // Maximum quotient
    let q = &foreign_field_modulus - BigUint::one();

    // Compute operands
    let a = &foreign_field_modulus / BigUint::two().pow(4);
    let b = (&q * &foreign_field_modulus) / &a;

    // Valid witness test
    let (result, witness) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        true,
        false,
        &a,
        &b,
        &foreign_field_modulus,
        vec![],
    );
    assert_eq!(result, Ok(()));
    assert_ne!(witness[7][0], PallasField::zero()); // carry1_hi is definitely not zero
    assert_eq!(
        &a * &b % &foreign_field_modulus,
        [witness[0][1], witness[1][1], witness[2][1]].compose()
    );

    // Invalid carry1_hi witness test
    let (result, witness) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        false, // Disable copy constraints so we can catch carry1_hi custom constraint failure
        false,
        &a,
        &b,
        &foreign_field_modulus,
        vec![((0, 7), PallasField::zero())], // Invalidate carry1_hi
    );
    // The 5th constraint (i.e. C7) should fail
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 5))
    );
    assert_eq!(
        a * b % &foreign_field_modulus,
        [witness[0][1], witness[1][1], witness[2][1]].compose()
    );
}

#[test]
// Test with nonzero second bit of carry1_hi
fn test_nonzero_second_bit_carry1_hi() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let a = rng.gen_biguint_range(
        &(secp256k1_modulus() - BigUint::two().pow(64)),
        &secp256k1_modulus(),
    );
    let b = secp256k1_max();

    // Valid witness test
    let (result, witness) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        true,
        false,
        &a,
        &b,
        &secp256k1_modulus(),
        vec![],
    );
    assert_eq!(result, Ok(()));
    assert_eq!(witness[7][0], PallasField::from(2u32)); // carry1_hi is not zero
    assert_eq!(
        &a * &b % secp256k1_modulus(),
        [witness[0][1], witness[1][1], witness[2][1]].compose()
    );

    // Invalid carry1_hi witness test
    let (result, witness) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        false, // Disable copy constraints so we can catch carry1_hi custom constraint failure
        false,
        &a,
        &b,
        &secp256k1_modulus(),
        vec![((0, 7), PallasField::one())], // Invalidate carry1_hi
    );
    // The 5th constraint (i.e. C7) should fail
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
// Test invalid carry1_hi range
fn test_invalid_carry1_hi_plookup() {
    let a = BigUint::zero();
    let b = BigUint::zero();

    // Invalid carry1_hi witness test
    let (result, _) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        true,
        false, // Disable external checks so we can catch carry1_hi plookup failure
        true,  // Target tests at lookup constraints only
        &a,
        &b,
        &secp256k1_modulus(),
        vec![
            ((0, 7), PallasField::from(8u32)), // carry1_hi > 3 bits (invalid)
        ],
    );
    assert_eq!(
        result,
        Err(CircuitGateError::InvalidLookupConstraint(
            GateType::ForeignFieldMul
        )),
    );
}

#[test]
fn test_invalid_wraparound_carry1_hi_plookup() {
    let a = BigUint::zero();
    let b = BigUint::zero();

    // Sanity check wraparound values
    let two_to_9 = PallasField::from(2u32).pow(&[9]);
    // Wraparound (exploit) value x s.t. x >= 2^12 AND 2^9 * x < 2^12
    // (credit to querolita for computing the real instances of this value for these test cases!)
    let wraparound_0 = two_to_9.inverse().expect("failed to get inverse");
    for i in 0..8 {
        let wraparound_i = wraparound_0 + PallasField::from(i);
        assert!(wraparound_i >= PallasField::from(2u32).pow(&[12u64]));
        assert!(two_to_9 * wraparound_i < PallasField::from(2u32).pow(&[12u64]));
        // Wraparound!!!
    }
    // edge case: x - 1 is not a wraparound value
    assert!(wraparound_0 - PallasField::one() >= PallasField::from(2u32).pow(&[12u64]));
    assert!(
        two_to_9 * (wraparound_0 - PallasField::one()) >= PallasField::from(2u32).pow(&[12u64])
    );
    // edge case: x + 8 is not a wraparound value
    assert!(wraparound_0 + PallasField::from(8) >= PallasField::from(2u32).pow(&[12u64]));
    assert!(
        two_to_9 * (wraparound_0 + PallasField::from(8)) >= PallasField::from(2u32).pow(&[12u64])
    );

    // Invalid carry1_hi witness that causes wrap around to something less than 3-bits
    let (result, witness) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        true,
        false, // Disable external checks so we can catch carry1_hi plookup failure
        true,  // Target tests at lookup constraints only
        &a,
        &b,
        &secp256k1_modulus(),
        vec![
            // Invalidate carry1_hi by wrapping
            // carry1_hi > 12 bits > 3 bits, but wraps around < 12-bits when scaled by 2^9
            (
                (0, 7),
                PallasField::from(512u32) // wraparound_0 + 1
                    .inverse()
                    .expect("failed to get inverse"),
            ),
        ],
    );
    assert!(witness[7][0] >= PallasField::from(2u32).pow(&[12u64]));
    assert!(two_to_9 * witness[7][0] < PallasField::from(2u32).pow(&[12u64]));
    assert_eq!(
        result,
        Err(CircuitGateError::InvalidLookupConstraint(
            GateType::ForeignFieldMul
        )),
    );
}

#[test]
// Test witness with invalid quotient fails verification
fn test_zero_mul_invalid_quotient() {
    let (result, _) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        true,
        false,
        &BigUint::zero(),
        &BigUint::zero(),
        &secp256k1_modulus(),
        vec![((0, 9), PallasField::one())], // Invalidate q0
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 4)),
    );

    let (result, _) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        true,
        false,
        &BigUint::zero(),
        &BigUint::zero(),
        &secp256k1_modulus(),
        vec![((0, 10), PallasField::one())], // Invalidate q1
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 2)),
    );

    let (result, _) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        true,
        false,
        &BigUint::zero(),
        &BigUint::zero(),
        &secp256k1_modulus(),
        vec![((0, 11), PallasField::one())], // Invalidate q2
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 5))
    );

    let (result, _) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        true,
        false,
        &secp256k1_sqrt(),
        &secp256k1_sqrt(),
        &secp256k1_modulus(),
        vec![((0, 9), PallasField::one())], // Invalidate q0
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 4))
    );

    let (result, _) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        true,
        false,
        &secp256k1_sqrt(),
        &secp256k1_sqrt(),
        &secp256k1_modulus(),
        vec![((0, 10), PallasField::one())], // Invalidate q1
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 2))
    );

    let (result, _) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        true,
        false,
        &secp256k1_sqrt(),
        &secp256k1_sqrt(),
        &secp256k1_modulus(),
        vec![((0, 11), PallasField::one())], // Invalidate q2
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 5))
    );
}

#[test]
// Test witness with invalid remainder fails
fn test_mul_invalid_remainder() {
    for col in 0..1 {
        let (result, _) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
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

    let (result, _) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
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
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 5))
    );
}

#[test]
// Test multiplying some random values and invalidating carry1_lo
fn test_random_multiplicands_carry1_lo() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    for _ in 0..10 {
        let left_input = rng.gen_biguint_range(&BigUint::zero(), &secp256k1_max());
        let right_input = rng.gen_biguint_range(&BigUint::zero(), &secp256k1_max());

        let (result, witness) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
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
            Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 5)),
        );
    }
}

#[test]
// Test multiplying some random values with secp256k1 foreign modulus
fn test_random_multiplicands_valid() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    for _ in 0..10 {
        let left_input = rng.gen_biguint_range(&BigUint::zero(), &secp256k1_max());
        let right_input = rng.gen_biguint_range(&BigUint::zero(), &secp256k1_max());

        let (result, witness) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
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
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(result, Ok(()),);
    }
}

#[test]
// Test multiplying some random values with foreign modulus smaller than native modulus
fn test_smaller_foreign_field_modulus() {
    let foreign_field_modulus = BigUint::two().pow(252u32) - BigUint::one();

    let rng = &mut StdRng::from_seed(RNG_SEED);

    for _ in 0..10 {
        let left_input = rng.gen_biguint_range(&BigUint::zero(), &foreign_field_modulus);
        let right_input = rng.gen_biguint_range(&BigUint::zero(), &foreign_field_modulus);

        let (result, witness) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
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
            [witness[0][1], witness[1][1], witness[2][1]].compose()
        );
        assert_eq!(result, Ok(()),);
    }
}

#[test]
// Tests targeting each custom constraint with secp256k1 (foreign field modulus)
// on Vesta (native field modulus)
fn test_custom_constraints_secp256k1_on_vesta() {
    test_custom_constraints::<Vesta, VestaBaseSponge, VestaScalarSponge>(&secp256k1_modulus());
}

#[test]
// Tests targeting each custom constraint with secp256k1 (foreign field modulus)
// on Pallas (native field modulus)
fn test_custom_constraints_secp256k1_on_pallas() {
    test_custom_constraints::<Pallas, PallasBaseSponge, PallasScalarSponge>(&secp256k1_modulus());
}

#[test]
// Tests targeting each custom constraint with Vesta (foreign field modulus) on Pallas (native field modulus)
fn test_custom_constraints_vesta_on_pallas() {
    test_custom_constraints::<Pallas, PallasBaseSponge, PallasScalarSponge>(
        &VestaField::modulus_biguint(),
    );
}

#[test]
// Tests targeting each custom constraint with Pallas (foreign field modulus) on Vesta (native field modulus)
fn test_custom_constraints_pallas_on_vesta() {
    test_custom_constraints::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        &PallasField::modulus_biguint(),
    );
}

#[test]
// Tests targeting each custom constraint with Vesta (foreign field modulus) on Vesta (native field modulus)
fn test_custom_constraints_vesta_on_vesta() {
    test_custom_constraints::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        &VestaField::modulus_biguint(),
    );
}

#[test]
// Tests targeting each custom constraint with Pallas (foreign field modulus) on Pallas (native field modulus)
fn test_custom_constraints_pallas_on_pallas() {
    test_custom_constraints::<Pallas, PallasBaseSponge, PallasScalarSponge>(
        &PallasField::modulus_biguint(),
    );
}

#[test]
// Tests targeting each custom constraint (foreign modulus smaller than native vesta)
fn test_custom_constraints_small_foreign_field_modulus_on_vesta() {
    test_custom_constraints::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        &(BigUint::two().pow(252u32) - BigUint::one()),
    );
}

#[test]
// Tests targeting each custom constraint (foreign modulus smaller than native pallas)
fn test_custom_constraints_small_foreign_field_modulus_on_pallas() {
    test_custom_constraints::<Pallas, PallasBaseSponge, PallasScalarSponge>(
        &(BigUint::two().pow(252u32) - BigUint::one()),
    );
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

#[test]
fn test_native_modulus_constraint() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let left_input = rng.gen_biguint_range(
        &(secp256k1_modulus() - BigUint::two().pow(96)),
        &secp256k1_modulus(),
    );
    let right_input = rng.gen_biguint_range(
        &(secp256k1_modulus() - BigUint::two().pow(96)),
        &secp256k1_modulus(),
    );

    let (result, _) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        false,
        false,
        &left_input,
        &right_input,
        &secp256k1_modulus(),
        vec![
            // Targeted attack on constraint 6
            ((0, 7), PallasField::from(8u32)),
            (
                (1, 2),
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
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 6))
    );
}

#[test]
fn test_constraint_c12() {
    // Attack C12 (i.e. the 9th custom constraint) another way
    let (result, _) = run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        false,
        false,
        false,
        &BigUint::zero(),
        &BigUint::zero(),
        &secp256k1_modulus(),
        vec![
            ((0, 12), PallasField::one()), // invalidate q'_carry
            (
                (1, 3),
                PallasField::from_bytes(&[
                    210, 3, 0, 0, 238, 48, 45, 153, 27, 249, 76, 9, 252, 152, 70, 34, 0, 0, 0, 0,
                    0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 63,
                ])
                .unwrap(),
            ), // Pacify 8th constraint by getting s01 - q'01 to cancel
        ],
    );
    assert_eq!(
        result,
        Err(CircuitGateError::Constraint(GateType::ForeignFieldMul, 9)),
    );
}
