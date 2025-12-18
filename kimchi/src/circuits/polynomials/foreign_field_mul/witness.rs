//! Foreign field multiplication witness computation

use crate::{
    auto_clone_array,
    circuits::{
        polynomial::COLUMNS,
        polynomials::{
            foreign_field_add,
            foreign_field_common::{
                BigUintArrayFieldHelpers, BigUintForeignFieldHelpers, FieldArrayBigUintHelpers,
                KimchiForeignElement,
            },
            range_check,
        },
        witness::{self, ConstantCell, VariableBitsCell, VariableCell, Variables, WitnessCell},
    },
    variable_map,
};
use ark_ff::{One, PrimeField};
use core::{array, ops::Div};
use num_bigint::BigUint;
use num_integer::Integer;
use o1_utils::{foreign_field::ForeignFieldHelpers, repeat_n};

use super::circuitgates;

// Witness layout
//   * The values and cell contents are in little-endian order, which
//     is important for compatibility with other gates.
//   * The witness sections for the multi range check gates should be set up
//     so that the last range checked value is the MS limb of the respective
//     foreign field element. For example, given foreign field element q
//     such that
//
//         q = q0 + 2^88 * q1 + 2^176 * q2
//
//     and multi-range-check gate witness W, where W[r][c] accesses row r
//     and column c, we should map q to W like this
//
//         W[0][0] = q0
//         W[1][0] = q1
//         W[2][0] = q2
//
//     so that most significant limb, q2, is in W[2][0].
//
fn create_layout<F: PrimeField>() -> [Vec<Box<dyn WitnessCell<F>>>; 2] {
    [
        // ForeignFieldMul row
        vec![
            // Copied for multi-range-check
            VariableCell::create("left_input0"),
            VariableCell::create("left_input1"),
            VariableCell::create("left_input2"),
            // Copied for multi-range-check
            VariableCell::create("right_input0"),
            VariableCell::create("right_input1"),
            VariableCell::create("right_input2"),
            VariableCell::create("product1_lo"), // Copied for multi-range-check
            VariableBitsCell::create("carry1", 0, Some(12)), // 12-bit lookup
            VariableBitsCell::create("carry1", 12, Some(24)), // 12-bit lookup
            VariableBitsCell::create("carry1", 24, Some(36)), // 12-bit lookup
            VariableBitsCell::create("carry1", 36, Some(48)), // 12-bit lookup
            VariableBitsCell::create("carry1", 84, Some(86)),
            VariableBitsCell::create("carry1", 86, Some(88)),
            VariableBitsCell::create("carry1", 88, Some(90)),
            VariableBitsCell::create("carry1", 90, None),
        ],
        // Zero row
        vec![
            // Copied for multi-range-check
            VariableCell::create("remainder01"),
            VariableCell::create("remainder2"),
            VariableCell::create("quotient0"),
            VariableCell::create("quotient1"),
            VariableCell::create("quotient2"),
            VariableCell::create("quotient_hi_bound"), // Copied for multi-range-check
            VariableCell::create("product1_hi_0"),     // Copied for multi-range-check
            VariableCell::create("product1_hi_1"),     // Dummy 12-bit lookup
            VariableBitsCell::create("carry1", 48, Some(60)), // 12-bit lookup
            VariableBitsCell::create("carry1", 60, Some(72)), // 12-bit lookup
            VariableBitsCell::create("carry1", 72, Some(84)), // 12-bit lookup
            VariableCell::create("carry0"),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
        ],
    ]
}

/// Perform integer bound computation for high limb x'2 = x2 + 2^l - f2 - 1
pub fn compute_high_bound(x: &BigUint, foreign_field_modulus: &BigUint) -> BigUint {
    let x_hi = &x.to_limbs()[2];
    let hi_fmod = foreign_field_modulus.to_limbs()[2].clone();
    let hi_limb = BigUint::two_to_limb() - hi_fmod - BigUint::one();
    let x_hi_bound = x_hi + hi_limb;
    assert!(x_hi_bound < BigUint::two_to_limb());
    x_hi_bound
}

/// Perform integer bound addition for all limbs x' = x + f'
pub fn compute_bound(x: &BigUint, neg_foreign_field_modulus: &BigUint) -> BigUint {
    let x_bound = x + neg_foreign_field_modulus;
    assert!(x_bound < BigUint::binary_modulus());
    x_bound
}

// Compute witness variables related to foreign field multiplication
pub(crate) fn compute_witness_variables<F: PrimeField>(
    products: &[BigUint; 3],
    remainder: &[BigUint; 3],
) -> [F; 5] {
    // Numerically this function must work on BigUints or there is something
    // wrong with our approach.  Specifically, BigUint will throw and exception
    // if a subtraction would underflow.
    //
    // By working in BigUint for this part, we implicitly check our invariant
    // that subtracting the remainder never underflows.
    //
    // See the foreign field multiplication RFC for more details.
    auto_clone_array!(products);
    auto_clone_array!(remainder);

    // C1-C2: Compute components of product1
    let (product1_hi, product1_lo) = products(1).div_rem(&BigUint::two_to_limb());
    let (product1_hi_1, product1_hi_0) = product1_hi.div_rem(&BigUint::two_to_limb());

    // C3-C5: Compute v0 = the top 2 bits of (p0 + 2^L * p10 - r0 - 2^L * r1) / 2^2L
    //   N.b. To avoid an underflow error, the equation must sum the intermediate
    //        product terms before subtracting limbs of the remainder.
    let carry0 = (products(0) + BigUint::two_to_limb() * product1_lo.clone()
        - remainder(0)
        - BigUint::two_to_limb() * remainder(1))
    .div(&BigUint::two_to_2limb());

    // C6-C7: Compute v1 = the top L + 3 bits (p2 + p11 + v0 - r2) / 2^L
    //   N.b. Same as above, to avoid an underflow error, the equation must
    //        sum the intermediate product terms before subtracting the remainder.
    let carry1 =
        (products(2) + product1_hi + carry0.clone() - remainder(2)).div(&BigUint::two_to_limb());

    // C8: witness data a, b, q, and r already present

    [product1_lo, product1_hi_0, product1_hi_1, carry0, carry1].to_fields()
}

/// Create a foreign field multiplication witness
/// Input: multiplicands left_input and right_input
pub fn create<F: PrimeField>(
    left_input: &BigUint,
    right_input: &BigUint,
    foreign_field_modulus: &BigUint,
) -> ([Vec<F>; COLUMNS], ExternalChecks<F>) {
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![]);
    let mut external_checks = ExternalChecks::<F>::default();

    // Compute quotient and remainder using foreign field modulus
    let (quotient, remainder) = (left_input * right_input).div_rem(foreign_field_modulus);

    // Compute negated foreign field modulus f' = 2^t - f public parameter
    let neg_foreign_field_modulus = foreign_field_modulus.negate();

    // Compute the intermediate products
    let products: [F; 3] = circuitgates::compute_intermediate_products(
        &left_input.to_field_limbs(),
        &right_input.to_field_limbs(),
        &quotient.to_field_limbs(),
        &neg_foreign_field_modulus.to_field_limbs(),
    );

    // Compute witness variables
    let [product1_lo, product1_hi_0, product1_hi_1, carry0, carry1] =
        compute_witness_variables(&products.to_limbs(), &remainder.to_limbs());

    // Compute high bounds for multi-range-checks on quotient and remainder, making 3 limbs (with zero)
    // Assumes that right's and left's high bounds are range checked at a different stage.
    let remainder_hi_bound = compute_high_bound(&remainder, foreign_field_modulus);
    let quotient_hi_bound = compute_high_bound(&quotient, foreign_field_modulus);

    // Track witness data for external multi-range-check quotient limbs
    external_checks.add_multi_range_check(&quotient.to_field_limbs());

    // Track witness data for external multi-range-check on certain components of quotient bound and intermediate product
    external_checks.add_multi_range_check(&[
        quotient_hi_bound.clone().into(),
        product1_lo,
        product1_hi_0,
    ]);

    // Track witness data for external multi-range-checks on quotient and remainder
    external_checks.add_compact_multi_range_check(&remainder.to_compact_field_limbs());
    // This only takes 1.33 of a row, but this can be used to aggregate 3 limbs into 1 MRC
    external_checks.add_limb_check(&remainder_hi_bound.into());
    // Extract the high limb of remainder to create a high bound check (Double generic)
    let remainder_hi = remainder.to_field_limbs()[2];
    external_checks.add_high_bound_computation(&remainder_hi);

    // NOTE: high bound checks and multi range checks for left and right should be done somewhere else

    // Extend the witness by two rows for foreign field multiplication
    for w in &mut witness {
        w.extend(repeat_n(F::zero(), 2));
    }

    // Create the foreign field multiplication witness rows
    let left_input = left_input.to_field_limbs();
    let right_input = right_input.to_field_limbs();
    let remainder = remainder.to_compact_field_limbs();
    let quotient = quotient.to_field_limbs();
    witness::init(
        &mut witness,
        0,
        &create_layout(),
        &variable_map![
            "left_input0" => left_input[0],
            "left_input1" => left_input[1],
            "left_input2" => left_input[2],
            "right_input0" => right_input[0],
            "right_input1" => right_input[1],
            "right_input2" => right_input[2],
            "remainder01" => remainder[0],
            "remainder2" => remainder[1],
            "quotient0" => quotient[0],
            "quotient1" => quotient[1],
            "quotient2" => quotient[2],
            "quotient_hi_bound" => quotient_hi_bound.into(),
            "product1_lo" => product1_lo,
            "product1_hi_0" => product1_hi_0,
            "product1_hi_1" => product1_hi_1,
            "carry0" => carry0,
            "carry1" => carry1
        ],
    );

    (witness, external_checks)
}

/// Track external check witness data
#[derive(Default)]
pub struct ExternalChecks<F: PrimeField> {
    pub multi_ranges: Vec<[F; 3]>,
    pub limb_ranges: Vec<F>,
    pub compact_multi_ranges: Vec<[F; 2]>,
    pub bounds: Vec<[F; 3]>,
    pub high_bounds: Vec<F>,
}

impl<F: PrimeField> ExternalChecks<F> {
    /// Track a bound check
    pub fn add_bound_check(&mut self, limbs: &[F; 3]) {
        self.bounds.push(*limbs);
    }

    /// Track a high bound computation
    pub fn add_high_bound_computation(&mut self, limb: &F) {
        self.high_bounds.push(*limb);
    }

    /// Track a limb-range-check
    pub fn add_limb_check(&mut self, limb: &F) {
        self.limb_ranges.push(*limb);
    }

    /// Track a multi-range-check
    pub fn add_multi_range_check(&mut self, limbs: &[F; 3]) {
        self.multi_ranges.push(*limbs);
    }

    /// Track a compact-multi-range-check
    pub fn add_compact_multi_range_check(&mut self, limbs: &[F; 2]) {
        self.compact_multi_ranges.push(*limbs);
    }

    /// Extend the witness with external multi range_checks
    pub fn extend_witness_multi_range_checks(&mut self, witness: &mut [Vec<F>; COLUMNS]) {
        for [v0, v1, v2] in self.multi_ranges.clone() {
            range_check::witness::extend_multi(witness, v0, v1, v2)
        }
        self.multi_ranges = vec![];
    }

    /// Extend the witness with external compact multi range_checks
    pub fn extend_witness_compact_multi_range_checks(&mut self, witness: &mut [Vec<F>; COLUMNS]) {
        for [v01, v2] in self.compact_multi_ranges.clone() {
            range_check::witness::extend_multi_compact(witness, v01, v2)
        }
        self.compact_multi_ranges = vec![];
    }

    /// Extend the witness with external compact multi range_checks
    pub fn extend_witness_limb_checks(&mut self, witness: &mut [Vec<F>; COLUMNS]) {
        for chunk in self.limb_ranges.clone().chunks(3) {
            // Pad with zeros if necessary
            let limbs = match chunk.len() {
                1 => [chunk[0], F::zero(), F::zero()],
                2 => [chunk[0], chunk[1], F::zero()],
                3 => [chunk[0], chunk[1], chunk[2]],
                _ => panic!("Invalid chunk length"),
            };
            range_check::witness::extend_multi(witness, limbs[0], limbs[1], limbs[2])
        }
        self.limb_ranges = vec![];
    }

    /// Extend the witness with external bound addition as foreign field addition
    pub fn extend_witness_bound_addition(
        &mut self,
        witness: &mut [Vec<F>; COLUMNS],
        foreign_field_modulus: &[F; 3],
    ) {
        for bound in self.bounds.clone() {
            foreign_field_add::witness::extend_witness_bound_addition(
                witness,
                &bound,
                foreign_field_modulus,
            );
        }
        self.bounds = vec![];
    }

    /// Extend the witness with external high bounds additions as double generic gates
    pub fn extend_witness_high_bounds_computation(
        &mut self,
        witness: &mut [Vec<F>; COLUMNS],
        foreign_field_modulus: &BigUint,
    ) {
        let hi_limb = KimchiForeignElement::<F>::two_to_limb()
            - foreign_field_modulus.to_field_limbs::<F>()[2]
            - F::one();
        for chunk in self.high_bounds.clone().chunks(2) {
            // Extend the witness for the generic gate
            for col in witness.iter_mut().take(COLUMNS) {
                col.extend(repeat_n(F::zero(), 1))
            }
            let last_row = witness[0].len() - 1;
            // Fill in with dummy if it is an odd number of bounds
            let mut pair = chunk.to_vec();
            if pair.len() == 1 {
                pair.push(F::zero());
            }
            // Fill values for the new generic row (second is dummy if odd)
            // l1 0 o1 [l2 0 o2]
            let first = pair[0] + hi_limb;
            witness[0][last_row] = pair[0];
            witness[2][last_row] = first;
            let second = pair[1] + hi_limb;
            witness[3][last_row] = pair[1];
            witness[5][last_row] = second;
        }
        // Empty the high bounds
        self.high_bounds = vec![];
    }
}
