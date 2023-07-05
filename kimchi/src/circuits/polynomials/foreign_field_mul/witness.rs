//! Foreign field multiplication witness computation

use crate::{
    auto_clone_array,
    circuits::{
        polynomial::COLUMNS,
        polynomials::{foreign_field_add, range_check},
        witness::{self, ConstantCell, VariableCell, Variables, WitnessCell},
    },
    variable_map,
};
use ark_ff::PrimeField;
use num_bigint::BigUint;
use num_integer::Integer;

use o1_utils::{
    foreign_field::{
        BigUintArrayFieldHelpers, BigUintForeignFieldHelpers, FieldArrayBigUintHelpers,
        ForeignFieldHelpers,
    },
    BigUintFieldHelpers,
};
use std::{array, ops::Div};

use super::constraints;

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
fn create_layout<F: PrimeField>() -> [[Box<dyn WitnessCell<F>>; COLUMNS]; 2] {
    [
        // ForeignFieldMul row
        [
            // Copied for multi-range-check
            VariableCell::create("left_input0"),
            VariableCell::create("left_input1"),
            VariableCell::create("left_input2"),
            // Copied for multi-range-check
            VariableCell::create("right_input0"),
            VariableCell::create("right_input1"),
            VariableCell::create("right_input2"),
            VariableCell::create("carry1_lo"), // Copied for multi-range-check
            VariableCell::create("carry1_hi"), // 12-bit lookup
            VariableCell::create("carry0"),
            VariableCell::create("product1_hi_1"),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
        ],
        // Zero row
        [
            // Copied for multi-range-check
            VariableCell::create("remainder01"),
            VariableCell::create("remainder2"),
            VariableCell::create("quotient0"),
            VariableCell::create("quotient1"),
            VariableCell::create("quotient2"),
            VariableCell::create("product1_lo"), 
            VariableCell::create("product1_hi_0"),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
        ],
    ]
}

/// Perform integer bound addition computation for high limb x'2 = x2 + f'2
pub fn compute_high_bound(x: &BigUint, neg_foreign_field_modulus: &BigUint) -> BigUint {
    let x_hi = x.to_limbs()[2];
    let neg_f_hi = neg_foreign_field_modulus.to_limbs()[2];
    let x_hi_bound = x_hi + neg_f_hi;
    assert!(x_hi_bound < BigUint::binary_modulus());
    x_hi_bound
}

// Compute witness variables related to foreign field multiplication
pub(crate) fn compute_witness_variables<F: PrimeField>(
    products: &[BigUint; 3],
    remainder: &[BigUint; 3],
) -> [F; 6] {
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
    // Compute v10 and v11
    let (carry1_hi, carry1_lo) = carry1.div_rem(&BigUint::two_to_limb());

    // C8: witness data a, b, q, and r already present

    [
        product1_lo,
        product1_hi_0,
        product1_hi_1,
        carry0,
        carry1_lo,
        carry1_hi,
    ]
    .to_fields()
}

/// Create a foreign field multiplication witness
/// Input: multiplicands left_input and right_input
pub fn create<F: PrimeField>(
    left_input: &BigUint,
    right_input: &BigUint,
    foreign_field_modulus: &BigUint,
) -> ([Vec<F>; COLUMNS], ExternalChecks<F>) {
    if *foreign_field_modulus > BigUint::max_foreign_field_modulus::<F>() {
        panic!(
            "foreign_field_modulus exceeds maximum: {} > {}",
            *foreign_field_modulus,
            BigUint::max_foreign_field_modulus::<F>()
        );
    }

    let mut witness = array::from_fn(|_| vec![F::zero(); 0]);
    let mut external_checks = ExternalChecks::<F>::default();

    // Compute quotient and remainder using foreign field modulus
    let (quotient, remainder) = (left_input * right_input).div_rem(foreign_field_modulus);

    // Compute negated foreign field modulus f' = 2^t - f public parameter
    let neg_foreign_field_modulus = foreign_field_modulus.negate();

    // Compute the intermediate products
    let products: [F; 3] = constraints::compute_intermediate_products(
        &left_input.to_field_limbs(),
        &right_input.to_field_limbs(),
        &quotient.to_field_limbs(),
        &neg_foreign_field_modulus.to_field_limbs(),
    );

    // Compute witness variables
    let [product1_lo, product1_hi_0, product1_hi_1, carry0, carry1_lo, carry1_hi] =
        compute_witness_variables(&products.to_limbs(), &remainder.to_limbs());

    // Track witness data for external multi-range-check on certain components of intermediate product and carry
    external_checks.add_multi_range_check(&[carry1_lo, product1_lo, product1_hi_0]);

    // Compute high bounds for multi-range-checks on quotient and remainder, making 3 limbs (with zero)
    // Assumes that right's and left's high bounds are range checked at a different stage.
    let right_hi_bound = compute_high_bound(&right_input, &neg_foreign_field_modulus);
    let quotient_hi_bound = compute_high_bound(&quotient, &neg_foreign_field_modulus);
    let remainder_hi_bound = compute_high_bound(&remainder, &neg_foreign_field_modulus);

    // Extract the high limb of remainder and quotient to create a high bound check (Double generic)
    let remainder_hi = remainder.to_field_limbs()[2];
    let quotient_hi = quotient.to_field_limbs()[2];

    // Track witness data for external multi-range-checks on quotient and remainder
    external_checks.add_compact_multi_range_check(&remainder.to_compact_field_limbs());
    external_checks.add_multi_range_check(&[remainder_hi_bound.into(), quotient_hi_bound.into(), F::zero()]);
    external_checks.add_high_bound_check(&[remainder_hi, quotient_hi]);

    // NOTE: high bound checks and multi range checks for left and right should be done somewhere else

    // Extend the witness by two rows for foreign field multiplication
    for w in &mut witness {
        w.extend(std::iter::repeat(F::zero()).take(2));
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
            "carry1_lo" => carry1_lo,
            "carry1_hi" => carry1_hi,
            "carry0" => carry0,
            "product1_hi_1" => product1_hi_1,
            "remainder01" => remainder[0],
            "remainder2" => remainder[1],
            "quotient0" => quotient[0],
            "quotient1" => quotient[1],
            "quotient2" => quotient[2],
            "product1_lo" => product1_lo,
            "product1_hi_0" => product1_hi_0,
        ],
    );

    (witness, external_checks)
}

/// Track external check witness data
#[derive(Default)]
pub struct ExternalChecks<F: PrimeField> {
    pub multi_ranges: Vec<[F; 3]>,
    pub compact_multi_ranges: Vec<[F; 2]>,
    pub high_bounds: Vec<[F; 2]>,
}

impl<F: PrimeField> ExternalChecks<F> {
    /// Track a bound check
    pub fn add_high_bound_check(&mut self, limbs: &[F; 2]) {
        self.high_bounds.push(*limbs);
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
    pub fn extend_witness_multi_range_checks(&self, witness: &mut [Vec<F>; COLUMNS]) {
        for [v0, v1, v2] in self.multi_ranges.clone() {
            range_check::witness::extend_multi(witness, v0, v1, v2)
        }
    }

    /// Extend the witness with external compact multi range_checks
    pub fn extend_witness_compact_multi_range_checks(&self, witness: &mut [Vec<F>; COLUMNS]) {
        for [v01, v2] in self.compact_multi_ranges.clone() {
            range_check::witness::extend_multi_compact(witness, v01, v2)
        }
    }

    /// Extend the witness with external bound addition
    pub fn extend_witness_high_bounds(
        &self,
        witness: &mut [Vec<F>; COLUMNS],
        neg_foreign_field_modulus: &[F; 3],
    ) {
        for bound in self.high_bounds.clone() {
            let out0 = bound[0] + neg_foreign_field_modulus[2];
            let out1 = bound[1] + neg_foreign_field_modulus[2];
            // Extend the witness for the generic gate
            for col in witness.iter_mut().take(COLUMNS) {
                col.extend(std::iter::repeat(F::zero()).take(1))
            }
            // Fill values for the new generic row
            // l1 r1 o1 l2 r2 o2
            let last_row = witness[0].len()-1;
            witness[0][last_row] = bound[0];
            witness[1][last_row] = neg_foreign_field_modulus[2];
            witness[2][last_row] = out0;
            witness[3][last_row] = bound[1];
            witness[4][last_row] = neg_foreign_field_modulus[2];
            witness[5][last_row] = out1;
        }
    }
}
