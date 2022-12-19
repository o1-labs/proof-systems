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
    },
    BigUintFieldHelpers,
};
use std::array;

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
            VariableCell::create("quotient0"),
            VariableCell::create("quotient1"),
            VariableCell::create("quotient2"),
            VariableCell::create("quotient_bound_carry"),
            VariableCell::create("product1_hi_1"),
            ConstantCell::create(F::zero()),
        ],
        // Zero row
        [
            // Copied for multi-range-check
            VariableCell::create("remainder0"),
            VariableCell::create("remainder1"),
            VariableCell::create("remainder2"),
            VariableCell::create("quotient_bound01"),
            VariableCell::create("quotient_bound2"),
            VariableCell::create("product1_lo"), // Copied for multi-range-check
            VariableCell::create("product1_hi_0"), // Copied for multi-range-check
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

pub fn compute_bound(x: &BigUint, neg_foreign_field_modulus: &BigUint) -> BigUint {
    let x_bound = x + neg_foreign_field_modulus;
    assert!(x_bound < BigUint::binary_modulus());
    x_bound
}

fn compute_witness_variables<F: PrimeField>(
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
    let (carry0, _) = (products(0) + BigUint::two_to_limb() * product1_lo.clone()
        - remainder(0)
        - BigUint::two_to_limb() * remainder(1))
    .div_rem(&BigUint::two_to_2limb());

    // C6-C7: Compute v1 = the top L + 3 bits (p2 + p11 + v0 - r2) / 2^L
    //   N.b. Same as above, to avoid an underflow error, the equation must
    //        sum the intermediate product terms before subtracting the remainder.
    let (carry1, _) = (products(2) + product1_hi + carry0.clone() - remainder(2))
        .div_rem(&BigUint::two_to_limb());
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

fn compute_bound_witness_carry<F: PrimeField>(
    sums: &[BigUint; 2],  // [sum01, sum2]
    bound: &[BigUint; 2], // [bound01, bound2]
) -> F {
    auto_clone_array!(sums);
    auto_clone_array!(bound);

    // C9: witness data is created by externally by called and multi-range-check gate

    // C10-C11: Compute q'_carry01 = (s01 - q'01)/2^2L
    let (quotient_bound_carry, _) = (sums(0) - bound(0)).div_rem(&BigUint::two_to_2limb());

    quotient_bound_carry.to_field::<F>().unwrap()
}

/// Create a foreign field multiplication witness
/// Input: multiplicands left_input and right_input
pub fn create<F: PrimeField>(
    left_input: &BigUint,
    right_input: &BigUint,
    foreign_field_modulus: &BigUint,
) -> ([Vec<F>; COLUMNS], ExternalChecks<F>) {
    let mut witness = array::from_fn(|_| vec![F::zero(); 0]);
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

    // Compute the intermediate sums [sum01, sum2] for quotient bound addition
    let sums: [F; 2] = circuitgates::compute_intermediate_sums(
        &quotient.to_field_limbs(),
        &neg_foreign_field_modulus.to_field_limbs(),
    );

    // Compute witness variables
    let [product1_lo, product1_hi_0, product1_hi_1, carry0, carry1_lo, carry1_hi] =
        compute_witness_variables(&products.to_limbs(), &remainder.to_limbs());

    // Track witness data for external multi-range-check on certain components of intermediate product and carry
    external_checks.add_multi_range_check(&[carry1_lo, product1_lo, product1_hi_0]);

    // Compute bounds for multi-range-checks on quotient and remainder
    let quotient_bound = compute_bound(&quotient, &neg_foreign_field_modulus);
    let remainder_bound = compute_bound(&remainder, &neg_foreign_field_modulus);

    // Track witness data for external multi-range-checks on quotient and remainder bounds
    external_checks.add_compact_multi_range_check(&quotient_bound.to_compact_field_limbs());
    external_checks.add_multi_range_check(&remainder_bound.to_field_limbs());
    external_checks.add_bound_check(&remainder.to_field_limbs());

    // Compute quotient bound addition witness variables
    let quotient_bound_carry =
        compute_bound_witness_carry(&sums.to_biguints(), &quotient_bound.to_compact_limbs());

    // Extend the witness by two rows for foreign field multiplication
    for w in &mut witness {
        w.extend(std::iter::repeat(F::zero()).take(2));
    }

    // Create the foreign field multiplication witness rows
    let left_input = left_input.to_field_limbs();
    let right_input = right_input.to_field_limbs();
    let quotient = quotient.to_field_limbs();
    let remainder = remainder.to_field_limbs();
    let quotient_bound = quotient_bound.to_compact_field_limbs();
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
            "product1_hi_1" => product1_hi_1,
            "carry0" => carry0,
            "quotient0" => quotient[0],
            "quotient1" => quotient[1],
            "quotient2" => quotient[2],
            "quotient_bound_carry" => quotient_bound_carry,
            "remainder0" => remainder[0],
            "remainder1" => remainder[1],
            "remainder2" => remainder[2],
            "quotient_bound01" => quotient_bound[0],
            "quotient_bound2" => quotient_bound[1],
            "product1_lo" => product1_lo,
            "product1_hi_0" => product1_hi_0
        ],
    );

    (witness, external_checks)
}

/// Track external check witness data
#[derive(Default)]
pub struct ExternalChecks<F: PrimeField> {
    pub multi_ranges: Vec<[F; 3]>,
    pub compact_multi_ranges: Vec<[F; 2]>,
    pub bounds: Vec<[F; 3]>,
}

impl<F: PrimeField> ExternalChecks<F> {
    /// Track a bound check
    pub fn add_bound_check(&mut self, limbs: &[F; 3]) {
        self.bounds.push(*limbs);
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
    pub fn extend_witness_bound_addition(
        &self,
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
    }
}
