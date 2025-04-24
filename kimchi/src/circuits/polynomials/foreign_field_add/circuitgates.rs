//! Foreign field addition gate.

use crate::circuits::{
    argument::{Argument, ArgumentEnv, ArgumentType},
    berkeley_columns::BerkeleyChallengeTerm,
    expr::{
        constraints::{compact_limb, ExprOps},
        Cache,
    },
    gate::GateType,
    polynomials::foreign_field_common::LIMB_COUNT,
};
use ark_ff::PrimeField;
use core::{array, marker::PhantomData};

//~ These circuit gates are used to constrain that
//~
//~ ```text
//~ left_input +/- right_input = field_overflow * foreign_modulus + result
//~```
//~
//~ ##### Documentation
//~
//~  For more details please see the [Foreign Field Addition](../kimchi/foreign_field_add.md) chapter.
//~
//~ ##### Mapping
//~
//~  To make things clearer, the following mapping between the variable names
//~  used in the code and those of the RFC document can be helpful.
//~
//~ ```text
//~     left_input_lo -> a0  right_input_lo -> b0  result_lo -> r0  bound_lo -> u0
//~     left_input_mi -> a1  right_input_mi -> b1  result_mi -> r1  bound_mi -> u1
//~     left_input_hi -> a2  right_input_hi -> b2  result_hi -> r2  bound_hi -> u2
//~
//~     field_overflow  -> q
//~     sign            -> s
//~     carry_lo        -> c0
//~     carry_mi        -> c1
//~     bound_carry_lo  -> k0
//~     bound_carry_mi  -> k1
//~```
//~
//~ Note: Our limbs are 88-bit long. We denote with:
//~
//~ * `lo` the least significant limb (in little-endian, this is from 0 to 87)
//~ * `mi` the middle limb            (in little-endian, this is from 88 to 175)
//~ * `hi` the most significant limb  (in little-endian, this is from 176 to 263)
//~
//~ Let `left_input_lo`, `left_input_mi`, `left_input_hi` be 88-bit limbs of the left element
//~
//~ Let `right_input_lo`, `right_input_mi`, `right_input_hi` be 88-bit limbs of the right element
//~
//~ Let `foreign_modulus_lo`, `foreign_modulus_mi`, `foreign_modulus_hi` be 88-bit limbs of the foreign modulus
//~
//~ Then the limbs of the result are
//~
//~ * `result_lo = left_input_lo +/- right_input_lo - field_overflow * foreign_modulus_lo - 2^{88} * result_carry_lo`
//~ * `result_mi = left_input_mi +/- right_input_mi - field_overflow * foreign_modulus_mi - 2^{88} * result_carry_mi + result_carry_lo`
//~ * `result_hi = left_input_hi +/- right_input_hi - field_overflow * foreign_modulus_hi + result_carry_mi`
//~
//~ `field_overflow` $=0$ or $1$ or $-1$ handles overflows in the field
//~
//~ `result_carry_i` $= -1, 0, 1$ are auxiliary variables that handle carries between limbs
//~
//~ Apart from the range checks of the chained inputs, we need to do an additional range check for a final bound
//~ to make sure that the result is less than the modulus, by adding `2^{3*88} - foreign_modulus` to it.
//~ (This can be computed easily from the limbs of the modulus)
//~ Note that `2^{264}` as limbs represents: (0, 0, 0, 1) then:
//~
//~ The upper-bound check can be calculated as:
//~
//~ * `bound_lo = result_lo - foreign_modulus_lo - bound_carry_lo * 2^{88}`
//~ * `bound_mi = result_mi - foreign_modulus_mi - bound_carry_mi * 2^{88} + bound_carry_lo`
//~ * `bound_hi = result_hi - foreign_modulus_hi + 2^{88} + bound_carry_mi`
//~
//~ Which is equivalent to another foreign field addition with right input 2^{264}, q = 1 and s = 1
//~
//~ * `bound_lo = result_lo + s *      0 - q * foreign_modulus_lo - bound_carry_lo * 2^{88}`
//~ * `bound_mi = result_mi + s *      0 - q * foreign_modulus_mi - bound_carry_mi * 2^{88} + bound_carry_lo`
//~ * `bound_hi = result_hi + s * 2^{88} - q * foreign_modulus_hi                           + bound_carry_mi`
//~
//~ `bound_carry_i` $= 0$ or $1$ or $-1$ are auxiliary variables that handle carries between limbs
//~
//~ The range check of `bound` can be skipped until the end of the operations
//~ and `result` is an intermediate value that is unused elsewhere (since the final `result`
//~ must have had the right amount of moduli subtracted along the way, meaning a multiple of the modulus).
//~ In other words, intermediate results could potentially give a valid witness that satisfies the constraints
//~ but where the result is larger than the modulus (yet smaller than 2^{264}). The reason that we have a
//~ final bound check is to make sure that the final result (`min_result`) is indeed the minimum one
//~ (meaning less than the modulus).
//~
//~ A more optimized version of these constraints is able to reduce by 2 the number of constraints and
//~ by 1 the number of witness cells needed. The idea is to condense the low and middle limbs in one longer
//~ limb of 176 bits (which fits inside our native field) and getting rid of the low carry flag.
//~ With this idea in mind, the sole carry flag we need is the one located between the middle and the high limbs.
//~
//~ ##### Layout
//~
//~ The sign of the operation (whether it is an addition or a subtraction) is stored in the fourth coefficient as
//~ a value +1 (for addition) or -1 (for subtraction). The first 3 coefficients are the 3 limbs of the foreign modulus.
//~ One could lay this out as a double-width gate for chained foreign additions and a final row, e.g.:
//~
//~ | col | `ForeignFieldAdd`        | chain `ForeignFieldAdd` | final `ForeignFieldAdd` | final `Zero`      |
//~ | --- | ------------------------ | ----------------------- | ----------------------- | ----------------- |
//~ |   0 | `left_input_lo`  (copy)  | `result_lo` (copy)      | `min_result_lo` (copy)  | `bound_lo` (copy) |
//~ |   1 | `left_input_mi`  (copy)  | `result_mi` (copy)      | `min_result_mi` (copy)  | `bound_mi` (copy) |
//~ |   2 | `left_input_hi`  (copy)  | `result_hi` (copy)      | `min_result_hi` (copy)  | `bound_hi` (copy) |
//~ |   3 | `right_input_lo` (copy)  |                         |  0              (check) |                   |
//~ |   4 | `right_input_mi` (copy)  |                         |  0              (check) |                   |
//~ |   5 | `right_input_hi` (copy)  |                         |  2^88           (check) |                   |
//~ |   6 | `field_overflow` (copy?) |                         |  1              (check) |                   |
//~ |   7 | `carry`                  |                         | `bound_carry`           |                   |
//~ |   8 |                          |                         |                         |                   |
//~ |   9 |                          |                         |                         |                   |
//~ |  10 |                          |                         |                         |                   |
//~ |  11 |                          |                         |                         |                   |
//~ |  12 |                          |                         |                         |                   |
//~ |  13 |                          |                         |                         |                   |
//~ |  14 |                          |                         |                         |                   |
//~
//~ We reuse the foreign field addition gate for the final bound check since this is an addition with a
//~ specific parameter structure. Checking that the correct right input, overflow, and overflow are used shall
//~ be done by copy constraining these values with a public input value. One could have a specific gate
//~ for just this check requiring less constrains, but the cost of adding one more selector gate outweights
//~ the savings of one row and a few constraints of difference.
//~
//~ ##### Integration
//~
//~ * Copy final overflow bit from public input containing value 1
//~ * Range check the final bound
//~

/// Implementation of the foreign field addition gate
/// - Operates on Curr and Next rows.
#[derive(Default)]
pub struct ForeignFieldAdd<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignFieldAdd<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignFieldAdd);
    const CONSTRAINTS: u32 = 4;

    fn constraint_checks<T: ExprOps<F, BerkeleyChallengeTerm>>(
        env: &ArgumentEnv<F, T>,
        _cache: &mut Cache,
    ) -> Vec<T> {
        let foreign_modulus: [T; LIMB_COUNT] = array::from_fn(|i| env.coeff(i));

        // stored as coefficient for better correspondance with the relation being proved
        // this reduces the number of copy constraints needed to check the operation
        // it also allows the final bound check to copy the overflow bit to be 1
        // because otherwise it did not fit in the first 7 columns of the row
        let sign = env.coeff(3);

        let left_input_lo = env.witness_curr(0);
        let left_input_mi = env.witness_curr(1);
        let left_input_hi = env.witness_curr(2);

        let right_input_lo = env.witness_curr(3);
        let right_input_mi = env.witness_curr(4);
        let right_input_hi = env.witness_curr(5);

        // sign in <7 to be able to check against public input of opcodes
        let field_overflow = env.witness_curr(6);

        // Result carry bits for limb overflows / underflows.
        let carry = env.witness_curr(7);

        let result_lo = env.witness_next(0);
        let result_mi = env.witness_next(1);
        let result_hi = env.witness_next(2);

        // Sign flag is 1 or -1
        // NOTE: we used to check this because sign was in the witness,
        // but now it is publicly checkable as part of the relation itself

        // Field overflow flag is 0 or s
        let mut checks = vec![field_overflow.clone() * (field_overflow.clone() - sign.clone())];

        // Constraints to check the carry flag is -1, 0, or 1.
        checks.push(is_carry(&carry));

        // Auxiliary inline function to obtain the constraints of a foreign field addition result

        // a_bot = a_0 + a_1 * 2^88
        // b_bot = b_0 + b_1 * 2^88
        // f_bot = f_0 + f_1 * 2^88
        // r_bot = a_bot + s * b_bot - q * f_bot - c * 2^176
        let result_bot = compact_limb(&left_input_lo, &left_input_mi)
            + sign.clone() * compact_limb(&right_input_lo, &right_input_mi)
            - field_overflow.clone() * compact_limb(&foreign_modulus[0], &foreign_modulus[1])
            - carry.clone() * T::two_to_2limb();
        // r_top = a_2 + s * b_2 - q * f_2 + c
        let result_top = left_input_hi + sign * right_input_hi
            - field_overflow * foreign_modulus[2].clone()
            + carry;
        // Result values match
        // r_bot = r_0 + r_1 * 2^88
        // r_top = r_2
        checks.push(result_bot - compact_limb(&result_lo, &result_mi));
        checks.push(result_top - result_hi);

        checks
    }
}

// Auxiliary function to obtain the constraints to check a carry flag
fn is_carry<F: PrimeField, T: ExprOps<F, BerkeleyChallengeTerm>>(flag: &T) -> T {
    // Carry bits are -1, 0, or 1.
    flag.clone() * (flag.clone() - T::one()) * (flag.clone() + T::one())
}
