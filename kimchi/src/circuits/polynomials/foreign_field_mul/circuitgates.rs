/// Foreign field multiplication circuit gates
///
/// These circuit gates are used to constrain that
///
///     left_input * right_input = quotient * foreign_modulus + remainder
///
/// For more details please see https://hackmd.io/37M7qiTaSIKaZjCC5OnM1w?view
/// and apply this mapping to the variable names.
///
/// The ideas behind this naming is:
/// - when a variable is split into 3 limbs we use: hi, mid, lo (where high is the most significant)
/// - when a variable is split in 2 halves we use: top, bottom  (where top is the most significant)
/// - when the bits of a variable are split in a limb string and some extra bits we use: limb, extra (where extra is the most significant)
///
///     left_input_hi  => a2  right_input_hi  => b2  quotient_hi  => q2  remainder_hi  => r2
///     left_input_mid => a1  right_input_mid => b1  quotient_mid => q1  remainder_mid => r1
///     left_input_lo  => a0  right_input_lo  => b0  quotient_lo  => q0  remainder_lo  => r0
///
///     product_mid_bottom => p10  product_mid_top_limb => p110  product_mid_top_extra => p111
///     carry_bottom       => v0   carry_top_limb       => v10   carry_top_extra => v11
///
/// Inputs:
///   * foreign_modulus        := foreign field modulus (currently stored in constraint system)
///   * left_input $~\in F_f$  := left foreign field element multiplicand
///   * right_input $~\in F_f$ := right foreign field element multiplicand
///
///   N.b. the native field modulus is obtainable from F, the native field's trait bound below.
///
/// Witness:
///   * quotient $~\in F_f$  := foreign field quotient
///   * remainder $~\in F_f$ := foreign field remainder
///   * carry_bottom         := a two bit carry
///   * carry_top_limb       := low 88 bits of carry_top
///   * carry_top_extra      := high 3 bits of carry_top
///
/// Layout:
///
///   Row(s) | Gate              | Witness
///      0-3 | multi-range-check | left_input multiplicand
///      4-7 | multi-range-check | right_input multiplicand
///     8-11 | multi-range-check | quotient
///    12-15 | multi-range-check | remainder
///    16-19 | multi-range-check | product_mid_bottom, product_mid_top_limb, carry_top_limb
///       20 | ForeignFieldMul   | (see below)
///       21 | Zero              | (see below)
///
/// The last two rows are layed out like this
///
///    | col | `ForeignFieldMul`         | `Zero`                   |
///    | --- | ------------------------- | ------------------------ |
///    |   0 | `left_input_lo`  (copy)   | `left_input_hi`   (copy) |
///    |   1 | `left_input_mid` (copy)   | `right_input_lo`  (copy) |
///    |   2 | `carry_shift`    (lookup) | `right_input_mid` (copy) |
///    |   3 | `quotient_shift` (lookup) | `right_input_hi`  (copy) |
///    |   4 | `quotient_lo`    (copy)   | `remainder_lo`    (copy) |
///    |   5 | `quotient_mid`   (copy)   | `remainder_mid`   (copy) |
///    |   6 | `quotient_hi`    (copy)   | `remainder_hi`    (copy) |
///    |   7 | `product_mid_bottom`      |                          |
///    |   8 | `product_mid_top_limb`    |                          |
///    |   9 | `product_mid_top_extra`   |                          |
///    |  10 | `carry_bottom`            |                          |
///    |  11 | `carry_top_limb`          |                          |
///    |  12 | `carry_top_extra`         |                          |
///    |  13 |                           |                          |
///    |  14 |                           |                          |
use std::marker::PhantomData;

use ark_ff::FftField;

use crate::circuits::{
    argument::{Argument, ArgumentType},
    expr::{constraints::crumb, witness_curr, witness_next, ConstantExpr, E},
    gate::GateType,
};

/// ForeignFieldMul0
///    Rows: Curr + Next
#[derive(Default)]
pub struct ForeignFieldMul<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignFieldMul<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignFieldMul);
    const CONSTRAINTS: u32 = 7;

    fn constraints() -> Vec<E<F>> {
        // WITNESS VALUES
        // witness values from the current and next rows according to the layout

        // -> define top, middle and lower limbs of the foreign field element `a`
        let left_input_lo = witness_curr(0);
        let left_input_mid = witness_next(1);
        let left_input_hi = witness_next(0);

        // -> define top, middle and lower limbs of the foreign field element `b`
        let right_input_lo = witness_next(1);
        let right_input_mid = witness_next(2);
        let right_input_hi = witness_next(3);

        // -> define top, middle and lower limbs of the quotient and remainder
        let quotient_lo = witness_curr(4);
        let quotient_mid = witness_curr(5);
        let quotient_hi = witness_curr(6);
        let remainder_lo = witness_next(4);
        let remainder_mid = witness_next(5);
        let remainder_hi = witness_next(6);

        // -> define shifted values of the quotient and witness values
        let carry_shift = witness_curr(2);
        let quotient_shift = witness_curr(3);

        // -> define decomposition values of the intermediate multiplication
        let product_mid_bottom = witness_curr(7);
        let product_mid_top_limb = witness_curr(8);
        let product_mid_top_extra = witness_curr(9);

        // -> define witness values for the zero sum
        let carry_bottom = witness_curr(10);
        let carry_top_limb = witness_curr(11);
        let carry_top_extra = witness_curr(12);

        // HELPERS

        let mut constraints = vec![];

        // powers of 2 for range constraints
        let eight = E::from(8);
        let two_to_8 = E::from(256);
        let two_to_9 = E::from(512);
        let two_to_88 = E::from(2).pow(88);
        let two_to_176 = E::from(2).pow(176);

        // negated foreign field modulus in 3 limbs: high, middle and low
        let neg_foreign_mod_hi = -E::constant(ConstantExpr::ForeignFieldModulus(2));
        let neg_foreign_mod_mid = -E::constant(ConstantExpr::ForeignFieldModulus(1));
        let neg_foreign_mod_lo = -E::constant(ConstantExpr::ForeignFieldModulus(0));

        // intermediate products for better readability of the constraints
        //
        //               p0 := a0 * b0 - q0 * f0
        //  <=>  product_lo := left_input_lo * right_input_lo - quotient_lo * foreign_mod_lo
        //
        //               p1 := a0 * b1 + a1 * b0 - q0 * f1 - q1 * f0
        //  <=> product_mid := left_input_lo * right_input_mid + left_input_mid * right_input_lo
        //                   - quotient_lo * foreign_mod_mid - quotient_mid * foreign_mod_lo
        //
        //               p2 := a0 * b2 + a2 * b0 + a1 * b1 - q0 * f2 - q2 * f0 - q1 * f1
        //  <=>  product_hi := left_input_lo * right_input_hi + left_input_hi * right_input_lo + left_input_mid * right_input_mid
        //                  - quotient_lo * foreign_mod_hi - quotient_hi * foreign_mod_lo - quotient_mid * foreign_mod_mid
        //
        let product_lo = left_input_lo.clone() * right_input_lo.clone()
            + quotient_lo.clone() * neg_foreign_mod_lo.clone();
        let product_mid = left_input_lo.clone() * right_input_mid.clone()
            + left_input_mid.clone() * right_input_lo.clone()
            + quotient_lo.clone() * neg_foreign_mod_mid.clone()
            + quotient_mid.clone() * neg_foreign_mod_lo.clone();
        let product_hi = left_input_lo * right_input_hi
            + left_input_hi * right_input_lo
            + left_input_mid * right_input_mid
            + quotient_lo * neg_foreign_mod_hi
            + quotient_hi.clone() * neg_foreign_mod_lo
            + quotient_mid * neg_foreign_mod_mid;

        // GATE CONSTRAINTS

        // 1) Constrain decomposition of middle intermediate product
        //
        //                p11 = 2^88 * p111 + p110
        //                p1' = 2^88 * p11 + p10
        //                 p1 = p1'
        //                   <=>
        //    product_mid_top = 2^88 * product_mid_top_extra + product_mid_top_limb
        //    product_mid_sum = 2^88 * product_mid_top + product_mid_bottom
        //    product_mid_sum = product_mid
        //                   <=>
        //    product_mid = 2^88 * (  2^88 * product_mid_top_extra + product_mid_top_limb ) + product_mid_bottom
        //
        let product_mid_top =
            two_to_88.clone() * product_mid_top_extra.clone() + product_mid_top_limb;
        let product_mid_sum =
            two_to_88.clone() * product_mid_top.clone() + product_mid_bottom.clone();
        constraints.push(product_mid - product_mid_sum);

        // 2) Constrain carry witness value `carry_bottom` $~\in [0, 2^2)$
        constraints.push(crumb(&carry_bottom));

        // 3) Constrain intermediate product fragment `product_mid_top_extra` $~\in [0, 2^2)$
        constraints.push(crumb(&product_mid_top_extra));

        // 4) Constrain `carry_shift` comes from shifting 9 bits the `carry_top_extra` value
        constraints.push(carry_shift - two_to_9 * carry_top_extra.clone());

        // 5) Check zero prefix of quotient, meaning that `quotient_shift` comes from shifting 8 bits the `quotient_hi` value
        constraints.push(quotient_shift - two_to_8 * quotient_hi);

        // 6) Constrain `carry_bottom` witness value to prove `zero_bottom`'s least significant bits are zero
        //    For details on `zero_bottom` ($u_0$) and why this is valid, please see this design document section:
        //        https://hackmd.io/37M7qiTaSIKaZjCC5OnM1w?view#Intermediate-products
        //
        //                  2^176 * v_0 = u_0         = p0 - r0 + 2^88 (p10 - r1)
        //    <=>  2^176 * carry_bottom = zero_bottom = product_lo - remainder_lo + 2^88 ( product_mid_bottom - remainder_mid )
        //
        let zero_bottom =
            product_lo - remainder_lo + two_to_88.clone() * (product_mid_bottom - remainder_mid);
        constraints.push(zero_bottom - two_to_176 * carry_bottom.clone());

        // 7) Constraint `carry_top` to prove `zero_top`'s bits are zero
        //    For details on `zero_top` ($u_1$) and why this is valid, please see this design document section:
        //        https://hackmd.io/37M7qiTaSIKaZjCC5OnM1w?view#Intermediate-products
        //
        //              v_1 = v_{10} + 2^3 * v_{11}$
        //        2^88 * v1 = u1 = v0 + p11 + p2 - r2
        //                 <=>
        //        carry_top = 2^3 * carry_top_extra + carry_top_limb
        // 2^88 * carry_top = zero_top = carry_bottom + product_mid_top + product_hi - remainder_hi
        //
        let carry_top = eight * carry_top_extra + carry_top_limb;
        let zero_top = carry_bottom + product_mid_top + product_hi - remainder_hi;
        constraints.push(zero_top - two_to_88 * carry_top);

        // 8-9) Plookups on the Next row @ columns 2 and 3
        constraints
    }
}
