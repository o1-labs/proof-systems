//! Foreign field multiplication circuit gates

//~ These circuit gates are used to constrain that
//~
//~ $$left_input * right_input = quotient * foreign_modulus + remainder$$
//~
//~ ##### Documentation:
//~
//~ For more details please see the [FFMul RFC](../rfcs/ffadd.md)
//~
//~ ##### Mapping:
//~ To make things clearer, the following mapping between the variable names
//~ used in the code and those of the document can be helpful.
//~
//~ ```text
//~ left_input_hi => a2  right_input_hi => b2  quotient_hi => q2  remainder_hi => r2
//~ left_input_mi => a1  right_input_mi => b1  quotient_mi => q1  remainder_mi => r1
//~ left_input_lo => a0  right_input_lo => b0  quotient_lo => q0  remainder_lo => r0
//~
//~ product_mi_bot => p10   product_mi_top_limb => p110   product_mi_top_over => p111
//~ carry_bot      => v0    carry_top_limb      => v10    carry_top_over      => v11
//~ ````
//~
//~ ##### Suffixes:
//~ The variable names in this code uses descriptive suffixes to convey information about the
//~ positions of the bits referred to.
//~
//~ - When a variable is split into 3 limbs we use: lo, mid, hi (where high is the most significant)
//~ - When a variable is split in 2 halves we use: bottom, top  (where top is the most significant)
//~ - When the bits of a variable are split into a limb and some over bits we use: limb,
//~   over (where over is the most significant)
//~
//~ ##### Inputs:
//~ * foreign_modulus        := foreign field modulus (currently stored in constraint system)
//~ * left_input $~\in F_f$  := left foreign field element multiplicand
//~ * right_input $~\in F_f$ := right foreign field element multiplicand
//~
//~ ```admonition::notice
//~ N.b. the native field modulus is obtainable from F, the native field's trait bound below.
//~ ```
//~
//~ ##### Witness:
//~ * quotient $~\in F_f$  := foreign field quotient
//~ * remainder $~\in F_f$ := foreign field remainder
//~ * carry_bot            := a two bit carry
//~ * carry_top_limb       := low 88 bits of carry_top
//~ * carry_top_over       := high 3 bits of carry_top
//~
//~ ##### Layout:
//~
//~ |  Row(s) | Gates             | Witness
//~ |---------|-------------------|------------------------------------------------------------ |
//~ |     0-3 | multi-range-check | `left_input` multiplicand                                   |
//~ |     4-7 | multi-range-check | `right_input` multiplicand                                  |
//~ |    8-11 | multi-range-check | `quotient`                                                  |
//~ |   12-15 | multi-range-check | `remainder`                                                 |
//~ |   16-19 | multi-range-check | `product_mi_bot`, `product_mi_top_limb`, `carry_top_limb`   |
//~ |      20 | `ForeignFieldMul` | (see below)                                                 |
//~ |      21 | `Zero`            | (see below)                                                 |
//~
//~ The last two rows are layed out like this
//~
//~ | col | `ForeignFieldMul`         | `Zero`                  |
//~ | --- | ------------------------- | ----------------------- |
//~ |   0 | `left_input_lo`  (copy)   | `right_input_hi` (copy) |
//~ |   1 | `left_input_mi`  (copy)   | `quotient_lo`    (copy) |
//~ |   2 | `left_input_hi`  (copy)   | `quotient_mi`    (copy) |
//~ |   3 | `right_input_lo` (copy)   | `quotient_hi`    (copy) |
//~ |   4 | `right_input_mi` (copy)   | `remainder_lo`   (copy) |
//~ |   5 | `carry_shift`    (lookup) | `remainder_mi`   (copy) |
//~ |   6 | `product_shift`  (lookup) | `remainder_hi`   (copy) |
//~ |   7 | `product_mi_bot`          | `aux_lo`                |
//~ |   8 | `product_mi_top_limb`     | `aux_mi`                |
//~ |   9 | `product_mi_top_over`     | `aux_hi`                |
//~ |  10 | `carry_bot`               |                         |
//~ |  11 | `carry_top_limb`          |                         |
//~ |  12 | `carry_top_over`          |                         |
//~ |  13 |                           |                         |
//~ |  14 |                           |                         |

use crate::circuits::{
    argument::{Argument, ArgumentType},
    expr::{constraints::crumb, witness_curr, witness_next, ConstantExpr, E},
    gate::GateType,
};
use ark_ff::FftField;
use num_traits::One;
use o1_utils::foreign_field::LIMB_BITS;
use std::marker::PhantomData;

/// Compute nonzero intermediate products with the bitstring format.
///
/// For details see this section of the design document
///
/// <https://hackmd.io/37M7qiTaSIKaZjCC5OnM1w?view#Intermediate-products>
///
/// Note: Thanks to the below trait bound, this code is reusable
///       as constraint code or as witness generation code
#[allow(clippy::too_many_arguments)] // Our use of many arguments is intentional
pub fn compute_intermediate_products<
    F: std::ops::Mul<Output = F>
        + std::ops::Sub<Output = F>
        + std::ops::Neg<Output = F>
        + std::ops::Add<Output = F>
        + std::cmp::PartialOrd
        + Clone
        + One,
>(
    left_input_lo: F,
    left_input_mi: F,
    left_input_hi: F,
    right_input_lo: F,
    right_input_mi: F,
    right_input_hi: F,
    quotient_lo: F,
    quotient_mi: F,
    quotient_hi: F,
    foreign_modulus_lo: F,
    foreign_modulus_mi: F,
    foreign_modulus_hi: F,
) -> (F, F, F) {
    //
    //               p0 := a0 * b0 - q0 * f0
    //  <=>  product_lo := left_input_lo * right_input_lo - quotient_lo * foreign_modulus_lo
    //
    //               p1 := a0 * b1 + a1 * b0 - q0 * f1 - q1 * f0
    //  <=> product_mi := left_input_lo * right_input_mi + left_input_mi * right_input_lo
    //                   - quotient_lo * foreign_modulus_mi - quotient_mi * foreign_modulus_lo
    //
    //               p2 := a0 * b2 + a2 * b0 + a1 * b1 - q0 * f2 - q2 * f0 - q1 * f1
    //  <=>  product_hi := left_input_lo * right_input_hi + left_input_hi * right_input_lo
    //                     + left_input_mi * right_input_mi - quotient_lo * foreign_modulus_hi
    //                     - quotient_hi * foreign_modulus_lo - quotient_mi * foreign_modulus_mi
    //
    let product_lo = left_input_lo.clone() * right_input_lo.clone()
        - quotient_lo.clone() * foreign_modulus_lo.clone();
    let product_mi = left_input_lo.clone() * right_input_mi.clone()
        + left_input_mi.clone() * right_input_lo.clone()
        - quotient_lo.clone() * foreign_modulus_mi.clone()
        - quotient_mi.clone() * foreign_modulus_lo.clone();
    let product_hi = left_input_lo * right_input_hi
        + left_input_hi * right_input_lo
        + left_input_mi * right_input_mi
        - quotient_lo * foreign_modulus_hi.clone()
        - quotient_hi * foreign_modulus_lo
        - quotient_mi * foreign_modulus_mi;

    (product_lo, product_mi, product_hi)
}

/// ForeignFieldMul0 - foreign field multiplication
///    * This circuit gate operates on the Curr and Next rows
///    * It uses copy, plookup, crumb and some custom constraints
#[derive(Default)]
pub struct ForeignFieldMul<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignFieldMul<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignFieldMul);
    const CONSTRAINTS: u32 = 7;

    fn constraints() -> Vec<E<F>> {
        let mut constraints = vec![];

        //
        // Define some helper variables to refer to the witness elements
        // described in the layout above
        //

        // -> define top, middle and lower limbs of the foreign field element `a`
        let left_input_lo = witness_curr(0);
        let left_input_mi = witness_curr(1);
        let left_input_hi = witness_curr(2);

        // -> define top, middle and lower limbs of the foreign field element `b`
        let right_input_lo = witness_curr(3);
        let right_input_mi = witness_curr(4);
        let right_input_hi = witness_next(0);

        // -> define top, middle and lower limbs of the quotient and remainder
        let quotient_lo = witness_next(1);
        let quotient_mi = witness_next(2);
        let quotient_hi = witness_next(3);
        let remainder_lo = witness_next(4);
        let remainder_mi = witness_next(5);
        let remainder_hi = witness_next(6);

        let aux_lo = witness_next(7);
        let aux_mi = witness_next(8);
        let aux_hi = witness_next(9);

        // -> define shifted values of the quotient and witness values
        let carry_shift = witness_curr(5);
        let product_shift = witness_curr(6);

        // -> define decomposition values of the intermediate multiplication
        let product_mi_bot = witness_curr(7);
        let product_mi_top_limb = witness_curr(8);
        let product_mi_top_over = witness_curr(9);

        // -> define witness values for the zero sum
        let carry_bot = witness_curr(10);
        let carry_top_limb = witness_curr(11);
        let carry_top_over = witness_curr(12);

        //
        // Define some helpers to be used in the constraints
        //

        // Powers of 2 for range constraints
        let two = E::from(2u64);
        let two_to_limb = two.clone().pow(LIMB_BITS as u64);
        let power_lo = two_to_limb.clone() * two_to_limb.clone() * two.clone(); // 2^{2L+1}
        let power_mi = power_lo.clone() * two.clone(); // 2^{2L+2}
        let power_hi = power_mi.clone() * two.clone(); // 2^{2L+3}
        let power_lo_top = two.clone();
        let power_mi_top = two.clone() * two.clone() * two_to_limb.clone();
        let two_to_8 = E::from(256);
        let two_to_9 = E::from(512);
        let two_to_88 = E::from(2).pow(88);
        let two_to_176 = E::from(2).pow(176);

        // Foreign field modulus in 3 limbs: low, middle and high
        let foreign_modulus_lo = E::constant(ConstantExpr::ForeignFieldModulus(0));
        let foreign_modulus_mi = E::constant(ConstantExpr::ForeignFieldModulus(1));
        let foreign_modulus_hi = E::constant(ConstantExpr::ForeignFieldModulus(2));

        // Intermediate products for better readability of the constraints
        // TODO: use a function with traits to reuse for Expr and Field as when we didnt have aux
        let (product_lo, product_mi, product_hi) = {
            let add_lo = left_input_lo.clone() + right_input_lo.clone();
            let sub_lo = quotient_lo.clone() + foreign_modulus_lo.clone();

            let add_mi = left_input_lo.clone() * right_input_mi.clone()
                + left_input_mi.clone() * right_input_lo.clone();
            let sub_mi = quotient_lo.clone() * foreign_modulus_mi.clone()
                + quotient_mi.clone() * foreign_modulus_lo.clone();

            let add_hi = left_input_lo * right_input_hi
                + left_input_hi * right_input_lo
                + left_input_mi * right_input_mi;
            let sub_hi = quotient_lo * foreign_modulus_hi.clone()
                + quotient_hi * foreign_modulus_lo
                + quotient_mi * foreign_modulus_mi;

            let product_lo = add_lo - sub_lo + aux_lo.clone() * power_lo;
            let product_mi = add_mi - sub_mi + aux_mi.clone() * power_mi;
            let product_hi = add_hi - sub_hi + aux_hi * power_hi;

            (product_lo, product_mi, product_hi)
        };

        //
        // Define constraints
        //

        // 1) Constrain decomposition of middle intermediate product
        //
        //                p11 = 2^88 * p111 + p110
        //                p1' = 2^88 * p11 + p10
        //                 p1 = p1'
        //                   <=>
        //    product_mi_top = 2^88 * product_mi_top_over + product_mi_top_limb
        //    product_mi_sum = 2^88 * product_mi_top + product_mi_bot
        //    product_mi_sum = product_mi
        //                   <=>
        //    product_mi = 2^88 * ( 2^88 * product_mi_top_over + product_mi_top_limb ) + product_mi_bot
        //
        let product_mi_top = two_to_88.clone() * product_mi_top_over.clone() + product_mi_top_limb;
        let product_mi_sum = two_to_88.clone() * product_mi_top.clone() + product_mi_bot.clone();
        constraints.push(product_mi - product_mi_sum);

        // 2) Constrain carry witness value carry_bot \in [0, 2^2)
        constraints.push(crumb(&carry_bot));

        // 3) Constrain intermediate product fragment product_mi_top_over \in [0, 2^2)
        constraints.push(crumb(&product_mi_top_over));

        // 4) Constrain carry_shift comes from shifting 9 bits the carry_top_over value
        constraints.push(carry_shift - two_to_8 * carry_top_over.clone());

        // 5) Check zero prefix of quotient, meaning that product_shift comes from
        //    shifting 8 bits the quotient_hi value
        constraints.push(product_shift - two_to_9 * product_mi_top_over);

        // 6) Constrain carry_bot witness value to prove zero_bot's LSB are zero
        //    For details on zero_bot and why this is valid, please see
        //        <https://hackmd.io/37M7qiTaSIKaZjCC5OnM1w?view#Intermediate-products>
        //
        //                  2^176 * v_0 = u_0         = p0 - r0 + 2^88 (p10 - r1)
        //    <=>  2^176 * carry_bot = zero_bot = product_lo - remainder_lo + 2^88 ( product_mi_bot - remainder_mi )
        //
        let zero_bot =
            product_lo - remainder_lo + two_to_88.clone() * (product_mi_bot - remainder_mi);
        constraints.push(zero_bot - two_to_176 * carry_bot.clone());

        // 7) Constraint carry_top to prove zero_top's bits are zero
        //    For details on zero_top and why this is valid, please see
        //        <https://hackmd.io/37M7qiTaSIKaZjCC5OnM1w?view#Intermediate-products<
        //
        //              v_1 = v_{10} + 2^88 * v_{11}$
        //        2^88 * v1 = u1 = v0 + p11 + p2 - r2
        //                 <=>
        //        carry_top = 2^88 * carry_top_over + carry_top_limb
        // 2^88 * carry_top = zero_top = carry_bot + product_mi_top + product_hi - remainder_hi
        //
        let carry_top = two_to_88.clone() * carry_top_over + carry_top_limb;
        let zero_top = carry_bot + product_mi_top + product_hi
            - remainder_hi
            - aux_lo * power_lo_top
            - aux_mi * power_mi_top;
        constraints.push(zero_top - two_to_88 * carry_top);

        // 8-9) Plookup constraints on columns 2 and 3 of the Next row
        constraints
    }
}
