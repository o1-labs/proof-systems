//! Foreign field multiplication

//~ This gadget is used to constrain that
//~
//~```text
//~ left_input * right_input = quotient * foreign_field_modulus + remainder
//~```
//~
//~ ##### Documentation
//~
//~ For more details please see the [Foreign Field Multiplication RFC](../rfcs/foreign_field_mul.md)
//~
//~ ##### Notations
//~
//~ For clarity, we use more descriptive variable names in the code than in
//~ the RFC, which uses mathematical notations.
//~
//~ In order to relate the two documents, the following mapping between the
//~ variable names used in the code and those of the RFC can be helpful.
//~
//~ ```text
//~ left_input0 => a0  right_input0 => b0  quotient0 => q0  remainder0 => r0
//~ left_input1 => a1  right_input1 => b1  quotient1 => q1  remainder1 => r1
//~ left_input2 => a2  right_input2 => b2  quotient2 => q2  remainder2 => r2
//~
//~    product1_lo => p10   product1_hi_0 => p110   product1_hi_1 => p111
//~      carry0 => v0        carry1_lo => v10          carry1_hi => v11
//~
//~                     scaled_carry1_hi => scaled_v11
//~          quotient_bound0 => q'0       quotient_bound12 => q'12
//~
//~   quotient_bound_carry0 => q'_carry0 quotient_bound_carry12 = q'_carry12
//~ ````
//~
//~ ##### Suffixes
//~
//~ The variable names in this code uses descriptive suffixes to convey information about the
//~ positions of the bits referred to.  When a word is split into up to `n` parts
//~ we use: `0`, `1` ... `n` (where `n` is the most significant).  For example, if we split
//~ word `x` into three limbs, we'd name them `x0`, `x1` and `x2` or `x[0]`, `x[1]` and `x[2]`.
//~
//~ Continuing in this fashion, when one of those words is subsequently split in half, then we
//~ add the suffixes `_lo` and `_hi`, where `hi` corresponds to the most significant bits.
//~ For our running example, `x1` would become `x1_lo` and `x1_hi`.  If we are splitting into
//~ more than two things, then we pick meaningful names for each.
//~
//~ So far we've explained our conventions for a splitting depth of up to 2.  For splitting
//~ deeper than two, we simply cycle back to our depth 1 suffixes again.  So for example, `x1_lo`
//~ would be split into `x1_lo_0` and `x1_lo_1`.
//~
//~ ##### Parameters
//~
//~ * `foreign_field_modulus` := foreign field modulus $f$ (stored in gate coefficients 0-2)
//~ * `neg_foreign_field_modulus` := negated foreign field modulus $f'$ (stored in gate coefficients 3-5)
//~
//~ ```admonition::notice
//~ NB: the native field modulus is obtainable from F, the native field's trait bound below.
//~ ```
//~
//~ ##### Witness
//~
//~ * `left_input` := left foreign field element multiplicand $ ~\in F_f$
//~ * `right_input` := right foreign field element multiplicand $ ~\in F_f$
//~ * `quotient` := foreign field quotient $ ~\in F_f$
//~ * `remainder` := foreign field remainder $ ~\in F_f$
//~ * `carry0` := 2 bit carry
//~ * `carry1_lo` := low 88 bits of `carry1`
//~ * `carry1_hi` := high 3 bits of `carry1`
//~ * `scaled_carry1_hi` : = `carry1_hi` scaled by 2^9
//~ * `product1_lo` := lowest 88 bits of middle intermediate product
//~ * `product1_hi_0` := lowest 88 bits of middle intermediate product's highest 88 + 2 bits
//~ * `product1_hi_1` := highest 2 bits of middle intermediate product
//~ * `quotient_bound` := quotient bound for checking `q < f`
//~ * `quotient_bound_carry01` := quotient bound addition 1st carry bit
//~ * `quotient_bound_carry2` := quotient bound addition 2nd carry bit
//~
//~ ##### Layout
//~
//~ The foreign field multiplication gate's rows are layed out like this
//~
//~ | col | `ForeignFieldMul`            | `Zero`                    |
//~ | --- | ---------------------------- | ------------------------- |
//~ |   0 | `left_input0`         (copy) | `remainder0`       (copy) |
//~ |   1 | `left_input1`         (copy) | `remainder1`       (copy) |
//~ |   2 | `left_input2`         (copy) | `remainder2`       (copy) |
//~ |   3 | `right_input0`        (copy) | `quotient_bound01` (copy) |
//~ |   4 | `right_input1`        (copy) | `quotient_bound2`  (copy) |
//~ |   5 | `right_input2`        (copy) | `product1_lo`      (copy) |
//~ |   6 | `carry1_lo`           (copy) | `product1_hi_0`    (copy) |
//~ |   7 | `carry1_hi`        (plookup) | `product1_hi_1`           |
//~ |   8 | `scaled_carry1_hi` (plookup) |                           |
//~ |   9 | `carry0`                     |                           |
//~ |  10 | `quotient0`                  |                           |
//~ |  11 | `quotient1`                  |                           |
//~ |  12 | `quotient2`                  |                           |
//~ |  13 | `quotient_bound_carry01`     |                           |
//~ |  14 | `quotient_bound_carry2`      |                           |
//~

use crate::{
    auto_clone_array,
    circuits::{
        argument::{Argument, ArgumentEnv, ArgumentType},
        expr::constraints::ExprOps,
        gate::GateType,
    },
};
use ark_ff::PrimeField;
use std::{array, marker::PhantomData};

/// Compute non-zero intermediate products
///
/// For more details see the "Intermediate products" Section of
/// the [Foreign Field Multiplication RFC](../rfcs/foreign_field_mul.md)
///
pub fn compute_intermediate_products<F: PrimeField, T: ExprOps<F>>(
    left_input: &[T; 3],
    right_input: &[T; 3],
    quotient: &[T; 3],
    neg_foreign_field_modulus: &[T; 3],
) -> [T; 3] {
    auto_clone_array!(left_input);
    auto_clone_array!(right_input);
    auto_clone_array!(quotient);
    auto_clone_array!(neg_foreign_field_modulus);

    [
        // p0 = a0 * b0 + q0 * f'0
        left_input(0) * right_input(0) + quotient(0) * neg_foreign_field_modulus(0),
        // p1 = a0 * b1 + a1 * b0 + q0 * f'1 + q1 * f'0
        left_input(0) * right_input(1)
            + left_input(1) * right_input(0)
            + quotient(0) * neg_foreign_field_modulus(1)
            + quotient(1) * neg_foreign_field_modulus(0),
        // p2 = a0 * b2 + a2 * b0 + a1 * b1 - q0 * f'2 + q2 * f'0 + q1 * f'1
        left_input(0) * right_input(2)
            + left_input(2) * right_input(0)
            + left_input(1) * right_input(1)
            + quotient(0) * neg_foreign_field_modulus(2)
            + quotient(2) * neg_foreign_field_modulus(0)
            + quotient(1) * neg_foreign_field_modulus(1),
    ]
}

/// Compute intermediate sums
///
/// For more details see the "Optimizations" Section of
/// the [Foreign Field Multiplication RFC](../rfcs/foreign_field_mul.md)
///
pub fn compute_intermediate_sums<F: PrimeField, T: ExprOps<F>>(
    quotient: &[T; 3],
    neg_foreign_field_modulus: &[T; 3],
) -> [T; 2] {
    auto_clone_array!(quotient);
    auto_clone_array!(neg_foreign_field_modulus);

    // q01 = q0 + 2^L * q1
    let quotient01 = quotient(0) + T::two_to_limb() * quotient(1);

    // f'01 = f'0 + 2^L * f'1
    let neg_foreign_field_modulus01 =
        neg_foreign_field_modulus(0) + T::two_to_limb() * neg_foreign_field_modulus(1);

    [
        // q'01 = q01 + f'01
        quotient01 + neg_foreign_field_modulus01,
        // q'2 = q2 + f'2
        quotient(2) + neg_foreign_field_modulus(2),
    ]
}

// Compute native modulus values
pub fn compute_native_modulus_values<F: PrimeField, T: ExprOps<F>>(
    left_input: &[T; 3],
    right_input: &[T; 3],
    quotient: &[T; 3],
    remainder: &[T; 3],
    foreign_field_modulus: &[T; 3],
) -> [T; 5] {
    auto_clone_array!(left_input);
    auto_clone_array!(right_input);
    auto_clone_array!(quotient);
    auto_clone_array!(remainder);
    auto_clone_array!(foreign_field_modulus);

    [
        // an = 2^2L * a2 + 2^L * a1 + a0
        T::two_to_2limb() * left_input(2) + T::two_to_limb() * left_input(1) + left_input(0),
        // bn = 2^2L * b2 + 2^L * b1 + b0
        T::two_to_2limb() * right_input(2) + T::two_to_limb() * right_input(1) + right_input(0),
        // qn = 2^2L * q2 + 2^L * q1 + b0
        T::two_to_2limb() * quotient(2) + T::two_to_limb() * quotient(1) + quotient(0),
        // rn = 2^2L * r2 + 2^L * r1 + r0
        T::two_to_2limb() * remainder(2) + T::two_to_limb() * remainder(1) + remainder(0),
        // fn = 2^2L * f2 + 2^L * f1 + f0
        T::two_to_2limb() * foreign_field_modulus(2)
            + T::two_to_limb() * foreign_field_modulus(1)
            + foreign_field_modulus(0),
    ]
}

// ForeignFieldMul - foreign field multiplication gate
///    * This gate operates on the Curr and Next rows
///    * It uses copy, plookup, crumb and custom constraints
#[derive(Default)]
pub struct ForeignFieldMul<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignFieldMul<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignFieldMul);
    const CONSTRAINTS: u32 = 11;
    // DEGREE is 4

    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>) -> Vec<T> {
        let mut constraints = vec![];

        //
        // Define some helper variables to refer to the witness elements
        // described in the layout.  Note that the limbs below are
        // defined with least significant bits in lower limbs indexes.
        //

        // Left multiplicand a
        let left_input = [
            // Copied for multi-range-check
            env.witness_curr(0),
            env.witness_curr(1),
            env.witness_curr(2),
        ];

        // Right multiplicand b
        let right_input = [
            // Copied for multi-range-check
            env.witness_curr(3),
            env.witness_curr(4),
            env.witness_curr(5),
        ];

        // Carry bits v10 (L bits) and original v11 that is 3 bits
        let carry1_lo = env.witness_curr(6); // Copied for multi-range-check
        let carry1_hi = env.witness_curr(7); // 12-bit plookup

        // Scaled v11 for smaller range check
        let scaled_carry1_hi = env.witness_curr(8); // 12-bit plookup

        // Carry bits v0
        let carry0 = env.witness_curr(9);

        // Quotient q
        let quotient = [
            env.witness_curr(10),
            env.witness_curr(11),
            env.witness_curr(12),
        ];

        // Carry bits for quotient_bound_carry01 and quotient_bound_carry2
        let quotient_bound_carry01 = env.witness_curr(13);
        let quotient_bound_carry2 = env.witness_curr(14);

        // Remainder r (a.k.a. result)
        let remainder = [
            // Copied for multi-range-check
            env.witness_next(0),
            env.witness_next(1),
            env.witness_next(2),
        ];

        // Quotient bound (copied for multi-range-check)
        let quotient_bound01 = env.witness_next(3);
        let quotient_bound2 = env.witness_next(4);

        // Decomposition of the middle intermediate product
        let product1_lo = env.witness_next(5); // Copied for multi-range-check
        let product1_hi_0 = env.witness_next(6); // Copied for multi-range-check
        let product1_hi_1 = env.witness_next(7);

        // Foreign field modulus limbs
        let foreign_field_modulus = array::from_fn(|i| env.coeff(i));

        // Negated foreign field modulus limbs
        let neg_foreign_field_modulus = array::from_fn(|i| env.coeff(3 + i));

        // Compute intermediate products
        auto_clone_array!(
            products,
            compute_intermediate_products(
                &left_input,
                &right_input,
                &quotient,
                &neg_foreign_field_modulus,
            )
        );

        // Compute intermediate sums
        let [sum01, sum2] = compute_intermediate_sums(&quotient, &neg_foreign_field_modulus);

        // Compute native modulus values
        let [left_input_n, right_input_n, quotient_n, remainder_n, foreign_field_modulus_n] =
            compute_native_modulus_values(
                &left_input,
                &right_input,
                &quotient,
                &remainder,
                &foreign_field_modulus,
            );

        // Define the constraints
        //   For more the details on each constraint please see the
        //   Foreign Field Multiplication RFC where each of the constraints
        //   numbered below are described in full detail.

        // C1: Constrain intermediate product fragment product1_hi_1 \in [0, 2^2)
        constraints.push(product1_hi_1.crumb());

        // C2: multi-range-check: v10, p10, p110
        //     That is, check carry1_lo, product1_lo, product1_hi_0 each in [0, 2^L)
        //     Must be done externally with a multi-range-check gadget

        // C3: Constrain decomposition of middle intermediate product p1
        //         p1 = 2^L*p11 + p10
        //     where p11 = 2^L * p111 + p110
        let product1_hi = T::two_to_limb() * product1_hi_1 + product1_hi_0;
        let product1 = T::two_to_limb() * product1_hi.clone() + product1_lo.clone();
        constraints.push(products(1) - product1);

        // C4: Constrain first carry witness value v0 \in [0, 2^2)
        constraints.push(carry0.crumb());

        // C5: Constrain that 2^2L * v0 = p0 + 2^L * p10 - 2^L * r1 - r0.  That is, that
        //         2^2L * carry0 = rhs
        constraints.push(
            T::two_to_2limb() * carry0.clone()
                - (products(0) + T::two_to_limb() * product1_lo
                    - remainder[0].clone()
                    - T::two_to_limb() * remainder[1].clone()),
        );

        // C6: Constrain v11 is 12-bits (done with plookup)

        // C7: Constrain scaled_v11 is 12-bits (done with plookup)

        // C8: Constrain scaled_v11 comes from scaling v11 by 2^9
        constraints.push(scaled_carry1_hi - T::from(512) * carry1_hi.clone());

        // C9: Constrain that 2^L * v1 = p2 + p11 + v0 - r2.  That is, that
        //         2^L * (2^L * carry1_hi + carry1_lo) = rhs
        constraints.push(
            T::two_to_limb() * (T::two_to_limb() * carry1_hi + carry1_lo)
                - (products(2) + product1_hi + carry0 - remainder[2].clone()),
        );

        // C10: Native modulus constraint a_n * b_n - q_n * f_n = r_n
        constraints.push(
            left_input_n * right_input_n - quotient_n * foreign_field_modulus_n - remainder_n,
        );

        // C11: multi-range-check q0', q1' q2'
        //      Constrain q'01 = q'0 + 2^L * q'1
        //      Must be done externally with a multi-range-check gadget
        //      configured to constrain q'12

        // C12: Constrain q'_carry01 is boolean
        constraints.push(quotient_bound_carry01.boolean());

        // C13: Constrain that  2^2L * q'_carry01 = s01 - q'01
        constraints
            .push(T::two_to_2limb() * quotient_bound_carry01.clone() - sum01 + quotient_bound01);

        // C14: Constrain q'_carry2 is boolean
        constraints.push(quotient_bound_carry2.boolean());

        // C15: Constrain that 2^L * q'_carry2 = s2 + q'_carry01 - q'2
        constraints.push(
            T::two_to_limb() * quotient_bound_carry2 - sum2 - quotient_bound_carry01
                + quotient_bound2,
        );

        constraints
    }
}
