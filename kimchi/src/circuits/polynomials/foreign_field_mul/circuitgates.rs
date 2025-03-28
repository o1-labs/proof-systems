//! Foreign field multiplication

//~ This gadget is used to constrain that
//~
//~```text
//~ left_input * right_input = quotient * foreign_field_modulus + remainder
//~```
//~
//~ ##### Documentation
//~
//~ For more details please see the [Foreign Field Multiplication](../kimchi/foreign_field_mul.md)
//~ chapter or the original [Foreign Field Multiplication RFC](https://github.com/o1-labs/rfcs/blob/main/0006-ffmul-revised.md).
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
//~ left_input0 => a0  right_input0 => b0  quotient0 => q0  remainder01 => r01
//~ left_input1 => a1  right_input1 => b1  quotient1 => q1
//~ left_input2 => a2  right_input2 => b2  quotient2 => q2  remainder2 => r2
//~
//~    product1_lo => p10      product1_hi_0 => p110     product1_hi_1 => p111
//~    carry0 => v0            carry1_lo => v10          carry1_hi => v11
//~    quotient_hi_bound => q'2
//~
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
//~ * `hi_foreign_field_modulus` := high limb of foreign field modulus $f$ (stored in gate coefficient 0)
//~ * `neg_foreign_field_modulus` := negated foreign field modulus $f'$ (stored in gate coefficients 1-3)
//~ * `n` := the native field modulus is obtainable from `F`, the native field's trait bound
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
//~ * `product1_lo` := lowest 88 bits of middle intermediate product
//~ * `product1_hi_0` := lowest 88 bits of middle intermediate product's highest 88 + 2 bits
//~ * `product1_hi_1` := highest 2 bits of middle intermediate product
//~ * `quotient_hi_bound` := quotient high bound for checking `q2 ≤ f2`
//~
//~ ##### Layout
//~
//~ The foreign field multiplication gate's rows are laid out like this
//~
//~ | col | `ForeignFieldMul`       | `Zero`                     |
//~ | --- | ----------------------- | -------------------------- |
//~ |   0 | `left_input0`    (copy) | `remainder01`       (copy) |
//~ |   1 | `left_input1`    (copy) | `remainder2`        (copy) |
//~ |   2 | `left_input2`    (copy) | `quotient0`         (copy) |
//~ |   3 | `right_input0`   (copy) | `quotient1`         (copy) |
//~ |   4 | `right_input1`   (copy) | `quotient2`         (copy) |
//~ |   5 | `right_input2`   (copy) | `quotient_hi_bound` (copy) |
//~ |   6 | `product1_lo`    (copy) | `product1_hi_0`     (copy) |
//~ |   7 | `carry1_0`    (plookup) | `product1_hi_1`    (dummy) |
//~ |   8 | `carry1_12    (plookup) | `carry1_48`      (plookup) |
//~ |   9 | `carry1_24`   (plookup) | `carry1_60`      (plookup) |
//~ |  10 | `carry1_36`   (plookup) | `carry1_72`      (plookup) |
//~ |  11 | `carry1_84`             | `carry0`                   |
//~ |  12 | `carry1_86`             |                            |
//~ |  13 | `carry1_88`             |                            |
//~ |  14 | `carry1_90`             |                            |
//~

use crate::{
    auto_clone_array,
    circuits::{
        argument::{Argument, ArgumentEnv, ArgumentType},
        berkeley_columns::BerkeleyChallengeTerm,
        expr::{constraints::ExprOps, Cache},
        gate::GateType,
    },
};
use ark_ff::PrimeField;
use core::{array, marker::PhantomData};

/// Compute non-zero intermediate products
///
/// For more details see the "Intermediate products" Section of
/// the [Foreign Field Multiplication RFC](https://github.com/o1-labs/rfcs/blob/main/0006-ffmul-revised.md)
///
pub fn compute_intermediate_products<F: PrimeField, T: ExprOps<F, BerkeleyChallengeTerm>>(
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
        // p2 = a0 * b2 + a2 * b0 + a1 * b1 + q0 * f'2 + q2 * f'0 + q1 * f'1
        left_input(0) * right_input(2)
            + left_input(2) * right_input(0)
            + left_input(1) * right_input(1)
            + quotient(0) * neg_foreign_field_modulus(2)
            + quotient(2) * neg_foreign_field_modulus(0)
            + quotient(1) * neg_foreign_field_modulus(1),
    ]
}

// Compute native modulus values
pub fn compute_native_modulus_values<F: PrimeField, T: ExprOps<F, BerkeleyChallengeTerm>>(
    left_input: &[T; 3],
    right_input: &[T; 3],
    quotient: &[T; 3],
    remainder: &[T; 2],
    neg_foreign_field_modulus: &[T; 3],
) -> [T; 5] {
    auto_clone_array!(left_input);
    auto_clone_array!(right_input);
    auto_clone_array!(quotient);
    auto_clone_array!(remainder);
    auto_clone_array!(neg_foreign_field_modulus);

    [
        // an = 2^2L * a2 + 2^L * a1 + a0
        T::two_to_2limb() * left_input(2) + T::two_to_limb() * left_input(1) + left_input(0),
        // bn = 2^2L * b2 + 2^L * b1 + b0
        T::two_to_2limb() * right_input(2) + T::two_to_limb() * right_input(1) + right_input(0),
        // qn = 2^2L * q2 + 2^L * q1 + b0
        T::two_to_2limb() * quotient(2) + T::two_to_limb() * quotient(1) + quotient(0),
        // rn = 2^2L * r2 + 2^L * r1 + r0 = 2^2L * r2 + r01
        T::two_to_2limb() * remainder(1) + remainder(0),
        // f'n = 2^2L * f'2 + 2^L * f'1 + f'0
        T::two_to_2limb() * neg_foreign_field_modulus(2)
            + T::two_to_limb() * neg_foreign_field_modulus(1)
            + neg_foreign_field_modulus(0),
    ]
}

/// Composes the 91-bit carry1 value from its parts
pub fn compose_carry<F: PrimeField, T: ExprOps<F, BerkeleyChallengeTerm>>(carry: &[T; 11]) -> T {
    auto_clone_array!(carry);
    carry(0)
        + T::two_pow(12) * carry(1)
        + T::two_pow(2 * 12) * carry(2)
        + T::two_pow(3 * 12) * carry(3)
        + T::two_pow(4 * 12) * carry(4)
        + T::two_pow(5 * 12) * carry(5)
        + T::two_pow(6 * 12) * carry(6)
        + T::two_pow(7 * 12) * carry(7)
        + T::two_pow(86) * carry(8)
        + T::two_pow(88) * carry(9)
        + T::two_pow(90) * carry(10)
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

    fn constraint_checks<T: ExprOps<F, BerkeleyChallengeTerm>>(
        env: &ArgumentEnv<F, T>,
        _cache: &mut Cache,
    ) -> Vec<T> {
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

        // Carry bits v1 decomposed into 7 sublimbs of 12 bits, 3 crumbs of 2 bits, and 1 bit
        // Total is 91 bits (v11 3 bits + v10 88 bits)
        let carry1_crumb0 = env.witness_curr(11);
        let carry1_crumb1 = env.witness_curr(12);
        let carry1_crumb2 = env.witness_curr(13);
        let carry1_bit = env.witness_curr(14);
        let carry1 = compose_carry(&[
            env.witness_curr(7),   // 12-bit lookup
            env.witness_curr(8),   // 12-bit lookup
            env.witness_curr(9),   // 12-bit lookup
            env.witness_curr(10),  // 12-bit lookup
            env.witness_next(8),   // 12-bit lookup
            env.witness_next(9),   // 12-bit lookup
            env.witness_next(10),  // 12-bit lookup
            carry1_crumb0.clone(), // 2-bit crumb
            carry1_crumb1.clone(), // 2-bit crumb
            carry1_crumb2.clone(), // 2-bit crumb
            carry1_bit.clone(),    // 1-bit
        ]);

        // Carry bits v0
        let carry0 = env.witness_next(11);

        // Quotient q
        let quotient = [
            env.witness_next(2),
            env.witness_next(3),
            env.witness_next(4),
        ];

        // Quotient high bound: q2 + 2^88 - f2
        // Copied for multi-range-check
        let quotient_hi_bound = env.witness_next(5);

        // Remainder r (a.k.a. result) in compact format
        // remainder01 := remainder0 + remainder1 * 2^88
        // Actual limbs of the result will be obtained from the multi-range-check
        // Copiable for multi-range-check
        let remainder = [env.witness_next(0), env.witness_next(1)];

        // Decomposition of the middle intermediate product
        let product1_lo = env.witness_curr(6); // Copied for multi-range-check
        let product1_hi_0 = env.witness_next(6); // Copied for multi-range-check
        let product1_hi_1 = env.witness_next(7); // dummy

        // Foreign field modulus high limb
        let hi_foreign_field_modulus = env.coeff(0);

        // Negated foreign field modulus limbs
        let neg_foreign_field_modulus = array::from_fn(|i| env.coeff(1 + i));

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

        // Compute native modulus values
        let [left_input_n, right_input_n, quotient_n, remainder_n, neg_foreign_field_modulus_n] =
            compute_native_modulus_values(
                &left_input,
                &right_input,
                &quotient,
                &remainder,
                &neg_foreign_field_modulus,
            );

        // bound = x2 + 2^88 - f2 - 1
        let bound = quotient[2].clone() + T::two_to_limb() - hi_foreign_field_modulus - T::one();

        // Define the constraints
        //   For more the details on each constraint please see the
        //   Foreign Field Multiplication RFC where each of the constraints
        //   numbered below are described in full detail.

        // External checks
        // multi-range-check: q'2, p10, p110
        // That is, check bound, product1_lo, product1_hi_0 each in [0, 2^L)
        // Must be done externally with a multi-range-check gadget

        // C1: Constrain intermediate product fragment product1_hi_1 \in [0, 2^2)
        // RFC: Corresponds to C3
        constraints.push(product1_hi_1.crumb());

        // C2: Constrain first carry witness value v0 \in [0, 2^2)
        // RFC: Corresponds to C5
        constraints.push(carry0.crumb());

        // C3: Constrain decomposition of middle intermediate product p1
        //         p1 = 2^L*p11 + p10
        //     where p11 = 2^L * p111 + p110
        // RFC: corresponds to C2
        let product1_hi = T::two_to_limb() * product1_hi_1 + product1_hi_0;
        let product1 = T::two_to_limb() * product1_hi.clone() + product1_lo.clone();
        constraints.push(products(1) - product1);

        // C4: Constrain that 2^2L * v0 = p0 + 2^L * p10 - r01. That is, that
        //         2^2L * carry0 = rhs
        // RFC: Corresponds to C4
        constraints.push(
            T::two_to_2limb() * carry0.clone()
                - (products(0) + T::two_to_limb() * product1_lo - remainder[0].clone()),
        );

        // C5: Native modulus constraint a_n * b_n + q_n * f'_n - q_n * 2^264 = r_n
        // RFC: Corresponds to C1
        constraints.push(
            left_input_n * right_input_n + quotient_n.clone() * neg_foreign_field_modulus_n
                - remainder_n
                - quotient_n * T::two_to_3limb(),
        );

        // Constrain v1 is 91-bits (done with 7 plookups, 3 crumbs, and 1 bit)
        // C6: 2-bit c1_84
        // RFC: Corresponds to C7
        constraints.push(carry1_crumb0.crumb());
        // C7: 2-bit c1_86
        // RFC: Corresponds to C8
        constraints.push(carry1_crumb1.crumb());
        // C8: 2-bit c1_88
        // RFC: Corresponds to C9
        constraints.push(carry1_crumb2.crumb());
        // C9: 1-bit c1_90
        // RFC: Corresponds to C10
        constraints.push(carry1_bit.boolean());

        // C10: Top part:
        //      Constrain that 2^L * v1 = p2 + p11 + v0 - r2. That is,
        //         2^L * (2^L * carry1_hi + carry1_lo) = rhs
        // RFC: Corresponds to C6
        constraints.push(
            T::two_to_limb() * carry1 - (products(2) + product1_hi + carry0 - remainder[1].clone()),
        );

        // C11: Constrain that q'2 is correct
        // RFC: Corresponds to C11
        constraints.push(quotient_hi_bound - bound);

        constraints
    }
}
