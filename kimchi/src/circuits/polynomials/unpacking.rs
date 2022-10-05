use std::marker::PhantomData;

use crate::circuits::{
    argument::{Argument, ArgumentEnv, ArgumentType},
    expr::constraints::ExprOps,
    gate::GateType,
};
use ark_ff::{PrimeField};
pub struct Unpacking<F>(PhantomData<F>);

impl<F> Argument<F> for Unpacking<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::Unpacking);
    const CONSTRAINTS: u32 = 30;

    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>) -> Vec<T> {
        // The first entry in the current row is the value to 'unpack'.
        let input_value = env.witness_curr(0);
        // The rest of the row is filled with single-bit values.
        let bit_1 = env.witness_curr(1);
        let bit_2 = env.witness_curr(2);
        let bit_3 = env.witness_curr(3);
        let bit_4 = env.witness_curr(4);
        let bit_5 = env.witness_curr(5);
        let bit_6 = env.witness_curr(6);
        let bit_7 = env.witness_curr(7);
        let bit_8 = env.witness_curr(8);
        let bit_9 = env.witness_curr(9);
        let bit_10 = env.witness_curr(10);
        let bit_11 = env.witness_curr(11);
        let bit_12 = env.witness_curr(12);
        let bit_13 = env.witness_curr(13);
        let bit_14 = env.witness_curr(14);
        // The next row is also filled with single-bit values.
        let bit_15 = env.witness_next(0);
        let bit_16 = env.witness_next(1);
        let bit_17 = env.witness_next(2);
        let bit_18 = env.witness_next(3);
        let bit_19 = env.witness_next(4);
        let bit_20 = env.witness_next(5);
        let bit_21 = env.witness_next(6);
        let bit_22 = env.witness_next(7);
        let bit_23 = env.witness_next(8);
        let bit_24 = env.witness_next(9);
        let bit_25 = env.witness_next(10);
        let bit_26 = env.witness_next(11);
        let bit_27 = env.witness_next(12);
        let bit_28 = env.witness_next(13);
        let bit_29 = env.witness_next(14);

        // Check that x * x = x, i.e. that x = 0 or x = 1.
        let check_is_boolean = |x: &T| { x.clone() * x.clone() - x.clone() };

        // The constraints: check that each bit is a boolean value (0 or 1).
        let mut constraints = vec![
            check_is_boolean(&bit_1),
            check_is_boolean(&bit_2),
            check_is_boolean(&bit_3),
            check_is_boolean(&bit_4),
            check_is_boolean(&bit_5),
            check_is_boolean(&bit_6),
            check_is_boolean(&bit_7),
            check_is_boolean(&bit_8),
            check_is_boolean(&bit_9),
            check_is_boolean(&bit_10),
            check_is_boolean(&bit_11),
            check_is_boolean(&bit_12),
            check_is_boolean(&bit_13),
            check_is_boolean(&bit_14),
            check_is_boolean(&bit_15),
            check_is_boolean(&bit_16),
            check_is_boolean(&bit_17),
            check_is_boolean(&bit_18),
            check_is_boolean(&bit_19),
            check_is_boolean(&bit_20),
            check_is_boolean(&bit_21),
            check_is_boolean(&bit_22),
            check_is_boolean(&bit_23),
            check_is_boolean(&bit_24),
            check_is_boolean(&bit_25),
            check_is_boolean(&bit_26),
            check_is_boolean(&bit_27),
            check_is_boolean(&bit_28),
            check_is_boolean(&bit_29),
        ];

        // Compute the value that the bits represent.
        let bits_added_together =
          bit_1
          + T::from(2u64) * (bit_2
          + T::from(2u64) * (bit_3
          + T::from(2u64) * (bit_4
          + T::from(2u64) * (bit_5
          + T::from(2u64) * (bit_6
          + T::from(2u64) * (bit_7
          + T::from(2u64) * (bit_8
          + T::from(2u64) * (bit_9
          + T::from(2u64) * (bit_10
          + T::from(2u64) * (bit_11
          + T::from(2u64) * (bit_12
          + T::from(2u64) * (bit_13
          + T::from(2u64) * (bit_14
          + T::from(2u64) * (bit_15
          + T::from(2u64) * (bit_16
          + T::from(2u64) * (bit_17
          + T::from(2u64) * (bit_18
          + T::from(2u64) * (bit_19
          + T::from(2u64) * (bit_20
          + T::from(2u64) * (bit_21
          + T::from(2u64) * (bit_22
          + T::from(2u64) * (bit_23
          + T::from(2u64) * (bit_24
          + T::from(2u64) * (bit_25
          + T::from(2u64) * (bit_26
          + T::from(2u64) * (bit_27
          + T::from(2u64) * (bit_28
          + T::from(2u64) * (bit_29))))))))))))))))))))))))))));

        // Check that bits_added_together = input_value
        constraints.push(bits_added_together - input_value);

        // Return the complete list of constraints.
        constraints
    }
}
