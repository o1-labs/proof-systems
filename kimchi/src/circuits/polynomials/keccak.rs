//! Keccak gadget
use std::array;

use ark_ff::{PrimeField, SquareRootField};

use crate::circuits::{
    gate::{CircuitGate, Connect},
    polynomial::COLUMNS,
    polynomials::generic::GenericGateSpec,
    wires::Wire,
};

/// Creates the 5x5 table of rotation bits for Keccak modulo 64
/// | x \ y |  0 |  1 |  2 |  3 |  4 |
/// | ----- | -- | -- | -- | -- | -- |
/// | 0     |  0 | 36 |  3 | 41 | 18 |
/// | 1     |  1 | 44 | 10 | 45 |  2 |
/// | 2     | 62 |  6 | 43 | 15 | 61 |
/// | 3     | 28 | 55 | 25 | 21 | 56 |
/// | 4     | 27 | 20 | 39 |  8 | 14 |
pub const ROT_TAB: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

//~
//~ | Columns  | [0...440) | [440...1540) | [1540...2440) | 2440 |
//~ | -------- | --------- | ------------ | ------------- | ---- |
//~ | `Keccak` | theta     | pirho        | chi           | iota |
//~
//~ | Columns  | [0...100) | [100...120) | [120...200) | [200...220) | [220...240) | [240...260)  | [260...280) | [280...300)  | 300...320)   | [320...340) | [340...440) |
//~ | -------- | --------- | ----------- | ----------- | ----------- | ----------- | ------------ | ----------- | ------------ | ------------ | ----------- | ----------- |
//~ | theta    | state_a   | state_c     | reset_c     | dense_c     | quotient_c  | remainder_c  | bound_c     | dense_rot_c  | expand_rot_c | state_d     | state_e     |
//~
//~ | Columns  | [440...840) | [840...940) | [940...1040) | [1040...1140) | [1140...1240) | [1240...1340) | [1440...1540) |
//~ | -------- | ----------- | ----------- | ------------ | ------------- | ------------- | ------------- | ------------- |
//~ | pirho    | reset_e     | dense_e     | quotient_e   | remainder_e   | bound_e       | dense_rot_e   | expand_rot_e  |
//~
//~ | Columns  | [1540...1940) | [1940...2340) | [2340...2440) |
//~ | -------- | ------------- | ------------- | ------------- |
//~ | chi      | reset_b       | reset_sum     | state_f       |
//~
//~ | Columns  | 2440 |
//~ | -------- | ---- |
//~ | iota     | g00  |
//~
#[derive(Default)]
pub struct Keccak<F>(PhantomData<F>);

impl<F> Argument<F> for Keccak<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::Keccak);
    const CONSTRAINTS: u32 = 20 + 55 + 100 + 125 + 200 + 4;

    // Constraints for one round of the Keccak permutation function
    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>, _cache: &mut Cache) -> Vec<T> {
        // Check that the last 8 columns are 2-bit crumbs
        // C1..C8: x * (x - 1) * (x - 2) * (x - 3) = 0
        let mut constraints = (7..COLUMNS)
            .map(|i| crumb(&env.witness_curr(i)))
            .collect::<Vec<T>>();

        // NOTE:
        // If we ever want to make this gate more generic, the power of two for the length
        // could be a coefficient of the gate instead of a fixed value in the constraints.
        let two_to_64 = T::two_pow(64);

        let word = env.witness_curr(0);
        let rotated = env.witness_curr(1);
        let excess = env.witness_curr(2);
        let shifted = env.witness_next(0);
        let two_to_rot = env.coeff(0);

        // Obtains the following checks:
        // C9: word * 2^{rot} = (excess * 2^64 + shifted)
        // C10: rotated = shifted + excess
        constraints.push(
            word * two_to_rot.clone() - (excess.clone() * two_to_64.clone() + shifted.clone()),
        );
        constraints.push(rotated - (shifted + excess.clone()));

        // Compute the bound from the crumbs and limbs
        let mut power_of_2 = T::one();
        let mut bound = T::zero();

        // Sum 2-bit limbs
        for i in (7..COLUMNS).rev() {
            bound += power_of_2.clone() * env.witness_curr(i);
            power_of_2 *= T::two_pow(2); // 2 bits
        }

        // Sum 12-bit limbs
        for i in (3..=6).rev() {
            bound += power_of_2.clone() * env.witness_curr(i);
            power_of_2 *= T::two_pow(12); // 12 bits
        }

        // Check that excess < 2^rot by checking that bound < 2^64
        // Check RFC of Keccak for more details on the proof of this
        // C11:bound = excess - 2^rot + 2^64
        constraints.push(bound - (excess - two_to_rot + two_to_64));

        constraints
    }
}
