//! Keccak gadget
use super::{constants::*, OFF};
use crate::{
    auto_clone, auto_clone_array,
    circuits::{
        argument::{Argument, ArgumentEnv, ArgumentType},
        expr::{
            constraints::{boolean, ExprOps},
            Cache,
        },
        gate::GateType,
    },
    grid,
};
use ark_ff::PrimeField;
use std::marker::PhantomData;

#[macro_export]
macro_rules! from_quarters {
    ($quarters:ident, $x:ident) => {
        $quarters($x, 0)
            + T::two_pow(16) * $quarters($x, 1)
            + T::two_pow(32) * $quarters($x, 2)
            + T::two_pow(48) * $quarters($x, 3)
    };
    ($quarters:ident, $y:ident, $x:ident) => {
        $quarters($y, $x, 0)
            + T::two_pow(16) * $quarters($y, $x, 1)
            + T::two_pow(32) * $quarters($y, $x, 2)
            + T::two_pow(48) * $quarters($y, $x, 3)
    };
}

#[macro_export]
macro_rules! from_shifts {
    ($shifts:ident, $i:ident) => {
        $shifts($i)
            + T::two_pow(1) * $shifts(100 + $i)
            + T::two_pow(2) * $shifts(200 + $i)
            + T::two_pow(3) * $shifts(300 + $i)
    };
    ($shifts:ident, $x:ident, $q:ident) => {
        $shifts(0, $x, $q)
            + T::two_pow(1) * $shifts(1, $x, $q)
            + T::two_pow(2) * $shifts(2, $x, $q)
            + T::two_pow(3) * $shifts(3, $x, $q)
    };
    ($shifts:ident, $y:ident, $x:ident, $q:ident) => {
        $shifts(0, $y, $x, $q)
            + T::two_pow(1) * $shifts(1, $y, $x, $q)
            + T::two_pow(2) * $shifts(2, $y, $x, $q)
            + T::two_pow(3) * $shifts(3, $y, $x, $q)
    };
}

//~
//~ | `KeccakRound` | [0...265) | [265...1165) | [1165...1965) |
//~ | ------------- | --------- | ------------ | ------------- |
//~ | Curr          | theta     | pirho        | chi           |
//~
//~ | `KeccakRound` | [0...100) |
//~ | ------------- | --------- |
//~ | Next          | iota      |
//~
//~ -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
//~
//~ | Columns  | [0...100) | [100...180) | [180...200) | [200...205) | [205...225)  | [225...245)  | [245...265)  |
//~ | -------- | --------- | ----------- | ----------- | ----------- | ------------ | ------------ | ------------ |
//~ | theta    | state_a   | shifts_c    | dense_c     | quotient_c  | remainder_c  | dense_rot_c  | expand_rot_c |
//~
//~ | Columns  | [265...665) | [665...765) | [765...865)  | [865...965) | [965...1065) | [1065...1165) |
//~ | -------- | ----------- | ----------- | ------------ | ----------- | ------------ | ------------- |
//~ | pirho    | shifts_e    | dense_e     | quotient_e   | remainder_e | dense_rot_e  | expand_rot_e  |
//~
//~ | Columns  | [1165...1565) | [1565...1965) |
//~ | -------- | ------------- | ------------- |
//~ | chi      | shifts_b      | shifts_sum    |
//~
//~ | Columns  | [0...4) | [4...100) |
//~ | -------- | ------- | --------- |
//~ | iota     | g00     | rest_g    |
//~
#[derive(Default)]
pub struct KeccakRound<F>(PhantomData<F>);

impl<F> Argument<F> for KeccakRound<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::KeccakRound);
    const CONSTRAINTS: u32 = 389;

    // Constraints for one round of the Keccak permutation function
    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>, _cache: &mut Cache) -> Vec<T> {
        let mut constraints = vec![];

        // DEFINE ROUND CONSTANT
        let rc = [env.coeff(0), env.coeff(1), env.coeff(2), env.coeff(3)];

        // LOAD STATES FROM WITNESS LAYOUT
        // THETA
        let state_a = grid!(
            100,
            env.witness_curr_chunk(THETA_STATE_A_OFF, THETA_SHIFTS_C_OFF)
        );
        let shifts_c = grid!(
            80,
            env.witness_curr_chunk(THETA_SHIFTS_C_OFF, THETA_DENSE_C_OFF)
        );
        let dense_c = grid!(
            20,
            env.witness_curr_chunk(THETA_DENSE_C_OFF, THETA_QUOTIENT_C_OFF)
        );
        let quotient_c = grid!(
            5,
            env.witness_curr_chunk(THETA_QUOTIENT_C_OFF, THETA_REMAINDER_C_OFF)
        );
        let remainder_c = grid!(
            20,
            env.witness_curr_chunk(THETA_REMAINDER_C_OFF, THETA_DENSE_ROT_C_OFF)
        );
        let dense_rot_c = grid!(
            20,
            env.witness_curr_chunk(THETA_DENSE_ROT_C_OFF, THETA_EXPAND_ROT_C_OFF)
        );
        let expand_rot_c = grid!(
            20,
            env.witness_curr_chunk(THETA_EXPAND_ROT_C_OFF, PIRHO_DENSE_E_OFF)
        );
        // PI-RHO
        let shifts_e = grid!(
            400,
            env.witness_curr_chunk(PIRHO_SHIFTS_E_OFF, PIRHO_DENSE_E_OFF)
        );
        let dense_e = grid!(
            100,
            env.witness_curr_chunk(PIRHO_DENSE_E_OFF, PIRHO_QUOTIENT_E_OFF)
        );
        let quotient_e = grid!(
            100,
            env.witness_curr_chunk(PIRHO_QUOTIENT_E_OFF, PIRHO_REMAINDER_E_OFF)
        );
        let remainder_e = grid!(
            100,
            env.witness_curr_chunk(PIRHO_REMAINDER_E_OFF, PIRHO_DENSE_ROT_E_OFF)
        );
        let dense_rot_e = grid!(
            100,
            env.witness_curr_chunk(PIRHO_DENSE_ROT_E_OFF, PIRHO_EXPAND_ROT_E_OFF)
        );
        let expand_rot_e = grid!(
            100,
            env.witness_curr_chunk(PIRHO_EXPAND_ROT_E_OFF, CHI_SHIFTS_B_OFF)
        );
        // CHI
        let shifts_b = grid!(
            400,
            env.witness_curr_chunk(CHI_SHIFTS_B_OFF, CHI_SHIFTS_SUM_OFF)
        );
        let shifts_sum = grid!(
            400,
            env.witness_curr_chunk(CHI_SHIFTS_SUM_OFF, IOTA_STATE_G_OFF)
        );
        // IOTA
        let state_g = grid!(100, env.witness_next_chunk(0, IOTA_STATE_G_LEN));

        // Define vectors containing witness expressions which are not in the layout for efficiency
        let mut state_c: Vec<Vec<T>> = vec![vec![T::zero(); QUARTERS]; DIM];
        let mut state_d: Vec<Vec<T>> = vec![vec![T::zero(); QUARTERS]; DIM];
        let mut state_e: Vec<Vec<Vec<T>>> = vec![vec![vec![T::zero(); QUARTERS]; DIM]; DIM];
        let mut state_b: Vec<Vec<Vec<T>>> = vec![vec![vec![T::zero(); QUARTERS]; DIM]; DIM];
        let mut state_f: Vec<Vec<Vec<T>>> = vec![vec![vec![T::zero(); QUARTERS]; DIM]; DIM];

        // STEP theta: 5 * ( 3 + 4 * 1 ) = 35 constraints
        for x in 0..DIM {
            let word_c = from_quarters!(dense_c, x);
            let rem_c = from_quarters!(remainder_c, x);
            let rot_c = from_quarters!(dense_rot_c, x);

            constraints
                .push(word_c * T::two_pow(1) - (quotient_c(x) * T::two_pow(64) + rem_c.clone()));
            constraints.push(rot_c - (quotient_c(x) + rem_c));
            constraints.push(boolean(&quotient_c(x)));

            for q in 0..QUARTERS {
                state_c[x][q] = state_a(0, x, q)
                    + state_a(1, x, q)
                    + state_a(2, x, q)
                    + state_a(3, x, q)
                    + state_a(4, x, q);
                constraints.push(state_c[x][q].clone() - from_shifts!(shifts_c, x, q));

                state_d[x][q] =
                    shifts_c(0, (x + DIM - 1) % DIM, q) + expand_rot_c((x + 1) % DIM, q);

                for (y, column_e) in state_e.iter_mut().enumerate() {
                    column_e[x][q] = state_a(y, x, q) + state_d[x][q].clone();
                }
            }
        } // END theta

        // STEP pirho: 5 * 5 * (2 + 4 * 1) = 150 constraints
        for (y, col) in OFF.iter().enumerate() {
            for (x, off) in col.iter().enumerate() {
                let word_e = from_quarters!(dense_e, y, x);
                let quo_e = from_quarters!(quotient_e, y, x);
                let rem_e = from_quarters!(remainder_e, y, x);
                let rot_e = from_quarters!(dense_rot_e, y, x);

                constraints.push(
                    word_e * T::two_pow(*off) - (quo_e.clone() * T::two_pow(64) + rem_e.clone()),
                );
                constraints.push(rot_e - (quo_e.clone() + rem_e));

                for q in 0..QUARTERS {
                    constraints.push(state_e[y][x][q].clone() - from_shifts!(shifts_e, y, x, q));
                    state_b[(2 * x + 3 * y) % DIM][y][q] = expand_rot_e(y, x, q);
                }
            }
        } // END pirho

        // STEP chi: 4 * 5 * 5 * 2 = 200 constraints
        for q in 0..QUARTERS {
            for x in 0..DIM {
                for y in 0..DIM {
                    let not = T::literal(F::from(0x1111111111111111u64))
                        - shifts_b(0, y, (x + 1) % DIM, q);
                    let sum = not + shifts_b(0, y, (x + 2) % DIM, q);
                    let and = shifts_sum(1, y, x, q);

                    constraints.push(state_b[y][x][q].clone() - from_shifts!(shifts_b, y, x, q));
                    constraints.push(sum - from_shifts!(shifts_sum, y, x, q));
                    state_f[y][x][q] = shifts_b(0, y, x, q) + and;
                }
            }
        } // END chi

        // STEP iota: 4 constraints
        for (q, c) in rc.iter().enumerate() {
            constraints.push(state_g(0, 0, q) - (state_f[0][0][q].clone() + c.clone()));
        } // END iota

        constraints
    }
}

//~
//~ | `KeccakSponge` | [0...100) | [100...168) | [168...200) | [200...400] | [400...800) |
//~ | -------------- | --------- | ----------- | ----------- | ----------- | ----------- |
//~ | Curr           | old_state | new_block   | zeros       | bytes       | shifts      |
//~ | Next           | xor_state |
//~
#[derive(Default)]
pub struct KeccakSponge<F>(PhantomData<F>);

impl<F> Argument<F> for KeccakSponge<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::KeccakSponge);
    const CONSTRAINTS: u32 = 500;

    // Constraints for the Keccak sponge
    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>, _cache: &mut Cache) -> Vec<T> {
        let mut constraints = vec![];

        // LOAD WITNESS
        let old_state = env.witness_curr_chunk(SPONGE_OLD_STATE_OFF, SPONGE_NEW_STATE_OFF);
        let new_state = env.witness_curr_chunk(SPONGE_NEW_STATE_OFF, SPONGE_BYTES_OFF);
        let new_block = env.witness_curr_chunk(SPONGE_NEW_BLOCK_OFF, SPONGE_ZEROS_OFF);
        let zeros = env.witness_curr_chunk(SPONGE_ZEROS_OFF, SPONGE_BYTES_OFF);
        let xor_state = env.witness_next_chunk(0, SPONGE_XOR_STATE_LEN);
        let bytes = env.witness_curr_chunk(SPONGE_BYTES_OFF, SPONGE_SHIFTS_OFF);
        let shifts =
            env.witness_curr_chunk(SPONGE_SHIFTS_OFF, SPONGE_SHIFTS_OFF + SPONGE_SHIFTS_LEN);
        auto_clone_array!(old_state);
        auto_clone_array!(new_state);
        auto_clone_array!(xor_state);
        auto_clone_array!(bytes);
        auto_clone_array!(shifts);

        // LOAD COEFFICIENTS
        let absorb = env.coeff(0);
        let squeeze = env.coeff(1);
        let root = env.coeff(2);
        let flags = env.coeff_chunk(4, 140);
        let pad = env.coeff_chunk(200, 336);
        auto_clone!(root);
        auto_clone!(absorb);
        auto_clone!(squeeze);
        auto_clone_array!(flags);
        auto_clone_array!(pad);

        // 32 + 68 + 100 * 2 + 64 + 136 = 500
        for z in zeros {
            // Absorb phase pads with zeros the new state
            constraints.push(absorb() * z);
        }
        for (i, new) in new_block.iter().enumerate() {
            // Absorbs the new block by performing XOR with the old state (no need full state because zeros)
            constraints.push(absorb() * (xor_state(i) - (old_state(i) + new.clone())));
        }
        for i in 0..STATE_LEN {
            // In first absorb, root state is all zeros
            constraints.push(root() * old_state(i));
            // In absorb, Check shifts correspond to the decomposition of the new state
            constraints.push(absorb() * (new_state(i) - from_shifts!(shifts, i)));
        }
        for i in 0..64 {
            // In squeeze, Check shifts correspond to the 256-bit prefix digest of the old state (current)
            constraints.push(squeeze() * (old_state(i) - from_shifts!(shifts, i)));
        }
        for i in 0..136 {
            // Check padding
            constraints.push(flags(i) * (pad(i) - bytes(i)));
        }

        constraints
    }
}
