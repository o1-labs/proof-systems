//! Keccak gadget
//! -------------
//! The Keccak gadget is a circuit that implements the Keccak hash function
//! for 64-bit words, output length of 256 bits and bit rate of 1088 bits.
//!
//! It is composed of 1 absorb sponge gate, followed by 24 rounds of permutation per block
//! and 1 final squeeze sponge gate that outputs the 256-bit hash.
//!
//! NOTE: The constraints used in this gadget assume a field size of at least 65 bits to be sound.
//!
use super::{DIM, OFF, QUARTERS};
use crate::{
    auto_clone, auto_clone_array,
    circuits::{
        argument::{Argument, ArgumentEnv, ArgumentType},
        expr::{constraints::ExprOps, Cache},
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

//~ | `KeccakRound` | [0...440) | [440...1540) | [1540...2344) |
//~ | ------------- | --------- | ------------ | ------------- |
//~ | Curr          | theta     | pirho        | chi           |
//~
//~ | `KeccakRound` | [0...100) |
//~ | ------------- | --------- |
//~ | Next          | iota      |
//~ -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
//~
//~ | Columns  | [0...100) | [100...120) | [120...200) | [200...220) | [220...240) | [240...260)  | [260...280) | [280...300)  | [300...320)  | [320...340) | [340...440) |
//~ | -------- | --------- | ----------- | ----------- | ----------- | ----------- | ------------ | ----------- | ------------ | ------------ | ----------- | ----------- |
//~ | theta    | state_a   | state_c     | shifts_c    | dense_c     | quotient_c  | remainder_c  | bound_c     | dense_rot_c  | expand_rot_c | state_d     | state_e     |
//~
//~ | Columns  | [440...840) | [840...940) | [940...1040) | [1040...1140) | [1140...1240) | [1240...1340) | [1340...1440) | [1440...1540) |
//~ | -------- | ----------- | ----------- | ------------ | ------------- | ------------- | ------------- | ------------- | ------------- |
//~ | pirho    | shifts_e    | dense_e     | quotient_e   | remainder_e   | bound_e       | dense_rot_e   | expand_rot_e  | state_b       |
//~
//~ | Columns  | [1540...1940) | [1940...2340) | [2340...2344 |
//~ | -------- | ------------- | ------------- | ------------ |
//~ | chi      | shifts_b      | shifts_sum    | f00          |
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
    const CONSTRAINTS: u32 = 754;

    // Constraints for one round of the Keccak permutation function
    fn constraint_checks<T: ExprOps<F>, const COLUMNS: usize>(
        env: &ArgumentEnv<F, T, COLUMNS>,
        _cache: &mut Cache,
    ) -> Vec<T> {
        let mut constraints = vec![];

        // DEFINE ROUND CONSTANT
        let rc = [env.coeff(0), env.coeff(1), env.coeff(2), env.coeff(3)];

        // LOAD STATES FROM WITNESS LAYOUT
        // THETA
        let state_a = grid!(100, env.witness_curr_chunk(0, 100));
        let state_c = grid!(20, env.witness_curr_chunk(100, 120));
        let shifts_c = grid!(80, env.witness_curr_chunk(120, 200));
        let dense_c = grid!(20, env.witness_curr_chunk(200, 220));
        let quotient_c = grid!(20, env.witness_curr_chunk(220, 240));
        let remainder_c = grid!(20, env.witness_curr_chunk(240, 260));
        let bound_c = grid!(20, env.witness_curr_chunk(260, 280));
        let dense_rot_c = grid!(20, env.witness_curr_chunk(280, 300));
        let expand_rot_c = grid!(20, env.witness_curr_chunk(300, 320));
        let state_d = grid!(20, env.witness_curr_chunk(320, 340));
        let state_e = grid!(100, env.witness_curr_chunk(340, 440));
        // PI-RHO
        let shifts_e = grid!(400, env.witness_curr_chunk(440, 840));
        let dense_e = grid!(100, env.witness_curr_chunk(840, 940));
        let quotient_e = grid!(100, env.witness_curr_chunk(940, 1040));
        let remainder_e = grid!(100, env.witness_curr_chunk(1040, 1140));
        let bound_e = grid!(100, env.witness_curr_chunk(1140, 1240));
        let dense_rot_e = grid!(100, env.witness_curr_chunk(1240, 1340));
        let expand_rot_e = grid!(100, env.witness_curr_chunk(1340, 1440));
        let state_b = grid!(100, env.witness_curr_chunk(1440, 1540));
        // CHI
        let shifts_b = grid!(400, env.witness_curr_chunk(1540, 1940));
        let shifts_sum = grid!(400, env.witness_curr_chunk(1940, 2340));
        let mut state_f: Vec<T> = env.witness_curr_chunk(2340, 2344);
        let mut tail = env.witness_next_chunk(4, 100);
        state_f.append(&mut tail);
        let state_f = grid!(100, state_f);
        // IOTA
        let mut state_g = env.witness_next_chunk(0, 4);
        let mut tail = env.witness_next_chunk(4, 100);
        state_g.append(&mut tail);
        let state_g = grid!(100, state_g);

        // STEP theta: 5 * ( 3 + 4 * (3 + 5 * 1) ) = 175 constraints
        for x in 0..DIM {
            let word_c = from_quarters!(dense_c, x);
            let quo_c = from_quarters!(quotient_c, x);
            let rem_c = from_quarters!(remainder_c, x);
            let bnd_c = from_quarters!(bound_c, x);
            let rot_c = from_quarters!(dense_rot_c, x);
            constraints
                .push(word_c * T::two_pow(1) - (quo_c.clone() * T::two_pow(64) + rem_c.clone()));
            constraints.push(rot_c - (quo_c.clone() + rem_c));
            constraints.push(bnd_c - (quo_c + T::two_pow(64) - T::two_pow(1)));

            for q in 0..QUARTERS {
                constraints.push(
                    state_c(x, q)
                        - (state_a(0, x, q)
                            + state_a(1, x, q)
                            + state_a(2, x, q)
                            + state_a(3, x, q)
                            + state_a(4, x, q)),
                );
                constraints.push(state_c(x, q) - from_shifts!(shifts_c, x, q));
                constraints.push(
                    state_d(x, q)
                        - (shifts_c(0, (x + DIM - 1) % DIM, q) + expand_rot_c((x + 1) % DIM, q)),
                );

                for y in 0..DIM {
                    constraints.push(state_e(y, x, q) - (state_a(y, x, q) + state_d(x, q)));
                }
            }
        } // END theta

        // STEP pirho: 5 * 5 * (3 + 4 * 2) = 275 constraints
        for (y, col) in OFF.iter().enumerate() {
            for (x, off) in col.iter().enumerate() {
                let word_e = from_quarters!(dense_e, y, x);
                let quo_e = from_quarters!(quotient_e, y, x);
                let rem_e = from_quarters!(remainder_e, y, x);
                let bnd_e = from_quarters!(bound_e, y, x);
                let rot_e = from_quarters!(dense_rot_e, y, x);

                constraints.push(
                    word_e * T::two_pow(*off) - (quo_e.clone() * T::two_pow(64) + rem_e.clone()),
                );
                constraints.push(rot_e - (quo_e.clone() + rem_e));
                constraints.push(bnd_e - (quo_e + T::two_pow(64) - T::two_pow(*off)));

                for q in 0..QUARTERS {
                    constraints.push(state_e(y, x, q) - from_shifts!(shifts_e, y, x, q));
                    constraints.push(state_b((2 * x + 3 * y) % DIM, y, q) - expand_rot_e(y, x, q));
                }
            }
        } // END pirho

        // STEP chi: 4 * 5 * 5 * 3 = 300 constraints
        for q in 0..QUARTERS {
            for x in 0..DIM {
                for y in 0..DIM {
                    let not = T::literal(F::from(0x1111111111111111u64))
                        - shifts_b(0, y, (x + 1) % DIM, q);
                    let sum = not + shifts_b(0, y, (x + 2) % DIM, q);
                    let and = shifts_sum(1, y, x, q);
                    constraints.push(state_b(y, x, q) - from_shifts!(shifts_b, y, x, q));
                    constraints.push(sum - from_shifts!(shifts_sum, y, x, q));
                    constraints.push(state_f(y, x, q) - (shifts_b(0, y, x, q) + and));
                }
            }
        } // END chi

        // STEP iota: 4 constraints
        for (q, c) in rc.iter().enumerate() {
            constraints.push(state_g(0, 0, q) - (state_f(0, 0, q) + c.clone()));
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
    const CONSTRAINTS: u32 = 568;

    // Constraints for the Keccak sponge
    fn constraint_checks<T: ExprOps<F>, const COLUMNS: usize>(
        env: &ArgumentEnv<F, T, COLUMNS>,
        _cache: &mut Cache,
    ) -> Vec<T> {
        let mut constraints = vec![];

        // LOAD WITNESS
        let old_state = env.witness_curr_chunk(0, 100);
        let new_block = env.witness_curr_chunk(100, 200);
        let zeros = env.witness_curr_chunk(168, 200);
        let xor_state = env.witness_next_chunk(0, 100);
        let bytes = env.witness_curr_chunk(200, 400);
        let shifts = env.witness_curr_chunk(400, 800);
        auto_clone_array!(old_state);
        auto_clone_array!(new_block);
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

        // 32 + 100 * 4 + 136 = 568
        for z in zeros {
            // Absorb phase pads with zeros the new state
            constraints.push(absorb() * z);
        }
        for i in 0..QUARTERS * DIM * DIM {
            // In first absorb, root state is all zeros
            constraints.push(root() * old_state(i));
            // Absorbs the new block by performing XOR with the old state
            constraints.push(absorb() * (xor_state(i) - (old_state(i) + new_block(i))));
            // In absorb, Check shifts correspond to the decomposition of the new state
            constraints.push(absorb() * (new_block(i) - from_shifts!(shifts, i)));
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
