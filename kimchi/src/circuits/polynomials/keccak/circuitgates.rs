//! Keccak gadget
use super::{DIM, QUARTERS};
use crate::{
    auto_clone, auto_clone_array,
    circuits::{
        argument::{Argument, ArgumentEnv, ArgumentType},
        expr::{constraints::ExprOps, Cache},
        gate::GateType,
    },
    state_from_vec,
};
use ark_ff::PrimeField;
use std::marker::PhantomData;

/// Creates the 5x5 table of rotation bits for Keccak modulo 64
/// | x \ y |  0 |  1 |  2 |  3 |  4 |
/// | ----- | -- | -- | -- | -- | -- |
/// | 0     |  0 | 36 |  3 | 41 | 18 |
/// | 1     |  1 | 44 | 10 | 45 |  2 |
/// | 2     | 62 |  6 | 43 | 15 | 61 |
/// | 3     | 28 | 55 | 25 | 21 | 56 |
/// | 4     | 27 | 20 | 39 |  8 | 14 |
/// Note that the order of the indexing is [y][x] to match the encoding of the witness algorithm
pub(crate) const OFF: [[u64; DIM]; DIM] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
];

//~
//~ | `KeccakRound` | [0...440) | [440...1540) | [1540...2344) |
//~ | ------------- | --------- | ------------ | ------------- |
//~ | Curr          | theta     | pirho        | chi           |
//~
//~ | `KeccakRound` | [0...100) |
//~ | ------------- | --------- |
//~ | Next          | iota      |
//~
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
    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>, _cache: &mut Cache) -> Vec<T> {
        let mut constraints = vec![];

        // DEFINE ROUND CONSTANT
        let rc = [env.coeff(0), env.coeff(1), env.coeff(2), env.coeff(3)];

        // LOAD STATES FROM WITNESS LAYOUT
        // THETA
        let state_a = state_from_vec!(env.witness_curr_chunk(0, 100));
        let state_c = state_from_vec!(env.witness_curr_chunk(100, 120));
        let shifts_c = state_from_vec!(env.witness_curr_chunk(120, 200));
        let dense_c = state_from_vec!(env.witness_curr_chunk(200, 220));
        let quotient_c = state_from_vec!(env.witness_curr_chunk(220, 240));
        let remainder_c = state_from_vec!(env.witness_curr_chunk(240, 260));
        let bound_c = state_from_vec!(env.witness_curr_chunk(260, 280));
        let dense_rot_c = state_from_vec!(env.witness_curr_chunk(280, 300));
        let expand_rot_c = state_from_vec!(env.witness_curr_chunk(300, 320));
        let state_d = state_from_vec!(env.witness_curr_chunk(320, 340));
        let state_e = state_from_vec!(env.witness_curr_chunk(340, 440));
        // PI-RHO
        let shifts_e = state_from_vec!(env.witness_curr_chunk(440, 840));
        let dense_e = state_from_vec!(env.witness_curr_chunk(840, 940));
        let quotient_e = state_from_vec!(env.witness_curr_chunk(940, 1040));
        let remainder_e = state_from_vec!(env.witness_curr_chunk(1040, 1140));
        let bound_e = state_from_vec!(env.witness_curr_chunk(1140, 1240));
        let dense_rot_e = state_from_vec!(env.witness_curr_chunk(1240, 1340));
        let expand_rot_e = state_from_vec!(env.witness_curr_chunk(1340, 1440));
        let state_b = state_from_vec!(env.witness_curr_chunk(1440, 1540));
        // CHI
        let shifts_b = state_from_vec!(env.witness_curr_chunk(1540, 1940));
        let shifts_sum = state_from_vec!(env.witness_curr_chunk(1940, 2340));
        let mut state_f = env.witness_curr_chunk(2340, 2344);
        let mut tail = env.witness_next_chunk(4, 100);
        state_f.append(&mut tail);
        let state_f = state_from_vec!(state_f);
        // IOTA
        let mut state_g = env.witness_next_chunk(0, 4);
        let mut tail = env.witness_next_chunk(4, 100);
        state_g.append(&mut tail);
        let state_g = state_from_vec!(state_g);

        // STEP theta: 5 * ( 3 + 4 * (3 + 5 * 1) ) = 175 constraints
        for x in 0..DIM {
            let word_c = compose_quarters(dense_c, x, 0);
            let quo_c = compose_quarters(quotient_c, x, 0);
            let rem_c = compose_quarters(remainder_c, x, 0);
            let bnd_c = compose_quarters(bound_c, x, 0);
            let rot_c = compose_quarters(dense_rot_c, x, 0);
            constraints
                .push(word_c * T::two_pow(1) - (quo_c.clone() * T::two_pow(64) + rem_c.clone()));
            constraints.push(rot_c - (quo_c.clone() + rem_c));
            constraints.push(bnd_c - (quo_c + T::two_pow(64) - T::two_pow(1)));

            for q in 0..QUARTERS {
                constraints.push(
                    state_c(0, x, 0, q)
                        - (state_a(0, x, 0, q)
                            + state_a(0, x, 1, q)
                            + state_a(0, x, 2, q)
                            + state_a(0, x, 3, q)
                            + state_a(0, x, 4, q)),
                );
                constraints.push(state_c(0, x, 0, q) - compose_shifts(shifts_c, x, 0, q));
                constraints.push(
                    state_d(0, x, 0, q)
                        - (shifts_c(0, (x - 1 + DIM) % DIM, 0, q)
                            + expand_rot_c(0, (x + 1) % DIM, 0, q)),
                );

                for y in 0..DIM {
                    constraints
                        .push(state_e(0, x, y, q) - (state_a(0, x, y, q) + state_d(0, x, 0, q)));
                }
            }
        } // END theta

        // STEP pirho: 5 * 5 * (3 + 4 * 2) = 275 constraints
        for (y, col) in OFF.iter().enumerate() {
            for (x, off) in col.iter().enumerate() {
                let word_e = compose_quarters(dense_e, x, y);
                let quo_e = compose_quarters(quotient_e, x, y);
                let rem_e = compose_quarters(remainder_e, x, y);
                let bnd_e = compose_quarters(bound_e, x, y);
                let rot_e = compose_quarters(dense_rot_e, x, y);

                constraints.push(
                    word_e * T::two_pow(*off) - (quo_e.clone() * T::two_pow(64) + rem_e.clone()),
                );
                constraints.push(rot_e - (quo_e.clone() + rem_e));
                constraints.push(bnd_e - (quo_e + T::two_pow(64) - T::two_pow(*off)));

                for q in 0..QUARTERS {
                    constraints.push(state_e(0, x, y, q) - compose_shifts(shifts_e, x, y, q));
                    constraints
                        .push(state_b(0, y, (2 * x + 3 * y) % DIM, q) - expand_rot_e(0, x, y, q));
                }
            }
        } // END pirho

        // STEP chi: 4 * 5 * 5 * 3 = 300 constraints
        for q in 0..QUARTERS {
            for x in 0..DIM {
                for y in 0..DIM {
                    let not =
                        T::literal(F::from(0x1111111111111111u64)) - shifts_b(0, (x + 1) % 5, y, q);
                    let sum = not + shifts_b(1, (x + 2) % 5, y, q);
                    let and = shifts_sum(1, x, y, q);
                    constraints.push(state_b(0, x, y, q) - compose_shifts(shifts_b, x, y, q));
                    constraints.push(sum - compose_shifts(shifts_sum, x, y, q));
                    constraints.push(state_f(0, x, y, q) - (shifts_b(0, x, y, q) + and));
                }
            }
        } // END chi

        // STEP iota: 4 constraints
        for (q, c) in rc.iter().enumerate() {
            constraints.push(state_g(0, 0, 0, q) - (state_f(0, 0, 0, q) + c.clone()));
        } // END iota

        constraints
    }
}

//~
//~ | `KeccakSponge` | [0...100) | [100...168) | [168...200) | [200...300) | [300...500] | [500...900) |
//~ | -------------- | --------- | ----------- | ----------- | ----------- | ----------- | ----------- |
//~ | Curr           | old_state | new_block   | zeros       | dense       | bytes       | shifts      |
//~ | Next           | xor_state |
//~
#[derive(Default)]
pub struct KeccakSponge<F>(PhantomData<F>);

impl<F> Argument<F> for KeccakSponge<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::KeccakSponge);
    const CONSTRAINTS: u32 = 448;

    // Constraints for one round of the Keccak permutation function
    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>, _cache: &mut Cache) -> Vec<T> {
        let mut constraints = vec![];

        // LOAD WITNESS
        let old_state = env.witness_curr_chunk(0, 100);
        let mut new_block = env.witness_curr_chunk(100, 168);
        let mut zeros = env.witness_curr_chunk(168, 200);
        new_block.append(&mut zeros);
        let xor_state = env.witness_next_chunk(0, 100);
        let dense = env.witness_curr_chunk(200, 300);
        let bytes = env.witness_curr_chunk(300, 500);
        let shifts = env.witness_curr_chunk(500, 900);
        auto_clone_array!(old_state);
        auto_clone_array!(new_block);
        auto_clone_array!(xor_state);
        auto_clone_array!(dense);
        auto_clone_array!(bytes);
        auto_clone_array!(shifts);

        // LOAD COEFFICIENTS
        let root = env.coeff(0);
        let absorb = env.coeff(1);
        let squeeze = env.coeff(2);
        auto_clone!(root);
        auto_clone!(absorb);
        auto_clone!(squeeze);

        // STEP absorb: 32 + 100 * 4 = 432
        for z in zeros {
            // Absorb phase pads with zeros the new state
            constraints.push(absorb() * z);
        }
        for i in 0..QUARTERS * DIM * DIM {
            // In first absorb, root state is all zeros
            constraints.push(root() * old_state(i));
            // Absorbs the new block by performing XOR with the old state
            constraints.push(absorb() * (xor_state(i) - (old_state(i) + new_block(i))));
            // Check shifts correspond to the decomposition of the new state
            constraints.push(absorb() * (new_block(i) - compose_shifts_from_vec(shifts, i)));
            // Both phases: check correctness of each dense term (16 bits) by composing two bytes
            constraints.push(dense(i) - (bytes(2 * i) + T::two_pow(8) * bytes(2 * i + 1)));
        }

        // STEP squeeze: 16 constraints
        for i in 0..16 {
            // Check shifts correspond to the 256-bit prefix digest of the old state (current)
            constraints.push(squeeze() * (old_state(i) - compose_shifts_from_vec(shifts, i)));
        }

        constraints
    }
}

fn compose_quarters<F: PrimeField, T: ExprOps<F>>(
    quarters: impl Fn(usize, usize, usize, usize) -> T,
    x: usize,
    y: usize,
) -> T {
    quarters(0, x, y, 0)
        + T::two_pow(16) * quarters(0, x, y, 1)
        + T::two_pow(32) * quarters(0, x, y, 2)
        + T::two_pow(48) * quarters(0, x, y, 3)
}

fn compose_shifts<F: PrimeField, T: ExprOps<F>>(
    shifts: impl Fn(usize, usize, usize, usize) -> T,
    x: usize,
    y: usize,
    q: usize,
) -> T {
    shifts(0, x, y, q)
        + T::two_pow(1) * shifts(1, x, y, q)
        + T::two_pow(2) * shifts(2, x, y, q)
        + T::two_pow(3) * shifts(3, x, y, q)
}

fn compose_shifts_from_vec<F: PrimeField, T: ExprOps<F>>(
    shifts: impl Fn(usize) -> T,
    i: usize,
) -> T {
    shifts(4 * i)
        + T::two_pow(1) * shifts(4 * i + 1)
        + T::two_pow(2) * shifts(4 * i + 2)
        + T::two_pow(3) * shifts(4 * i + 3)
}
