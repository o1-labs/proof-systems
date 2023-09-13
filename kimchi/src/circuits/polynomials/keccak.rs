//! Keccak gadget
use crate::circuits::{
    argument::{Argument, ArgumentEnv, ArgumentType},
    expr::{constraints::ExprOps, Cache},
    gate::GateType,
};
use ark_ff::PrimeField;
use std::marker::PhantomData;

pub const DIM: usize = 5;
pub const QUARTERS: usize = 4;

#[macro_export]
macro_rules! state_from_layout {
    ($var:ident, $expr:expr) => {
        let $var = $expr;
        let $var = |i: usize, x: usize, y: usize, q: usize| {
            $var[q + QUARTERS * (x + DIM * (y + DIM * i))].clone()
        };
    };
    ($var:ident) => {
        let $var = |i: usize, x: usize, y: usize, q: usize| {
            $var[q + QUARTERS * (x + DIM * (y + DIM * i))].clone()
        };
    };
}

/// Creates the 5x5 table of rotation bits for Keccak modulo 64
/// | x \ y |  0 |  1 |  2 |  3 |  4 |
/// | ----- | -- | -- | -- | -- | -- |
/// | 0     |  0 | 36 |  3 | 41 | 18 |
/// | 1     |  1 | 44 | 10 | 45 |  2 |
/// | 2     | 62 |  6 | 43 | 15 | 61 |
/// | 3     | 28 | 55 | 25 | 21 | 56 |
/// | 4     | 27 | 20 | 39 |  8 | 14 |
pub const OFF: [[u64; DIM]; DIM] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

pub const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
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
//~ | theta    | state_a   | state_c     | reset_c     | dense_c     | quotient_c  | remainder_c  | bound_c     | dense_rot_c  | expand_rot_c | state_d     | state_e     |
//~
//~ | Columns  | [440...840) | [840...940) | [940...1040) | [1040...1140) | [1140...1240) | [1240...1340) | [1340...1440) | [1440...1540) |
//~ | -------- | ----------- | ----------- | ------------ | ------------- | ------------- | ------------- | ------------- | ------------- |
//~ | pirho    | reset_e     | dense_e     | quotient_e   | remainder_e   | bound_e       | dense_rot_e   | expand_rot_e  | state_b       |
//~
//~ | Columns  | [1540...1940) | [1940...2340) | [2340...2344 |
//~ | -------- | ------------- | ------------- | ------------ |
//~ | chi      | reset_b       | reset_sum     | f00          |
//~
//~ | Columns  | [0...4) | [4...100) |
//~ | -------- | ------- | --------- |
//~ | iota     | g00     | state_f   |
//~
#[derive(Default)]
pub struct Keccak<F>(PhantomData<F>);

impl<F> Argument<F> for Keccak<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::Keccak);
    const CONSTRAINTS: u32 = 754;

    // Constraints for one round of the Keccak permutation function
    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>, _cache: &mut Cache) -> Vec<T> {
        let mut constraints = vec![];

        // DEFINE ROUND CONSTANT
        let rc = [env.coeff(0), env.coeff(1), env.coeff(2), env.coeff(3)];

        // LOAD WITNESS LAYOUT
        // THETA
        let state_a = env.witness_curr_chunk(0, 100);
        let state_c = env.witness_curr_chunk(100, 120);
        let reset_c = env.witness_curr_chunk(120, 200);
        let dense_c = env.witness_curr_chunk(200, 220);
        let quotient_c = env.witness_curr_chunk(220, 240);
        let remainder_c = env.witness_curr_chunk(240, 260);
        let bound_c = env.witness_curr_chunk(260, 280);
        let dense_rot_c = env.witness_curr_chunk(280, 300);
        let expand_rot_c = env.witness_curr_chunk(300, 320);
        let state_d = env.witness_curr_chunk(320, 340);
        let state_e = env.witness_curr_chunk(340, 440);
        // PI-RHO
        let reset_e = env.witness_curr_chunk(440, 840);
        let dense_e = env.witness_curr_chunk(840, 940);
        let quotient_e = env.witness_curr_chunk(940, 1040);
        let remainder_e = env.witness_curr_chunk(1040, 1140);
        let bound_e = env.witness_curr_chunk(1140, 1240);
        let dense_rot_e = env.witness_curr_chunk(1240, 1340);
        let expand_rot_e = env.witness_curr_chunk(1340, 1440);
        let state_b = env.witness_curr_chunk(1440, 1540);
        // CHI
        let reset_b = env.witness_curr_chunk(1540, 1940);
        let reset_sum = env.witness_curr_chunk(1940, 2340);
        let mut state_f = env.witness_curr_chunk(2340, 2344);
        let mut tail = env.witness_next_chunk(4, 100);
        state_f.append(&mut tail);
        // IOTA
        let mut state_g = env.witness_next_chunk(0, 4);
        state_g.append(&mut tail);

        // LOAD STATES FROM LAYOUT
        state_from_layout!(state_a);
        state_from_layout!(state_c);
        state_from_layout!(reset_c);
        state_from_layout!(dense_c);
        state_from_layout!(quotient_c);
        state_from_layout!(remainder_c);
        state_from_layout!(bound_c);
        state_from_layout!(dense_rot_c);
        state_from_layout!(expand_rot_c);
        state_from_layout!(state_d);
        state_from_layout!(state_e);
        state_from_layout!(reset_e);
        state_from_layout!(dense_e);
        state_from_layout!(quotient_e);
        state_from_layout!(remainder_e);
        state_from_layout!(bound_e);
        state_from_layout!(dense_rot_e);
        state_from_layout!(expand_rot_e);
        state_from_layout!(state_b);
        state_from_layout!(reset_b);
        state_from_layout!(reset_sum);
        state_from_layout!(state_f);
        state_from_layout!(state_g);

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
                constraints.push(state_c(0, x, 0, q) - compose_shifts(reset_c, x, 0, q));
                constraints.push(
                    state_d(0, x, 0, q)
                        - (reset_c(0, (x - 1 + DIM) % DIM, 0, q)
                            + expand_rot_c(0, (x + 1) % DIM, 0, q)),
                );

                for y in 0..DIM {
                    constraints
                        .push(state_e(0, x, y, q) - (state_a(0, x, y, q) + state_d(0, x, 0, q)));
                }
            }
        } // END theta

        // STEP pirho: 5 * 5 * (3 + 4 * 2) = 275 constraints
        for (x, row) in OFF.iter().enumerate() {
            for (y, off) in row.iter().enumerate() {
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
                    constraints.push(state_e(0, x, y, q) - compose_shifts(reset_e, x, y, q));
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
                        T::literal(F::from(0x1111111111111111u64)) - reset_b(0, (x + 1) % 5, y, q);
                    let sum = not + reset_b(1, (x + 2) % 5, y, q);
                    let and = reset_sum(1, x, y, q);
                    constraints.push(state_b(0, x, y, q) - compose_shifts(reset_b, x, y, q));
                    constraints.push(sum - compose_shifts(reset_sum, x, y, q));
                    constraints.push(state_f(0, x, y, q) - (reset_b(0, x, y, q) + and));
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
    resets: impl Fn(usize, usize, usize, usize) -> T,
    x: usize,
    y: usize,
    q: usize,
) -> T {
    resets(0, x, y, q)
        + T::two_pow(1) * resets(1, x, y, q)
        + T::two_pow(2) * resets(2, x, y, q)
        + T::two_pow(3) * resets(3, x, y, q)
}
