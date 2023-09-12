//! Keccak gadget
use crate::circuits::{
    argument::{Argument, ArgumentEnv, ArgumentType},
    expr::{constraints::ExprOps, Cache},
    gate::GateType,
};
use ark_ff::PrimeField;
use std::marker::PhantomData;

#[macro_export]
macro_rules! state_from_layout {
    ($var:ident, $expr:expr) => {
        let $var = $expr;
        let $var = |i: usize, x: usize, y: usize, q: usize| {
            $var[q + PARTS * (x + DIM * (y + DIM * i))].clone()
        };
    };
    ($var:ident) => {
        let $var = |i: usize, x: usize, y: usize, q: usize| {
            $var[q + PARTS * (x + DIM * (y + DIM * i))].clone()
        };
    };
}

pub const DIM: usize = 5;
pub const PARTS: usize = 4;

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
        let mut constraints = vec![];

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
        let state_f = env.witness_curr_chunk(2340, 2440);
        // IOTA
        let g00 = env.witness_curr_chunk(2440, 2444);

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
        state_from_layout!(g00);

        // STEP theta

        constraints
    }
}
