//! Keccak gadget
use crate::circuits::{
    argument::{Argument, ArgumentEnv, ArgumentType},
    expr::{constraints::ExprOps, Cache},
    gate::{CircuitGate, GateType},
    lookup::{
        self,
        tables::{GateLookupTable, LookupTable},
    },
    wires::Wire,
};
use ark_ff::{PrimeField, SquareRootField};
use std::marker::PhantomData;

pub const DIM: usize = 5;
pub const QUARTERS: usize = 4;
pub const ROUNDS: usize = 24;
pub const RATE: usize = 136;

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

fn expand<F: PrimeField, T: ExprOps<F>>(word: u64) -> Vec<T> {
    format!("{:064b}", word)
        .chars()
        .collect::<Vec<char>>()
        .chunks(16)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<String>>()
        .iter()
        .map(|c| T::literal(F::from(u64::from_str_radix(c, 16).unwrap())))
        .collect::<Vec<T>>()
}

impl<F: PrimeField + SquareRootField> CircuitGate<F> {
    /// Extends a Keccak circuit to hash up to one block of message (up to 135 bytes)
    pub fn extend_keccak(new_row: usize) -> usize {
        // pad
    }

    /// Creates a Keccak256 circuit, capacity 512 bits, rate 1088 bits, for a padded message of a given bytelength
    fn create_keccak_sponge(new_row: usize, bytelength: usize) -> Vec<Self> {
        let mut gates = Self::create_keccak_absorb(new_row, bytelength);
    }

    fn create_keccak_squeeze(new_row: usize) -> Vec<Self> {}

    fn create_keccak_absorb(new_row: usize, bytelength: usize) -> Vec<Self> {
        for i in 0..(bytelength / RATE) {
            let mut gates = Self::create_keccak_setup(new_row);
            let mut gates = Self::create_keccak_permutation(new_row);
        }
    }

    fn create_keccak_setup(new_row: usize) -> Vec<Self> {
        let mut gates = vec![];

        gates
    }

    fn create_keccak_permutation(new_row: usize) -> Vec<Self> {
        let mut gates = vec![];
        for round in 0..ROUNDS {
            gates.push(Self::create_keccak_round(new_row + gates.len(), round));
        }
        gates
    }

    fn create_keccak_round(new_row: usize, round: usize) -> Self {
        CircuitGate {
            typ: GateType::Keccak,
            wires: Wire::for_row(new_row),
            coeffs: expand(RC[round]),
        }
    }

    /// Extend one rotation
    /// Right now it only creates a Generic gate followed by the Rot64 gates
    /// It allows to configure left or right rotation.
    /// Input:
    /// - gates : the full circuit
    /// - rot : the rotation offset
    /// - side : the rotation side
    /// - zero_row : the row of the Generic gate to constrain the 64-bit check of shifted word
    /// Warning:
    /// - witness word should come from the copy of another cell so it is intrinsic that it is 64-bits length,
    /// - same with rotated word
    pub fn extend_rot(gates: &mut Vec<Self>, rot: u32) -> usize {
        let (_new_row, mut keccak_gates) = Self::create_keccak(gates.len(), rot, side);
        gates.append(&mut rot_gates);
        gates.len()
    }

    /// Create one rotation
    /// Right now it only creates a Generic gate followed by the Rot64 gates
    /// It allows to configure left or right rotation.
    /// Input:
    /// - rot : the rotation offset
    /// - side : the rotation side
    /// Warning:
    /// - Word should come from the copy of another cell so it is intrinsic that it is 64-bits length,
    /// - same with rotated word
    /// - need to check that the 2 most significant limbs of shifted are zero
    pub fn create_rot(new_row: usize, rot: u32, side: RotMode) -> (usize, Vec<Self>) {
        // Initial Generic gate to constrain the output to be zero
        let rot_gates = if side == RotMode::Left {
            Self::create_rot64(new_row, rot)
        } else {
            Self::create_rot64(new_row, 64 - rot)
        };

        (new_row + rot_gates.len(), rot_gates)
    }
}

/// Get the keccak lookup table
pub fn lookup_table<F: PrimeField>() -> LookupTable<F> {
    lookup::tables::get_table::<F>(GateLookupTable::Sparse)
}

//~
//~ | Columns  | [0...200) | [0...440) | [440...1540) | [1540...2440) | 2440 |
//~ | -------- | --------- | ------------ | ------------- | ---- |
//~ | `Keccak` | xor       | theta     | pirho        | chi           | iota |
//~
//~ | Columns  | [0...100) | [100...200) |
//~ | -------- | --------- | ----------- |
//~ | xor      | old_state | new_state   |
//~
//~ | Columns  | [200...300) | [300...320) | [320...400) | [400...420) | [420...440) | [440...460)  | [460...480) | [480...500)  | 500...520)   | [520...540) | [540...640) |
//~ | -------- | ----------- | ----------- | ----------- | ----------- | ----------- | ------------ | ----------- | ------------ | ------------ | ----------- | ----------- |
//~ | theta    | state_a     | state_c     | reset_c     | dense_c     | quotient_c  | remainder_c  | bound_c     | dense_rot_c  | expand_rot_c | state_d     | state_e     |
//~
//~ | Columns  | [640...1040) | [1040...1140) | [1140...1240) | [1240...1340) | [1340...1440) | [1440...1540) | [1640...1740) |
//~ | -------- | ------------ | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- |
//~ | pirho    | reset_e      | dense_e       | quotient_e    | remainder_e   | bound_e       | dense_rot_e   | expand_rot_e  |
//~
//~ | Columns  | [1740...2140) | [2140...2540) | [2540...2640) |
//~ | -------- | ------------- | ------------- | ------------- |
//~ | chi      | reset_b       | reset_sum     | state_f       |
//~
//~ | Columns  | [2640...2644) |
//~ | -------- | ------------- |
//~ | iota     | g00           |
//~
#[derive(Default)]
pub struct Keccak<F>(PhantomData<F>);

impl<F> Argument<F> for Keccak<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::Keccak);
    const CONSTRAINTS: u32 = 954;

    // Constraints for one round of the Keccak permutation function
    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>, _cache: &mut Cache) -> Vec<T> {
        let mut constraints = vec![];

        // DEFINE ROUND CONSTANT
        let rc = [env.coeff(0), env.coeff(1), env.coeff(2), env.coeff(3)];

        // LOAD WITNESS LAYOUT
        // XOR
        let old_state = env.witness_curr_chunk(0, 100);
        let new_state = env.witness_curr_chunk(100, 200);
        // THETA
        let state_a = env.witness_curr_chunk(200, 300);
        let state_c = env.witness_curr_chunk(300, 320);
        let reset_c = env.witness_curr_chunk(320, 400);
        let dense_c = env.witness_curr_chunk(400, 420);
        let quotient_c = env.witness_curr_chunk(420, 440);
        let remainder_c = env.witness_curr_chunk(440, 460);
        let bound_c = env.witness_curr_chunk(460, 480);
        let dense_rot_c = env.witness_curr_chunk(480, 500);
        let expand_rot_c = env.witness_curr_chunk(500, 520);
        let state_d = env.witness_curr_chunk(520, 540);
        let state_e = env.witness_curr_chunk(540, 640);
        // PI-RHO
        let reset_e = env.witness_curr_chunk(640, 1040);
        let dense_e = env.witness_curr_chunk(1040, 1140);
        let quotient_e = env.witness_curr_chunk(1140, 1240);
        let remainder_e = env.witness_curr_chunk(1240, 1340);
        let bound_e = env.witness_curr_chunk(1340, 1440);
        let dense_rot_e = env.witness_curr_chunk(1440, 1540);
        let expand_rot_e = env.witness_curr_chunk(1540, 1640);
        let state_b = env.witness_curr_chunk(1640, 1740);
        // CHI
        let reset_b = env.witness_curr_chunk(1740, 2140);
        let reset_sum = env.witness_curr_chunk(2140, 2540);
        let state_f = env.witness_curr_chunk(2540, 2640);
        // IOTA
        let g00 = env.witness_curr_chunk(2640, 2644);
        // NEXT
        let next_state = env.witness_next_chunk(0, 100);

        // LOAD STATES FROM LAYOUT
        state_from_layout!(old_state);
        state_from_layout!(new_state);
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
        state_from_layout!(next_state);

        // STEP xor: 100 constraints
        for q in 0..QUARTERS {
            for x in 0..DIM {
                for y in 0..DIM {
                    constraints.push(
                        state_a(0, x, y, q) - (old_state(0, x, y, q) + new_state(0, x, y, q)),
                    );
                }
            }
        }

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
            constraints.push(g00(0, 0, 0, q) - (state_f(0, 0, 0, q) + c.clone()));
        } // END iota

        // WIRE TO NEXT ROUND: 4 * 5 * 5 * 1 = 100 constraints
        for q in 0..QUARTERS {
            for x in 0..DIM {
                for y in 0..DIM {
                    if x == 0 && y == 0 {
                        constraints.push(next_state(0, 0, 0, q) - g00(0, 0, 0, q));
                    } else {
                        constraints.push(next_state(0, x, y, q) - state_f(0, x, y, q));
                    }
                }
            }
        } // END wiring

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

fn _expand<F: PrimeField, T: ExprOps<F>>(word: u64) -> Vec<T> {
    format!("{:064b}", word)
        .chars()
        .collect::<Vec<char>>()
        .chunks(16)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<String>>()
        .iter()
        .map(|c| T::literal(F::from(u64::from_str_radix(c, 16).unwrap())))
        .collect::<Vec<T>>()
}
