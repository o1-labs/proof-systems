//! This module contains the definition and implementation of the Keccak environment
//! including the common functions between the witness and the constraints environments
//! for arithmetic, boolean, and column operations.
use crate::keccak::{
    column::{KeccakWitness, PAD_BYTES_LEN, ROUND_COEFFS_LEN},
    constraints::{Constraints, Env as ConstraintsEnv},
    grid_index, pad_blocks,
    witness::Env as WitnessEnv,
    BoolOps, KeccakColumn, DIM, E, HASH_BYTELENGTH, QUARTERS, WORDS_IN_HASH,
};
use ark_ff::{Field, One};
use kimchi::{
    auto_clone_array,
    circuits::{
        expr::{ConstantTerm::Literal, Operations},
        polynomials::keccak::{
            constants::*,
            witness::{Chi, Iota, PiRho, Theta},
            Keccak,
        },
    },
    grid,
    o1_utils::Two,
};
use std::array;

/// This struct contains all that needs to be kept track of during the execution of the Keccak step interpreter
#[derive(Clone, Debug)]
pub struct KeccakEnv<F> {
    /// Environment for the constraints (includes lookups)
    pub constraints_env: ConstraintsEnv<F>,
    /// Environment for the witness (includes multiplicities)
    pub witness_env: WitnessEnv<F>,

    /// What step of the hash is being executed (or None, if just ended)
    pub keccak_step: Option<KeccakStep>,

    /// Hash index in the circuit
    pub(crate) hash_idx: u64,
    /// Step counter of the total number of steps executed so far in the current hash (starts with 0)
    pub(crate) step_idx: u64,
    /// Current block of preimage data
    pub(crate) block_idx: u64,

    /// Expanded block of previous step
    pub(crate) prev_block: Vec<u64>,
    /// How many blocks are left to absorb (including current absorb)
    pub(crate) blocks_left_to_absorb: u64,
    /// Padded preimage data
    pub(crate) padded: Vec<u8>,
    /// Byte-length of the 10*1 pad (<=136)
    pub(crate) pad_len: u64,
}

/// Variants of Keccak steps available for the interpreter
#[derive(Clone, Debug, PartialEq, Copy)]
pub enum KeccakStep {
    Sponge(Sponge),
    Round(u64),
}

/// Variants of Keccak sponges
#[derive(Clone, Debug, PartialEq, Copy)]
pub enum Sponge {
    Absorb(Absorb),
    Squeeze,
}

/// Order of absorb steps in the computation depending on the number of blocks to absorb
#[derive(Clone, Debug, PartialEq, Copy)]
pub enum Absorb {
    First,        // Also known as the root absorb
    Middle,       // Any other absorb
    Last,         // Also known as the padding absorb
    FirstAndLast, // In case there is only one block to absorb (preimage data is less than 136 bytes)
}

impl<F: Field> KeccakEnv<F> {
    /// Starts a new Keccak environment for a given hash index and bytestring of preimage data
    pub fn new(hash_idx: u64, preimage: &[u8]) -> Self {
        let mut env = Self {
            constraints_env: ConstraintsEnv::default(),
            witness_env: WitnessEnv::default(),
            keccak_step: None,
            hash_idx,
            step_idx: 0,
            block_idx: 0,
            prev_block: vec![],
            blocks_left_to_absorb: 0,
            padded: vec![],
            pad_len: 0,
        };

        // Store hash index in the witness
        env.write_column(KeccakColumn::HashIndex, env.hash_idx);

        // Update the number of blocks left to be absorbed depending on the length of the preimage
        env.blocks_left_to_absorb = Keccak::num_blocks(preimage.len()) as u64;

        // Configure first step depending on number of blocks remaining
        env.keccak_step = if env.blocks_left_to_absorb == 1 {
            Some(KeccakStep::Sponge(Sponge::Absorb(Absorb::FirstAndLast)))
        } else {
            Some(KeccakStep::Sponge(Sponge::Absorb(Absorb::First)))
        };
        env.step_idx = 0;

        // Root state (all zeros) shall be used for the first step
        env.prev_block = vec![0u64; STATE_LEN];

        // Pad preimage with the 10*1 padding rule
        env.padded = Keccak::pad(preimage);
        env.block_idx = 0;
        env.pad_len = (env.padded.len() - preimage.len()) as u64;

        env
    }

    /// Writes an integer value to a column of the Keccak witness
    pub fn write_column(&mut self, column: KeccakColumn, value: u64) {
        self.witness_env.witness[column] = F::from(value);
    }

    /// Writes a field value to a column of the Keccak witness
    pub fn write_column_field(&mut self, column: KeccakColumn, value: F) {
        self.witness_env.witness[column] = value;
    }

    /// Nullifies the KeccakWitness of the environment by resetting it to default values
    pub fn null_state(&mut self) {
        self.witness_env.witness = KeccakWitness::default();
        self.witness_env.check_idx = 0; // Reset constraint count for debugging
    }

    /// Entrypoint for the interpreter. It executes one step of the Keccak circuit (one row),
    /// and updates the environment accordingly (including the witness and inter-step lookups).
    /// When it finishes, it updates the value of the current step, so that the next call to
    /// the `step()` function executes the next step.
    pub fn step(&mut self) {
        // Reset columns to zeros to avoid conflicts between steps
        self.null_state();

        match self.keccak_step.unwrap() {
            KeccakStep::Sponge(typ) => self.run_sponge(typ),
            KeccakStep::Round(i) => self.run_round(i),
        }
        self.write_column(KeccakColumn::StepIndex, self.step_idx);

        self.update_step();
    }

    /// This function updates the next step of the environment depending on the current step
    pub fn update_step(&mut self) {
        match self.keccak_step {
            Some(step) => match step {
                KeccakStep::Sponge(sponge) => match sponge {
                    Sponge::Absorb(_) => self.keccak_step = Some(KeccakStep::Round(0)),

                    Sponge::Squeeze => self.keccak_step = None,
                },
                KeccakStep::Round(round) => {
                    if round < ROUNDS as u64 - 1 {
                        self.keccak_step = Some(KeccakStep::Round(round + 1));
                    } else {
                        self.blocks_left_to_absorb -= 1;
                        match self.blocks_left_to_absorb {
                            0 => self.keccak_step = Some(KeccakStep::Sponge(Sponge::Squeeze)),
                            1 => {
                                self.keccak_step =
                                    Some(KeccakStep::Sponge(Sponge::Absorb(Absorb::Last)))
                            }
                            _ => {
                                self.keccak_step =
                                    Some(KeccakStep::Sponge(Sponge::Absorb(Absorb::Middle)))
                            }
                        }
                    }
                }
            },
            None => panic!("No step to update"),
        }
        self.step_idx += 1;
    }

    /// Updates the witness corresponding to the `FlagRound` column with a value in [0..24)
    fn set_flag_round(&mut self, round: u64) {
        assert!(round < ROUNDS as u64);
        self.write_column(KeccakColumn::FlagRound, round);
    }
    /// Sets the witness corresponding to the `FlagSqueeze` column to 1
    fn set_flag_squeeze(&mut self) {
        self.write_column(KeccakColumn::FlagSqueeze, 1);
    }
    /// Sets the witness corresponding to the `FlagAbsorb` column to 1 and
    /// updates and any other sponge flag depending on the kind of absorb step (root, padding, both).
    fn set_flag_absorb(&mut self, absorb: Absorb) {
        self.write_column(KeccakColumn::FlagAbsorb, 1);
        match absorb {
            Absorb::First => self.set_flag_root(),
            Absorb::Last => self.set_flag_pad(),
            Absorb::FirstAndLast => {
                self.set_flag_root();
                self.set_flag_pad()
            }
            Absorb::Middle => (),
        }
    }
    /// Sets the witness corresponding to the `FlagRoot` column to 1
    fn set_flag_root(&mut self) {
        self.write_column(KeccakColumn::FlagRoot, 1);
    }
    /// Sets the witness corresponding to the `FlagPad` column to 1, and updates the remaining columns
    /// related to padding flags such as `PadLength`, `InvPadLength`, `TwoToPad`, `PadBytesFlags`, and `PadSuffix`.
    fn set_flag_pad(&mut self) {
        self.write_column(KeccakColumn::PadLength, self.pad_len);
        self.write_column_field(
            KeccakColumn::InvPadLength,
            F::inverse(&F::from(self.pad_len)).unwrap(),
        );
        self.write_column_field(KeccakColumn::TwoToPad, F::two_pow(self.pad_len));
        let pad_range = RATE_IN_BYTES - self.pad_len as usize..RATE_IN_BYTES;
        for i in pad_range {
            self.write_column(KeccakColumn::PadBytesFlags(i), 1);
        }
        let pad_blocks = pad_blocks::<F>(self.pad_len as usize);
        for (idx, value) in pad_blocks.iter().enumerate() {
            self.write_column_field(KeccakColumn::PadSuffix(idx), *value);
        }
    }

    /// Assigns the witness values needed in a sponge step (absorb or squeeze)
    fn run_sponge(&mut self, sponge: Sponge) {
        match sponge {
            Sponge::Absorb(absorb) => self.run_absorb(absorb),
            Sponge::Squeeze => self.run_squeeze(),
        }
    }
    /// Assigns the witness values needed in an absorb step (root, padding, or middle)
    fn run_absorb(&mut self, absorb: Absorb) {
        self.set_flag_absorb(absorb);

        // Compute witness values
        let ini_idx = RATE_IN_BYTES * self.block_idx as usize;
        let mut block = self.padded[ini_idx..ini_idx + RATE_IN_BYTES].to_vec();
        self.write_column(KeccakColumn::BlockIndex, self.block_idx);

        // Pad with zeros
        block.append(&mut vec![0; CAPACITY_IN_BYTES]);

        //    Round + Mode of Operation (Sponge)
        //    state -> permutation(state) -> state'
        //              ----> either [0] or state'
        //             |            new state = Exp(block)
        //             |         ------------------------
        //    Absorb: state  + [  block      +     0...0 ]
        //                       1088 bits          512
        //            ----------------------------------
        //                         XOR STATE
        let old_state = self.prev_block.clone();
        let new_state = Keccak::expand_state(&block);
        let xor_state = old_state
            .iter()
            .zip(new_state.clone())
            .map(|(x, y)| x + y)
            .collect::<Vec<u64>>();

        let shifts = Keccak::shift(&new_state);
        let bytes = block.iter().map(|b| *b as u64).collect::<Vec<u64>>();

        // Write absorb-related columns
        for idx in 0..STATE_LEN {
            self.write_column(KeccakColumn::Input(idx), old_state[idx]);
            self.write_column(KeccakColumn::SpongeNewState(idx), new_state[idx]);
            self.write_column(KeccakColumn::Output(idx), xor_state[idx]);
        }
        for (idx, value) in bytes.iter().enumerate() {
            self.write_column(KeccakColumn::SpongeBytes(idx), *value);
        }
        for (idx, value) in shifts.iter().enumerate() {
            self.write_column(KeccakColumn::SpongeShifts(idx), *value);
        }
        // Rest is zero thanks to null_state

        // Update environment
        self.prev_block = xor_state;
        self.block_idx += 1; // To be used in next absorb (if any)
    }
    /// Assigns the witness values needed in a squeeze step
    fn run_squeeze(&mut self) {
        self.set_flag_squeeze();

        // Compute witness values
        let state = self.prev_block.clone();
        let shifts = Keccak::shift(&state);
        let dense = Keccak::collapse(&Keccak::reset(&shifts));
        let bytes = Keccak::bytestring(&dense);

        // Write squeeze-related columns
        for (idx, value) in state.iter().enumerate() {
            self.write_column(KeccakColumn::Input(idx), *value);
        }
        for (idx, value) in bytes.iter().enumerate().take(HASH_BYTELENGTH) {
            self.write_column(KeccakColumn::SpongeBytes(idx), *value);
        }
        for idx in 0..WORDS_IN_HASH * QUARTERS {
            self.write_column(KeccakColumn::SpongeShifts(idx), shifts[idx]);
            self.write_column(KeccakColumn::SpongeShifts(100 + idx), shifts[100 + idx]);
            self.write_column(KeccakColumn::SpongeShifts(200 + idx), shifts[200 + idx]);
            self.write_column(KeccakColumn::SpongeShifts(300 + idx), shifts[300 + idx]);
        }

        // Rest is zero thanks to null_state
    }
    /// Assigns the witness values needed in the round step for the given round index
    fn run_round(&mut self, round: u64) {
        self.set_flag_round(round);

        let state_a = self.prev_block.clone();
        let state_e = self.run_theta(&state_a);
        let state_b = self.run_pirho(&state_e);
        let state_f = self.run_chi(&state_b);
        let state_g = self.run_iota(&state_f, round as usize);

        // Update block for next step with the output of the round
        self.prev_block = state_g;
    }
    /// Assigns the witness values needed in the theta algorithm
    /// ```text
    /// for x in 0…4
    ///   C[x] = A[x,0] xor A[x,1] xor \
    ///          A[x,2] xor A[x,3] xor \
    ///          A[x,4]
    /// for x in 0…4
    ///   D[x] = C[x-1] xor rot(C[x+1],1)
    /// for (x,y) in (0…4,0…4)
    ///   A[x,y] = A[x,y] xor D[x]
    /// ```
    fn run_theta(&mut self, state_a: &[u64]) -> Vec<u64> {
        let theta = Theta::create(state_a);

        // Write Theta-related columns
        for x in 0..DIM {
            self.write_column(KeccakColumn::ThetaQuotientC(x), theta.quotient_c(x));
            for q in 0..QUARTERS {
                let idx = grid_index(QUARTERS * DIM, 0, 0, x, q);
                self.write_column(KeccakColumn::ThetaDenseC(idx), theta.dense_c(x, q));
                self.write_column(KeccakColumn::ThetaRemainderC(idx), theta.remainder_c(x, q));
                self.write_column(KeccakColumn::ThetaDenseRotC(idx), theta.dense_rot_c(x, q));
                self.write_column(KeccakColumn::ThetaExpandRotC(idx), theta.expand_rot_c(x, q));
                for y in 0..DIM {
                    let idx = grid_index(THETA_STATE_A_LEN, 0, y, x, q);
                    self.write_column(KeccakColumn::Input(idx), state_a[idx]);
                }
                for i in 0..QUARTERS {
                    let idx = grid_index(THETA_SHIFTS_C_LEN, i, 0, x, q);
                    self.write_column(KeccakColumn::ThetaShiftsC(idx), theta.shifts_c(i, x, q));
                }
            }
        }
        theta.state_e()
    }
    /// Assigns the witness values needed in the pirho algorithm
    /// ```text
    /// for (x,y) in (0…4,0…4)
    ///   B[y,2*x+3*y] = rot(A[x,y], r[x,y])
    /// ```
    fn run_pirho(&mut self, state_e: &[u64]) -> Vec<u64> {
        let pirho = PiRho::create(state_e);

        // Write PiRho-related columns
        for y in 0..DIM {
            for x in 0..DIM {
                for q in 0..QUARTERS {
                    let idx = grid_index(STATE_LEN, 0, y, x, q);
                    self.write_column(KeccakColumn::PiRhoDenseE(idx), pirho.dense_e(y, x, q));
                    self.write_column(KeccakColumn::PiRhoQuotientE(idx), pirho.quotient_e(y, x, q));
                    self.write_column(
                        KeccakColumn::PiRhoRemainderE(idx),
                        pirho.remainder_e(y, x, q),
                    );
                    self.write_column(
                        KeccakColumn::PiRhoDenseRotE(idx),
                        pirho.dense_rot_e(y, x, q),
                    );
                    self.write_column(
                        KeccakColumn::PiRhoExpandRotE(idx),
                        pirho.expand_rot_e(y, x, q),
                    );
                    for i in 0..QUARTERS {
                        self.write_column(
                            KeccakColumn::PiRhoShiftsE(grid_index(PIRHO_SHIFTS_E_LEN, i, y, x, q)),
                            pirho.shifts_e(i, y, x, q),
                        );
                    }
                }
            }
        }
        pirho.state_b()
    }
    /// Assigns the witness values needed in the chi algorithm
    /// ```text
    /// for (x,y) in (0…4,0…4)
    ///   A[x, y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y])
    /// ```
    fn run_chi(&mut self, state_b: &[u64]) -> Vec<u64> {
        let chi = Chi::create(state_b);

        // Write Chi-related columns
        for i in 0..SHIFTS {
            for y in 0..DIM {
                for x in 0..DIM {
                    for q in 0..QUARTERS {
                        let idx = grid_index(SHIFTS_LEN, i, y, x, q);
                        self.write_column(KeccakColumn::ChiShiftsB(idx), chi.shifts_b(i, y, x, q));
                        self.write_column(
                            KeccakColumn::ChiShiftsSum(idx),
                            chi.shifts_sum(i, y, x, q),
                        );
                    }
                }
            }
        }
        chi.state_f()
    }
    /// Assigns the witness values needed in the iota algorithm
    /// ```text
    /// A[0,0] = A[0,0] xor RC
    /// ```
    fn run_iota(&mut self, state_f: &[u64], round: usize) -> Vec<u64> {
        let iota = Iota::create(state_f, round);
        let state_g = iota.state_g();

        // Update columns
        for (idx, g) in state_g.iter().enumerate() {
            self.write_column(KeccakColumn::Output(idx), *g);
        }
        for idx in 0..QUARTERS {
            self.write_column(KeccakColumn::RoundConstants(idx), iota.round_constants(idx));
        }

        state_g
    }
}

impl<Fp: Field> BoolOps for KeccakEnv<Fp> {
    type Column = KeccakColumn;
    type Variable = E<Fp>;
    type Fp = Fp;

    fn is_boolean(x: Self::Variable) -> Self::Variable {
        x.clone() * (x - Self::Variable::one())
    }

    fn not(x: Self::Variable) -> Self::Variable {
        Self::Variable::one() - x
    }

    fn is_one(x: Self::Variable) -> Self::Variable {
        Self::not(x)
    }

    fn is_nonzero(x: Self::Variable, x_inv: Self::Variable) -> Self::Variable {
        Self::is_one(x * x_inv)
    }

    fn xor(x: Self::Variable, y: Self::Variable) -> Self::Variable {
        x.clone() + y.clone() - Self::constant(2) * x * y
    }

    fn or(x: Self::Variable, y: Self::Variable) -> Self::Variable {
        x.clone() + y.clone() - x * y
    }

    fn either_zero(x: Self::Variable, y: Self::Variable) -> Self::Variable {
        x * y
    }
}

/// This trait includes functionalities needed to obtain the variables of the Keccak circuit needed for constraints
pub(crate) trait KeccakEnvironment {
    type Column;
    type Variable: std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + Clone;
    type Fp: std::ops::Neg<Output = Self::Fp>;

    /// This function returns the composed sparse variable from shifts of any correct length:
    /// - When the length is 400, two index configurations are possible:
    ///     - If `i` is `Some`, then this sole index could range between [0..400)
    ///     - If `i` is `None`, then `y`, `x` and `q` must be `Some` and
    ///         - `y` must range between [0..5)
    ///         - `x` must range between [0..5)
    ///         - `q` must range between [0..4)
    /// - When the length is 80, both `i` and `y` should be `None`, and `x` and `q` must be `Some` with:
    ///     - `x` must range between [0..5)
    ///     - `q` must range between [0..4)
    fn from_shifts(
        shifts: &[Self::Variable],
        i: Option<usize>,
        y: Option<usize>,
        x: Option<usize>,
        q: Option<usize>,
    ) -> Self::Variable;

    /// This function returns the composed variable from dense quarters of any correct length:
    /// - When `y` is `Some`, then the length must be 100 and:
    ///     - `y` must range between [0..5)
    ///     - `x` must range between [0..5)
    /// - When `y` is `None`, then the length must be 20 and:
    ///     - `x` must range between [0..5)
    fn from_quarters(quarters: &[Self::Variable], y: Option<usize>, x: usize) -> Self::Variable;

    /// Returns a variable that encodes whether the current step is a sponge (1 = yes)
    fn is_sponge(&self) -> Self::Variable;
    /// Returns a variable that encodes whether the current step is an absorb sponge (1 = yes)
    fn is_absorb(&self) -> Self::Variable;
    /// Returns a variable that encodes whether the current step is a squeeze sponge (1 = yes)
    fn is_squeeze(&self) -> Self::Variable;
    /// Returns a variable that encodes whether the current step is the first absorb sponge (1 = yes)
    fn is_root(&self) -> Self::Variable;
    /// Returns a degree-2 variable that encodes whether the current step is the last absorb sponge (1 = yes)
    fn is_pad(&self) -> Self::Variable;

    /// Returns a variable that encodes whether the current step is a permutation round (1 = yes)
    fn is_round(&self) -> Self::Variable;
    /// Returns a variable that encodes the current round number [0..24)
    fn round(&self) -> Self::Variable;

    /// Returns a variable that encodes the bytelength of the padding if any [0..136)
    fn pad_length(&self) -> Self::Variable;
    /// Returns a variable that encodes the value 2^pad_length
    fn two_to_pad(&self) -> Self::Variable;

    /// Returns a variable that encodes whether the `idx`-th byte of the new block is involved in the padding (1 = yes)
    fn in_padding(&self, idx: usize) -> Self::Variable;

    /// Returns a variable that encodes the `idx`-th chunk of the padding suffix
    /// - if `idx` = 0, then the length is 12 bytes at most
    /// - if `idx` = [1..5), then the length is 31 bytes at most
    fn pad_suffix(&self, idx: usize) -> Self::Variable;

    /// Returns a variable that encodes the `idx`-th block of bytes of the new block
    /// by composing the bytes variables, with `idx` in [0..5)
    fn bytes_block(&self, idx: usize) -> Vec<Self::Variable>;

    /// Returns the 136 flags indicating which bytes of the new block are involved in the padding, as variables
    fn pad_bytes_flags(&self) -> [Self::Variable; PAD_BYTES_LEN];

    /// Returns a vector of pad bytes flags as variables, with `idx` in [0..5)
    /// - if `idx` = 0, then the length of the vector is at most 12
    /// - if `idx` = [1..5), then the length of the vector is at most 31
    fn flags_block(&self, idx: usize) -> Vec<Self::Variable>;

    /// This function returns a variable that is computed as the accumulated value of the
    /// operation `byte * flag * 2^8` for each byte block and flag block of the new block.
    /// This function will be used in constraints to determine whether the padding is located
    /// at the end of the preimage data, as consecutive bits that are involved in the padding.
    fn block_in_padding(&self, idx: usize) -> Self::Variable;

    /// Returns the 4 expanded quarters that encode the round constant, as variables
    fn round_constants(&self) -> [Self::Variable; ROUND_COEFFS_LEN];

    /// Returns the `idx`-th old state expanded quarter, as a variable
    fn old_state(&self, idx: usize) -> Self::Variable;

    /// Returns the `idx`-th new state expanded quarter, as a variable
    fn new_state(&self, idx: usize) -> Self::Variable;

    /// Returns the output of an absorb sponge, which is the XOR of the old state and the new state
    fn xor_state(&self, idx: usize) -> Self::Variable;

    /// Returns the last 32 terms that are added to the new block in an absorb sponge, as variables which should be zeros
    fn sponge_zeros(&self) -> [Self::Variable; SPONGE_ZEROS_LEN];

    /// Returns the 400 terms that compose the shifts of the sponge, as variables
    fn vec_sponge_shifts(&self) -> [Self::Variable; SPONGE_SHIFTS_LEN];
    /// Returns the `idx`-th term of the shifts of the sponge, as a variable
    fn sponge_shifts(&self, idx: usize) -> Self::Variable;

    /// Returns the 200 bytes of the sponge, as variables
    fn sponge_bytes(&self) -> [Self::Variable; SPONGE_BYTES_LEN];
    /// Returns the `idx`-th byte of the sponge, as a variable
    fn sponge_byte(&self, idx: usize) -> Self::Variable;

    /// Returns the (y,x,q)-th input of the theta algorithm, as a variable
    fn state_a(&self, y: usize, x: usize, q: usize) -> Self::Variable;

    /// Returns the 80 variables corresponding to ThetaShiftsC
    fn vec_shifts_c(&self) -> [Self::Variable; THETA_SHIFTS_C_LEN];
    /// Returns the (i,x,q)-th variable of ThetaShiftsC
    fn shifts_c(&self, i: usize, x: usize, q: usize) -> Self::Variable;

    /// Returns the 20 variables corresponding to ThetaDenseC
    fn vec_dense_c(&self) -> [Self::Variable; THETA_DENSE_C_LEN];
    /// Returns the (x,q)-th term of ThetaDenseC, as a variable
    fn dense_c(&self, x: usize, q: usize) -> Self::Variable;

    /// Returns the 5 variables corresponding to ThetaQuotientC
    fn vec_quotient_c(&self) -> [Self::Variable; THETA_QUOTIENT_C_LEN];
    /// Returns the (x)-th term of ThetaQuotientC, as a variable
    fn quotient_c(&self, x: usize) -> Self::Variable;

    /// Returns the 20 variables corresponding to ThetaRemainderC
    fn vec_remainder_c(&self) -> [Self::Variable; THETA_REMAINDER_C_LEN];
    /// Returns the (x,q)-th variable of ThetaRemainderC
    fn remainder_c(&self, x: usize, q: usize) -> Self::Variable;

    /// Returns the 20 variables corresponding to ThetaDenseRotC
    fn vec_dense_rot_c(&self) -> [Self::Variable; THETA_DENSE_ROT_C_LEN];
    /// Returns the (x,q)-th variable of ThetaDenseRotC
    fn dense_rot_c(&self, x: usize, q: usize) -> Self::Variable;

    /// Returns the 20 variables corresponding to ThetaExpandRotC
    fn vec_expand_rot_c(&self) -> [Self::Variable; THETA_EXPAND_ROT_C_LEN];
    /// Returns the (x,q)-th variable of ThetaExpandRotC
    fn expand_rot_c(&self, x: usize, q: usize) -> Self::Variable;

    /// Returns the 400 variables corresponding to PiRhoShiftsE
    fn vec_shifts_e(&self) -> [Self::Variable; PIRHO_SHIFTS_E_LEN];
    /// Returns the (i,y,x,q)-th variable of PiRhoShiftsE
    fn shifts_e(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable;

    /// Returns the 100 variables corresponding to PiRhoDenseE
    fn vec_dense_e(&self) -> [Self::Variable; PIRHO_DENSE_E_LEN];
    /// Returns the (y,x,q)-th variable of PiRhoDenseE
    fn dense_e(&self, y: usize, x: usize, q: usize) -> Self::Variable;

    /// Returns the 100 variables corresponding to PiRhoQuotientE
    fn vec_quotient_e(&self) -> [Self::Variable; PIRHO_QUOTIENT_E_LEN];
    /// Returns the (y,x,q)-th variable of PiRhoQuotientE
    fn quotient_e(&self, y: usize, x: usize, q: usize) -> Self::Variable;

    /// Returns the 100 variables corresponding to PiRhoRemainderE
    fn vec_remainder_e(&self) -> [Self::Variable; PIRHO_REMAINDER_E_LEN];
    /// Returns the (y,x,q)-th variable of PiRhoRemainderE
    fn remainder_e(&self, y: usize, x: usize, q: usize) -> Self::Variable;

    /// Returns the 100 variables corresponding to PiRhoDenseRotE
    fn vec_dense_rot_e(&self) -> [Self::Variable; PIRHO_DENSE_ROT_E_LEN];
    /// Returns the (y,x,q)-th variable of PiRhoDenseRotE
    fn dense_rot_e(&self, y: usize, x: usize, q: usize) -> Self::Variable;

    /// Returns the 100 variables corresponding to PiRhoExpandRotE
    fn vec_expand_rot_e(&self) -> [Self::Variable; PIRHO_EXPAND_ROT_E_LEN];
    /// Returns the (y,x,q)-th variable of PiRhoExpandRotE
    fn expand_rot_e(&self, y: usize, x: usize, q: usize) -> Self::Variable;

    /// Returns the 400 variables corresponding to ChiShiftsB
    fn vec_shifts_b(&self) -> [Self::Variable; CHI_SHIFTS_B_LEN];
    /// Returns the (i,y,x,q)-th variable of ChiShiftsB
    fn shifts_b(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable;

    /// Returns the 400 variables corresponding to ChiShiftsSum
    fn vec_shifts_sum(&self) -> [Self::Variable; CHI_SHIFTS_SUM_LEN];
    /// Returns the (i,y,x,q)-th variable of ChiShiftsSum
    fn shifts_sum(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable;

    /// Returns the `idx`-th output of a round step as a variable
    fn state_g(&self, idx: usize) -> Self::Variable;

    /// Returns the hash index as a variable
    fn hash_index(&self) -> Self::Variable;
    /// Returns the block index as a variable
    fn block_index(&self) -> Self::Variable;
    /// Returns the step index as a variable
    fn step_index(&self) -> Self::Variable;

    /// Returns the 100 step input variables, which correspond to the:
    /// - State A when the current step is a permutation round
    /// - Old state when the current step is a non-root sponge
    fn input(&self) -> [Self::Variable; STATE_LEN];
    /// Returns a slice of the input variables of the current step
    /// including the current hash index and step index
    fn input_of_step(&self) -> Vec<Self::Variable>;

    /// Returns the 100 step output variables, which correspond to the:
    /// - State G when the current step is a permutation round
    /// - Xor state when the current step is an absorb sponge
    fn output(&self) -> [Self::Variable; STATE_LEN];
    /// Returns a slice of the output variables of the current step (= input of next step)
    /// including the current hash index and step index
    fn output_of_step(&self) -> Vec<Self::Variable>;
}

impl<Fp: Field> KeccakEnvironment for KeccakEnv<Fp> {
    type Column = KeccakColumn;
    type Variable = E<Fp>;
    type Fp = Fp;

    fn from_shifts(
        shifts: &[Self::Variable],
        i: Option<usize>,
        y: Option<usize>,
        x: Option<usize>,
        q: Option<usize>,
    ) -> Self::Variable {
        match shifts.len() {
            400 => {
                if let Some(i) = i {
                    auto_clone_array!(shifts);
                    shifts(i)
                        + Self::two_pow(1) * shifts(100 + i)
                        + Self::two_pow(2) * shifts(200 + i)
                        + Self::two_pow(3) * shifts(300 + i)
                } else {
                    let shifts = grid!(400, shifts);
                    shifts(0, y.unwrap(), x.unwrap(), q.unwrap())
                        + Self::two_pow(1) * shifts(1, y.unwrap(), x.unwrap(), q.unwrap())
                        + Self::two_pow(2) * shifts(2, y.unwrap(), x.unwrap(), q.unwrap())
                        + Self::two_pow(3) * shifts(3, y.unwrap(), x.unwrap(), q.unwrap())
                }
            }
            80 => {
                let shifts = grid!(80, shifts);
                shifts(0, x.unwrap(), q.unwrap())
                    + Self::two_pow(1) * shifts(1, x.unwrap(), q.unwrap())
                    + Self::two_pow(2) * shifts(2, x.unwrap(), q.unwrap())
                    + Self::two_pow(3) * shifts(3, x.unwrap(), q.unwrap())
            }
            _ => panic!("Invalid length of shifts"),
        }
    }

    fn from_quarters(quarters: &[Self::Variable], y: Option<usize>, x: usize) -> Self::Variable {
        if let Some(y) = y {
            assert!(quarters.len() == 100, "Invalid length of quarters");
            let quarters = grid!(100, quarters);
            quarters(y, x, 0)
                + Self::two_pow(16) * quarters(y, x, 1)
                + Self::two_pow(32) * quarters(y, x, 2)
                + Self::two_pow(48) * quarters(y, x, 3)
        } else {
            assert!(quarters.len() == 20, "Invalid length of quarters");
            let quarters = grid!(20, quarters);
            quarters(x, 0)
                + Self::two_pow(16) * quarters(x, 1)
                + Self::two_pow(32) * quarters(x, 2)
                + Self::two_pow(48) * quarters(x, 3)
        }
    }

    fn is_sponge(&self) -> Self::Variable {
        Self::xor(self.is_absorb().clone(), self.is_squeeze().clone())
    }

    fn is_absorb(&self) -> Self::Variable {
        self.variable(KeccakColumn::FlagAbsorb)
    }

    fn is_squeeze(&self) -> Self::Variable {
        self.variable(KeccakColumn::FlagSqueeze)
    }

    fn is_root(&self) -> Self::Variable {
        self.variable(KeccakColumn::FlagRoot)
    }

    fn is_pad(&self) -> Self::Variable {
        self.pad_length() * self.variable(KeccakColumn::InvPadLength)
    }

    fn is_round(&self) -> Self::Variable {
        Self::not(self.is_sponge())
    }

    fn round(&self) -> Self::Variable {
        self.variable(KeccakColumn::FlagRound)
    }

    fn pad_length(&self) -> Self::Variable {
        self.variable(KeccakColumn::PadLength)
    }

    fn two_to_pad(&self) -> Self::Variable {
        self.variable(KeccakColumn::TwoToPad)
    }

    fn in_padding(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::PadBytesFlags(idx))
    }

    fn pad_suffix(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::PadSuffix(idx))
    }

    fn bytes_block(&self, idx: usize) -> Vec<Self::Variable> {
        match idx {
            0 => self.sponge_bytes()[0..12].to_vec(),
            1..=4 => self.sponge_bytes()[12 + (idx - 1) * 31..12 + idx * 31].to_vec(),
            _ => panic!("No more blocks of bytes can be part of padding"),
        }
    }

    fn pad_bytes_flags(&self) -> [Self::Variable; PAD_BYTES_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PadBytesFlags(idx)))
    }

    fn flags_block(&self, idx: usize) -> Vec<Self::Variable> {
        match idx {
            0 => self.pad_bytes_flags()[0..12].to_vec(),
            1..=4 => self.pad_bytes_flags()[12 + (idx - 1) * 31..12 + idx * 31].to_vec(),
            _ => panic!("No more blocks of flags can be part of padding"),
        }
    }

    fn block_in_padding(&self, idx: usize) -> Self::Variable {
        let bytes = self.bytes_block(idx);
        let flags = self.flags_block(idx);
        assert_eq!(bytes.len(), flags.len());
        let pad = bytes
            .iter()
            .zip(flags)
            .fold(Self::zero(), |acc, (byte, flag)| {
                acc * Self::two_pow(8) + byte.clone() * flag.clone()
            });

        pad
    }

    fn round_constants(&self) -> [Self::Variable; ROUND_COEFFS_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::RoundConstants(idx)))
    }

    fn old_state(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::Input(idx))
    }

    fn new_state(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::SpongeNewState(idx))
    }

    fn xor_state(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::Output(idx))
    }

    fn sponge_zeros(&self) -> [Self::Variable; SPONGE_ZEROS_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::SpongeZeros(idx)))
    }

    fn sponge_byte(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::SpongeBytes(idx))
    }

    fn sponge_bytes(&self) -> [Self::Variable; SPONGE_BYTES_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::SpongeBytes(idx)))
    }

    fn vec_sponge_shifts(&self) -> [Self::Variable; SPONGE_SHIFTS_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::SpongeShifts(idx)))
    }

    fn sponge_shifts(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::SpongeShifts(idx))
    }

    fn state_a(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(THETA_STATE_A_LEN, 0, y, x, q);
        self.variable(KeccakColumn::Input(idx))
    }

    fn vec_shifts_c(&self) -> [Self::Variable; THETA_SHIFTS_C_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ThetaShiftsC(idx)))
    }
    fn shifts_c(&self, i: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(THETA_SHIFTS_C_LEN, i, 0, x, q);
        self.variable(KeccakColumn::ThetaShiftsC(idx))
    }

    fn vec_dense_c(&self) -> [Self::Variable; THETA_DENSE_C_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ThetaDenseC(idx)))
    }

    fn dense_c(&self, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(THETA_DENSE_C_LEN, 0, 0, x, q);
        self.variable(KeccakColumn::ThetaDenseC(idx))
    }

    fn vec_quotient_c(&self) -> [Self::Variable; THETA_QUOTIENT_C_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ThetaQuotientC(idx)))
    }

    fn quotient_c(&self, x: usize) -> Self::Variable {
        self.variable(KeccakColumn::ThetaQuotientC(x))
    }

    fn vec_remainder_c(&self) -> [Self::Variable; THETA_REMAINDER_C_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ThetaRemainderC(idx)))
    }

    fn remainder_c(&self, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(THETA_REMAINDER_C_LEN, 0, 0, x, q);
        self.variable(KeccakColumn::ThetaRemainderC(idx))
    }

    fn vec_dense_rot_c(&self) -> [Self::Variable; THETA_DENSE_ROT_C_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ThetaDenseRotC(idx)))
    }

    fn dense_rot_c(&self, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(THETA_DENSE_ROT_C_LEN, 0, 0, x, q);
        self.variable(KeccakColumn::ThetaDenseRotC(idx))
    }

    fn vec_expand_rot_c(&self) -> [Self::Variable; THETA_EXPAND_ROT_C_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ThetaExpandRotC(idx)))
    }

    fn expand_rot_c(&self, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(THETA_EXPAND_ROT_C_LEN, 0, 0, x, q);
        self.variable(KeccakColumn::ThetaExpandRotC(idx))
    }

    fn vec_shifts_e(&self) -> [Self::Variable; PIRHO_SHIFTS_E_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PiRhoShiftsE(idx)))
    }

    fn shifts_e(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(PIRHO_SHIFTS_E_LEN, i, y, x, q);
        self.variable(KeccakColumn::PiRhoShiftsE(idx))
    }

    fn vec_dense_e(&self) -> [Self::Variable; PIRHO_DENSE_E_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PiRhoDenseE(idx)))
    }

    fn dense_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(PIRHO_DENSE_E_LEN, 0, y, x, q);
        self.variable(KeccakColumn::PiRhoDenseE(idx))
    }

    fn vec_quotient_e(&self) -> [Self::Variable; PIRHO_QUOTIENT_E_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PiRhoQuotientE(idx)))
    }

    fn quotient_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(PIRHO_QUOTIENT_E_LEN, 0, y, x, q);
        self.variable(KeccakColumn::PiRhoQuotientE(idx))
    }

    fn vec_remainder_e(&self) -> [Self::Variable; PIRHO_REMAINDER_E_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PiRhoRemainderE(idx)))
    }

    fn remainder_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(PIRHO_REMAINDER_E_LEN, 0, y, x, q);
        self.variable(KeccakColumn::PiRhoRemainderE(idx))
    }

    fn vec_dense_rot_e(&self) -> [Self::Variable; PIRHO_DENSE_ROT_E_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PiRhoDenseRotE(idx)))
    }

    fn dense_rot_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(PIRHO_DENSE_ROT_E_LEN, 0, y, x, q);
        self.variable(KeccakColumn::PiRhoDenseRotE(idx))
    }

    fn vec_expand_rot_e(&self) -> [Self::Variable; PIRHO_EXPAND_ROT_E_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PiRhoExpandRotE(idx)))
    }

    fn expand_rot_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(PIRHO_EXPAND_ROT_E_LEN, 0, y, x, q);
        self.variable(KeccakColumn::PiRhoExpandRotE(idx))
    }

    fn vec_shifts_b(&self) -> [Self::Variable; CHI_SHIFTS_B_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ChiShiftsB(idx)))
    }

    fn shifts_b(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(CHI_SHIFTS_B_LEN, i, y, x, q);
        self.variable(KeccakColumn::ChiShiftsB(idx))
    }

    fn vec_shifts_sum(&self) -> [Self::Variable; CHI_SHIFTS_SUM_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ChiShiftsSum(idx)))
    }

    fn shifts_sum(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(CHI_SHIFTS_SUM_LEN, i, y, x, q);
        self.variable(KeccakColumn::ChiShiftsSum(idx))
    }

    fn state_g(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::Output(idx))
    }

    fn hash_index(&self) -> Self::Variable {
        self.variable(KeccakColumn::HashIndex)
    }
    fn block_index(&self) -> Self::Variable {
        self.variable(KeccakColumn::BlockIndex)
    }
    fn step_index(&self) -> Self::Variable {
        self.variable(KeccakColumn::StepIndex)
    }

    fn input(&self) -> [Self::Variable; STATE_LEN] {
        array::from_fn::<_, STATE_LEN, _>(|idx| self.variable(KeccakColumn::Input(idx)))
    }

    fn input_of_step(&self) -> Vec<Self::Variable> {
        let mut input_of_step = Vec::with_capacity(STATE_LEN + 2);
        input_of_step.push(self.hash_index());
        input_of_step.push(self.step_index());
        input_of_step.extend_from_slice(&self.input());
        input_of_step
    }

    fn output(&self) -> [Self::Variable; STATE_LEN] {
        array::from_fn::<_, STATE_LEN, _>(|idx| self.variable(KeccakColumn::Output(idx)))
    }

    fn output_of_step(&self) -> Vec<Self::Variable> {
        let mut output_of_step = Vec::with_capacity(STATE_LEN + 2);
        output_of_step.push(self.hash_index());
        output_of_step.push(self.step_index() + Self::one());
        output_of_step.extend_from_slice(&self.output());
        output_of_step
    }
}
