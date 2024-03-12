//! This module contains the definition and implementation of the Keccak environment
//! including the common functions between the witness and the constraints environments
//! for arithmetic, boolean, and column operations.
use crate::keccak::{
    column::KeccakWitness, constraints::Env as ConstraintsEnv, grid_index, pad_blocks,
    witness::Env as WitnessEnv, KeccakColumn, DIM, HASH_BYTELENGTH, QUARTERS, WORDS_IN_HASH,
};
use ark_ff::Field;
use kimchi::{
    circuits::polynomials::keccak::{
        constants::*,
        witness::{Chi, Iota, PiRho, Theta},
        Keccak,
    },
    o1_utils::Two,
};

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
        self.witness_env.error = None; // Reset results of constraints for the new row
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
