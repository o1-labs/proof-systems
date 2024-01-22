/// This file contains the implementation of the witness for the Keccak permutation.
/// For a pseudo code implementation of Keccap-f, see
/// https://keccak.team/keccak_specs_summary.html
use super::{
    column::KeccakColumn,
    environment::KeccakEnv,
    grid_index,
    interpreter::{Absorb, KeccakInterpreter, KeccakStep, Sponge},
    lookups::Lookups,
    DIM, HASH_BYTELENGTH, QUARTERS, WORDS_IN_HASH,
};
use ark_ff::Field;
use kimchi::circuits::polynomials::keccak::{
    constants::{
        CAPACITY_IN_BYTES, PIRHO_SHIFTS_E_LEN, RATE_IN_BYTES, ROUNDS, SHIFTS, SHIFTS_LEN,
        STATE_LEN, THETA_SHIFTS_C_LEN, THETA_STATE_A_LEN,
    },
    witness::{Chi, Iota, PiRho, Theta},
    Keccak,
};

pub(crate) fn pad_blocks<Fp: Field>(pad_bytelength: usize) -> Vec<Fp> {
    // Blocks to store padding. The first one uses at most 12 bytes, and the rest use at most 31 bytes.
    let mut blocks = vec![Fp::zero(); 5];
    let mut pad = [Fp::zero(); RATE_IN_BYTES];
    pad[RATE_IN_BYTES - pad_bytelength] = Fp::one();
    pad[RATE_IN_BYTES - 1] += Fp::from(0x80u8);
    blocks[0] = pad
        .iter()
        .take(12)
        .fold(Fp::zero(), |acc, x| acc * Fp::from(256u32) + *x);
    for (i, block) in blocks.iter_mut().enumerate().take(5).skip(1) {
        // take 31 elements from pad, starting at 12 + (i - 1) * 31 and fold them into a single Fp
        *block = pad
            .iter()
            .skip(12 + (i - 1) * 31)
            .take(31)
            .fold(Fp::zero(), |acc, x| acc * Fp::from(256u32) + *x);
    }

    blocks
}

impl<Fp: Field> KeccakInterpreter for KeccakEnv<Fp> {
    type Position = KeccakColumn;

    type Variable = Fp;

    // FIXME: read preimage from memory and pad and expand
    fn step(&mut self) {
        // Reset columns to zeros to avoid conflicts between steps
        self.null_state();

        match self.keccak_step.unwrap() {
            KeccakStep::Sponge(typ) => self.run_sponge(typ),
            KeccakStep::Round(i) => self.run_round(i),
        }
        self.write_column(KeccakColumn::StepIndex, self.step_idx);

        // INTER-STEP CHANNEL
        // Write outputs for next step if not a squeeze and read inputs of curr step if not a root
        self.lookup_steps();

        self.update_step();
    }

    fn set_flag_root(&mut self) {
        self.write_column(KeccakColumn::FlagRoot, 1);
    }

    fn set_flag_pad(&mut self) {
        self.write_column(KeccakColumn::FlagPad, 1);
        self.write_column(KeccakColumn::FlagLength, self.pad_len);
        let pad_range = RATE_IN_BYTES - self.pad_len as usize..RATE_IN_BYTES;
        for i in pad_range {
            self.write_column(KeccakColumn::PadBytesFlags(i), 1);
        }
    }

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

    fn set_flag_round(&mut self, round: u64) {
        assert!(round < ROUNDS as u64);
        self.write_column(KeccakColumn::FlagRound, round);
    }

    fn run_sponge(&mut self, sponge: Sponge) {
        match sponge {
            Sponge::Absorb(absorb) => self.run_absorb(absorb),
            Sponge::Squeeze => self.run_squeeze(),
        }
    }

    fn run_squeeze(&mut self) {
        self.write_column(KeccakColumn::FlagSqueeze, 1);

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
        for (idx, value) in shifts.iter().enumerate().take(QUARTERS * WORDS_IN_HASH) {
            self.write_column(KeccakColumn::SpongeShifts(idx), *value);
        }

        // Rest is zero thanks to null_state

        // COMMUNICATION CHANNEL: Write hash output
        self.lookup_syscall_hash();
    }

    fn run_absorb(&mut self, absorb: Absorb) {
        self.set_flag_absorb(absorb);

        // Compute witness values
        let ini_idx = RATE_IN_BYTES * self.block_idx as usize;
        let mut block = self.padded[ini_idx..ini_idx + RATE_IN_BYTES].to_vec();

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
        let pad_blocks = pad_blocks::<Fp>(self.pad_len as usize);
        for (idx, value) in pad_blocks.iter().enumerate() {
            self.write_column_field(KeccakColumn::PadSuffix(idx), *value);
        }
        // Rest is zero thanks to null_state

        // COMMUNICATION CHANNEL: read bytes of current block
        self.lookup_syscall_preimage();

        // Update environment
        self.prev_block = xor_state;
        self.block_idx += 1; // To be used in next absorb (if any)
    }

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

    /// Computing
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

    /// Computing
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

    /// Computing
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

    /// Computing
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
