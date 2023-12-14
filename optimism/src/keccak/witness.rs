use ark_ff::Field;
use kimchi::circuits::polynomials::keccak::{Keccak, CAPACITY_IN_BYTES, RATE_IN_BYTES, RC, ROUNDS};

use super::{
    column::KeccakColumn,
    environment::KeccakEnv,
    interpreter::{Absorb, KeccakInterpreter, KeccakStep, Sponge},
    DIM, HASH_BYTELENGTH, QUARTERS, WORDS_IN_HASH,
};

impl<Fp: Field> KeccakInterpreter for KeccakEnv<Fp> {
    type Position = KeccakColumn;

    type Variable = Fp;

    fn hash(&mut self, preimage: Vec<u8>) {
        // FIXME Read preimage

        self.blocks_left_to_absorb = Keccak::num_blocks(preimage.len()) as u64;

        // Configure first step depending on number of blocks remaining
        self.curr_step = if self.blocks_left_to_absorb == 1 {
            Some(KeccakStep::Sponge(Sponge::Absorb(Absorb::FirstAndLast)))
        } else {
            Some(KeccakStep::Sponge(Sponge::Absorb(Absorb::First)))
        };

        // Root state is zero
        self.prev_block = vec![0u64; QUARTERS * DIM * DIM];

        // Pad preimage
        self.padded = Keccak::pad(&preimage);
        self.block_idx = 0;
        self.pad_len = (self.padded.len() - preimage.len()) as u64;

        // Run all steps of hash
        while self.curr_step.is_some() {
            self.step();
        }
    }

    // FIXME: read preimage from memory and pad and expand
    fn step(&mut self) {
        // Reset columns to zeros to avoid conflicts between steps
        self.null_state();

        // FIXME sparse notation

        match self.curr_step.unwrap() {
            KeccakStep::Sponge(typ) => self.run_sponge(typ),
            KeccakStep::Round(i) => self.run_round(i),
        }
        self.update_step();
    }

    fn add_constraint(&mut self, _assert_equals_zero: Self::Variable) {
        todo!()
    }

    fn set_flag_root(&mut self) {
        self.write_column(KeccakColumn::FlagRoot, 1);
    }

    fn set_flag_pad(&mut self) {
        self.write_column(KeccakColumn::FlagPad, 1);
        self.write_column(KeccakColumn::FlagLength, self.pad_len)
    }

    fn set_flag_absorb(&mut self, absorb: Absorb) {
        self.write_column(KeccakColumn::FlagAbsorb, 1);
        match absorb {
            Absorb::First => self.set_flag_root(),
            Absorb::Last => self.set_flag_pad(),
            _ => {
                self.set_flag_root();
                self.set_flag_pad()
            }
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
        for (i, value) in state.iter().enumerate() {
            self.write_column(KeccakColumn::SpongeOldState(i), *value);
        }
        for (i, value) in bytes.iter().enumerate().take(HASH_BYTELENGTH) {
            self.write_column(KeccakColumn::SpongeBytes(i), *value);
        }
        for (i, value) in shifts.iter().enumerate().take(QUARTERS * WORDS_IN_HASH) {
            self.write_column(KeccakColumn::SpongeShifts(i), *value);
        }

        // Rest is zero thanks to null_state

        // TODO: more updates to the env?
    }

    fn run_absorb(&mut self, absorb: Absorb) {
        self.set_flag_absorb(absorb);

        // Compute witness values
        let ini_idx = self.block_idx * RATE_IN_BYTES;
        let mut block = self.padded[ini_idx..ini_idx + RATE_IN_BYTES].to_vec();
        // Pad with zeros
        let old_state = self.prev_block.clone();
        block.append(&mut vec![0; CAPACITY_IN_BYTES]);
        let new_state = Keccak::expand_state(&block);
        let shifts = Keccak::shift(&new_state);
        let bytes = block.iter().map(|b| *b as u64).collect::<Vec<u64>>();
        let xor_state = old_state
            .iter()
            .zip(new_state.clone())
            .map(|(x, y)| x + y)
            .collect::<Vec<u64>>();

        // Write absorb-related columns
        for i in 0..QUARTERS * DIM * DIM {
            self.write_column(KeccakColumn::SpongeOldState(i), old_state[i]);
            self.write_column(KeccakColumn::SpongeNewState(i), new_state[i]);
            self.write_column(KeccakColumn::NextState(i), xor_state[i]);
        }
        for (i, value) in bytes.iter().enumerate() {
            self.write_column(KeccakColumn::SpongeBytes(i), *value);
        }
        for (i, value) in shifts.iter().enumerate() {
            self.write_column(KeccakColumn::SpongeShifts(i), *value);
        }

        // Rest is zero thanks to null_state

        // Update environment
        self.prev_block = xor_state;
        self.block_idx += 1; // To be used in next absorb (if any)
    }

    fn run_round(&mut self, round: u64) {
        self.set_flag_round(round);

        let rc = Keccak::sparse(RC[round as usize]);
        let state_a = self.prev_block.clone();
        let state_e = self.run_theta(&state_a);
        let state_b = self.run_pirho(&state_e);
        let state_f = self.run_chi(&state_b);
        self.run_iota(&state_f, &rc);

        // Compute witness values
    }

    fn run_theta(&mut self, _state_a: &[u64]) -> Vec<u64> {
        todo!()
    }
    fn run_pirho(&mut self, _state_e: &[u64]) -> Vec<u64> {
        todo!()
    }
    fn run_chi(&mut self, _state_b: &[u64]) -> Vec<u64> {
        todo!()
    }
    fn run_iota(&mut self, _state_f: &[u64], _rc: &[u64]) {
        todo!()
    }
}
