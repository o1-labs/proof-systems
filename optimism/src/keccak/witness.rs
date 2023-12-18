use ark_ff::Field;
use kimchi::circuits::polynomials::keccak::{Keccak, ROUNDS};

use super::{
    column::KeccakColumn,
    environment::KeccakEnv,
    interpreter::{Absorb, KeccakInterpreter, KeccakStep, Sponge},
    DIM, QUARTERS,
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

    fn run_sponge(&mut self, _sponge: Sponge) {
        todo!()
    }
    fn run_absorb(&mut self, _absorb: Absorb) {
        todo!()
    }
    fn run_squeeze(&mut self) {
        todo!()
    }
    fn run_round(&mut self, _round: u64) {
        todo!()
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
