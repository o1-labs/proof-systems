use ark_ff::Field;
use kimchi::circuits::polynomials::keccak::Keccak;

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
        self.padded = pad(&preimage);
        self.block_idx = 0;
        self.pad_len = (self.padded.len() - preimage.len()) as u64;

        // Run all steps of hash
        while self.curr_step.is_some() {
            self.step();
            self.update_step();
        }
    }
}
