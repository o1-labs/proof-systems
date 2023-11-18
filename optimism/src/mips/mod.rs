pub mod columns;
pub mod constraints;
pub mod interpreter;
pub mod registers;
pub mod witness;

pub const NUM_GLOBAL_LOOKUP_TERMS: usize = 1;
pub const NUM_DECODING_LOOKUP_TERMS: usize = 2;
pub const NUM_INSTRUCTION_LOOKUP_TERMS: usize = 5;
pub const NUM_LOOKUP_TERMS: usize =
    NUM_GLOBAL_LOOKUP_TERMS + NUM_DECODING_LOOKUP_TERMS + NUM_INSTRUCTION_LOOKUP_TERMS;
pub const SCRATCH_SIZE: usize = 25;
