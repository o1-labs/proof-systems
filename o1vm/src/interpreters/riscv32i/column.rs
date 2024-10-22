use super::{INSTRUCTION_SET_SIZE, SCRATCH_SIZE};

pub struct Colunm {
    pub scratch_state: [usize; SCRATCH_SIZE],
    pub selectors: [usize; INSTRUCTION_SET_SIZE],
}
