use crate::gate;
use ark_ff::{BigInteger, FftField, Field, PrimeField};

/// Cairo memory stack
pub struct CairoMemory<F: FftField> {
    /// length of the public memory 
    pub pubsize: usize,
    /// full memory stack
    pub stack: Vec<F>,
}

impl<F: FftField> CairoMemory {
    pub fn new_memory(input: CairoProgram) -> CairoMemory {
        CairoMemory {
            pubsize = len(&input),
            stack = input,
        }
    }
    pub fn get_pub_size(&self) -> usize {
        self.pubsize
    }
    pub fn get_mem_size(&self) -> usize {
        len(&self.stack)
    }
    pub fn write_memory(&self, elem: F) {
        &self.stack.push(elem);
    }
    pub fn read_memory(&self, index: usize) -> F {
        &self.stack[index]
    }
}
