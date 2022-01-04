use ark_ff::{BigInteger, FftField, Field, PrimeField};

pub struct CairoMemory<F: FftField> {
    pub pubsize: usize,
    pub stack: Vec<F>,
}

impl<F: FftField> CairoMemory {
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
    pub fn initialize_memory(&self, input: Vec<F>) {
        &self.pubsize = len(&input);
        &self.stack = input;
    }
}
