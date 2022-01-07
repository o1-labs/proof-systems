use ark_ff::{BigInteger, FftField, Field, PrimeField};
use cairo::instruction;

/// Cairo memory stack
#[derive(Copy, Clone)]
pub struct CairoMemory<F: FftField> {
    /// length of the public memory
    pub pubsize: usize,
    /// full memory stack
    pub stack: Vec<CairoInstruction<F>>,
}

impl<F: FftField> CairoMemory {
    /// Create a new memory structure from a vector of u64
    pub fn new_memory(input: Vec<u64>) -> CairoMemory {
        CairoMemory {
            pubsize: len(&input),
            stack: Vec::from([|i| instruction::create(input[i])]),
        }
    }

    /// Get size of the public memory
    pub fn get_pub_size(&self) -> usize {
        self.pubsize
    }

    /// Get size of the full memory
    pub fn get_mem_size(&self) -> usize {
        len(&self.stack)
    }

    /// Write field element in memory address
    pub fn write_memory(&self, index: F, elem: u64) {
        std::mem::replace(&self.stack[index as usize], instruction::create(elem));
    }

    /// Read field element in memory address
    pub fn read_memory(&self, index: F) -> u64 {
        F::from(self.stack[index as usize].word)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cairo_memory() {
        let instrs: Vec<u64> = vec![0x480680017fff8000, 10, 0x208b7fff7fff7ffe];
        let mem = new_memory(instrs);
        println!(mem.get_pub_size());
        println!(mem.get_mem_size());
        println!(mem.read_memory(2));
    }
}
