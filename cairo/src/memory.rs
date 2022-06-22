//! This module represents the Cairo memory, containing the
//! compiled Cairo program that occupies the first few entries

use std::fmt::{Display, Formatter, Result};
use std::ops::{Index, IndexMut};

use crate::helper::*;
use crate::word::CairoWord;
use ark_ff::Field;
use core::iter::repeat;

/// This data structure stores the memory of the program
pub struct CairoMemory<F> {
    /// length of the public memory
    codelen: usize,
    /// full memory vector, None if non initialized
    data: Vec<Option<CairoWord<F>>>,
}

impl<F: Field> Index<F> for CairoMemory<F> {
    type Output = Option<CairoWord<F>>;
    fn index(&self, idx: F) -> &Self::Output {
        // Safely convert idx from F to usize (since this is a memory address
        // idx should not be too big, this should be safe)
        let addr: u64 = idx.to_u64();
        &self.data[addr as usize]
    }
}

impl<F: Field> IndexMut<F> for CairoMemory<F> {
    fn index_mut(&mut self, idx: F) -> &mut Self::Output {
        let addr: u64 = idx.to_u64();
        self.resize(addr); // Resize if necessary
        &mut self.data[addr as usize]
    }
}

impl<F: Field> Display for CairoMemory<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        for i in 1..self.len() {
            // Visualize content of memory excluding the 0th dummy entry
            if let Some(elem) = self[F::from(i)] {
                writeln!(f, "{0:>6}: 0x{1:}", i, elem.word().to_hex_be())
                    .map_err(|_| core::fmt::Error)?;
            } else {
                writeln!(f, "{0:>6}: None", i).map_err(|_| core::fmt::Error)?;
            }
        }
        Ok(())
    }
}

impl<F: Field> CairoMemory<F> {
    /// Create a new memory structure from a vector of field elements
    pub fn new(input: Vec<F>) -> CairoMemory<F> {
        // Initialized with the public memory (compiled instructions only)
        // starts intentionally with a zero word for ease of testing
        let mut aux = vec![F::zero()];
        aux.extend(input);
        CairoMemory {
            codelen: aux.len() - 1,
            data: aux.into_iter().map(|i| Some(CairoWord::new(i))).collect(),
        }
    }

    /// Get size of the public memory
    pub fn get_codelen(&self) -> usize {
        self.codelen
    }

    /// Get size of the full memory including dummy 0th entry
    pub fn len(&self) -> u64 {
        self.data.len() as u64
    }

    /// Returns whether the memory is empty (either length 0, or with the dummy first entry)
    pub fn is_empty(&self) -> bool {
        self.data.len() < 2
    }

    /// Resizes memory with enough additional None slots if necessary before writing or reading
    fn resize(&mut self, addr: u64) {
        // if you want to access an index of the memory but its size is less or equal than this
        // you will need to extend the vector with enough spaces (taking into account that
        // vectors start by index 0, the 0 address is dummy, and size starts in 1)
        if let Some(additional) = addr.checked_sub(self.len() - 1) {
            self.data.extend(repeat(None).take(additional as usize));
        }
    }

    /// Write u64 element in memory address
    pub fn write(&mut self, addr: F, elem: F) {
        self[addr] = Some(CairoWord::new(elem));
    }

    /// Read element in memory address
    pub fn read(&mut self, addr: F) -> Option<F> {
        self.resize(addr.to_u64()); // Resize if necessary
        self[addr].map(|x| x.word())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::One;
    use mina_curves::pasta::fp::Fp as F;

    #[test]
    fn test_cairo_bytecode() {
        // This test starts with the public memory corresponding to a simple Cairo program
        // func main{}():
        //    tempvar x = 10;
        //    return()
        // end
        // And checks that memory writing and reading works as expected by completing
        // the total memory of executing the program
        let instrs = vec![0x480680017fff8000, 10, 0x208b7fff7fff7ffe]
            .iter()
            .map(|&i: &i64| F::from(i))
            .collect();
        let mut memory = CairoMemory::new(instrs);
        memory.write(F::from(memory.len()), F::from(7u64));
        memory.write(F::from(memory.len()), F::from(7u64));
        memory.write(F::from(memory.len()), F::from(10u64));
        println!("{}", memory);
        // Check content of an address
        assert_eq!(
            memory.read(F::one()).unwrap(),
            F::from(0x480680017fff8000u64)
        );
        // Check that the program contained 3 words
        assert_eq!(3, memory.get_codelen());
        // Check we have 6 words, excluding the dummy entry
        assert_eq!(6, memory.len() - 1);
        memory.read(F::from(10u32));
    }
}
