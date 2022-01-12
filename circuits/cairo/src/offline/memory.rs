use crate::offline::word::CairoWord;

pub struct CairoMemory {
    /// length of the public memory
    pub publen: u64,
    /// full memory stack
    pub stack: Vec<CairoWord>,
}

impl CairoMemory {
    /// Create a new memory structure from a vector of u64
    pub fn new(input: Vec<u64>) -> CairoMemory {
        CairoMemory {
            publen: input.len() as u64,
            stack: (input.into_iter().map(|i| CairoWord::new(i)).collect()),
        }
    }

    /// Get size of the public memory
    pub fn public(&self) -> u64 {
        self.publen
    }

    /// Get size of the full memory
    pub fn len(&self) -> u64 {
        self.stack.len() as u64
    }

    /// Write field element in memory address
    pub fn write(&mut self, index: u64, elem: u64) {
        if self.len() <= index {
            let additional = index - self.len() + 1;
            self.stack.reserve(additional.try_into().unwrap());
            for _ in 0..additional {
                // Consider CairoMemory having Option<CairoWord> so one can have None here
                self.stack.push(CairoWord::new(0));
            }
        }
        self.stack[index as usize] = CairoWord::new(elem);
        //std::mem::replace(self.stack[index], CairoWord::new(elem));
    }

    /// Read field element in memory address
    pub fn read(&self, index: u64) -> u64 {
        self.stack[index as usize].word
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cairo_memory() {
        // This test starts with the public memory corresponding to a simple Cairo program
        // func main{}():
        //    tempvar x = 10;
        //    return()
        // end
        // And checks that memory writing and reading works as expected by completing
        // the total memory of executing the program
        let instrs: Vec<u64> = vec![0x480680017fff8000, 10, 0x208b7fff7fff7ffe];
        let mut memo = CairoMemory::new(instrs);
        memo.write(memo.len(), 7);
        memo.write(memo.len(), 7);
        memo.write(memo.len(), 10);
        for i in 0..memo.len() {
            println!("0x{:x}", memo.read(i));
        }
        assert_eq!(3, memo.public());
        assert_eq!(6, memo.len());
    }
}
