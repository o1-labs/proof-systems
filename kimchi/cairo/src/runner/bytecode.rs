// TODO(querolita):
// - be able to index memory with any type (u256 in particular) not only usize

use crate::runner::word::CairoWord;

/// This data structure stores the memory of the program
pub struct CairoBytecode {
    /// length of the public memory
    publen: u64,
    /// full memory vector, None if non initialized
    pub vect: Vec<Option<CairoWord>>,
}

impl CairoBytecode {
    /// Create a new memory structure from a vector of u64
    pub fn new(input: Vec<i128>) -> CairoBytecode {
        // Initialized with the public memory (compiled instructions only)
        // starts intentionally with a zero word for ease of testing
        let mut aux = vec![0];
        aux.extend(input);
        CairoBytecode {
            publen: (aux.len() - 1) as u64,
            vect: aux.into_iter().map(|i| Some(CairoWord::new(i))).collect(),
        }
    }

    /// Get size of the public memory
    pub fn public(&self) -> u64 {
        self.publen
    }

    /// Get size of the full memory including dummy 0th entry
    pub fn size(&self) -> u64 {
        (self.vect.len()) as u64
    }

    /// Enlarges memory with enough additional None slots if necessary before writing or reading
    fn enlarge(&mut self, index: u64) {
        // if you want to access an index of the memory but its size is less or equal than this
        if self.size() <= index {
            // you will need to extend the vector with enough spaces (taking into account that
            // vectors start by index 0 and size starts in 1)
            let additional = index - self.size() + 1;
            self.vect.reserve(additional.try_into().unwrap());
            for _ in 0..additional {
                // Consider CairoBytecode having Option<CairoWord> so one can have None here
                self.vect.push(None);
            }
        }
    }

    /// Write u64 element in memory address
    pub fn write(&mut self, index: u64, elem: i128) {
        self.enlarge(index);
        self.vect[index as usize] = Some(CairoWord::new(elem));
    }

    /// Read element in memory address
    /// Because of how assignments work in Cairo (called assert-equal), they
    /// behave in two ways: either check two variables are equal or assign
    /// the value of one variable to the address of the other one so that
    /// their content will be the same. This means you may first read to
    /// addressses of memory that were still not instantiated, and you need
    /// to enlarge the vector before reading (with None values).
    pub fn read(&mut self, index: u64) -> Option<i128> {
        self.enlarge(index);
        if self.vect[index as usize].is_some() {
            Some(self.vect[index as usize].unwrap().to_i128())
        } else {
            None
        }
    }

    /// Visualize content of memory excluding the 0th dummy entry
    pub fn view(&mut self) {
        for i in 1..self.size() {
            println!("{}: 0x{:x}", i, self.read(i).unwrap_or_default());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cairo_bytecode() {
        // This test starts with the public memory corresponding to a simple Cairo program
        // func main{}():
        //    tempvar x = 10;
        //    return()
        // end
        // And checks that memory writing and reading works as expected by completing
        // the total memory of executing the program
        let instrs = vec![0x480680017fff8000, 10, 0x208b7fff7fff7ffe];
        let mut memo = CairoBytecode::new(instrs);
        memo.write(memo.size(), 7);
        memo.write(memo.size(), 7);
        memo.write(memo.size(), 10);
        memo.view();
        // Check that the program contained 3 words
        assert_eq!(3, memo.public());
        // Check we have 6 words, excluding the dummy entry
        assert_eq!(6, memo.size() - 1);
    }
}
