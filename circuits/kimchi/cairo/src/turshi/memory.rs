use crate::runner::bytecode::CairoBytecode;
use crate::turshi::instruction::CairoInstruction;
use ark_ff::FftField;

// think about representing the cairo stack as a polynomial over F
pub struct CairoMemory<F: FftField> {
    /// full memory stack
    pub stack: Vec<CairoInstruction<F>>,
}

impl<F: FftField> CairoMemory<F> {
    /// Create a new memory stack structure from a full Cairo memory
    pub fn new(input: &mut CairoBytecode) -> CairoMemory<F> {
        CairoMemory {
            stack: (input
                .vect
                .clone()
                .into_iter()
                .map(|i| CairoInstruction::<F>::new(i.word))
                .collect()),
        }
    }

    /// Read field element in memory address (still need to convert to polynomial)
    fn read(&self, index: u64) -> F {
        self.stack[index as usize].elem
    }

    pub fn view(&self) {
        for i in 0..self.stack.len() {
            println!("{}: {}", i, self.read(i as u64));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mina_curves::pasta::fp::Fp;

    #[test]
    fn test_cairo_memory() {
        // This test starts with the public memory corresponding to a simple Cairo program
        // func main{}():
        //    tempvar x = 10;
        //    return()
        // end
        // And checks that memory writing and reading works as expected by completing
        // the total memory of executing the program

        let instrs = vec![0x480680017fff8000, 10, 0x208b7fff7fff7ffe, 6, 6, 10];
        let mut mem = CairoBytecode::new(instrs);
        let stack = CairoMemory::<Fp>::new(&mut mem);
        stack.view();
    }
}
