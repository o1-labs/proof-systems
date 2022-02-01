// TODO(querolita):
// - Read Cairo source code to understand how they deal with auxiliary hints
// - Run automatic tests using Cairo's official tests and compare against them

//! This module represents a full Cairo program, that is represented
//! by the execution of consecutive Cairo steps

use crate::runner::bytecode::CairoBytecode;
use crate::runner::step::{CairoRegisters, CairoStep};

/// A Cairo full program
pub struct CairoProgram<'a> {
    /// full execution memory
    mem: &'a mut CairoBytecode,
    /// initial computation registers regs
    regs: CairoRegisters,
}

impl<'a> CairoProgram<'a> {
    /// Creates a Cairo machine from the public input
    pub fn new(mem: &mut CairoBytecode, pc: u64, ap: u64) -> CairoProgram {
        CairoProgram {
            mem,
            regs: CairoRegisters::new(pc, ap, ap),
        }
    }

    /// This function simulates an execution of the Cairo program received as input.
    /// It generates the full memory stack and the execution trace
    pub fn execute(&mut self) {
        // set finishing flag to false, as it just started
        let mut end = false;
        // saves local copy of the initial (claimed) registers of the program
        let mut regs = self.regs;
        // first timestamp
        //let mut i = 0;
        // keep executing steps until the end is reached
        while !end {
            // save allocation pointer before the execution
            let curr_ap = regs.ap;
            // create current step of computation
            let mut step = CairoStep::new(self.mem, regs);
            // execute current step and increase time counter
            step.execute();
            //i += 1;
            match step.next {
                None => end = true, // if find no next registers, end
                _ => {
                    // if there are next registers
                    end = false;
                    regs = step.next.unwrap();
                    if curr_ap <= regs.pc {
                        // if reading from unallocated memory, end
                        end = true;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //use super::*;

    #[test]
    fn test_cairo_program() {
        let instrs = vec![0x480680017fff8000, 10, 0x208b7fff7fff7ffe];
        let mut mem = super::CairoBytecode::new(instrs);
        // Need to know how to find out
        // Is it final ap and/or final fp? Will write to starkware guys to learn about this
        mem.write(4, 7); //beginning of output
        mem.write(5, 7); //end of output
        let mut prog = super::CairoProgram::new(&mut mem, 1, 6);
        prog.execute();
        prog.mem.view();
    }

    #[test]
    fn test_cairo_output() {
        // This is a test for a longer program, involving builtins, imports and outputs
        /*
        %builtins output
        from starkware.cairo.common.serialize import serialize_word
        func main{output_ptr : felt*}():
            tempvar x = 10
            tempvar y = x + x
            tempvar z = y * y + x
            serialize_word(x)
            serialize_word(y)
            serialize_word(z)
            return ()
        end
        */
        let instrs = vec![
            0x400380007ffc7ffd,
            0x482680017ffc8000,
            1,
            0x208b7fff7fff7ffe,
            0x480680017fff8000,
            10,
            0x48307fff7fff8000,
            0x48507fff7fff8000,
            0x48307ffd7fff8000,
            0x480a7ffd7fff8000,
            0x48127ffb7fff8000,
            0x1104800180018000,
            -11,
            0x48127ff87fff8000,
            0x1104800180018000,
            -14,
            0x48127ff67fff8000,
            0x1104800180018000,
            -17,
            0x208b7fff7fff7ffe,
            /*41, // beginning of outputs
            44,   // end of outputs
            44,   // input
            */
        ];
        let mut mem = super::CairoBytecode::new(instrs);
        // Need to know how to find out
        mem.write(21, 41); // beginning of outputs
        mem.write(22, 44); // end of outputs
        mem.write(23, 44); //end of program
        let mut prog = super::CairoProgram::new(&mut mem, 5, 24);
        prog.execute();
        prog.mem.view();
        assert_eq!(prog.mem.read(24).unwrap(), 10);
        assert_eq!(prog.mem.read(25).unwrap(), 20);
        assert_eq!(prog.mem.read(26).unwrap(), 400);
        assert_eq!(prog.mem.read(27).unwrap(), 410);
        assert_eq!(prog.mem.read(28).unwrap(), 41);
        assert_eq!(prog.mem.read(29).unwrap(), 10);
        assert_eq!(prog.mem.read(30).unwrap(), 24);
        assert_eq!(prog.mem.read(31).unwrap(), 14);
        assert_eq!(prog.mem.read(32).unwrap(), 42);
        assert_eq!(prog.mem.read(33).unwrap(), 20);
        assert_eq!(prog.mem.read(34).unwrap(), 24);
        assert_eq!(prog.mem.read(35).unwrap(), 17);
        assert_eq!(prog.mem.read(36).unwrap(), 43);
        assert_eq!(prog.mem.read(37).unwrap(), 410);
        assert_eq!(prog.mem.read(38).unwrap(), 24);
        assert_eq!(prog.mem.read(39).unwrap(), 20);
        assert_eq!(prog.mem.read(40).unwrap(), 44);
        assert_eq!(prog.mem.read(41).unwrap(), 10);
        assert_eq!(prog.mem.read(42).unwrap(), 20);
        assert_eq!(prog.mem.read(43).unwrap(), 410);
    }
}
