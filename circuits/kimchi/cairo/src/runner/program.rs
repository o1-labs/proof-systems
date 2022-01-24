use crate::runner::bytecode::CairoBytecode;
use crate::runner::word::CairoWord;

/// A structure to store program counter, allocation pointer and frame pointer
#[derive(Clone, Copy)]
struct CairoRegisters {
    pc: u64,
    ap: u64,
    fp: u64,
}

impl CairoRegisters {
    /// Creates a new triple of registers
    pub fn new(pc: u64, ap: u64, fp: u64) -> CairoRegisters {
        CairoRegisters { pc, ap, fp }
    }
}

/// A structure to store auxiliary variables throughout computation
struct CairoVariables {
    dst: Option<i128>,
    op0: Option<i128>,
    op1: Option<i128>,
    res: Option<i128>,
    dst_dir: u64,
    op0_dir: u64,
    op1_dir: u64,
    size: u64,
}

impl CairoVariables {
    pub fn new() -> CairoVariables {
        CairoVariables {
            dst: None,
            op0: None,
            op1: None,
            res: None,
            dst_dir: 0,
            op0_dir: 0,
            op1_dir: 0,
            size: 0,
        }
    }
}

/// A data structure to store a current step of Cairo computation
struct CairoStep<'a> {
    // current step of computation
    //step: u64,
    /// current word of the program
    mem: &'a mut CairoBytecode,
    /// current registers
    curr: CairoRegisters,
    /// (if any) next registers
    next: Option<CairoRegisters>,
    /// state auxiliary variables
    vars: CairoVariables,
}

/// A Cairo full program
pub struct CairoProgram<'a> {
    /// full execution memory
    mem: &'a mut CairoBytecode,
    /// initial computation registers
    regs: CairoRegisters,
}

/// Performs the addition of a u64 register with a signed offset
fn add_off(reg: u64, off: i128) -> u64 {
    // 1. Since the output address is u64, the offset cannot be larger than this
    // 2. The absolute value of the offset will fit in u64
    // 3. If it was negative, subtract. If it was positive, sum.
    if off.is_negative() {
        reg - (off.abs() as u64)
    } else {
        reg + (off.abs() as u64)
    }
}

impl<'a> CairoStep<'a> {
    /// Creates a new Cairo execution step from a step index, a Cairo word, and current registers
    pub fn new(mem: &mut CairoBytecode, regs: CairoRegisters) -> CairoStep {
        CairoStep {
            //step: idx,
            mem,
            curr: regs,
            next: None,
            vars: CairoVariables::new(),
        }
    }

    /// Executes a Cairo step from the current registers
    pub fn execute(&mut self) {
        println!("this instr 0x{:x}", self.mem.read(self.curr.pc).unwrap());
        // This order is important in order to allocate the memory in time
        self.set_op0();
        self.set_op1();
        self.set_res();
        self.set_dst();
        // The Option<> thing is not a guarantee for continuation of the program, may be removing this
        let next_pc = self.next_pc();
        println!(
            "curr pc{}, next pc{}",
            self.curr.pc.clone(),
            next_pc.unwrap().clone()
        );
        let (next_ap, next_fp) = self.next_apfp();
        self.next = Some(CairoRegisters::new(
            next_pc.unwrap(),
            next_ap.unwrap(),
            next_fp.unwrap(),
        ));
    }

    /// This function returns the current word instruction being executed
    pub fn instr(&mut self) -> CairoWord {
        CairoWord::new(self.mem.read(self.curr.pc).unwrap())
    }

    /// This function computes the first operand address
    pub fn set_op0(&mut self) {
        if self.instr().op0_reg() == 0 {
            // reads first word from memory
            self.vars.op0_dir = add_off(self.curr.ap, self.instr().off_op0().into());
        } else {
            // reads first word from parameters
            self.vars.op0_dir = add_off(self.curr.fp, self.instr().off_op0().into());
        }
        self.vars.op0 = self.mem.read(self.vars.op0_dir);
        println!(
            "op0dir {}, op0{}",
            self.vars.op0_dir,
            self.vars.op0.unwrap_or_default()
        );
    }

    /// This function computes the second operand address and content and the instruction size
    pub fn set_op1(&mut self) {
        if self.instr().op1_src() == 0 {
            // op1_src = 000
            self.vars.size = 1; // double indexing
            self.vars.op1_dir =
                add_off(self.vars.op0.unwrap() as u64, self.instr().off_op1().into()); // should be positive for address
            self.vars.op1 = self.mem.read(self.vars.op1_dir);
        } else if self.instr().op1_src() == 1 {
            // op1_src = 001
            self.vars.size = 2; // immediate value
            self.vars.op1_dir = add_off(self.curr.pc, self.instr().off_op1().into()); // if off_op1=1 then op1 contains a plain value
            self.vars.op1 = self.mem.read(self.vars.op1_dir);
        } else if self.instr().op1_src() == 2 {
            // op1_src = 010
            self.vars.size = 1;
            self.vars.op1_dir = add_off(self.curr.fp, self.instr().off_op1().into()); // second operand offset relative to fp
            self.vars.op1 = self.mem.read(self.vars.op1_dir);
        } else if self.instr().op1_src() == 4 {
            // op1_src = 100
            self.vars.size = 1;
            self.vars.op1_dir = add_off(self.curr.ap, self.instr().off_op1().into()); // second operand offset relative to ap
            self.vars.op1 = self.mem.read(self.vars.op1_dir);
        } else {
            unimplemented!(); // invalid instruction
        }
        println!(
            "op1dir {}, op0{}",
            self.vars.op1_dir,
            self.vars.op1.unwrap_or_default()
        );
    }

    /// This function computes the value of the result of the arithmetic operation
    pub fn set_res(&mut self) {
        println!("set_res");
        if self.instr().pc_up() == 4 {
            // jnz instruction
            if self.instr().res_log() == 0
                && self.instr().opcode() == 0
                && self.instr().ap_up() != 1
            {
                self.vars.res = Some(0); // "unused"
            } else {
                unimplemented!(); // invalid instruction
            }
        } else if self.instr().pc_up() == 0
            || self.instr().pc_up() == 1
            || self.instr().pc_up() == 2
        {
            // rest of types of updates
            // common increase || absolute jump || relative jump
            if self.instr().res_log() == 0 {
                self.vars.res = self.vars.op1; // right part is single operand
                println!(
                    "estoy en reslog sin y op1 {} con res {}",
                    self.vars.op1.unwrap_or_default(),
                    self.vars.res.unwrap_or_default()
                );
            } else if self.instr().res_log() == 1 {
                self.vars.res = Some(self.vars.op0.unwrap() + self.vars.op1.unwrap());
            // right part is addition
            } else if self.instr().res_log() == 2 {
                self.vars.res = Some(self.vars.op0.unwrap() * self.vars.op1.unwrap());
            // right part is multiplication
            } else {
                unimplemented!();
            } // invalid instruction
        } else {
            // multiple bits take value 1
            unimplemented!(); // invalid instruction
        }
    }

    /// This function computes the destination address
    pub fn set_dst(&mut self) {
        if self.instr().dst_reg() == 0 {
            self.vars.dst_dir = add_off(self.curr.ap, self.instr().off_dst().into());
        // read from stack
        } else {
            self.vars.dst_dir = add_off(self.curr.fp, self.instr().off_dst().into());
            // read from parameters
        }
        self.vars.dst = self.mem.read(self.vars.dst_dir);
        println!(
            "dstdir {}, dst{}",
            self.vars.dst_dir,
            self.vars.dst.unwrap_or_default()
        );
    }

    /// This function computes the next program counter
    pub fn next_pc(&mut self) -> Option<u64> {
        println!("next_pc");
        println!("res {}", self.vars.res.unwrap_or_default());
        if self.instr().pc_up() == 0 {
            // next instruction is right after the current one
            Some(self.curr.pc + self.vars.size) // the common case
        } else if self.instr().pc_up() == 1 {
            // next instruction is in res
            println!(
                "hola estoy en un return con res {}",
                self.vars.res.unwrap_or_default()
            );
            Some(self.vars.res.unwrap() as u64) // absolute jump
        } else if self.instr().pc_up() == 2 {
            // relative jump
            Some(add_off(self.curr.pc, self.vars.res.unwrap())) // go to some address relative to pc
        } else if self.instr().pc_up() == 4 {
            // conditional relative jump (jnz)
            if self.vars.dst == Some(0) {
                Some(self.curr.pc + self.vars.size) // if condition false, common case
            } else {
                // if condition true, relative jump with second operand
                Some(add_off(self.curr.pc, self.vars.op1.unwrap()))
            }
        } else {
            unimplemented!(); // invalid instruction
        }
    }
    // This function computes the next values of the allocation and frame pointers
    fn next_apfp(&mut self) -> (Option<u64>, Option<u64>) {
        println!("set_apfp");
        let (next_ap, next_fp);
        // The following branches don't include the assertions. That is done in the verification.
        if self.instr().opcode() == 1 {
            // "call" instruction
            self.mem.write(self.curr.ap, self.curr.fp.into()); // Save current fp
            self.mem
                .write(self.curr.ap + 1, (self.curr.pc + self.vars.size).into()); // Save next instruction
                                                                                  // Update fp
            next_fp = Some(self.curr.ap + 2); // pointer for next frame is after current fp and instruction after call
                                              // Update ap
            if self.instr().ap_up() == 0 {
                next_ap = Some(self.curr.ap + 2); // two words were written so advance 2 positions
            } else {
                unimplemented!(); // ap increments not allowed in call instructions
            }
        } else if self.instr().opcode() == 0
            || self.instr().opcode() == 2
            || self.instr().opcode() == 4
        {
            // rest of types of instruction
            // jumps and increments || return || assert equal
            if self.instr().ap_up() == 0 {
                next_ap = Some(self.curr.ap) // no modification on ap
            } else if self.instr().ap_up() == 1 {
                next_ap = Some(add_off(self.curr.ap, self.vars.res.unwrap())); // ap += <op> // should be larger than current
            } else if self.instr().ap_up() == 2 {
                next_ap = Some(self.curr.ap + 1); // ap++
            } else {
                unimplemented!(); // invalid instruction}
            }
            if self.instr().opcode() == 0 {
                next_fp = Some(self.curr.fp); // no modification on fp
            } else if self.instr().opcode() == 2 {
                next_fp = Some(self.vars.dst.unwrap() as u64); // ret sets fp to previous fp that was in [ap-2]
            } else if self.instr().opcode() == 4 {
                println!(
                    "actualiza dst_dir {} con res {}",
                    self.vars.dst_dir,
                    self.vars.res.unwrap_or_default()
                );
                // The following conditional is a fix that is not explained in the whitepaper
                // The goal is to distinguish two types of ASSERT_EQUAL where one checks that
                // dst = res , but in order for this to be true, one sometimes needs to write
                // the res in mem(dst_dir) and sometimes write dst in mem(res_dir). The only
                // case where res can be None is when res = op1 and thus res_dir = op1_dir
                if self.vars.res.is_none() {
                    self.mem.write(self.vars.op1_dir, self.vars.dst.unwrap()); // res = dst
                } else {
                    self.mem.write(self.vars.dst_dir, self.vars.res.unwrap()); // dst = res
                }
                next_fp = Some(self.curr.fp); // no modification on fp
            } else {
                unimplemented!();
            }
        } else {
            unimplemented!(); // invalid instruction
        }
        println!("next ap {}, next fp {}", next_ap.unwrap(), next_fp.unwrap());
        (next_ap, next_fp)
    }
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
            let mut step = CairoStep::new(&mut self.mem, regs);
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

mod tests {
    //use super::*;

    #[test]
    fn test_cairo_step() {
        // This tests that CairoStep works for a 2 word instruction
        //    tempvar x = 10;
        let instrs = vec![0x480680017fff8000, 10, 0x208b7fff7fff7ffe];
        let mut mem = super::CairoBytecode::new(instrs);
        // Need to know how to find out
        // Is it final ap and/or final fp? Will write to starkware guys to learn about this
        mem.write(4, 7);
        mem.write(5, 7);
        let regs = super::CairoRegisters::new(1, 6, 6);
        let mut step = super::CairoStep::new(&mut mem, regs);

        let _next = step.execute();
        assert_eq!(step.next.unwrap().pc, 3);
        assert_eq!(step.next.unwrap().ap, 7);
        assert_eq!(step.next.unwrap().fp, 6);

        step.mem.view();
    }

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
