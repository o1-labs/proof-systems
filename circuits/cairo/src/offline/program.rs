use crate::offline::memory::CairoMemory;
use crate::offline::word::CairoWord;

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
    dst: u64,
    op0: u64,
    op1: u64,
    res: u64,
    dst_dir: u64,
    op0_dir: u64,
    op1_dir: u64,
    size: u64,
}

impl CairoVariables {
    pub fn new() -> CairoVariables {
        CairoVariables {
            dst: 0,
            op0: 0,
            op1: 0,
            res: 0,
            dst_dir: 0,
            op0_dir: 0,
            op1_dir: 0,
            size: 0,
        }
    }
}

/// A data structure to store a current step of Cairo computation
struct CairoStep {
    /// current step of computation
    step: u64,
    /// current word of the program
    memo: CairoMemory,
    /// current registers
    curr: CairoRegisters,
    /// (if any) next registers
    next: Option<CairoRegisters>,
    /// state auxiliary variables
    vars: CairoVariables,
}

/// Performs the addition of a u64 register with a i16 offset
fn add_off(reg: u64, off: i16) -> u64 {
    if off.is_negative() {
        // 1. Convert item to i64, so that the absolute value fits (e.g. 2^15 could not fit in i16 otherwise)
        // 2. Once it is a positive value, store it as u64
        reg - ((i64::from(off)).abs() as u64)
    } else {
        reg + (off.abs() as u64)
    }
}

impl CairoStep {
    /// Creates a new Cairo execution step from a step index, a Cairo word, and current registers
    pub fn new(idx: u64, memo: CairoMemory, regs: CairoRegisters) -> CairoStep {
        CairoStep {
            step: idx,
            memo,
            curr: regs,
            next: None,
            vars: CairoVariables::new(),
        }
    }

    pub fn execute(&mut self) -> bool {
        self.set_dst();
        self.set_op0();
        self.set_op1();
        self.set_res();
        let next_pc = self.next_pc();
        let (next_ap, next_fp) = self.next_apfp();
        self.next = Some(CairoRegisters::new(
            next_pc.unwrap(),
            next_ap.unwrap(),
            next_fp.unwrap(),
        ));
        return true;
    }

    /// This function returns the current word instruction being executed
    pub fn instr(&self) -> CairoWord {
        CairoWord::new(self.memo.read(self.curr.pc))
    }

    /// This function computes the destination address
    pub fn set_dst(&mut self) {
        if self.instr().dst_reg() == 0 {
            self.vars.dst_dir = add_off(self.curr.ap, self.instr().off_dst());
        // read from stack
        } else {
            self.vars.dst_dir = add_off(self.curr.fp, self.instr().off_dst()); // read from parameters
        }
        self.vars.dst = self.memo.read(self.vars.dst_dir);
    }

    /// This function computes the first operand address
    pub fn set_op0(&mut self) {
        if self.instr().op0_reg() == 0 {
            // reads first word from memory
            self.vars.op0_dir = add_off(self.curr.ap, self.instr().off_op0());
        } else {
            // reads first word from parameters
            self.vars.op0_dir = add_off(self.curr.fp, self.instr().off_op0());
        }
        self.vars.op0 = self.memo.read(self.vars.op0_dir);
    }

    pub fn set_op1(&mut self) {
        if self.instr().op1_src() == 0 {
            // op1_src = 000
            self.vars.size = 1; // double indexing
            self.vars.op1_dir = add_off(self.vars.op0, self.instr().off_op1());
            self.vars.op1 = self.memo.read(self.vars.op1_dir);
        } else if self.instr().op1_src() == 1 {
            // op1_src = 001
            self.vars.size = 2; // immediate value
            self.vars.op1_dir = add_off(self.curr.pc, self.instr().off_op1()); // if off_op1=1 then op1 contains a plain value
            self.vars.op1 = self.memo.read(self.vars.op1_dir);
        } else if self.instr().op1_src() == 2 {
            // op1_src = 010
            self.vars.size = 1;
            self.vars.op1_dir = add_off(self.curr.fp, self.instr().off_op1()); // second operand offset relative to fp
            self.vars.op1 = self.memo.read(self.vars.op1_dir);
        } else if self.instr().op1_src() == 4 {
            // op1_src = 100
            self.vars.size = 1;
            self.vars.op1_dir = add_off(self.curr.ap, self.instr().off_op1()); // second operand offset relative to ap
            self.vars.op1 = self.memo.read(self.vars.op1_dir);
        } else {
            unimplemented!(); // invalid instruction
        }
    }

    /// This function computes the value of the result of the arithmetic operation
    pub fn set_res(&mut self) {
        if self.instr().pc_up() == 4 {
            // jnz instruction
            if self.instr().res_log() == 0
                && self.instr().opcode() == 0
                && self.instr().ap_up() != 1
            {
                self.vars.res = 0; // "unused"
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
            } else if self.instr().res_log() == 1 {
                self.vars.res = self.vars.op0 + self.vars.op1; // right part is addition
            } else if self.instr().res_log() == 2 {
                self.vars.res = self.vars.op0 * self.vars.op1; // right part is multiplication
            } else {
                unimplemented!();
            } // invalid instruction
        } else {
            // multiple bits take value 1
            unimplemented!(); // invalid instruction
        }
    }

    // This function computes the next program counter
    pub fn next_pc(&mut self) -> Option<u64> {
        if self.instr().pc_up() == 0 {
            // next instruction is right after the current one
            Some(self.curr.pc + self.vars.size) // the common case
        } else if self.instr().pc_up() == 1 {
            // next instruction is in res
            Some(self.vars.res) // absolute jump
        } else if self.instr().pc_up() == 2 {
            // relative jump
            Some(self.curr.pc + self.vars.res) // go to some address relative to pc
        } else if self.instr().pc_up() == 4 {
            // conditional relative jump (jnz)
            if self.vars.dst == 0 {
                Some(self.curr.pc + self.vars.size) // if condition false, common case
            } else {
                // if condition true, relative jump with second operand
                Some(self.curr.pc + self.vars.op1)
            }
        } else {
            unimplemented!(); // invalid instruction
        }
    }
    // This function computes the next values of the allocation and frame pointers
    fn next_apfp(&mut self) -> (Option<u64>, Option<u64>) {
        let (next_ap, next_fp);
        // The following branches don't include the assertions. That is done in the verification.
        if self.instr().opcode() == 1 {
            // "call" instruction
            self.memo.write(self.curr.ap, self.curr.fp); // Save current fp
            self.memo
                .write(self.curr.ap + 1, self.curr.pc + self.vars.size); // Save next instruction
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
                next_ap = Some(self.curr.ap + self.vars.res); // ap += <op>
            } else if self.instr().ap_up() == 2 {
                next_ap = Some(self.curr.ap + 1); // ap++
            } else {
                unimplemented!(); // invalid instruction}
            }
            if self.instr().opcode() == 0 || self.instr().opcode() == 4 {
                next_fp = Some(self.curr.fp); // no modification on fp
            } else if self.instr().opcode() == 2 {
                next_fp = Some(self.vars.dst); // ret sets fp to previous fp that was in [ap-2]
            } else {
                unimplemented!();
            }
        } else {
            unimplemented!(); // invalid instruction
        }
        return (next_ap, next_fp);
    }
}

/// A Cairo full program
pub struct CairoProgram {
    /// full execution memory
    memo: CairoMemory,
    /// initial computation registers
    regs: CairoRegisters,
}

impl CairoProgram {
    /// Creates a Cairo machine from the public input
    pub fn new(memo: CairoMemory, pc: u64, ap: u64) -> CairoProgram {
        CairoProgram {
            memo,
            regs: CairoRegisters::new(pc, ap, ap),
        }
    }
    /*
    /// This function simulates an execution of the Cairo program received as input.
    /// It generates the full memory stack and the execution trace
    pub fn execute(&mut self) {
        // create first step
        let mut next = true;
        let i = 0;
        while i < 3 {
            let mut i = 0;
            let mut step = CairoStep::new(i, self.memo, self.regs);
            next = step.execute();
            i = i + 1;
        }
    }
    */
}
