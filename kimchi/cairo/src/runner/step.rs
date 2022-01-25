use crate::runner::bytecode::CairoBytecode;
use crate::runner::definitions::*;
use crate::runner::word::CairoWord;

/// A structure to store program counter, allocation pointer and frame pointer
#[derive(Clone, Copy)]
pub struct CairoRegisters {
    /// Program counter: points to address in memory
    pub pc: u64,
    /// Allocation pointer: points to first free space in memory
    pub ap: u64,
    /// Frame pointer: points to the beginning of the stack in memory (for arguments)
    pub fp: u64,
}

impl CairoRegisters {
    /// Creates a new triple of registers
    pub fn new(pc: u64, ap: u64, fp: u64) -> CairoRegisters {
        CairoRegisters { pc, ap, fp }
    }
}

/// A structure to store auxiliary variables throughout computation
pub struct CairoVariables {
    /// Destination
    pub dst: Option<i128>,
    /// First operand
    pub op0: Option<i128>,
    /// Second operand
    pub op1: Option<i128>,
    /// Result
    pub res: Option<i128>,
    /// Destination address
    pub dst_addr: u64,
    /// First operand address
    pub op0_addr: u64,
    /// Second operand address
    pub op1_addr: u64,
    /// Size of the instruction
    pub size: u64,
}

impl CairoVariables {
    pub fn new() -> CairoVariables {
        CairoVariables {
            dst: None,
            op0: None,
            op1: None,
            res: None,
            dst_addr: 0,
            op0_addr: 0,
            op1_addr: 0,
            size: 0,
        }
    }
}
impl Default for CairoVariables {
    fn default() -> Self {
        Self::new()
    }
}

/// A data structure to store a current step of Cairo computation
pub struct CairoStep<'a> {
    // current step of computation
    //step: u64,
    /// current word of the program
    pub mem: &'a mut CairoBytecode,
    // comment instr for efficiency
    /// current registers
    pub curr: CairoRegisters,
    /// (if any) next registers
    pub next: Option<CairoRegisters>,
    /// state auxiliary variables
    pub vars: CairoVariables,
}

/// Performs the addition of a u64 register with a signed offset
fn add_off(reg: u64, off: i128) -> u64 {
    // TODO(@querolita) check helper to avoid casting manually
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
        // This order is important in order to allocate the memory in time
        self.set_op0();
        self.set_op1();
        self.set_res();
        self.set_dst();
        // If the Option<> thing is not a guarantee for continuation of the program, we may be removing this
        let next_pc = self.next_pc();
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
        if self.instr().op0_reg() == OP0_AP {
            // reads first word from allocated memory
            self.vars.op0_addr = add_off(self.curr.ap, self.instr().off_op0().into());
        } else {
            // reads first word from input parameters
            self.vars.op0_addr = add_off(self.curr.fp, self.instr().off_op0().into());
        } // no more values than 0 and 1 because op0_reg is one bit
        self.vars.op0 = self.mem.read(self.vars.op0_addr);
    }

    /// This function computes the second operand address and content and the instruction size
    pub fn set_op1(&mut self) {
        if self.instr().op1_src() == OP1_DBL {
            self.vars.size = 1; // double indexing
            self.vars.op1_addr =
                add_off(self.vars.op0.unwrap() as u64, self.instr().off_op1().into()); // should be positive for address
            self.vars.op1 = self.mem.read(self.vars.op1_addr);
        } else if self.instr().op1_src() == OP1_VAL {
            self.vars.size = 2; // immediate value
            self.vars.op1_addr = add_off(self.curr.pc, self.instr().off_op1().into()); // if off_op1=1 then op1 contains a plain value
            self.vars.op1 = self.mem.read(self.vars.op1_addr);
        } else if self.instr().op1_src() == OP1_FP {
            self.vars.size = 1;
            self.vars.op1_addr = add_off(self.curr.fp, self.instr().off_op1().into()); // second operand offset relative to fp
            self.vars.op1 = self.mem.read(self.vars.op1_addr);
        } else if self.instr().op1_src() == OP1_AP {
            self.vars.size = 1;
            self.vars.op1_addr = add_off(self.curr.ap, self.instr().off_op1().into()); // second operand offset relative to ap
            self.vars.op1 = self.mem.read(self.vars.op1_addr);
        } else {
            unimplemented!(); // invalid instruction, no single one bit flagset
        }
    }

    /// This function computes the value of the result of the arithmetic operation
    pub fn set_res(&mut self) {
        if self.instr().pc_up() == PC_JNZ {
            // jnz instruction
            if self.instr().res_log() == RES_ONE
                && self.instr().opcode() == OPC_JMP_INC
                && self.instr().ap_up() != AP_ADD
            {
                self.vars.res = Some(0); // "unused"
            } else {
                unimplemented!(); // invalid instruction
            }
        } else if self.instr().pc_up() == PC_SIZ
            || self.instr().pc_up() == PC_ABS
            || self.instr().pc_up() == PC_REL
        {
            // rest of types of updates
            // common increase || absolute jump || relative jump
            if self.instr().res_log() == RES_ONE {
                self.vars.res = self.vars.op1; // right part is single operand
            } else if self.instr().res_log() == RES_ADD {
                self.vars.res = Some(self.vars.op0.unwrap() + self.vars.op1.unwrap());
            // right part is addition
            } else if self.instr().res_log() == RES_MUL {
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
        if self.instr().dst_reg() == DST_AP {
            self.vars.dst_addr = add_off(self.curr.ap, self.instr().off_dst().into());
            // read from stack
        } else {
            self.vars.dst_addr = add_off(self.curr.fp, self.instr().off_dst().into());
            // read from parameters
        }
        self.vars.dst = self.mem.read(self.vars.dst_addr);
    }

    /// This function computes the next program counter
    pub fn next_pc(&mut self) -> Option<u64> {
        if self.instr().pc_up() == PC_SIZ {
            // next instruction is right after the current one
            Some(self.curr.pc + self.vars.size) // the common case
        } else if self.instr().pc_up() == PC_ABS {
            // next instruction is in res
            Some(self.vars.res.unwrap() as u64) // absolute jump
        } else if self.instr().pc_up() == PC_REL {
            // relative jump
            Some(add_off(self.curr.pc, self.vars.res.unwrap())) // go to some address relative to pc
        } else if self.instr().pc_up() == PC_JNZ {
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
        let (next_ap, next_fp);
        // The following branches don't include the assertions. That is done in the verification.
        if self.instr().opcode() == OPC_CALL {
            // "call" instruction
            self.mem.write(self.curr.ap, self.curr.fp.into()); // Save current fp
            self.mem
                .write(self.curr.ap + 1, (self.curr.pc + self.vars.size).into()); // Save next instruction
                                                                                  // Update fp
            next_fp = Some(self.curr.ap + 2); // pointer for next frame is after current fp and instruction after call
                                              // Update ap
            if self.instr().ap_up() == AP_Z2 {
                next_ap = Some(self.curr.ap + 2); // two words were written so advance 2 positions
            } else {
                unimplemented!(); // ap increments not allowed in call instructions
            }
        } else if self.instr().opcode() == OPC_JMP_INC
            || self.instr().opcode() == OPC_RET
            || self.instr().opcode() == OPC_AEQ
        {
            // rest of types of instruction
            // jumps and increments || return || assert equal
            if self.instr().ap_up() == AP_Z2 {
                next_ap = Some(self.curr.ap) // no modification on ap
            } else if self.instr().ap_up() == AP_ADD {
                next_ap = Some(add_off(self.curr.ap, self.vars.res.unwrap())); // ap += <op> // should be larger than current
            } else if self.instr().ap_up() == AP_ONE {
                next_ap = Some(self.curr.ap + 1); // ap++
            } else {
                unimplemented!(); // invalid instruction}
            }
            if self.instr().opcode() == OPC_JMP_INC {
                next_fp = Some(self.curr.fp); // no modification on fp
            } else if self.instr().opcode() == OPC_RET {
                next_fp = Some(self.vars.dst.unwrap() as u64); // ret sets fp to previous fp that was in [ap-2]
            } else if self.instr().opcode() == OPC_AEQ {
                // The following conditional is a fix that is not explained in the whitepaper
                // The goal is to distinguish two types of ASSERT_EQUAL where one checks that
                // dst = res , but in order for this to be true, one sometimes needs to write
                // the res in mem(dst_addr) and sometimes write dst in mem(res_dir). The only
                // case where res can be None is when res = op1 and thus res_dir = op1_addr
                if self.vars.res.is_none() {
                    self.mem.write(self.vars.op1_addr, self.vars.dst.unwrap()); // res = dst
                } else {
                    self.mem.write(self.vars.dst_addr, self.vars.res.unwrap()); // dst = res
                }
                next_fp = Some(self.curr.fp); // no modification on fp
            } else {
                unimplemented!();
            }
        } else {
            unimplemented!(); // invalid instruction
        }
        (next_ap, next_fp)
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
}
