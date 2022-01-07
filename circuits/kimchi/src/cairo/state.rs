use cairo::instruction;
use cairo::memory;

use ark_ff::{BigInteger, FftField, Field, PrimeField};

/// A Cairo state
struct CairoState {
    pc: u64,
    ap: u64,
    fp: u64,
    dst: Option<u64>,
    op0: Option<u64>,
    op1: Option<u64>,
    res: Option<u64>,
    dst_dir: Option<u64>,
    op0_dir: Option<u64>,
    op1_dir: Option<u64>,
    size: Option<u64>,
}

impl CairoState {
    pub fn new_state(pc: u64, ap: u64, fp: u64) -> CairoState {
        CairoState { pc, ap, fp }
    }

    // This function computes the destination address
    pub fn set_dst(&self, instr: &CairoInstruction<F>, mem: &CairoMemory) {
        if instr.dst_reg() == 0 {
            self.dst_dir = self.ap + instr.off_dst; // read from stack
        } else {
            self.dst_dir = self.fp + instr.off_dst; // read from parameters
        }
        self.dst = mem.read_memory(self.dst_dir);
    }

    // This function computes the first operand address
    pub fn set_op0(&self, instr: &CairoInstruction<F>, mem: &CairoMemory) {
        if instr.op0_reg() == 0 {
            // reads first word from memory
            self.op0_dir = self.ap + instr.off_op0;
        } else {
            // reads first word from parameters
            self.op0_dir = self.fp + instr.off_op0;
        }
        self.op0 = mem.read_memory(self.op0_dir);
    }

    pub fn set_op1(&self, instr: &CairoInstruction<F>, mem: &CairoMemory) {
        if instr.op1_src() == 0 {
            // op1_src = 000
            self.size = 1; // double indexing
            self.op1_dir = self.op0 + instr.off_op1;
            self.op1 = mem.read_memory(self.op1_dir);
        } else if instr.op1_src() == 1 {
            // op1_src = 001
            self.size = 2; // immediate value
            self.op1_dir = self.pc + instr.off_op1; // if off_op1=1 then op1 contains a plain value
            self.op1 = mem.read_memory(self.op1_dir);
        } else if instr.op1_src() == 2 {
            // op1_src = 010
            self.size = 1;
            self.op1_dir = self.fp + instr.off_op1; // second operand offset relative to fp
            self.op1 = mem.read_memory(self.op1_dir);
        } else if instr.op1_src() == 4 {
            // op1_src = 100
            self.size = 1;
            self.op1_dir = self.ap + instr.off_op1; // second operand offset relative to ap
            self.op1 = mem.read_memory(self.op1_dir);
        } else {
            unimplemented!(); // invalid instruction
        }
    }

    // This function computes the value of the result of the arithmetic operation
    pub fn set_res(&self, instr: &CairoInstruction<F>, mem: &Memory) {
        if instr.pc_up() == 4 {
            // jnz instruction
            if instr.res_log() == 0 && instr.opcode() == 0 && instr.ap_up() != 1 {
                self.res = 0; // "unused"
            } else {
                unimplemented!(); // invalid instruction
            }
        } else if instr.pc_up() == 0 || instr.pc_up() == 1 || instr.pc_up() == 2 {
            // rest of types of updates
            // common increase || absolute jump || relative jump
            if instr.res_log() == 0 {
                self.res = self.op1; // right part is single operand
            } else if instr.res_log() == 1 {
                self.res = self.op0 + self.op1; // right part is addition
            } else if instr.res_log() == 2 {
                self.res = self.op0 * self.op1; // right part is multiplication
            } else {
                unimplemented!();
            } // invalid instruction
        } else {
            // multiple bits take value 1
            unimplemented!(); // invalid instruction
        }
    }
}
