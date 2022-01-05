use crate::instruction;
use crate::memory;

use ark_ff::{BigInteger, FftField, Field, PrimeField};

/// A Cairo compiled program
pub struct CairoProgram<F: FftField> {
    /// vector of Cairo instructions
    pub program: Vec<CairoInstruction<F>>,
}

impl<F: FftField> CairoProgram {
    pub fn new_program(instrs: Vec<CairoInstruction<F>>) -> CairoProgram {
        CairoProgram { program: instrs }
    }

    /// This function simulates an execution of the Cairo program received as input.
    /// It generates the full memory stack
    pub fn execute_program(&self) -> CairoMemory<F> {
        let mem: CairoMemory<F> = new_memory(&self);
    }

    // This function computes the destination address
    fn get_dst_dir(dst_reg: Fp, off_dst: Fp, ap: Fp, fp: Fp) -> Fp {
        let dst_dir = {
            if dst_reg == Fp::from(0) {
                ap + off_dst // read from stack
            } else {
                fp + off_dst // read from parameters
            }
        };
        return dst_dir;
    }

    // This function computes the first operand address
    fn get_op0_dir(op0_reg: Fp, off_op0: Fp, ap: Fp, fp: Fp) -> Fp {
        let op0_dir = {
            if op0_reg == Fp::from(0) {
                // reads first word from memory
                ap + off_op0
            } else {
                // reads first word from parameters
                fp + off_op0
            }
        };
        return op0_dir;
    }

    fn get_op1_dir(op1_src: Fp, off_op1: Fp, op0: Fp, pc: Fp, ap: Fp, fp: Fp) -> (Fp, Fp) {
        let (op1_dir, size);
        if op1_src == Fp::from(0) {
            // op1_src = 000
            size = 1.into(); // double indexing
            op1_dir = op0 + off_op1;
        } else if op1_src == Fp::from(1) {
            // op1_src = 001
            size = 2.into(); // immediate value
            op1_dir = pc + off_op1; // if off_op1=1 then op1 contains a plain value
        } else if op1_src == Fp::from(2) {
            // op1_src = 010
            size = 1.into();
            op1_dir = fp + off_op1; // second operand offset relative to fp
        } else if op1_src == Fp::from(4) {
            // op1_src = 100
            size = 1.into();
            op1_dir = ap + off_op1; // second operand offset relative to ap
        } else {
            unimplemented!(); // invalid instruction
        }
        return (op1_dir, size);
    }

    // This function computes the value of the result of the arithmetic operation
    fn get_res(res_log: Fp, pc_up: Fp, ap_up: Fp, opcode: Fp, op1: Fp, op0: Fp) -> Fp {
        let res;
        if pc_up == 4.into() {
            // jnz instruction
            if res_log == 0.into() && opcode == 0.into() && ap_up != 1.into() {
                res = 0.into(); // "unused"
            } else {
                unimplemented!(); // invalid instruction
            }
        } else if pc_up == 0.into() || pc_up == 1.into() || pc_up == 2.into() {
            // rest of types of updates
            // common increase || absolute jump || relative jump
            if res_log == 0.into() {
                res = op1; // right part is single operand
            } else if res_log == 1.into() {
                res = op0 + op1; // right part is addition
            } else if res_log == 2.into() {
                res = op0 * op1; // right part is multiplication
            } else {
                unimplemented!();
            } // invalid instruction
        } else {
            // multiple bits take value 1
            unimplemented!(); // invalid instruction
        }
        return res;
    }
    // This function computes the next program counter
    fn get_next_pc(pc_up: Fp, res: Fp, dst: Fp, op1: Fp, pc: Fp, size: Fp) -> Fp {
        let next_pc = {
            if pc_up == Fp::from(0) {
                // next instruction is right after the current one
                pc + size // the common case
            } else if pc_up == Fp::from(1) {
                // next instruction is in res
                res // absolute jump
            } else if pc_up == Fp::from(2) {
                // relative jump
                pc + res // go to some address relative to pc
            } else if pc_up == Fp::from(4) {
                // conditional relative jump (jnz)
                if dst == Fp::from(0) {
                    pc + size // if condition false, common case
                } else {
                    // if condition true, relative jump with second operand
                    pc + op1
                }
            } else {
                unimplemented!(); // invalid instruction
            }
        };
        return next_pc;
    }
    // This function computes the next values of the allocation and frame pointers
    fn get_next_apfp(
        ap_up: Fp,
        opcode: Fp,
        dst: Fp,
        op0: Fp,
        res: Fp,
        pc: Fp,
        ap: Fp,
        fp: Fp,
        size: Fp,
    ) -> (Fp, Fp) {
        let (next_ap, next_fp);
        // The following branches don't include the assertions. That is done in the verification.
        if opcode == Fp::from(1) {
            // "call" instruction
            // Update fp
            next_fp = ap + Fp::from(2); // pointer for next frame is after current fp and instruction after call
                                        // Update ap
            if ap_up == Fp::from(0) {
                next_ap = ap + Fp::from(2); // two words were written so advance 2 positions
            } else {
                unimplemented!(); // ap increments not allowed in call instructions
            }
        } else if opcode == Fp::from(0) || opcode == Fp::from(2) || opcode == Fp::from(4) {
            // rest of types of instruction
            // jumps and increments || return || assert equal
            if ap_up == Fp::from(0) {
                next_ap = ap // no modification on ap
            } else if ap_up == Fp::from(1) {
                next_ap = ap + res; // ap += <op>
            } else if ap_up == Fp::from(2) {
                next_ap = ap + Fp::from(1); // ap++
            } else {
                unimplemented!(); // invalid instruction}
            }
            if opcode == Fp::from(0) || opcode == Fp::from(4) {
                next_fp = fp; // no modification on fp
            } else if opcode == Fp::from(2) {
                next_fp = dst; // ret sets fp to previous fp that was in [ap-2]
            } else {
                unimplemented!();
            }
        } else {
            unimplemented!(); // invalid instruction
        }
        return (next_ap, next_fp);
    }

    // This function returns dst_dir, op0_dir, op1_dir and size from current instruction and registers
    fn get_wires(
        instr: u64,
        pc: Fp,
        ap: Fp,
        fp: Fp,
    ) -> (Fp, Fp, Fp, Fp, Fp, Fp, Fp, Fp, Fp, Fp, Fp) {
        let ins_vec = deserialize_vec::<Fp>(instr);
        let (dst_reg, op0_reg, op1_src, res_log, pc_up, ap_up, opcode) = sets_of_flags(ins_vec);
        let (off_op1, off_op0, off_dst) = sets_of_offsets(ins_vec);

        // Compute auxiliary value destination ("left" hand side)
        let dst_dir = get_dst_dir(dst_reg, off_dst, ap, fp);
        let dst = memory(dst_dir);

        // Auxiliary value op0 contains memory value of first operand of instruction
        let op0_dir = get_op0_dir(op0_reg, off_op0, ap, fp);
        let op0 = memory(op0_dir);

        // Compute auxiliary value op1 and instruction size
        let (op1_dir, size) = get_op1_dir(op1_src, off_op1, op0, pc, ap, fp);
        let op1 = memory(op1_dir);

        // Compute auxiliary value res
        let res = get_res(res_log, pc_up, ap_up, opcode, op1, op0);

        // Compute new value of pc
        let next_pc = get_next_pc(pc_up, res, dst, op1, pc, size);

        // Compute new value of ap and fp based on the opcode
        let (next_ap, next_fp) = get_next_apfp(ap_up, opcode, dst, op0, res, pc, ap, fp, size);

        return (
            next_pc, next_ap, next_fp, dst, op0, op1, res, dst_dir, op0_dir, op1_dir, size,
        );
    }
}
