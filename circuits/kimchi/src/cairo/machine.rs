use cairo::instruction;
use cairo::memory;
use cairo::state;

use ark_ff::{BigInteger, FftField, Field, PrimeField};

/// A Cairo compiled program
pub struct CairoMachine<F: FftField> {
    /// number of steps of computation
    pub steps: usize,
    /// public memory with compiled Cairo program
    pub memory: CairoMemory<F>,
    /// claimed registers
    pub regs: CairoRegisters<F>,
}

/// A set of claimed values for Cairo registers
pub struct CairoRegisters<F: FftField> {
    /// claimed initial program counter
    pub pc_ini: F,
    /// claimed final program counter
    pub pc_fin: F,
    /// claimed initial allocation pointer
    pub ap_ini: F,
    /// claimed final allocation pointer
    pub ap_fin: F,
}

impl<F: FftField> CairoMachine<F> {
    /// Creates a Cairo program from a vectoor of instructions
    pub fn new_program(
        steps: usize,
        instrs: CairoMemory<F>,
        regs: CairoRegisters<F>,
    ) -> CairoMachine {
        CairoMachine {
            steps,
            memory: instrs,
            regs,
        }
    }

    /// Obtain claimed values for program counter
    pub fn get_claimed_pc(&self) -> (F, F) {
        (self.regs.pc_ini, self.regs.pc_fin)
    }

    /// Obtain claimed values for allocation pointer
    pub fn get_claimed_ap(&self) -> (F, F) {
        (self.regs.ap_ini, self.regs.ap_fin)
    }

    /// This function simulates an execution of the Cairo program received as input.
    /// It generates the full memory stack and the execution trace
    pub fn execute_program(&self) -> CairoMemory<F> {
        let fullmem: CairoMemory<F> = &self.memory.copy();
        let state: CairoState = state::new_state(
            self.get_claimed_pc[0],
            self.get_claimed_ap[0],
            self.get_claimed_ap[0],
        );
        let ret = false;
        let mut i = 0;
        while !ret {
            instr = self[i];
            state.set_dst(&instr, &mem);
            state.set_op0(&instr, &mem);
            state.set_op1(&instr, &mem);
            state.set_res(&instr, &mem);
            let state: CairoState = state::new_state(pc, ap, fp);
        }
    }

    // This function computes the next program counter
    fn get_next_pc(
        state: &CairoState,
        instr: &CairoInstruction<F>,
        mem: &CairoMemory,
    ) -> Option<u64> {
        if instr.pc_up() == 0 {
            // next instruction is right after the current one
            pc + state.size // the common case
        } else if instr.pc_up() == 1 {
            // next instruction is in res
            state.res // absolute jump
        } else if instr.pc_up() == 2 {
            // relative jump
            pc + state.res // go to some address relative to pc
        } else if instr.pc_up() == 4 {
            // conditional relative jump (jnz)
            if state.dst == 0 {
                pc + state.size // if condition false, common case
            } else {
                // if condition true, relative jump with second operand
                pc + state.op1
            }
        } else {
            unimplemented!(); // invalid instruction
        }
    }
    // This function computes the next values of the allocation and frame pointers
    fn get_next_apfp(
        state: &CairoState,
        instr: &CairoInstruction<F>,
        mem: &CairoMemory,
    ) -> (u64, u64) {
        let (next_ap, next_fp);
        // The following branches don't include the assertions. That is done in the verification.
        if opcode == 1 {
            // "call" instruction
            // Update fp
            next_fp = ap + 2; // pointer for next frame is after current fp and instruction after call
                              // Update ap
            if ap_up == 0 {
                next_ap = ap + 2; // two words were written so advance 2 positions
            } else {
                unimplemented!(); // ap increments not allowed in call instructions
            }
        } else if opcode == 0 || opcode == 2 || opcode == 4 {
            // rest of types of instruction
            // jumps and increments || return || assert equal
            if ap_up == 0 {
                next_ap = ap // no modification on ap
            } else if ap_up == 1 {
                next_ap = ap + res; // ap += <op>
            } else if ap_up == 2 {
                next_ap = ap + 1; // ap++
            } else {
                unimplemented!(); // invalid instruction}
            }
            if opcode == 0 || opcode == 4 {
                next_fp = fp; // no modification on fp
            } else if opcode == 2 {
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
