/*****************************************************************************************************************

This source file implements Cairo instruction gate primitive.

*****************************************************************************************************************/

use crate::gate::{CircuitGate, GateType};
use crate::wires::{GateWires, COLUMNS};
use ark_ff::FftField;
use array_init::array_init;

pub const NUM_FLAGS: usize = 16;
pub const OP1_COEFF: usize = NUM_FLAGS;
pub const OP0_COEFF: usize = OP1_COEFF + 1;
pub const DST_COEFF: usize = OP0_COEFF + 1;

fn biased_rep(offset: u16) -> i16 {
    let mut num: i32 = -2i32.pow(15u32);
    for i in 0..16 {
        // num = -2^15 + sum_(i=0..15) b_i * 2^i
        num += 2i32.pow(i) * ((offset as i32 >> i) % 2);
    }
    num as i16
}

/// Converts a 64bit word Cairo bytecode instruction into an array of 19 field elements
fn deserialize<F: FftField>(instruction: u64) -> [F; NUM_FLAGS + 3] {
    let mut flags = Vec::with_capacity(NUM_FLAGS);
    let (off_dst, off_op0, off_op1): (i16, i16, i16);
    let array = [F; NUM_FLAGS + 3];
    /// The least significant 16 bits
    off_dst = biased_rep((instruction % 2u64.pow(16u32)) as u16);
    /// From the 32nd bit to the 17th
    off_op0 = biased_rep(((instruction % (2u64.pow(32u32))) >> 16) as u16);
    /// From the 48th bit to the 33rd
    off_op1 = biased_rep(((instruction % (2u64.pow(48u32))) >> 32) as u16);
    /// The most significant 16 bits
    for i in 0..NFLAGS {
        flags.push((instruction >> (48 + i)) % 2);
        array.push(flags[i]);
    }
    array.push(F::from(off_op1));
    array.push(F::from(off_op0));
    array.push(F::from(off_dst));
    /// Returns [f0..f15,off_op1,off_op0,off_dst]
    array
}

impl<F: FftField> CircuitGate<F> {
    pub fn create_cairo(wires: GateWires, instr: u64) -> Self {
        CircuitGate {
            typ: GateType::Cairo,
            wires,
            c: deserialize(instr).to_vec(),
        }
    }

    /// verifies that the Cairo gate constraints are solved by the witness
    pub fn verify_gate_cairo(&self, row: usize, witness: &[Vec<F>; COLUMNS]) -> Result<(), String> {
        // witness layout:
        // 0       1       2        3   4   5   6   7 8 9 10 11 12 13 14 15
        // pc      ap      fp      dst op0 op1 res
        // next_pc next_ap next_fp
        // assignments
        let this: [F; COLUMNS] = array_init(|i| witness[i][row]);
        let next: [F; COLUMNS] = array_init(|i| witness[i][row + 1]);
        let pc = this[0];
        let ap = this[1];
        let fp = this[2];
        let dst = this[3];
        let op0 = this[4];
        let op1 = this[5];
        let res = this[6];
        let next_pc = next[0];
        let next_ap = next[1];
        let next_fp = next[2];

        // zero field element for assertions
        let zero = F::zero();

        // flags and offsets in the gate instruction
        let off_dst = self.c[DST_COEFF];
        let off_op0 = self.c[OP0_COEFF];
        let off_op1 = self.c[OP1_COEFF];
        let flags = self.c[0..FLAGS];
        let fDST_REG = u16::from(flags[0]);
        let fOP0_REG = flags[1];
        let fOP1_VAL = flags[2];
        let fOP1_FP = flags[3];
        let fOP1_AP = flags[4];
        let fRES_ADD = flags[5];
        let fRES_MUL = flags[6];
        let fPC_ABS = flags[7];
        let fPC_REL = flags[8];
        let fPC_JNZ = flags[9];
        let fAP_INC = flags[10];
        let fAP_ADD1 = flags[11];
        let fOP_CALL = flags[12];
        let fOP_RET = flags[13];
        let fOP_AEQ = flags[14];
        let f15 = flags[15];

        // compute the seven sets of Cairo flags
        let dst_reg = fDST_REG;
        let op0_reg = fOP0_REG;
        let op1_src = 4 * fOP1_AP + 2 * fOP1_FP + fOP1_VAL;
        let res_log = 2 * fRES_MUL + fRES_ADD;
        let pc_up = 4 * fPC_JNZ + 2 * fPC_REL + fPC_ABS;
        let ap_up = 2 * fAP_ADD1 + fAP_INC;
        let opcode = 4 * fOP_AEQ + 2 * fOP_RET + fOP_CALL;

        // contents
        let (dst, op0, op1, res): (F, F, F, F);
        let (dst_dir, op0_dir, op1_dir): (F, F, F);
        let size;

        // check if it's the correct gate
        ensure_eq!(self.typ, GateType::Cairo, "generic: incorrect gate");

        // check last flag is a zero
        ensure_eq!(zero, f15);

        // COMPUTE AUXILIARY VALUES

        // Compute new value of pc
        match pc_up {
            0 => {
                // next instruction is right after the current one
                next_pc = pc + size // the common case
            }
            1 => {
                // next instruction is in res
                next_pc = res // absolute jump
            }
            2 => {
                // relative jump
                next_pc = pc + res // go to some address relative to pc
            }
            4 => {
                // conditional relative jump (jnz)
                if dst == 0 {
                    next_pc = pc + size; // if condition false, common case
                } else {
                    // if condition true, relative jump with second operand
                    next_pc = pc + op1;
                }
            }
            _ => unimplemented!(), // invalid instruction
        }

        // Compute new value of ap and fp based on the opcode
        if opcode == 1 {
            // "call" instruction
            assert_eq!(dst, fp); // checks [ap] contains fp
            assert_eq!(op0, pc + size); // checks [ap+1] contains instruction after call

            // Update fp
            next_fp = ap + 2; // pointer for next frame is after current fp and instruction after call

            // Update ap
            match ap_up {
                0 => next_ap = ap + 2, // two words were written so advance 2 positions
                _ => unimplemented!(), // ap increments not allowed in call instructions
            }
        } else if opcode == 0 || opcode == 2 || opcode == 4 {
            // rest of types of instruction
            // jumps and increments || return || assert equal
            match ap_up {
                0 => next_ap = ap,       // no modification on ap
                1 => next_ap = ap + res, // ap += <op>
                2 => next_ap = ap + 1,   // ap++
                _ => unimplemented!(),   // invalid instruction
            }
            match opcode {
                0 => next_fp = fp,  // no modification on fp
                2 => next_fp = dst, // ret sets fp to previous fp that was in [ap-2]
                4 => {
                    assert_eq!(res, dst); // assert equal result and destination
                    next_fp = fp // no modification on fp
                }
            }
        } else {
            unimplemented!(); // invalid instruction
        }

        Ok(())
    }

    /// Checks if a circuit gate corresponds to a Cairo gate
    pub fn cairo(&self) -> F {
        if self.typ == GateType::Cairo {
            F::one()
        } else {
            F::zero()
        }
    }
}
