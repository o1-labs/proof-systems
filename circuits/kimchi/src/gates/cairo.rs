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
fn deserialize<F: FftField>(instruction: u64) -> (u16, u16, u16, Vec<u64>) {
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
        // 0       1       2        3   4   5   6   7       8       9       10   11 12 13 14 15
        // pc      ap      fp      dst op0 op1 res  dst_dir op0_dir op1_dir size
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
        let dst_dir = this[7]; // shouldnt be wit?
        let op0_dir = this[8]; // shouldnt be wit?
        let op1_dir = this[9]; // shouldnt be wit?
        let size = this[10]; // shouldnt be wit?
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
        let fDST_REG = flags[0];
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

        // compute the seven sets of Cairo flags PARECE QUE NO
        let dst_reg = fDST_REG;
        let op0_reg = fOP0_REG;
        let op1_src = 4 * fOP1_AP + 2 * fOP1_FP + fOP1_VAL;
        let res_log = 2 * fRES_MUL + fRES_ADD;
        let pc_up = 4 * fPC_JNZ + 2 * fPC_REL + fPC_ABS;
        let ap_up = 2 * fAP_ADD1 + fAP_INC;
        let opcode = 4 * fOP_AEQ + 2 * fOP_RET + fOP_CALL;

        // FLAGS RELATED

        // check if it's the correct gate
        ensure_eq!(self.typ, GateType::Cairo, "incorrect cairo gate");

        // check last flag is a zero
        ensure_eq!(zero, f15, "last flag is nonzero");

        // check booleanity of flags
        for i in 0..15 {
            ensure_eq!(zero, flags[i] * (1 - flags[i]), "non-boolean flags");
        }

        // check no two flags of same set are nonzero
        ensure_eq!(
            zero,
            (fOP1_AP + fOP1_FP + fOP1_VAL) * (1 - (fOP1_AP + fOP1_FP + fOP1_VAL)),
            "invalid format of `op1_src`"
        );
        ensure_eq!(
            zero,
            (fRES_MUL + fRES_ADD) * (1 - (fRES_MUL + fRES_ADD)),
            "invalid format of `res_log`"
        );
        ensure_eq!(
            zero,
            (fPC_JNZ + fPC_REL + fPC_ABS) * (1 - (fPC_JNZ + fPC_REL + fPC_ABS)),
            "invalid format of `pc_up`"
        );
        ensure_eq!(
            zero,
            (fAP_ADD1 + fAP_INC) * (1 - (fAP_ADD1 + fAP_INC)),
            "invalid format of `ap_up`"
        );
        ensure_eq!(
            zero,
            (fOP_AEQ + fOP_RET + fOP_CALL) * (1 - (fOP_AEQ + fOP_RET + fOP_CALL)),
            "invalid format of `opcode`"
        );

        // OPERANDS RELATED

        // * Destination address
        // if dst_reg = 0 : dst_dir = ap + off_dst
        // if dst_reg = 1 : dst_dir = fp + off_dst
        ensure_eq!(
            dst_dir,
            fDST_REG * fp + (1 - fDST_REG) * ap + off_dst,
            "invalid destination address"
        );

        // * First operand address
        // if op0_reg = 0 : op0_dir = ap + off_dst
        // if op0_reg = 1 : op0_dir = fp + off_dst
        ensure_eq!(
            op0_dir,
            fOP0_REG * fp + (1 - fOP0_REG) * ap + off_op0,
            "invalid first operand address"
        );

        // * Second operand address
        ensure_eq!(
            op1_dir, //                                      op1_dir = ..
            (fOP1_AP * ap                              // if op1_src == 4 : ap
            + fOP1_FP * fp                             // if op1_src == 2 : fp 
            + fOP1_VAL * pc                            // if op1_src == 1 : pc
            + (1 - fOP1_FP - fOP1_AP - fOP1_VAL) * op0 // if op1_src == 0 : op0 
            + off_op1), //                                                      + off_op1
            "invalid second operand address"
        );

        // OPERATIONS RELATED

        // * Check value of result
        ensure_eq!(
            (1 - fPC_JNZ) * res, //               if  pc_up != 4 : res = ..  // no res in conditional jumps
            fRES_MUL * op0 * op1               // if res_log = 2 : op0 * op1
            + fRES_ADD * (op0 + op1)           // if res_log = 1 : op0 + op1
            + (1 - fRES_ADD - fRES_MUL) * op1, // if res_log = 0 : op1
            "invalid result"
        );

        // * Check storage of current fp for a call instruction
        ensure_eq!(
            zero,
            fOPC_CALL * (dst - fp),
            "current fp after call not stored"
        ); // if opcode = 1 : dst = fp

        // * Check storage of next instruction after a call instruction
        ensure_eq!(
            zero,
            fOPC_CALL * (op0 - (pc + size)),
            "next instruction after call not stored"
        ); // if opcode = 1 : op0 = pc + size

        // * Check destination = result after assert-equal
        ensure_eq!(zero, fOPC_ASSEQ * (dst - res), "false assert equal"); // if opcode = 4 : dst = res

        // REGISTERS RELATED

        // * Check next allocation pointer
        ensure_eq!(
            next_ap, //          next_ap =
            ap               //             ap + 
            + fAP_INC * res  //  if ap_up == 1 : res
            + fAP_ADD1       //  if ap_up == 2 : 1
            + fOPC_CALL * 2, // if opcode == 1 : 2
            "wrong next allocation pointer"
        );

        // * Check next frame pointer
        ensure_eq!(
            next_fp, //                                       next_fp =
            fOPC_CALL * (ap + 2)               // if opcode == 1      : ap + 2
            + fOPC_RET * dst                   // if opcode == 2      : dst
            + (1 - fOPC_CALL - fOPC_RET) * fp, // if opcode == 4 or 0 : fp
            "wrong next frame pointer"
        );

        // * Check next program counter
        ensure_eq!(
            zero,
            fPC_JNZ * (dst * res - 1) * (next_pc - (pc - size)), // <=> pc_up = 4 and dst = 0 : next_pc = pc + size // no jump
            "wrong next program counter"
        );
        ensure_eq!(
            zero,
            fPC_JNZ * dst * (next_pc - (pc + op1))                // <=> pc_up = 4 and dst != 0 : next_pc = pc + op1  // condition holds
            + (1 - fPC_JNZ) * next_pc                             // <=> pc_up = {0,1,2} : next_pc = ... // not a conditional jump
                - (1 - fPC_ABS - fPC_RES - fPC_JNZ) * (pc + size) // <=> pc_up = 0 : next_pc = pc + size // common case
                - fPC_ABS * res                                   // <=> pc_up = 1 : next_pc = res       // absolute jump
                - fPC_REL * (pc + res), //                           <=> pc_up = 2 : next_pc = pc + res  // relative jump
            "wrong next program counter"
        );

        // TODO(querolita): check intial and final claims for registers

        // TODO(querolita): memory related checks

        Ok(())
    }

    /// Checks if a circuit gate corresponds to a Cairo gate
    pub fn is_cairo(&self) -> F {
        if self.typ == GateType::Cairo {
            F::one()
        } else {
            F::zero()
        }
    }
}
