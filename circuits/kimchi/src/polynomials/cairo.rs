/* This implements the verification of a Cairo execution trace

 Cairo programs can have the following assembly-like instructions:
 - Memory access: [x]
 - Assert equal: <left_hand_op> = <right_hand_op>
 · val
 · [reg1 + off_op1]
 · [reg0 + off_op0] +|* [reg1 + off_op1]
 · [reg0 + off_op0] +|* val
 · [[reg0 + off_op0] + off_op1]
 - Jumps
 · jmp abs <address>     // unconditional absolute jump
 · jmp rel <offset>      // unconditional relative jump
 · jmp rel <offset> if <op> != 0    // conditional jump
 - Functions
 · call abs <address>    // calls a function (absolute location)
 · call rel <offset>     // calls a function (relative location)
 · ret                   // returns to execution after the call
 - Increments
 · ap += <op>
 · ap++

 A Cairo program runs accross a number of state transitions.
 Each state transition has the following structure:

 * Has access to a read-only memory
 * Input: 3 types of registers
  - pc (= program counter):  address of current instruction
  - ap (= allocation pointer): first free memory address
  - fp (= frame pointer): beginning of stack (for function arguments)
 * Output:
  - next_pc: address of next instruction
  - next_ap: address of next free memory slot
  - next_fp: pointer to stack (can remain the same as fp)

Cairo words are field elements of characteristic > 2^64
Cairo instructions are stored as words (63 or 64 bits - actual instruction or immediate value)
Instructions with immediate values are stored in 2 words
- The first word stores instruction
- The second word stores the value
Words of instructions consist of
* 3 signed offsets of 16 bits each, in the range [-2^15,2^15) biased representation
 - off_dst (= offset from destination address): used to compute address of assignment
 - off_op0 (= offset from first operand): used to compute address of first operand in instruction
 - off_op1 (= offset from second operand): used to compute address of second operand in instruction
* 15 bits of flags divided into 7 groups
  When multiple bits, at most one can be 1 and the rest must be 0
 - dst_reg [0] = fDST_REG : indicates what pointer off_dst refers to ( 0 => ap , 1 => fp )
 - op0_reg [1] = fOP0_REG : indicates what pointer off_op0 refers to ( 0 => ap , 1 => fp )
 - op1_src [2-4] : encodes the type of second operand
  · 0: indicates off_op1 is b in the double indexing [[ point + a ] + b ]
  · 1: indicates off_op1 is an immediate value = fOP1_VAL = 1
  · 2: indicates offset off_op1 relative to fp = fOP1_FP = 1
  · 4: indicates offset off_op1 relative to ap = fOP1_AP = 1
 - res_logic [5-6]: defines (if any) arithmetic operation in right part
  · 0: right part is single operand
  · 1: right part is addition = fRES_ADD = 1
  · 2: right part is multiplication = fRES_MUL = 1
 - pc_update [7-9]: defines the type of update for the pc
  · 0 = regular increase by size of current instruction
  · 1 = absolute jump to res address = fPC_ABS_JMP = 1
  · 2 = relative jump of step res = fPC_REL_JMP = 1
  · 4 = conditional jump (jnz) with step in op1 = fPC_JNZ = 1
 - ap_update [10-11]: defines the type of update for the ap
  · 0: means the new ap is the same, same free position
  · 1: means there is an ap+=<op> instruction = fAP_INC = 1
  · 2: means there is an ap++ instruction = fAP_ADD1 = 1
 - opcode [12-14]: encodes type of assembly instruction
  · 0: jumps or increments instruction
  · 1: call instruction = fOPC_CALL = 1
  · 2: return instruction = fOPC_RET = 1
  · 4: assert equal instruction (assignment to value or check equality) = fOPC_ASSEQ = 1
* in little-endian form = leftmost least significant bit

The transition function uses 4 auxiliary values:
- dst: left part of instruction, destination
- op0: content of first operand of right part
- op1: content of second operand of right part
- res: result of the operation in the right part

 The Kimchi 15 columns are:
 row: 0   |  1 |  2 | 3       | 4       | 5       | 6       | 7       | 8       | 9   | 10  | 11  | 12  |  13  | 14
 --------------------------------------------------------------------------------------------------------------------
       pc | ap | fp | off_dst | off_op0 | off_op1 | sft_dst | sft_op0 | sft_op1 | dst | op0 | op1 | res | size | f15
 --------------------------------------------------------------------------------------------------------------------
 row+1: 0   | 1         |  2      | 3       | 4       | 5        | 6        | 7       | 8       | 9       | 10      | 11       | 12       |  13     | 14
 -------------------------------------------------------------------------------------------------------------------------------------------------------------
   fDST_REG | fOP0_REG | fOP1_VAL | fOP1_FP | fOP1_AP | fRES_ADD | fRES_MUL | fPC_ABS | fPC_REL | fPC_JNZ | fAP_INC | fAP_ADD1 | fOP_CALL | fOP_RET | fOP_AEQ
 ------------------------------------------------------------------------------------------------------------------------------
  row+2: again like in current row but for the next instruction
 next_pc next_ap next_fp
 ------------------------------------------------------------------------------------------------------------------------------
 */

use crate::expr::{Cache, Column, ConstantExpr, Expr, E};
use crate::gate::{CircuitGate, CurrOrNext, GateType};
use crate::wires::COLUMNS;
use ark_ff::{FftField, Field, One};
use CurrOrNext::*;

pub fn constraint<F: Field>(memory: Vec<F>) -> (Expr<F>) {
    let v_curr = |c| E::cell(c, Curr);
    let w_curr = |i| v_curr(Column::Witness(i));
    let v_next = |c| E::cell(c, Next);
    let w_next = |i| v_next(Column::Witness(i));
    // need to load next+1 as well for next_pc, next_ap, next_fp

    // load all variables of the witness
    let pc = w_curr(0);
    let ap = w_curr(1);
    let fp = w_curr(2);
    let off_dst = w_curr(3);
    let off_op0 = w_curr(4);
    let off_op1 = w_curr(5);
    let sft_dst = w_curr(6);
    let sft_op0 = w_curr(7);
    let sft_op1 = w_curr(8);
    let dst = w_curr(9);
    let op0 = w_curr(10);
    let op1 = w_curr(11);
    let res = w_curr(12);
    let size = w_curr(13);
    let f15 = w_curr(14);

    let fDST_REG = w_next(0);
    let fOP0_REG = w_next(1);
    let fOP1_VAL = w_next(2);
    let fOP1_FP = w_next(3);
    let fOP1_AP = w_next(4);
    let fRES_ADD = w_next(5);
    let fRES_MUL = w_next(6);
    let fPC_ABS = w_next(7);
    let fPC_REL = w_next(8);
    let fPC_JNZ = w_next(9);
    let fAP_INC = w_next(10);
    let fAP_ADD1 = w_next(11);
    let fOP_CALL = w_next(12);
    let fOP_RET = w_next(13);
    let fOP_AEQ = w_next(14);

    // let next_pc
    // let next_ap
    // let next_fp

    // LIST OF CONSTRAINTS
    // -------------------
    let mut constraints: Vec<Expr<ConstantExpr<F>>>;

    // INSTRUCTIONS RELATED

    // * Check last flag is always zero
    // f15 == 0
    constraints.push(f15);

    // * Check booleanity of all flags
    // fi * (1-fi) == 0 for i=[0..15)
    for i in 0..15 {
        constraints.push(flags[i] * (1 - flags[i]));
    }

    // * Shape of instruction (does not fit in 15 wires)
    let shape: u64 = {
        let sft_dst: u16 = (off_dst + 2u32.pow(15)) as u16;
        let sft_op0: u16 = (off_op0 + 2u32.pow(15)) as u16;
        let sft_op1: u16 = (off_op1 + 2u32.pow(15)) as u16;
        let aux = sft_op1 * 2u64.pow(32) + sft_op0 * 2u64.pow(16) + sft_dst;
        for i in 0..16 {
            aux += flags[i] * 2u64.pow(32 + i);
        }
        aux
    };
    constraints.push(instr - shape);

    // OPERANDS RELATED

    // * Destination address
    // if dst_reg = 0 : dst_dir = ap + off_dst
    // if dst_reg = 1 : dst_dir = fp + off_dst
    constraints.push(fDST_REG * fp + (1 - fDST_REG) * ap + off_dst - dst_dir);

    // * First operand address
    // if op0_reg = 0 : op0_dir = ap + off_dst
    // if op0_reg = 1 : op0_dir = fp + off_dst
    constraints.push(fOP0_REG * fp + (1 - fOP0_REG) * ap + off_op0 - op0_dir);

    // * Second operand address
    constraints.push(
        op1_dir                                        //         op1_dir = ..
            - (fOP1_AP * ap                            // if op1_src == 4 : ap
            + fOP1_FP * fp                             // if op1_src == 2 : fp 
            + fOP1_VAL * pc                            // if op1_src == 1 : pc
            + (1 - fOP1_FP - fOP1_AP - fOP1_VAL) * op0 // if op1_src == 0 : op0 
            + off_op1), //                                                      + off_op1
    );

    // OPERATIONS-RELATED

    // * Check value of result
    constraints.push(
        (1 - fPC_JNZ) * res                     // if pc_up != 4 : res = ..        // no res in conditional jumps
            + (fRES_MUL * op0 * op1             //      if res_log = 2 : op0 * op1
            + fRES_ADD * (op0 + op1)            //      if res_log = 1 : op0 + op1
            + (1 - fRES_ADD - fRES_MUL) * op1), //      if res_log = 0 : op1
    );

    // * Check storage of current fp for a call instruction
    // <=> assert_eq!(dst, fp);
    constraints.push(fOPC_CALL * (dst - fp)); // if opcode = 1 : dst = fp

    // * Check storage of next instruction after a call instruction
    // <=> assert_eq!(op0, pc + size); // checks [ap+1] contains instruction after call
    constraints.push(fOPC_CALL * (op0 - (pc + size))); // if opcode = 1 : op0 = pc + size

    // * Check destination = result after assert-equal
    // <=> assert_eq!(res, dst);
    constraints.push(fOPC_ASSEQ * (dst - res)); // if opcode = 4 : dst = res

    // REGISTERS-RELATED

    // * Check next allocation pointer
    constraints.push(
        next_ap                     //  next_ap = 
            - (ap                   //             ap + 
        + fAP_INC * res             //  if ap_up == 1 : res             res
        + fAP_ADD1                  //  if ap_up == 2 : 1
        + fOPC_CALL * 2), //           if opcode == 1 : 2
    ); //

    // * Check next frame pointer
    constraints.push(
        next_fp                                  //             next_fp = 
            - (fOPC_CALL * (ap + 2)              // if opcode == 1      : ap + 2
            + fOPC_RET * dst                     // if opcode == 2      : dst
            + (1 - fOPC_CALL - fOPC_RET) * fp ), // if opcode == 4 or 0 : fp
    );

    // * Check next program counter (pc update)
    // need to fix it
    constraints.push(
        fPC_JNZ * dst * res * (next_pc - (pc + op1))          // <=> pc_up = 4 and dst != 0 : next_pc = pc + op1  // condition holds
        + fPC_JNZ * (1 - dst) * (next_pc - (pc+size))         // <=> pc_up = 4 and dst == 0 : next_pc = pc + size // condition false
            + (1 - fPC_JNZ) * next_pc                         // <=> pc_up = {0,1,2} : next_pc = ... // not a conditional jump
            - (1 - fPC_ABS - fPC_RES - fPC_JNZ) * (pc + size) // <=> pc_up = 0 : next_pc = pc + size // common case
            - fPC_ABS * res                                   // <=> pc_up = 1 : next_pc = res       // absolute jump
            - fPC_REL * (pc + res), //                           <=> pc_up = 2 : next_pc = pc + res  // relative jump
    );

    // * Check initial and final ap, fp, pc
    constraints.push(ap0 - ini_ap); // ap0 = ini_ap
    constraints.push(fp0 - ini_ap); // fp0 = ini_ap
    constraints.push(apT - fin_ap); // apT = fin_ap
    constraints.push(pc0 - ini_pc); // pc0 = ini_pc
    constraints.push(pcT - fin_pc); // pcT = fin_pc

    // MEMORY-RELATED

    // * Memory checks: continuity and single value

    // * Memory permutation check

    // * PLONK's copy constraints??
}

fn biased_rep(offset: u16) -> i16 {
    let mut num: i32 = -2i32.pow(15u32);
    for i in 0..16 {
        // num = -2^15 + sum_(i=0..15) b_i * 2^i
        num += 2i32.pow(i) * ((offset as i32 >> i) % 2);
    }
    num as i16
}

fn deserialize<F: Field>(instruction: u64) -> (i16, i16, i16, Vec<u64>) {
    let nflags = 16;
    let mut flags = Vec::with_capacity(nflags);
    let (off_dst, off_op0, off_op1): (i16, i16, i16);
    // The least significant 16 bits
    off_dst = biased_rep((instruction % 2u64.pow(16u32)) as u16);
    // From the 32nd bit to the 17th
    off_op0 = biased_rep(((instruction % (2u64.pow(32u32))) >> 16) as u16);
    // From the 48th bit to the 33rd
    off_op1 = biased_rep(((instruction % (2u64.pow(48u32))) >> 32) as u16);
    // The most significant 16 bits
    for i in 0..nflags {
        flags.push((instruction >> (48 + i)) % 2);
    }
    (off_dst, off_op0, off_op1, flags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mina_curves::pasta::fp::Fp;
    use mina_curves::pasta::pallas as Pallas;
    // Affine curve point
    // use Pallas::Affine as CurvePoint;
    // Base field element
    // pub type BaseField = <CurvePoint as AffineCurve>::BaseField;

    #[test]
    fn testingcairo() {
        let instruction: u64 = 0x480680017fff8000; // tempvar x = 10 // next word must have a 10 on it
        let memory: [i64; 1000]; // memory of 1k entries

        // Load offsets and flags
        let (off_dst, off_op0, off_op1, flags) = deserialize::<Fp>(instruction);
        println!("off_dst {}", off_dst);
        println!("off_op0 {}", off_op0);
        println!("off_op1 {}", off_op1);
        assert_eq!(off_dst, 0);
        assert_eq!(off_op0, -1);
        assert_eq!(off_op1, 1);

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

        assert_eq!(fDST_REG, 0);
        assert_eq!(fOP0_REG, 1);
        assert_eq!(fOP1_VAL, 1);
        assert_eq!(fOP1_FP, 0);
        assert_eq!(fOP1_AP, 0);
        assert_eq!(fRES_ADD, 0);
        assert_eq!(fRES_MUL, 0);
        assert_eq!(fPC_ABS, 0);
        assert_eq!(fPC_REL, 0);
        assert_eq!(fPC_JNZ, 0);
        assert_eq!(fAP_INC, 0);
        assert_eq!(fAP_ADD1, 1);
        assert_eq!(fOP_CALL, 0);
        assert_eq!(fOP_RET, 0);
        assert_eq!(fOP_AEQ, 1);
        assert_eq!(f15, 0);

        let dst_reg = fDST_REG;
        let op0_reg = fOP0_REG;
        let op1_src = 4 * fOP1_AP + 2 * fOP1_FP + fOP1_VAL;
        let res_log = 2 * fRES_MUL + fRES_ADD;
        let pc_up = 4 * fPC_JNZ + 2 * fPC_REL + fPC_ABS;
        let ap_up = 2 * fAP_ADD1 + fAP_INC;
        let opcode = 4 * fOP_AEQ + 2 * fOP_RET + fOP_CALL;

        assert_eq!(dst_reg, 0);
        assert_eq!(op0_reg, 1);
        assert_eq!(op1_src, 1);
        assert_eq!(res_log, 0);
        assert_eq!(pc_up, 0);
        assert_eq!(ap_up, 2);
        assert_eq!(opcode, 4);

        assert_eq!(
            0x4806,
            dst_reg
                + 2 * op0_reg
                + 2u16.pow(2) * op1_src
                + 2u16.pow(5) * res_log
                + 2u16.pow(7) * pc_up
                + 2u16.pow(10) * ap_up
                + 2u16.pow(12) * opcode
        );

        // Finished testing shape of instruction

        // contents
        let (dst, op0, op1, res): (i64, i64, i64, i64);
        let (dst_dir, op0_dir, op1_dir): (i64, i64, i64);
        let size;
        let (pc, ap, fp) = (1, 9, 9);

        // COMPUTE AUXILIARY VALUES

        // Compute auxiliary value destination ("left" hand side)
        if dst_reg == 0 {
            dst_dir = (ap + off_dst) as i64; // read from stack
        } else {
            dst_dir = (fp + off_dst) as i64; // read from parameters
        }
        dst = memory[dst_dir as usize];

        // Auxiliary value op0 contains memory value of first operand of instruction
        if op0_reg == 0 {
            // reads first word from memory
            op0_dir = (ap + off_op0) as i64;
        } else {
            // reads first word from parameters
            op0_dir = (fp + off_op0) as i64;
        }
        op0 = memory[op0_dir as usize];

        // Compute auxiliary value op1 and instruction size
        match op1_src {
            0 => {
                // op1_src = 000
                size = 1; // double indexing
                op1_dir = (op0 + off_op1) as i64;
            }
            1 => {
                // op1_src = 001
                size = 2; // immediate value
                op1_dir = pc + off_op1; // if off_op1=1 then op1 contains a plain value
            }
            2 => {
                // op1_src = 010
                size = 1;
                op1_dir = (fp + off_op1) as u16; // second operand offset relative to fp
            }
            4 => {
                // op1_src = 100
                size = 1;
                op1_dir = (ap + off_op1) as u16; // second operand offset relative to ap
            }
            _ => unimplemented!(), // invalid instruction
        }
        op1 = memory[op1_dir as usize];

        // Compute auxiliary value res
        if pc_up == 4 {
            // jnz instruction
            if res_log == 0 && opcode == 0 && ap_up != 1 {
                res = 0; // "unused"
            } else {
                unimplemented!(); // invalid instruction
            }
        } else if pc_up == 0 || pc_up == 1 || pc_up == 2 {
            // rest of types of updates
            // common increase || absolute jump || relative jump
            match res_log {
                0 => res = op1,        // right part is single operand
                1 => res = op0 + op1,  // right part is addition
                2 => res = op0 * op1,  // right part is multiplication
                _ => unimplemented!(), // invalid instruction
            }
        } else {
            // multiple bits take value 1
            unimplemented!(); // invalid instruction
        }

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

        // convert to Fp all of it

        constraint();
    }
}
/*

impl<F: FftField> CircuitGate<F> {
    /// Check the correctness of witness values for a complete-add gate.
    pub fn verify_complete_add(
        &self,
        row: usize,
        witness: &[Vec<F>; COLUMNS],
    ) -> Result<(), String> {
        let x1 = witness[0][row];
        let y1 = witness[1][row];
        let x2 = witness[2][row];
        let y2 = witness[3][row];
        let x3 = witness[4][row];
        let y3 = witness[5][row];
        let inf = witness[6][row];
        let same_x = witness[7][row];
        let s = witness[8][row];
        let inf_z = witness[9][row];
        let x21_inv = witness[10][row];

        if x1 == x2 {
            ensure_eq!(same_x, F::one(), "Expected same_x = true");
        } else {
            ensure_eq!(same_x, F::zero(), "Expected same_x = false");
        }

        if same_x == F::one() {
            let x1_squared = x1.square();
            ensure_eq!(
                (s + s) * y1,
                (x1_squared.double() + x1_squared),
                "double s wrong"
            );
        } else {
            ensure_eq!((x2 - x1) * s, y2 - y1, "add s wrong");
        }

        ensure_eq!(s.square(), x1 + x2 + x3, "x3 wrong");
        let expected_y3 = s * (x1 - x3) - y1;
        ensure_eq!(
            y3,
            expected_y3,
            format!("y3 wrong {}: (expected {}, got {})", row, expected_y3, y3)
        );

        let not_same_y = F::from((y1 != y2) as u64);
        ensure_eq!(inf, same_x * not_same_y, "inf wrong");

        if y1 == y2 {
            ensure_eq!(inf_z, F::zero(), "wrong inf z (y1 == y2)");
        } else {
            let a = if same_x == F::one() {
                (y2 - y1).inverse().unwrap()
            } else {
                F::zero()
            };
            ensure_eq!(inf_z, a, "wrong inf z (y1 != y2)");
        }

        if x1 == x2 {
            ensure_eq!(x21_inv, F::zero(), "wrong x21_inv (x1 == x2)");
        } else {
            ensure_eq!(
                x21_inv,
                (x2 - x1).inverse().unwrap(),
                "wrong x21_inv (x1 != x2)"
            );
        }

        Ok(())
    }
}
*/
