/*****************************************************************************************************************

This source file implements Cairo instruction gate primitive.

*****************************************************************************************************************/

use ark_ec::AffineCurve;
use ark_ff::{BigInteger, FftField, Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use array_init::array_init;
use mina_curves::pasta::pallas as Pallas;

/// Affine curve point type
pub use Pallas::Affine as CurvePoint;
/// Base field element type
pub type BaseField = <CurvePoint as AffineCurve>::BaseField;
/// Scalar field element type
pub type ScalarField = <CurvePoint as AffineCurve>::ScalarField;

/// A Cairo instruction
pub struct CairoInstruction {
    /// 64bit word
    pub word: u64,
}

pub impl<F: FftField> CairoInstruction {
    pub const NUM_FLAGS: usize = 16;

    /// Creates a CairoInstruction from a 64bit word
    pub fn create(word: u64) -> CairoInstruction {
        CairoInstruction { word }
    }

    pub fn off_dst(&self) -> F {
        // The least significant 16 bits
        to_field::<F>(biased_rep((self.word % 2u64.pow(16u32)) as u16))
    }

    pub fn off_op0(&self) -> F {
        // From the 32nd bit to the 17th
        to_field::<F>(biased_rep(((self.word % (2u64.pow(32u32))) >> 16) as u16))
    }

    pub fn off_op1(&self) -> F {
        // From the 48th bit to the 33rd
        to_field::<F>(biased_rep(((self.word % (2u64.pow(48u32))) >> 32) as u16))
    }

    /// Returns vector of 16 flags
    pub fn flags(&self) -> Vec<F> {
        let mut flags = Vec::with_capacity(NUM_FLAGS);
        // The most significant 16 bits
        for i in 0..NUM_FLAGS {
            flags.push(F::from(word.flag_at(i)));
        }
        flags
    }

    /// Returns i-th bit-flag as u64
    fn flag_at(&self, pos: usize) -> u64 {
        (self.word >> (48 + pos)) % 2
    }

    /// Returns bit-flag for destination register as field element
    pub fn fDST_REG(&self) -> F {
        F::from(self.flag_at(0))
    }

    /// Returns bit-flag for first operand register as field element
    pub fn fOP0_REG(&self) -> F {
        F::from(self.flag_at(1))
    }

    /// Returns bit-flag for immediate value for second register as field element
    pub fn fOP1_VAL(&self) -> F {
        F::from(self.flag_at(2))
    }

    /// Returns bit-flag for frame pointer for second register as field element
    pub fn fOP1_FP(&self) -> F {
        F::from(self.flag_at(3))
    }

    /// Returns bit-flag for allocation pointer for second regsiter as field element
    pub fn fOP1_AP(&self) -> F {
        F::from(self.flag_at(4))
    }

    /// Returns bit-flag for addition operation in right side as field element
    pub fn fRES_ADD(&self) -> F {
        F::from(self.flag_at(5))
    }

    /// Returns bit-flag for multiplication operation in right side as field element
    pub fn fRES_MUL(&self) -> F {
        F::from(self.flag_at(6))
    }

    /// Returns bit-flag for program counter update being absolute jump as field element
    pub fn fPC_ABS(&self) -> F {
        F::from(self.flag_at(7))
    }

    /// Returns bit-flag for program counter update being relative jump as field element
    pub fn fPC_REL(&self) -> F {
        F::from(self.flag_at(8))
    }

    /// Returns bit-flag for program counter update being conditional jump as field element
    pub fn fPC_JNZ(&self) -> F {
        F::from(self.flag_at(9))
    }

    /// Returns bit-flag for allocation counter update being a manual addition as field element
    pub fn fAP_ADD(&self) -> F {
        F::from(self.flag_at(10))
    }

    /// Returns bit-flag for allocation counter update being a self increment as field element
    pub fn fAP_ONE(&self) -> F {
        F::from(self.flag_at(11))
    }

    /// Returns bit-flag for operation being a call as field element
    pub fn fOPC_CALL(&self) -> F {
        F::from(self.flag_at(12))
    }

    /// Returns bit-flag for operation being a return as field element
    pub fn fOPC_RET(&self) -> F {
        F::from(self.flag_at(13))
    }

    /// Returns bit-flag for operation being an assert-equal as field element
    pub fn fOPC_AEQ(&self) -> F {
        F::from(self.flag_at(14))
    }

    /// Returns bit-flag for 16th position
    pub fn f15(&self) -> F {
        F::from(self.flag_at(15))
    }

    /// Returns flagset for destination register
    pub fn dst_reg(&self) -> u64 {
        // dst_reg = fDST_REG
        self.fDST_REG() as u64
    }

    /// Returns flagset for first operand register
    pub fn op0_reg(&self) -> u64 {
        // op0_reg = fOP0_REG
        self.fOP0_REG() as u64
    }

    /// Returns flagset for second operand register
    pub fn op1_src(&self) -> u64 {
        // op1_src = 4*fOP1_AP + 2*fOP1_FP + fOP1_VAL
        ((self.fOP1_AP().double() + self.fOP1_FP()).double() + self.fOP1_VAL()) as u64
    }

    /// Returns flagset for result logics
    pub fn res_log(&self) -> u64 {
        // res_log = 2*fRES_MUL + fRES_ADD
        (self.fRES_MUL().double() + self.fRES_ADD()) as u64
    }

    /// Returns flagset for program counter update
    pub fn pc_up(&self) -> u64 {
        // pc_up = 4*fPC_JNZ + 2*fPC_REL + fPC_ABS
        ((self.fPC_JNZ().double() + self.fPC_REL()).double() + self.fPC_ABS()) as u64
    }

    /// Returns flagset for allocation pointer update
    pub fn ap_up(&self) -> u64 {
        // ap_up = 2*fAP_ONE + fAP_ADD
        (self.fAP_ONE().double() + self.fAP_ADD()) as u64
    }

    /// Returns flagset for operation code
    pub fn opcode(&self) -> u64 {
        // opcode = 4*fOPC_AEQ + 2*fOPC_RET + fOPC_CALL
        ((self.fOPC_AEQ().double() + self.fOPC_RET()).double() + self.fOPC_CALL()) as u64
    }

    /// Converts a 64bit word Cairo bytecode instruction into a tuple of flags and 3 offsets
    pub fn deserialize(&self) -> (Vec<u64>, i16, i16, i16) {
        let mut flags = Vec::with_capacity(NUM_FLAGS);
        let (off_dst, off_op0, off_op1): (i16, i16, i16);
        // The least significant 16 bits
        off_dst = biased_rep((self.word % 2u64.pow(16u32)) as u16);
        // From the 32nd bit to the 17th
        off_op0 = biased_rep(((self.word % (2u64.pow(32u32))) >> 16) as u16);
        // From the 48th bit to the 33rd
        off_op1 = biased_rep(((self.word % (2u64.pow(48u32))) >> 32) as u16);
        // The most significant 16 bits
        for i in 0..NUM_FLAGS {
            flags.push(self.flag_at(i));
        }
        (flags, off_op1, off_op0, off_dst)
    }

    /// Returns an offset of 16bits to its biased representation in the interval [-2^15,2^15)
    fn biased_rep(offset: u16) -> i16 {
        let mut num: i32 = -2i32.pow(15u32);
        for i in 0..16 {
            // num = -2^15 + sum_(i=0..15) b_i * 2^i
            num += 2i32.pow(i) * ((offset as i32 >> i) % 2);
        }
        num as i16
    }

    /// Transforms a signed i16 element to a field element. This is used to compute offsets.
    fn to_field<F: FftField>(item: i16) -> F {
        if item < 0 {
            // 1. Convert item to i32, so that the absolute value fits (e.g. 2^15 could not fit in i16 otherwise)
            // 2. Once it is a positive value, store it as u32
            // 3. Then it can be transformed to a field element
            // 4. The transformed value is the negate of that field element (<=> F::from(0) - elem)
            (F::from((i32::from(item)).abs() as u32)).neg()
        } else {
            F::from(item as u32)
        }
    }
}

impl<F: FftField> CircuitGate<F> {
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

        // some useful field elements for assertions
        let zero = F::zero();
        let one = F::one();
        let two: F = 2u32.into();
        let four: F = 4u32.into();

        // FLAGS RELATED

        // check if it's the correct gate
        ensure_eq!(self.typ, GateType::Cairo, "incorrect cairo gate");

        // check last flag is a zero
        // f15 == 0
        ensure_eq!(zero, f15, "last flag is nonzero");

        // check booleanity of flags
        // fi * (1-fi) == 0 for i=[0..15)
        for i in 0..15 {
            ensure_eq!(zero, flags[i] * (one - flags[i]), "non-boolean flags");
        }

        // check no two flags of same set are nonzero
        ensure_eq!(
            zero,
            (fOP1_AP + fOP1_FP + fOP1_VAL) * (one - (fOP1_AP + fOP1_FP + fOP1_VAL)),
            "invalid format of `op1_src`"
        );
        ensure_eq!(
            zero,
            (fRES_MUL + fRES_ADD) * (one - (fRES_MUL + fRES_ADD)),
            "invalid format of `res_log`"
        );
        ensure_eq!(
            zero,
            (fPC_JNZ + fPC_REL + fPC_ABS) * (one - (fPC_JNZ + fPC_REL + fPC_ABS)),
            "invalid format of `pc_up`"
        );
        ensure_eq!(
            zero,
            (fAP_ADD1 + fAP_INC) * (one - (fAP_ADD1 + fAP_INC)),
            "invalid format of `ap_up`"
        );
        ensure_eq!(
            zero,
            (fOP_AEQ + fOP_RET + fOP_CALL) * (one - (fOP_AEQ + fOP_RET + fOP_CALL)),
            "invalid format of `opcode`"
        );

        // OPERANDS RELATED

        // * Destination address
        // if dst_reg = 0 : dst_dir = ap + off_dst
        // if dst_reg = 1 : dst_dir = fp + off_dst
        ensure_eq!(
            dst_dir,
            fDST_REG * fp + (one - fDST_REG) * ap + off_dst,
            "invalid destination address"
        );

        // * First operand address
        // if op0_reg = 0 : op0_dir = ap + off_dst
        // if op0_reg = 1 : op0_dir = fp + off_dst
        ensure_eq!(
            op0_dir,
            fOP0_REG * fp + (one - fOP0_REG) * ap + off_op0,
            "invalid first operand address"
        );

        // * Second operand address
        ensure_eq!(
            op1_dir, //                                        op1_dir = ..
            (fOP1_AP * ap                                // if op1_src == 4 : ap
            + fOP1_FP * fp                               // if op1_src == 2 : fp 
            + fOP1_VAL * pc                              // if op1_src == 1 : pc
            + (one - fOP1_FP - fOP1_AP - fOP1_VAL) * op0 // if op1_src == 0 : op0 
            + off_op1), //                                                        + off_op1
            "invalid second operand address"
        );

        // OPERATIONS RELATED

        // * Check value of result
        ensure_eq!(
            (one - fPC_JNZ) * res, //         if  pc_up != 4 : res = ..  // no res in conditional jumps
            fRES_MUL * op0 * op1                 // if res_log = 2 : op0 * op1
            + fRES_ADD * (op0 + op1)             // if res_log = 1 : op0 + op1
            + (one - fRES_ADD - fRES_MUL) * op1, // if res_log = 0 : op1
            "invalid result"
        );

        // * Check storage of current fp for a call instruction
        ensure_eq!(
            zero,
            fOP_CALL * (dst - fp),
            "current fp after call not stored"
        ); // if opcode = 1 : dst = fp

        // * Check storage of next instruction after a call instruction
        ensure_eq!(
            zero,
            fOP_CALL * (op0 - (pc + size)),
            "next instruction after call not stored"
        ); // if opcode = 1 : op0 = pc + size

        // * Check destination = result after assert-equal
        ensure_eq!(zero, fOP_AEQ * (dst - res), "false assert equal"); // if opcode = 4 : dst = res

        // REGISTERS RELATED

        // * Check next allocation pointer
        ensure_eq!(
            next_ap, //               next_ap =
            ap                   //             ap + 
            + fAP_INC * res      //  if ap_up == 1 : res
            + fAP_ADD1           //  if ap_up == 2 : 1
            + fOP_CALL.double(), // if opcode == 1 : 2
            "wrong next allocation pointer"
        );

        // * Check next frame pointer
        ensure_eq!(
            next_fp, //                                       next_fp =
            fOP_CALL * (ap + F::from(2u32))      // if opcode == 1      : ap + 2
            + fOP_RET * dst                    // if opcode == 2      : dst
            + (one - fOP_CALL - fOP_RET) * fp, // if opcode == 4 or 0 : fp
            "wrong next frame pointer"
        );

        // * Check next program counter
        ensure_eq!(
            zero,
            fPC_JNZ * (dst * res - one) * (next_pc - (pc - size)), // <=> pc_up = 4 and dst = 0 : next_pc = pc + size // no jump
            "wrong next program counter"
        );
        ensure_eq!(
            zero,
            fPC_JNZ * dst * (next_pc - (pc + op1))                  // <=> pc_up = 4 and dst != 0 : next_pc = pc + op1  // condition holds
            + (one - fPC_JNZ) * next_pc                             // <=> pc_up = {0,1,2} : next_pc = ... // not a conditional jump
                - (one - fPC_ABS - fPC_REL - fPC_JNZ) * (pc + size) // <=> pc_up = 0 : next_pc = pc + size // common case
                - fPC_ABS * res                                     // <=> pc_up = 1 : next_pc = res       // absolute jump
                - fPC_REL * (pc + res), //                             <=> pc_up = 2 : next_pc = pc + res  // relative jump
            "wrong next program counter"
        );

        // TODO(querolita): check intial and final claims for registers

        // TODO(querolita): memory related checks

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{One, Zero};
    use mina_curves::pasta::fp::Fp;

    #[test]
    fn test_cairo_gate() {
        // This test is for the following short program:
        // func main{}():
        //    tempvar x = 10
        //    return()
        // end

        // Create a vector of gates (i.e. the circuit)
        let mut gates = vec![];
        // Create wires for the first gate
        let wires = Wire::new(0);
        // Introduce the first wire to the circuit
        let instr1 = 0x480680017fff8000;
        gates.push(CircuitGate::create_cairo(wires, instr1));
        // Create wires for second gate
        let wires = Wire::new(1);
        // Introduce the second wire to the circuit
        let instr2 = 0x208b7fff7fff7ffe;
        gates.push(CircuitGate::create_cairo(wires, instr2));

        let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![Fp::zero(); 2]);

        // indices for columns and rows
        let pc_idx = 0;
        let ap_idx = 1;
        let fp_idx = 2;
        let mut row = 0;

        let (pc, ap, fp) = (1u32.into(), 6u32.into(), 6u32.into());
        let (next_pc, next_ap, next_fp, dst, op0, op1, res, dst_dir, op0_dir, op1_dir, size) =
            get_wires(instr1, pc, ap, fp);

        // load registers of current step
        witness[pc_idx][row] = pc;
        witness[ap_idx][row] = ap;
        witness[fp_idx][row] = fp;
        witness[3][row] = dst_dir;
        witness[4][row] = op0_dir;
        witness[5][row] = op1_dir;
        witness[6][row] = dst;
        witness[7][row] = op0;
        witness[8][row] = op1;
        witness[9][row] = res;
        witness[10][row] = size;

        // load next registers
        row += 1;
        witness[pc_idx][row] = next_pc;
        witness[ap_idx][row] = next_ap;
        witness[fp_idx][row] = next_fp;
        assert_eq!(next_pc, 3u32.into());
        assert_eq!(next_ap, 7u32.into());
        assert_eq!(next_fp, 6u32.into());

        CircuitGate::verify_gadget_cairo(&gates, &witness);
    }

    #[test]
    fn test_deserial_vec() {
        // This unit test is for the deserialize_vec() function for offsets. It makes sure
        // that conversions with hexadecimal numbers, signed and unsigned integers is
        // performed as it should. It also tests to_field() for negative numbers.
        let ins = 0x480680017fff8000;
        let ins_vec = deserialize_vec::<BaseField>(ins);
        let off_dst = ins_vec[DST_COEFF];
        let off_op0 = ins_vec[OP0_COEFF];
        let off_op1 = ins_vec[OP1_COEFF];

        assert_eq!(off_dst, Fp::from(0));
        assert_eq!(off_op0, to_field::<Fp>(-1));
        assert_eq!(off_op1, Fp::from(1));
    }

    #[test]
    fn test_deserial_tup() {
        // This unit test is for the deserialize_tup() function. It makes sure that conversions
        // with hexadecimal numbers, signed and unsigned integers is performed as it should
        let ins = 0x480680017fff8000;
        let (flags, off_op1, off_op0, off_dst) = deserialize_tup(ins);

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
                + 2u64.pow(2) * op1_src
                + 2u64.pow(5) * res_log
                + 2u64.pow(7) * pc_up
                + 2u64.pow(10) * ap_up
                + 2u64.pow(12) * opcode
        );
    }

    //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    //++++++++++++++++++++++++++ AUXILIARY FUNCTIONS ++++++++++++++++++++++++++

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
