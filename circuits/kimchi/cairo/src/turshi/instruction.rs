/*****************************************************************************************************************

This source file implements Cairo instruction primitive.

*****************************************************************************************************************/

//use ark_ec::AffineCurve;
use ark_ff::FftField;
//use ark_serialize::CanonicalSerialize;
//use array_init::array_init;
//use mina_curves::pasta::pallas as Pallas;

// Affine curve point type
//pub use Pallas::Affine as CurvePoint;
// Base field element type
//pub type BaseField = <CurvePoint as AffineCurve>::BaseField;
// Scalar field element type
//pub type ScalarField = <CurvePoint as AffineCurve>::ScalarField;

use crate::runner::word::CairoWord;

const NUM_FLAGS: usize = 16;
const NUM_OFFSETS: usize = 3;
const DST_COEFF: usize = 0;
const OP0_COEFF: usize = 1;
const OP1_COEFF: usize = 2;

/// A Cairo instruction
pub struct CairoInstruction<F: FftField> {
    /// Cairo word for execution
    pub word: CairoWord,
    /// Corresponding field element,
    pub elem: F,
    /// Vector of 16 flags as field elements
    pub flags: Vec<F>,
    /// Vector of 3 offsets as field elements
    pub offsets: Vec<F>,
}

/// Transforms a signed i16 element to a field element. This is used to compute offsets.
fn i16_to_field<F: FftField>(item: i16) -> F {
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

/// Returns the vector of 3 offsets as field elements
fn offsets_to_field<F: FftField>(word: &CairoWord) -> Vec<F> {
    let mut offsets = Vec::with_capacity(NUM_OFFSETS);
    offsets.push(i16_to_field::<F>(word.off_dst()));
    offsets.push(i16_to_field::<F>(word.off_op0()));
    offsets.push(i16_to_field::<F>(word.off_op1()));
    offsets
}

/// Returns the vector of 16 flags as field elements
fn flags_to_field<F: FftField>(word: &CairoWord) -> Vec<F> {
    let mut flags = Vec::with_capacity(NUM_FLAGS);
    for i in 0..NUM_FLAGS {
        flags.push(F::from(word.flag_at(i)));
    }
    flags
}

/*
/// Returns the shifted value of an offset as a field element
fn shift<F: FftField>(offset: F) -> F {
    // Adds 2^15 to nil the biased representation of the offset
    offset + F::from(2u16.pow(15))
}
*/

impl<F: FftField> CairoInstruction<F> {
    /// Creates a new Cairo instruction
    pub fn new(word: u64) -> CairoInstruction<F> {
        let cairoword = CairoWord::new(word.into());
        CairoInstruction {
            word: cairoword,
            elem: F::from(word),
            flags: flags_to_field::<F>(&cairoword),
            offsets: offsets_to_field::<F>(&cairoword),
        }
    }
    /// Returns the destination offset as a field element
    pub fn off_dst(&self) -> F {
        self.flags[DST_COEFF]
    }
    /// Returns the first operand offset as a field element
    pub fn off_op0(&self) -> F {
        self.offsets[OP0_COEFF]
    }
    /// Returns the second operand offset as a field element
    pub fn off_op1(&self) -> F {
        self.flags[OP1_COEFF]
    }
    /*
    /// Returns the shifted value of off_dst
    fn sft_dst(&self) -> F {
        shift(self.off_dst())
    }
    /// Returns the shifted value of off_op0
    fn sft_op0(&self) -> F {
        shift(self.off_op0())
    }
    /// Returns the shifted value of off_op1
    fn sft_op1(&self) -> F {
        shift(self.off_op1())
    }
    */
    /// Returns the 0th flag as a field element
    pub fn f_dst_reg(&self) -> F {
        self.flags[0]
    }
    /// Returns the 1st flag as a field element
    pub fn f_op0_reg(&self) -> F {
        self.flags[1]
    }
    /// Returns the 2nd flag as a field element
    pub fn f_op1_val(&self) -> F {
        self.flags[2]
    }
    /// Returns the 3rd flag as a field element
    pub fn f_op1_fp(&self) -> F {
        self.flags[3]
    }
    /// Returns the 4th flag as a field element
    pub fn f_op1_ap(&self) -> F {
        self.flags[4]
    }
    /// Returns the 5th flag as a field element
    pub fn f_res_add(&self) -> F {
        self.flags[5]
    }
    /// Returns the 6th flag as a field element
    pub fn f_res_mul(&self) -> F {
        self.flags[6]
    }
    /// Returns the 7th flag as a field element
    pub fn f_pc_abs(&self) -> F {
        self.flags[7]
    }
    /// Returns the 8th flag as a field element
    pub fn f_pc_rel(&self) -> F {
        self.flags[8]
    }
    /// Returns the 9th flag as a field element
    pub fn f_pc_jnz(&self) -> F {
        self.flags[9]
    }
    /// Returns the 10th flag as a field element
    pub fn f_ap_add(&self) -> F {
        self.flags[10]
    }
    /// Returns the 11th flag as a field element
    pub fn f_ap_one(&self) -> F {
        self.flags[11]
    }
    /// Returns the 12th flag as a field element
    pub fn f_opc_call(&self) -> F {
        self.flags[12]
    }
    /// Returns the 13th flag as a field element
    pub fn f_opc_ret(&self) -> F {
        self.flags[13]
    }
    /// Returns the 14th flag as a field element
    pub fn f_opc_aeq(&self) -> F {
        self.flags[14]
    }
    /// Returns the 15th flag as a field element
    pub fn f15(&self) -> F {
        self.flags[15]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{One, Zero};
    use mina_curves::pasta::fp::Fp;

    #[test]
    fn test_cairo_instxn() {
        let inst = CairoInstruction::<Fp>::new(0x480680017fff8000);

        assert_eq!(inst.off_dst(), Fp::zero());
        assert_eq!(inst.off_op0(), i16_to_field(-1));
        assert_eq!(inst.off_op1(), Fp::one());
        // Check conversion from i16 to field
        assert_eq!(Fp::zero() - Fp::one(), i16_to_field(-1));

        assert_eq!(inst.f_dst_reg(), Fp::zero());
        assert_eq!(inst.f_op0_reg(), Fp::one());
        assert_eq!(inst.f_op1_val(), Fp::one());
        assert_eq!(inst.f_op1_fp(), Fp::zero());
        assert_eq!(inst.f_op1_ap(), Fp::zero());
        assert_eq!(inst.f_res_add(), Fp::zero());
        assert_eq!(inst.f_res_mul(), Fp::zero());
        assert_eq!(inst.f_pc_abs(), Fp::zero());
        assert_eq!(inst.f_pc_rel(), Fp::zero());
        assert_eq!(inst.f_pc_jnz(), Fp::zero());
        assert_eq!(inst.f_ap_add(), Fp::zero());
        assert_eq!(inst.f_ap_one(), Fp::one());
        assert_eq!(inst.f_opc_call(), Fp::zero());
        assert_eq!(inst.f_opc_ret(), Fp::zero());
        assert_eq!(inst.f_opc_aeq(), Fp::one());
        assert_eq!(inst.f15(), Fp::zero());
    }
}

/*
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

*/
