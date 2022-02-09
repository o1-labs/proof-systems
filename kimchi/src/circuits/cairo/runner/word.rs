//! The Cairo Language works natively for field elements in the finite field with
//! modulus 0x800000000000011000000000000000000000000000000000000000000000001
//! This is the hexadecimal value for 2 ^ 251 + 17 * 2 ^ 192 + 1
//! Our Pallas curves have 256 bits, so Cairo native instructions will fit.

// TODO(querolita):
// - Enlarge native word type to F

use crate::circuits::cairo::runner::definitions::*;
use crate::circuits::cairo::runner::helper::*;
use ark_ff::{FftField, PrimeField};
use o1_utils::field_helpers;

/// A Cairo instruction for simulation
#[derive(Clone, Copy)]
pub struct CairoWord<F: PrimeField> {
    /// field element. Instructions will fit in 64 bits
    word: F,
}

/*
// Returns an offset of 16bits to its biased representation in the interval [-2^15,2^15)
fn biased_rep(offset: u16) -> i16 {
    let mut num: i32 = -(2i32.pow(15u32));
    for i in 0..16 {
        // num = -2^15 + sum_(i=0..15) b_i * 2^i
        num += 2i32.pow(i) * ((offset as i32 >> i) % 2);
    }
    num as i16
}
*/

/// Returns an offset of 16bits to its biased representation in the interval [-2^15,2^15) as a field element
fn bias<F: PrimeField>(offset: F) -> F {
    offset - F::from(2u16.pow(15u32)) // -2^15 + sum_(i=0..15) b_i * 2^i
}

impl<F: PrimeField> CairoWord<F> {
    /// Creates a CairoWord from a field element
    pub fn new(word: F) -> CairoWord<F> {
        CairoWord { word }
    }

    pub fn get_word(&self) -> F {
        self.word
    }

    /// Returns the destination offset in biased representation
    pub fn off_dst(&self) -> F {
        // The least significant 16 bits
        bias(self.get_word().chunk(POS_DST))
        //biased_rep((self.word % 2u64.pow(16u32)) as u16)
    }

    /// Returns the first operand offset in biased representation
    pub fn off_op0(&self) -> F {
        // From the 32nd bit to the 17th
        bias(self.get_word().chunk(POS_OP0))
        //biased_rep(((self.word % (2u64.pow(32u32))) >> 16) as u16)
    }

    /// Returns the second operand offset in biased representation
    pub fn off_op1(&self) -> F {
        // From the 48th bit to the 33rd
        bias(self.get_word().chunk(POS_OP1))
        //biased_rep(((self.word % (2u64.pow(48u32))) >> 32) as u16)
    }

    /// Returns vector of 16 flags
    pub fn flags(&self) -> Vec<F> {
        let mut flags = Vec::with_capacity(NUM_FLAGS);
        // The most significant 16 bits
        for i in 0..NUM_FLAGS {
            flags.push(self.flag_at(i));
        }
        flags
    }

    /// Returns i-th bit-flag
    pub fn flag_at(&self, pos: usize) -> F {
        self.get_word().to_bits()[POS_FLAGS + pos].into()
        //F::from((self.word.try_into() >> (48 + pos)) % 2)
    }

    /// Returns bit-flag for destination register as F
    pub fn f_dst_fp(&self) -> F {
        self.flag_at(0)
    }

    /// Returns bit-flag for first operand register as F
    pub fn f_op0_fp(&self) -> F {
        self.flag_at(1)
    }

    /// Returns bit-flag for immediate value for second register as F
    pub fn f_op1_val(&self) -> F {
        self.flag_at(2)
    }

    /// Returns bit-flag for frame pointer for second register as F
    pub fn f_op1_fp(&self) -> F {
        self.flag_at(3)
    }

    /// Returns bit-flag for allocation pointer for second regsiter as F
    pub fn f_op1_ap(&self) -> F {
        self.flag_at(4)
    }

    /// Returns bit-flag for addition operation in right side as F
    pub fn f_res_add(&self) -> F {
        self.flag_at(5)
    }

    /// Returns bit-flag for multiplication operation in right side as F
    pub fn f_res_mul(&self) -> F {
        self.flag_at(6)
    }

    /// Returns bit-flag for program counter update being absolute jump as F
    pub fn f_pc_abs(&self) -> F {
        self.flag_at(7)
    }

    /// Returns bit-flag for program counter update being relative jump as F
    pub fn f_pc_rel(&self) -> F {
        self.flag_at(8)
    }

    /// Returns bit-flag for program counter update being conditional jump as F
    pub fn f_pc_jnz(&self) -> F {
        self.flag_at(9)
    }

    /// Returns bit-flag for allocation counter update being a manual addition as F
    pub fn f_ap_add(&self) -> F {
        self.flag_at(10)
    }

    /// Returns bit-flag for allocation counter update being a self increment as F
    pub fn f_ap_one(&self) -> F {
        self.flag_at(11)
    }

    /// Returns bit-flag for operation being a call as F
    pub fn f_opc_call(&self) -> F {
        self.flag_at(12)
    }

    /// Returns bit-flag for operation being a return as F
    pub fn f_opc_ret(&self) -> F {
        self.flag_at(13)
    }

    /// Returns bit-flag for operation being an assert-equal as F
    pub fn f_opc_aeq(&self) -> F {
        self.flag_at(14)
    }

    /// Returns bit-flag for 16th position
    pub fn f15(&self) -> F {
        self.flag_at(15)
    }

    /// Returns flagset for destination register
    pub fn dst_reg(&self) -> u8 {
        // dst_reg = fDST_REG
        self.f_dst_fp().to_byte()
    }

    /// Returns flagset for first operand register
    pub fn op0_reg(&self) -> u8 {
        // op0_reg = fOP0_REG
        self.f_op0_fp().to_byte()
    }

    /// Returns flagset for second operand register
    pub fn op1_src(&self) -> u8 {
        // op1_src = 4*fOP1_AP + 2*fOP1_FP + fOP1_VAL
        2 * (2 * self.f_op1_ap().to_byte() + self.f_op1_fp().to_byte()) + self.f_op1_val().to_byte()
    }

    /// Returns flagset for result logics
    pub fn res_log(&self) -> u8 {
        // res_log = 2*fRES_MUL + fRES_ADD
        2 * self.f_res_mul().to_byte() + self.f_res_add().to_byte()
    }

    /// Returns flagset for program counter update
    pub fn pc_up(&self) -> u8 {
        // pc_up = 4*fPC_JNZ + 2*fPC_REL + fPC_ABS
        2 * (2 * self.f_pc_jnz().to_byte() + self.f_pc_rel().to_byte()) + self.f_pc_abs().to_byte()
    }

    /// Returns flagset for allocation pointer update
    pub fn ap_up(&self) -> u8 {
        // ap_up = 2*fAP_ONE + fAP_ADD
        2 * self.f_ap_one().to_byte() + self.f_ap_add().to_byte()
    }

    /// Returns flagset for operation code
    pub fn opcode(&self) -> u8 {
        // opcode = 4*fOPC_AEQ + 2*fOPC_RET + fOPC_CALL
        2 * (2 * self.f_opc_aeq().to_byte() + self.f_opc_ret().to_byte())
            + self.f_opc_call().to_byte()
    }
}

#[cfg(test)]
mod tests {
    use crate::circuits::cairo::runner::definitions::*;
    use ark_ff::{One, Zero};
    use mina_curves::pasta::fp::Fp as F;

    #[test]
    fn test_biased() {
        assert_eq!(F::one(), super::bias(F::from(0x8001)));
        assert_eq!(F::zero(), super::bias(F::from(0x8000)));
        assert_eq!(-F::one(), super::bias(F::from(0x7fff)));
    }

    #[test]
    fn test_cairo_word() {
        // Tests the structure of a Cairo word corresponding to the Cairo instruction: tempvar x = val
        // This unit test checks offsets computation, flagbits and flagsets.
        let word = super::CairoWord::new(F::from(0x480680017fff8000u64));

        assert_eq!(word.off_dst(), F::zero());
        assert_eq!(word.off_op0(), -F::one());
        assert_eq!(word.off_op1(), F::one());

        assert_eq!(word.f_dst_fp(), F::zero());
        assert_eq!(word.f_op0_fp(), F::one());
        assert_eq!(word.f_op1_val(), F::one());
        assert_eq!(word.f_op1_fp(), F::zero());
        assert_eq!(word.f_op1_ap(), F::zero());
        assert_eq!(word.f_res_add(), F::zero());
        assert_eq!(word.f_res_mul(), F::zero());
        assert_eq!(word.f_pc_abs(), F::zero());
        assert_eq!(word.f_pc_rel(), F::zero());
        assert_eq!(word.f_pc_jnz(), F::zero());
        assert_eq!(word.f_ap_add(), F::zero());
        assert_eq!(word.f_ap_one(), F::one());
        assert_eq!(word.f_opc_call(), F::zero());
        assert_eq!(word.f_opc_ret(), F::zero());
        assert_eq!(word.f_opc_aeq(), F::one());
        assert_eq!(word.f15(), F::zero());

        assert_eq!(word.dst_reg(), DST_AP);
        assert_eq!(word.op0_reg(), 1 - OP0_AP);
        assert_eq!(word.op1_src(), OP1_VAL);
        assert_eq!(word.res_log(), RES_ONE);
        assert_eq!(word.pc_up(), PC_SIZ);
        assert_eq!(word.ap_up(), AP_ONE);
        assert_eq!(word.opcode(), OPC_AEQ);

        assert_eq!(
            0x4806,
            u32::from(word.dst_reg())
                + 2 * u32::from(word.op0_reg())
                + 2u32.pow(2) * u32::from(word.op1_src())
                + 2u32.pow(5) * u32::from(word.res_log())
                + 2u32.pow(7) * u32::from(word.pc_up())
                + 2u32.pow(10) * u32::from(word.ap_up())
                + 2u32.pow(12) * u32::from(word.opcode())
        );
    }
}
