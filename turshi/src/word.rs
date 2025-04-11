//! The Cairo language works natively for field elements in the finite field with
//! modulus 0x800000000000011000000000000000000000000000000000000000000000001
//! This is the hexadecimal value for 2 ^ 251 + 17 * 2 ^ 192 + 1
//! Our Pallas curves have 255 bits, so Cairo native instructions will fit.
//! This means that our Cairo implementation can admit a larger domain for
//! immediate values than theirs.

use crate::{flags::*, helper::CairoFieldHelpers};
use ark_ff::Field;
use o1_utils::field_helpers::FieldHelpers;

/// A Cairo word for the runner. Some words are instructions (which fit inside a
/// `u64`). Others are immediate values (any `F` element).
#[derive(Clone, Copy)]
pub struct CairoWord<F>(F);

/// Returns an offset of 16 bits to its biased representation in the interval
/// `[-2^15,2^15)` as a field element
pub fn bias<F: Field>(offset: F) -> F {
    offset - F::from(2u16.pow(15u32)) // -2^15 + sum_(i=0..15) b_i * 2^i
}

impl<F: Field> CairoWord<F> {
    /// Creates a [CairoWord] from a field element
    pub fn new(word: F) -> CairoWord<F> {
        CairoWord(word)
    }

    /// Returns the content of the word as a field element
    pub fn word(&self) -> F {
        self.0
    }

    /// Returns i-th bit-flag
    fn flag_at(&self, pos: usize) -> F {
        self.word().to_bits()[POS_FLAGS + pos].into()
    }
}

/// This trait contains methods to obtain the offset decomposition of a
/// [CairoWord]
pub trait Offsets<F> {
    /// Returns the destination offset in biased representation
    fn off_dst(&self) -> F;

    /// Returns the first operand offset in biased representation
    fn off_op0(&self) -> F;

    /// Returns the second operand offset in biased representation
    fn off_op1(&self) -> F;
}

/// This trait contains methods that decompose a field element into [CairoWord]
/// flagbits
pub trait FlagBits<F> {
    /// Returns bit-flag for destination register as `F`
    fn f_dst_fp(&self) -> F;

    /// Returns bit-flag for first operand register as `F`
    fn f_op0_fp(&self) -> F;

    /// Returns bit-flag for immediate value for second register as `F`
    fn f_op1_val(&self) -> F;

    /// Returns bit-flag for frame pointer for second register as `F`
    fn f_op1_fp(&self) -> F;

    /// Returns bit-flag for allocation pointer for second register as `F`
    fn f_op1_ap(&self) -> F;

    /// Returns bit-flag for addition operation in right side as `F`
    fn f_res_add(&self) -> F;

    /// Returns bit-flag for multiplication operation in right side as `F`
    fn f_res_mul(&self) -> F;

    /// Returns bit-flag for program counter update being absolute jump as `F`
    fn f_pc_abs(&self) -> F;

    /// Returns bit-flag for program counter update being relative jump as `F`
    fn f_pc_rel(&self) -> F;

    /// Returns bit-flag for program counter update being conditional jump as
    /// `F`
    fn f_pc_jnz(&self) -> F;

    /// Returns bit-flag for allocation counter update being a manual addition
    /// as `F`
    fn f_ap_add(&self) -> F;

    /// Returns bit-flag for allocation counter update being a self increment as
    /// `F`
    fn f_ap_one(&self) -> F;

    /// Returns bit-flag for operation being a call as `F`
    fn f_opc_call(&self) -> F;

    /// Returns bit-flag for operation being a return as `F`
    fn f_opc_ret(&self) -> F;

    /// Returns bit-flag for operation being an assert-equal as `F`
    fn f_opc_aeq(&self) -> F;

    /// Returns bit-flag for 16th position
    fn f15(&self) -> F;
}

/// This trait contains methods that decompose a field element into [CairoWord]
/// flagsets
pub trait FlagSets<F> {
    /// Returns flagset for destination register
    fn dst_reg(&self) -> u8;

    /// Returns flagset for first operand register
    fn op0_reg(&self) -> u8;

    /// Returns flagset for second operand register
    fn op1_src(&self) -> u8;

    /// Returns flagset for result logics
    fn res_log(&self) -> u8;

    /// Returns flagset for program counter update
    fn pc_up(&self) -> u8;

    /// Returns flagset for allocation pointer update
    fn ap_up(&self) -> u8;

    /// Returns flagset for operation code
    fn opcode(&self) -> u8;
}

impl<F: Field> Offsets<F> for CairoWord<F> {
    fn off_dst(&self) -> F {
        // The least significant 16 bits
        bias(self.word().u16_chunk(POS_DST))
    }

    fn off_op0(&self) -> F {
        // From the 32nd bit to the 17th
        bias(self.word().u16_chunk(POS_OP0))
    }

    fn off_op1(&self) -> F {
        // From the 48th bit to the 33rd
        bias(self.word().u16_chunk(POS_OP1))
    }
}

impl<F: Field> FlagBits<F> for CairoWord<F> {
    fn f_dst_fp(&self) -> F {
        self.flag_at(0)
    }

    fn f_op0_fp(&self) -> F {
        self.flag_at(1)
    }

    fn f_op1_val(&self) -> F {
        self.flag_at(2)
    }

    fn f_op1_fp(&self) -> F {
        self.flag_at(3)
    }

    fn f_op1_ap(&self) -> F {
        self.flag_at(4)
    }

    fn f_res_add(&self) -> F {
        self.flag_at(5)
    }

    fn f_res_mul(&self) -> F {
        self.flag_at(6)
    }

    fn f_pc_abs(&self) -> F {
        self.flag_at(7)
    }

    fn f_pc_rel(&self) -> F {
        self.flag_at(8)
    }

    fn f_pc_jnz(&self) -> F {
        self.flag_at(9)
    }

    fn f_ap_add(&self) -> F {
        self.flag_at(10)
    }

    fn f_ap_one(&self) -> F {
        self.flag_at(11)
    }

    fn f_opc_call(&self) -> F {
        self.flag_at(12)
    }

    fn f_opc_ret(&self) -> F {
        self.flag_at(13)
    }

    fn f_opc_aeq(&self) -> F {
        self.flag_at(14)
    }

    fn f15(&self) -> F {
        self.flag_at(15)
    }
}

impl<F: Field> FlagSets<F> for CairoWord<F> {
    fn dst_reg(&self) -> u8 {
        // dst_reg = fDST_REG
        self.f_dst_fp().lsb()
    }

    fn op0_reg(&self) -> u8 {
        // op0_reg = fOP0_REG
        self.f_op0_fp().lsb()
    }

    fn op1_src(&self) -> u8 {
        // op1_src = 4*fOP1_AP + 2*fOP1_FP + fOP1_VAL
        2 * (2 * self.f_op1_ap().lsb() + self.f_op1_fp().lsb()) + self.f_op1_val().lsb()
    }

    fn res_log(&self) -> u8 {
        // res_log = 2*fRES_MUL + fRES_ADD
        2 * self.f_res_mul().lsb() + self.f_res_add().lsb()
    }

    fn pc_up(&self) -> u8 {
        // pc_up = 4*fPC_JNZ + 2*fPC_REL + fPC_ABS
        2 * (2 * self.f_pc_jnz().lsb() + self.f_pc_rel().lsb()) + self.f_pc_abs().lsb()
    }

    fn ap_up(&self) -> u8 {
        // ap_up = 2*fAP_ONE + fAP_ADD
        2 * self.f_ap_one().lsb() + self.f_ap_add().lsb()
    }

    fn opcode(&self) -> u8 {
        // opcode = 4*fOPC_AEQ + 2*fOPC_RET + fOPC_CALL
        2 * (2 * self.f_opc_aeq().lsb() + self.f_opc_ret().lsb()) + self.f_opc_call().lsb()
    }
}
