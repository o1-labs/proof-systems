//! The Cairo Language works natively for field elements in the finite field with
//! modulus 0x800000000000011000000000000000000000000000000000000000000000001
//! This is the hexadecimal value for 2 ^ 251 + 17 * 2 ^ 192 + 1
//! Our Pallas curves have 256 bits, so Cairo native instructions will fit.

// TODO(querolita):
// - Enlarge native word type to u256

/// Number of Cairo flags
pub const NUM_FLAGS: usize = 16;

/// A Cairo instruction for simulation
#[derive(Clone, Copy)]
pub struct CairoWord {
    /// 64-bit word
    pub word: u64,
    /// flag to indicate if word is negative
    pub neg: bool,
}

/// Returns an offset of 16bits to its biased representation in the interval [-2^15,2^15)
fn biased_rep(offset: u16) -> i16 {
    let mut num: i32 = -(2i32.pow(15u32));
    for i in 0..16 {
        // num = -2^15 + sum_(i=0..15) b_i * 2^i
        num += 2i32.pow(i) * ((offset as i32 >> i) % 2);
    }
    num as i16
}

impl CairoWord {
    /// Creates a CairoWord from a 64bit unsigned integer
    pub fn new(entry: i128) -> CairoWord {
        CairoWord {
            word: entry.abs() as u64, //u256,
            //overloaded vector
            neg: entry.is_negative(),
        }
    }

    /// Returns the destination offset in biased representation as i16
    pub fn off_dst(&self) -> i16 {
        // The least significant 16 bits
        biased_rep((self.word % 2u64.pow(16u32)) as u16)
    }

    /// Returns the first operand offset in biased representation as i16
    pub fn off_op0(&self) -> i16 {
        // From the 32nd bit to the 17th
        biased_rep(((self.word % (2u64.pow(32u32))) >> 16) as u16)
    }

    /// Returns the second operand offset in biased representation as i16
    pub fn off_op1(&self) -> i16 {
        // From the 48th bit to the 33rd
        biased_rep(((self.word % (2u64.pow(48u32))) >> 32) as u16)
    }

    /// Returns vector of 16 flags
    pub fn flags(&self) -> Vec<u64> {
        let mut flags = Vec::with_capacity(NUM_FLAGS);
        // The most significant 16 bits
        for i in 0..NUM_FLAGS {
            flags.push(self.flag_at(i));
        }
        flags
    }

    /// Returns i-th bit-flag as u64
    pub fn flag_at(&self, pos: usize) -> u64 {
        (self.word >> (48 + pos)) % 2
    }

    /// Returns bit-flag for destination register as u64
    pub fn f_dst_fp(&self) -> u64 {
        self.flag_at(0)
    }

    /// Returns bit-flag for first operand register as u64
    pub fn f_op0_fp(&self) -> u64 {
        self.flag_at(1)
    }

    /// Returns bit-flag for immediate value for second register as u64
    pub fn f_op1_val(&self) -> u64 {
        self.flag_at(2)
    }

    /// Returns bit-flag for frame pointer for second register as u64
    pub fn f_op1_fp(&self) -> u64 {
        self.flag_at(3)
    }

    /// Returns bit-flag for allocation pointer for second regsiter as u64
    pub fn f_op1_ap(&self) -> u64 {
        self.flag_at(4)
    }

    /// Returns bit-flag for addition operation in right side as u64
    pub fn f_res_add(&self) -> u64 {
        self.flag_at(5)
    }

    /// Returns bit-flag for multiplication operation in right side as u64
    pub fn f_res_mul(&self) -> u64 {
        self.flag_at(6)
    }

    /// Returns bit-flag for program counter update being absolute jump as u64
    pub fn f_pc_abs(&self) -> u64 {
        self.flag_at(7)
    }

    /// Returns bit-flag for program counter update being relative jump as u64
    pub fn f_pc_rel(&self) -> u64 {
        self.flag_at(8)
    }

    /// Returns bit-flag for program counter update being conditional jump as u64
    pub fn f_pc_jnz(&self) -> u64 {
        self.flag_at(9)
    }

    /// Returns bit-flag for allocation counter update being a manual addition as u64
    pub fn f_ap_add(&self) -> u64 {
        self.flag_at(10)
    }

    /// Returns bit-flag for allocation counter update being a self increment as u64
    pub fn f_ap_one(&self) -> u64 {
        self.flag_at(11)
    }

    /// Returns bit-flag for operation being a call as u64
    pub fn f_opc_call(&self) -> u64 {
        self.flag_at(12)
    }

    /// Returns bit-flag for operation being a return as u64
    pub fn f_opc_ret(&self) -> u64 {
        self.flag_at(13)
    }

    /// Returns bit-flag for operation being an assert-equal as u64
    pub fn f_opc_aeq(&self) -> u64 {
        self.flag_at(14)
    }

    /// Returns bit-flag for 16th position
    pub fn f15(&self) -> u64 {
        self.flag_at(15)
    }

    /// Returns flagset for destination register
    pub fn dst_reg(&self) -> u64 {
        // dst_reg = fDST_REG
        self.f_dst_fp()
    }

    /// Returns flagset for first operand register
    pub fn op0_reg(&self) -> u64 {
        // op0_reg = fOP0_REG
        self.f_op0_fp()
    }

    /// Returns flagset for second operand register
    pub fn op1_src(&self) -> u64 {
        // op1_src = 4*fOP1_AP + 2*fOP1_FP + fOP1_VAL
        2 * (2 * self.f_op1_ap() + self.f_op1_fp()) + self.f_op1_val()
    }

    /// Returns flagset for result logics
    pub fn res_log(&self) -> u64 {
        // res_log = 2*fRES_MUL + fRES_ADD
        2 * self.f_res_mul() + self.f_res_add()
    }

    /// Returns flagset for program counter update
    pub fn pc_up(&self) -> u64 {
        // pc_up = 4*fPC_JNZ + 2*fPC_REL + fPC_ABS
        2 * (2 * self.f_pc_jnz() + self.f_pc_rel()) + self.f_pc_abs()
    }

    /// Returns flagset for allocation pointer update
    pub fn ap_up(&self) -> u64 {
        // ap_up = 2*fAP_ONE + fAP_ADD
        2 * self.f_ap_one() + self.f_ap_add()
    }

    /// Returns flagset for operation code
    pub fn opcode(&self) -> u64 {
        // opcode = 4*fOPC_AEQ + 2*fOPC_RET + fOPC_CALL
        2 * (2 * self.f_opc_aeq() + self.f_opc_ret()) + self.f_opc_call()
    }

    /// Transforms a Cairo word to the original i128 element
    pub fn to_i128(&self) -> i128 {
        // word * (-1)^(neg): if neg = true returns -word, else +word
        i128::from(self.word) * (-1i128).pow(self.neg as u32)
    }
}

#[cfg(test)]
mod tests {
    use crate::circuits::cairo::runner::definitions::*;

    #[test]
    fn test_biased() {
        assert_eq!(1, super::biased_rep(0x8001));
        assert_eq!(0, super::biased_rep(0x8000));
        assert_eq!(-1, super::biased_rep(0x7fff));
    }

    #[test]
    fn test_cairo_word() {
        // Tests the structure of a Cairo word corresponding to the Cairo instruction: tempvar x = val
        // This unit test checks offsets computation, flagbits and flagsets.
        let word = super::CairoWord::new(0x480680017fff8000);

        assert_eq!(word.off_dst(), 0);
        assert_eq!(word.off_op0(), -1);
        assert_eq!(word.off_op1(), 1);

        assert_eq!(word.f_dst_fp(), 0);
        assert_eq!(word.f_op0_fp(), 1);
        assert_eq!(word.f_op1_val(), 1);
        assert_eq!(word.f_op1_fp(), 0);
        assert_eq!(word.f_op1_ap(), 0);
        assert_eq!(word.f_res_add(), 0);
        assert_eq!(word.f_res_mul(), 0);
        assert_eq!(word.f_pc_abs(), 0);
        assert_eq!(word.f_pc_rel(), 0);
        assert_eq!(word.f_pc_jnz(), 0);
        assert_eq!(word.f_ap_add(), 0);
        assert_eq!(word.f_ap_one(), 1);
        assert_eq!(word.f_opc_call(), 0);
        assert_eq!(word.f_opc_ret(), 0);
        assert_eq!(word.f_opc_aeq(), 1);
        assert_eq!(word.f15(), 0);

        assert_eq!(word.dst_reg(), DST_AP);
        assert_eq!(word.op0_reg(), 1 - OP0_AP);
        assert_eq!(word.op1_src(), OP1_VAL);
        assert_eq!(word.res_log(), RES_ONE);
        assert_eq!(word.pc_up(), PC_SIZ);
        assert_eq!(word.ap_up(), AP_ONE);
        assert_eq!(word.opcode(), OPC_AEQ);

        assert_eq!(
            0x4806,
            word.dst_reg()
                + 2 * word.op0_reg()
                + 2u64.pow(2) * word.op1_src()
                + 2u64.pow(5) * word.res_log()
                + 2u64.pow(7) * word.pc_up()
                + 2u64.pow(10) * word.ap_up()
                + 2u64.pow(12) * word.opcode()
        );
        /* // I commented out aa different notation for the same thing
        let flags = word.flags();
        let f_dst_fp = flags[0];
        let f_op0_fp = flags[1];
        let f_op1_val = flags[2];
        let f_op1_fp = flags[3];
        let f_op1_ap = flags[4];
        let f_res_add = flags[5];
        let f_res_mul = flags[6];
        let f_pc_abs = flags[7];
        let f_pc_rel = flags[8];
        let f_pc_jnz = flags[9];
        let f_ap_add = flags[10];
        let f_ap_one = flags[11];
        let f_opc_call = flags[12];
        let f_opc_ret = flags[13];
        let f_opc_aeq = flags[14];
        let f15 = flags[15];

        let dst_reg = f_dst_fp;
        let op0_reg = f_op0_fp;
        let op1_src = 4 * f_op1_ap + 2 * f_op1_fp + f_op1_val;
        let res_log = 2 * f_res_mul + f_res_add;
        let pc_up = 4 * f_pc_jnz + 2 * f_pc_rel + f_pc_abs;
        let ap_up = 2 * f_ap_one + f_ap_add;
        let opcode = 4 * f_opc_aeq + 2 * f_opc_ret + f_opc_call;

        assert_eq!(word.f_dst_fp(), f_dst_fp);
        assert_eq!(word.f_op0_fp(), f_op0_fp);
        assert_eq!(word.f_op1_val(), f_op1_val);
        assert_eq!(word.f_op1_fp(), f_op1_fp);
        assert_eq!(word.f_op1_ap(), f_op1_ap);
        assert_eq!(word.f_res_add(), f_res_add);
        assert_eq!(word.f_res_mul(), f_res_mul);
        assert_eq!(word.f_pc_abs(), f_pc_abs);
        assert_eq!(word.f_pc_rel(), f_pc_rel);
        assert_eq!(word.f_pc_jnz(), f_pc_jnz);
        assert_eq!(word.f_ap_add(), f_ap_add);
        assert_eq!(word.f_ap_one(), f_ap_one);
        assert_eq!(word.f_opc_call(), f_opc_call);
        assert_eq!(word.f_opc_ret(), f_opc_ret);
        assert_eq!(word.f_opc_aeq(), f_opc_aeq);
        assert_eq!(word.f15(), f15);

        assert_eq!(word.dst_reg(), dst_reg);
        assert_eq!(word.op0_reg(), op0_reg);
        assert_eq!(word.op1_src(), op1_src);
        assert_eq!(word.res_log(), res_log);
        assert_eq!(word.pc_up(), pc_up);
        assert_eq!(word.ap_up(), ap_up);
        assert_eq!(word.opcode(), opcode);
        */
    }
}
