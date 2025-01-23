use ark_ff::{One, Zero};
use mina_curves::pasta::Fp as F;
use turshi::{
    flags::*,
    word::{bias, CairoWord, FlagBits, FlagSets, Offsets},
};

#[test]
fn test_biased() {
    assert_eq!(F::one(), bias(F::from(0x8001)));
    assert_eq!(F::zero(), bias(F::from(0x8000)));
    assert_eq!(-F::one(), bias(F::from(0x7fff)));
}

#[test]
fn test_cairo_word() {
    // Tests the structure of a Cairo word corresponding to the Cairo instruction:
    // tempvar x = val This unit test checks offsets computation, flagbits and
    // flagsets.
    let word = CairoWord::new(F::from(0x480680017fff8000u64));

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
