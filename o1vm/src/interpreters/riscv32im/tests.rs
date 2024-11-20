use crate::interpreters::riscv32im::{
    constraints,
    interpreter::{
        IInstruction, MInstruction, RInstruction, SBInstruction, SInstruction, SyscallInstruction,
        UInstruction, UJInstruction,
    },
};
use mina_curves::pasta::Fp;
use strum::EnumCount;

#[test]
// Sanity check that we have as many selector as we have instructions
fn test_regression_selectors_for_instructions() {
    let mips_con_env = constraints::Env::<Fp>::default();
    let constraints = mips_con_env.get_selector_constraints();
    assert_eq!(
        // We substract 1 as we have one boolean check per sel
        // and 1 constraint to check that one and only one
        // sel is activated
        constraints.len() - 1,
        // This should match the list in
        // crate::interpreters::riscv32im::interpreter::Instruction
        RInstruction::COUNT
            + IInstruction::COUNT
            + SInstruction::COUNT
            + SBInstruction::COUNT
            + UInstruction::COUNT
            + UJInstruction::COUNT
            + SyscallInstruction::COUNT
            + MInstruction::COUNT
    );
    // All instructions are degree 1 or 2.
    constraints
        .iter()
        .for_each(|c| assert!(c.degree(1, 0) == 2 || c.degree(1, 0) == 1));
}
