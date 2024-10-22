use strum::{EnumCount, IntoEnumIterator};
use strum_macros::{EnumCount, EnumIter};

// FIXME: split in the future in instruction types?
#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum Instruction {
    #[default]
    BranchEq, // beq
    BranchEqZero,  // beqz
    BranchNeq,     // bne
    BranchLeqZero, // blez
    BranchGtZero,  // bgtz
    BranchLtZero,  // bltz
    BranchGeqZero, // bgez

    // Pseudo instruction
    // j offset -> jal x0, offset - Jump
    Jump, // j
    // jal offset -> jal x1, offset - Jump and Link
    JumpAndLink, // jal
    // jr rs -> jalr x0, 0(rs) - Jump Register
    JumpRegister, // jr
    // jalr rs -> jalr x1, 0(rs) - Jump and Link Register
    JumpAndLinkRegister, // jalr
    // jalr x0, 0(x1) - Return from Subroutine
    Return, // ret
    // call x0, offset - Call far-away subroutine
    // auipc x1, offset[31 : 12] + offset[11]
    // jalr x1, offset[11:0](x1)
    Call, // call
    // tail offset -
    // auipc x1, offset[31 : 12] + offset[11]
    Tail,
}
