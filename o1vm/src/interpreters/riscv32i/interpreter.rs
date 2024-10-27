use strum::{EnumCount, IntoEnumIterator};
use strum_macros::{EnumCount, EnumIter};

#[derive(Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Hash, Ord, PartialOrd)]
pub enum Instruction {
    RType(RInstruction),
    IType(IInstruction),
    SType(SInstruction),
    SBType(SBInstruction),
    UType(UInstruction),
    UJType(UJInstruction),
}

// See
// https://www.cs.cornell.edu/courses/cs3410/2024fa/assignments/cpusim/riscv-instructions.pdf
// for the order
#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum RInstruction {
    #[default]
    Add, // add
    Sub,                  // sub
    ShiftLeftLogical,     // sll
    SetLessThan,          // slt
    SetLessThanUnsigned,  // sltu
    Xor,                  // xor
    ShiftRightLogical,    // srl
    ShiftRightArithmetic, // sra
    Or,                   // or
    And,                  // and
    Fence,                // fence
    FenceI,               // fence.i
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum IInstruction {
    #[default]
    LoadByte, // lb
    LoadHalf,         // lh
    LoadWord,         // lw
    LoadByteUnsigned, // lbu
    LoadHalfUnsigned, // lhu

    ShiftLeftLogicalImmediate,     // slli
    ShiftRightLogicalImmediate,    // srli
    ShiftRightArithmeticImmediate, // srai
    SetLessThanImmediate,          // slti
    SetLessThanImmediateUnsigned,  // sltiu

    AddImmediate, // addi
    AndImmediate, // andi
    XorImmediate, // xori
    OrImmediate,  // ori
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum SInstruction {
    #[default]
    StoreByte, // sb
    StoreHalf, // sh
    StoreWord, // sw
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum SBInstruction {
    #[default]
    BranchEq, // beq
    BranchNeq,              // bne
    BranchLessThan,         // blt
    BranchGe,               // bge
    BranchLessThanUnsigned, // bltu
    BranchGreaterThanEqual, // bgeu
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum UInstruction {
    #[default]
    LoadUpperImmediate, // lui
    // Add upper immediate to PC
    AddUpperImmediate, // auipc
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum UJInstruction {
    #[default]
    JumpAndLink, // jal
    JumpAndLinkRegister, // jalr
}

impl IntoIterator for Instruction {
    type Item = Instruction;
    type IntoIter = std::vec::IntoIter<Instruction>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Instruction::RType(_) => {
                let mut iter_contents = Vec::with_capacity(RInstruction::COUNT);
                for rtype in RInstruction::iter() {
                    iter_contents.push(Instruction::RType(rtype));
                }
                iter_contents.into_iter()
            }
            Instruction::IType(_) => {
                let mut iter_contents = Vec::with_capacity(IInstruction::COUNT);
                for itype in IInstruction::iter() {
                    iter_contents.push(Instruction::IType(itype));
                }
                iter_contents.into_iter()
            }
            Instruction::SType(_) => {
                let mut iter_contents = Vec::with_capacity(SInstruction::COUNT);
                for stype in SInstruction::iter() {
                    iter_contents.push(Instruction::SType(stype));
                }
                iter_contents.into_iter()
            }
            Instruction::SBType(_) => {
                let mut iter_contents = Vec::with_capacity(SBInstruction::COUNT);
                for sbtype in SBInstruction::iter() {
                    iter_contents.push(Instruction::SBType(sbtype));
                }
                iter_contents.into_iter()
            }
            Instruction::UType(_) => {
                let mut iter_contents = Vec::with_capacity(UInstruction::COUNT);
                for utype in UInstruction::iter() {
                    iter_contents.push(Instruction::UType(utype));
                }
                iter_contents.into_iter()
            }
            Instruction::UJType(_) => {
                let mut iter_contents = Vec::with_capacity(UJInstruction::COUNT);
                for ujtype in UJInstruction::iter() {
                    iter_contents.push(Instruction::UJType(ujtype));
                }
                iter_contents.into_iter()
            }
        }
    }
}

impl std::fmt::Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Instruction::RType(rtype) => write!(f, "{}", rtype),
            Instruction::IType(itype) => write!(f, "{}", itype),
            Instruction::SType(stype) => write!(f, "{}", stype),
            Instruction::SBType(sbtype) => write!(f, "{}", sbtype),
            Instruction::UType(utype) => write!(f, "{}", utype),
            Instruction::UJType(ujtype) => write!(f, "{}", ujtype),
        }
    }
}

impl std::fmt::Display for RInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RInstruction::Add => write!(f, "add"),
            RInstruction::Sub => write!(f, "sub"),
            RInstruction::ShiftLeftLogical => write!(f, "sll"),
            RInstruction::SetLessThan => write!(f, "slt"),
            RInstruction::SetLessThanUnsigned => write!(f, "sltu"),
            RInstruction::Xor => write!(f, "xor"),
            RInstruction::ShiftRightLogical => write!(f, "srl"),
            RInstruction::ShiftRightArithmetic => write!(f, "sra"),
            RInstruction::Or => write!(f, "or"),
            RInstruction::And => write!(f, "and"),
            RInstruction::Fence => write!(f, "fence"),
            RInstruction::FenceI => write!(f, "fence.i"),
        }
    }
}

impl std::fmt::Display for IInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IInstruction::LoadByte => write!(f, "lb"),
            IInstruction::LoadHalf => write!(f, "lh"),
            IInstruction::LoadWord => write!(f, "lw"),
            IInstruction::LoadByteUnsigned => write!(f, "lbu"),
            IInstruction::LoadHalfUnsigned => write!(f, "lhu"),
            IInstruction::ShiftLeftLogicalImmediate => write!(f, "slli"),
            IInstruction::ShiftRightLogicalImmediate => write!(f, "srli"),
            IInstruction::ShiftRightArithmeticImmediate => write!(f, "srai"),
            IInstruction::SetLessThanImmediate => write!(f, "slti"),
            IInstruction::SetLessThanImmediateUnsigned => write!(f, "sltiu"),
            IInstruction::AddImmediate => write!(f, "addi"),
            IInstruction::XorImmediate => write!(f, "xori"),
            IInstruction::OrImmediate => write!(f, "ori"),
            IInstruction::AndImmediate => write!(f, "andi"),
        }
    }
}

impl std::fmt::Display for SInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SInstruction::StoreByte => write!(f, "sb"),
            SInstruction::StoreHalf => write!(f, "sh"),
            SInstruction::StoreWord => write!(f, "sw"),
        }
    }
}

impl std::fmt::Display for SBInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SBInstruction::BranchEq => write!(f, "beq"),
            SBInstruction::BranchNeq => write!(f, "bne"),
            SBInstruction::BranchLessThan => write!(f, "blt"),
            SBInstruction::BranchGe => write!(f, "bge"),
            SBInstruction::BranchLessThanUnsigned => write!(f, "bltu"),
            SBInstruction::BranchGreaterThanEqual => write!(f, "bgeu"),
        }
    }
}

impl std::fmt::Display for UInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UInstruction::LoadUpperImmediate => write!(f, "lui"),
            UInstruction::AddUpperImmediate => write!(f, "auipc"),
        }
    }
}

impl std::fmt::Display for UJInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UJInstruction::JumpAndLink => write!(f, "jal"),
            UJInstruction::JumpAndLinkRegister => write!(f, "jalr"),
        }
    }
}
