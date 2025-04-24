//! This module implement an interpreter for the RISCV32 IM instruction set
//! architecture.
//!
//! The implementation mostly follows (and copy) code from the MIPS interpreter
//! available [here](../mips/interpreter.rs).
//!
//! ## Credits
//!
//! We would like to thank the authors of the following documentations:
//! - <https://msyksphinz-self.github.io/riscv-isadoc/html/rvm.html> ([CC BY
//!   4.0](https://creativecommons.org/licenses/by/4.0/)) from
//!   [msyksphinz-self](https://github.com/msyksphinz-self/riscv-isadoc)
//! - <https://www.cs.cornell.edu/courses/cs3410/2024fa/assignments/cpusim/riscv-instructions.pdf>
//!   from the course [CS 3410: Computer System Organization and
//!   Programming](https://www.cs.cornell.edu/courses/cs3410/2024fa/home.html) at
//!   Cornell University.
//!
//! The format and description of each instruction is taken from these sources,
//! and copied in this file for offline reference.
//! If you are the author of the above documentations and would like to add or
//! modify the credits, please open a pull request.
//!
//! For each instruction, we provide the format, description, and the
//! semantic in pseudo-code of the instruction.
//! When `signed` is mentioned in the pseudo-code, it means that the
//! operation is performed as a signed operation (i.e. signed(v) where `v` is a
//! 32 bits value means that `v` must be interpreted as a i32 value in Rust, the
//! most significant bit being the sign - 1 for negative, 0 for positive).
//! By default, unsigned operations are performed.

use super::registers::{REGISTER_CURRENT_IP, REGISTER_HEAP_POINTER, REGISTER_NEXT_IP};
use crate::lookups::{Lookup, LookupTableIDs};
use ark_ff::{One, Zero};
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
    SyscallType(SyscallInstruction),
    MType(MInstruction),
}

// See
// https://www.cs.cornell.edu/courses/cs3410/2024fa/assignments/cpusim/riscv-instructions.pdf
// for the order
#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum RInstruction {
    #[default]
    /// Format: `add rd, rs1, rs2`
    ///
    /// Description: Adds the registers rs1 and rs2 and stores the result in rd.
    /// Arithmetic overflow is ignored and the result is simply the low 32
    /// bits of the result.
    Add, // add
    /// Format: `sub rd, rs1, rs2`
    ///
    /// Description: Subs the register rs2 from rs1 and stores the result in rd.
    /// Arithmetic overflow is ignored and the result is simply the low 32
    /// bits of the result.
    Sub, // sub
    /// Format: `sll rd, rs1, rs2`
    ///
    /// Description: Performs logical left shift on the value in register rs1 by
    /// the shift amount held in the lower 5 bits of register rs2.
    ShiftLeftLogical, // sll
    /// Format: `slt rd, rs1, rs2`
    ///
    /// Description: Place the value 1 in register rd if register rs1 is less
    /// than register rs2 when both are treated as signed numbers, else 0 is
    /// written to rd.
    SetLessThan, // slt
    /// Format: `sltu rd, rs1, rs2`
    ///
    /// Description: Place the value 1 in register rd if register rs1 is less
    /// than register rs2 when both are treated as unsigned numbers, else 0 is
    /// written to rd.
    SetLessThanUnsigned, // sltu
    /// Format: `xor rd, rs1, rs2`
    ///
    /// Description: Performs bitwise XOR on registers rs1 and rs2 and place the
    /// result in rd
    Xor, // xor
    /// Format: `srl rd, rs1, rs2`
    ///
    /// Description: Logical right shift on the value in register rs1 by the
    /// shift amount held in the lower 5 bits of register rs2
    ShiftRightLogical, // srl
    /// Format: `sra rd, rs1, rs2`
    ///
    /// Description: Performs arithmetic right shift on the value in register
    /// rs1 by the shift amount held in the lower 5 bits of register rs2
    ShiftRightArithmetic, // sra
    /// Format: `or rd, rs1, rs2`
    ///
    /// Description: Performs bitwise OR on registers rs1 and rs2 and place the
    /// result in rd
    Or, // or
    /// Format: `and rd, rs1, rs2`
    ///
    /// Description: Performs bitwise AND on registers rs1 and rs2 and place the
    /// result in rd
    And, // and
    /// Format: `fence`
    ///
    /// Description: Used to order device I/O and memory accesses as viewed by
    /// other RISC-V harts and external devices or coprocessors.
    /// Any combination of device input (I), device output (O), memory reads
    /// (R), and memory writes (W) may be ordered with respect to any
    /// combination of the same. Informally, no other RISC-V hart or external
    /// device can observe any operation in the successor set following a FENCE
    /// before any operation in the predecessor set preceding the FENCE.
    Fence, // fence
    /// Format: `fence.i`
    ///
    /// Description: Provides explicit synchronization between writes to
    /// instruction memory and instruction fetches on the same hart.
    FenceI, // fence.i
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum IInstruction {
    #[default]
    /// Format: `lb rd, offset(rs1)`
    ///
    /// Description: Loads a 8-bit value from memory and sign-extends this to
    /// 32 bits before storing it in register rd.
    LoadByte, // lb
    /// Format: `lh rd, offset(rs1)`
    ///
    /// Description: Loads a 16-bit value from memory and sign-extends this to
    /// 32 bits before storing it in register rd.
    LoadHalf, // lh
    /// Format: `lw rd, offset(rs1)`
    ///
    /// Description: Loads a 32-bit value from memory and sign-extends this to
    /// 32 bits before storing it in register rd.
    LoadWord, // lw
    /// Format: `lbu rd, offset(rs1)`
    ///
    /// Description: Loads a 8-bit value from memory and zero-extends this to
    /// 32 bits before storing it in register rd.
    LoadByteUnsigned, // lbu
    /// Format: `lhu rd, offset(rs1)`
    ///
    /// Description: Loads a 16-bit value from memory and zero-extends this to
    /// 32 bits before storing it in register rd.
    LoadHalfUnsigned, // lhu

    /// Format: `slli rd, rs1, shamt`
    ///
    /// Description: Performs logical left shift on the value in register rs1 by
    /// the shift amount held in the lower 5 bits of the immediate
    ShiftLeftLogicalImmediate, // slli
    /// Format: `srli rd, rs1, shamt`
    ///
    /// Description: Performs logical right shift on the value in register rs1
    /// by the shift amount held in the lower 5 bits of the immediate
    ShiftRightLogicalImmediate, // srli
    /// Format: `srai rd, rs1, shamt`
    ///
    /// Description: Performs arithmetic right shift on the value in register
    /// rs1 by the shift amount held in the lower 5 bits of the immediate
    ShiftRightArithmeticImmediate, // srai
    /// Format: `slti rd, rs1, imm`
    ///
    /// Description: Place the value 1 in register rd if register rs1 is less
    /// than the signextended immediate when both are treated as signed numbers,
    /// else 0 is written to rd.
    SetLessThanImmediate, // slti
    /// Format: `sltiu rd, rs1, imm`
    ///
    /// Description: Place the value 1 in register rd if register rs1 is less
    /// than the immediate when both are treated as unsigned numbers, else 0 is
    /// written to rd.
    SetLessThanImmediateUnsigned, // sltiu

    /// Format: `addi rd, rs1, imm`
    ///
    /// Description: Adds the sign-extended 12-bit immediate to register rs1.
    /// Arithmetic overflow is ignored and the result is simply the low 32
    /// bits of the result. ADDI rd, rs1, 0 is used to implement the MV rd, rs1
    /// assembler pseudo-instruction.
    AddImmediate, // addi
    /// Format: `xori rd, rs1, imm`
    ///
    /// Description: Performs bitwise XOR on register rs1 and the sign-extended
    /// 12-bit immediate and place the result in rd Note, “XORI rd, rs1, -1”
    /// performs a bitwise logical inversion of register rs1(assembler
    /// pseudo-instruction NOT rd, rs)
    XorImmediate, // xori
    /// Format: `ori rd, rs1, imm`
    ///
    /// Description: Performs bitwise OR on register rs1 and the sign-extended
    /// 12-bit immediate and place the result in rd
    OrImmediate, // ori
    /// Format: `andi rd, rs1, imm`
    ///
    /// Description: Performs bitwise AND on register rs1 and the sign-extended
    /// 12-bit immediate and place the result in rd
    AndImmediate, // andi

    /// Format: `jalr rd, rs1, imm`
    ///
    /// Description: Jump to address and place return address in rd.
    JumpAndLinkRegister, // jalr
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum SInstruction {
    #[default]
    /// Format: `sb rs2, offset(rs1)`
    ///
    /// Description: Store 8-bit, values from the low bits of register rs2 to
    /// memory.
    StoreByte, // sb
    /// Format: `sh rs2, offset(rs1)`
    ///
    /// Description: Store 16-bit, values from the low bits of register rs2 to
    /// memory.
    StoreHalf, // sh
    /// Format: `sw rs2, offset(rs1)`
    ///
    /// Description: Store 32-bit, values from the low bits of register rs2 to
    /// memory.
    StoreWord, // sw
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum SBInstruction {
    #[default]
    /// Format: `beq rs1, rs2, offset`
    ///
    /// Description: Take the branch if registers rs1 and rs2 are equal.
    BranchEq, // beq
    /// Format: `bne rs1, rs2, offset`
    ///
    /// Description: Take the branch if registers rs1 and rs2 are not equal.
    BranchNeq, // bne
    /// Format: `blt rs1, rs2, offset`
    ///
    /// Description: Take the branch if registers rs1 is less than rs2, using
    /// signed comparison.
    BranchLessThan, // blt
    /// Format: `bge rs1, rs2, offset`
    ///
    /// Description: Take the branch if registers rs1 is greater than or equal
    /// to rs2, using signed comparison.
    BranchGreaterThanEqual, // bge
    /// Format: `bltu rs1, rs2, offset`
    ///
    /// Description: Take the branch if registers rs1 is less than rs2, using
    /// unsigned comparison.
    BranchLessThanUnsigned, // bltu
    /// Format: `bgeu rs1, rs2, offset`
    ///
    /// Description: Take the branch if registers rs1 is greater than or equal
    /// to rs2, using unsigned comparison.
    BranchGreaterThanEqualUnsigned, // bgeu
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum UInstruction {
    #[default]
    /// Format: `lui rd,imm`
    ///
    /// Description: Build 32-bit constants and uses the U-type format. LUI
    /// places the U-immediate value in the top 20 bits of the destination
    /// register rd, filling in the lowest 12 bits with zeros.
    LoadUpperImmediate, // lui
    /// Format: `auipc rd,imm`
    ///
    /// Description: Build pc-relative addresses and uses the U-type format.
    /// AUIPC (Add upper immediate to PC) forms a 32-bit offset from the 20-bit
    /// U-immediate, filling in the lowest 12 bits with zeros, adds this offset
    /// to the pc, then places the result in register rd.
    AddUpperImmediate, // auipc
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum UJInstruction {
    #[default]
    /// Format: `jal rd,imm`
    ///
    /// Description: Jump to address and place return address in rd.
    JumpAndLink, // jal
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum SyscallInstruction {
    #[default]
    SyscallSuccess,
}

/// M extension instructions
/// Following <https://msyksphinz-self.github.io/riscv-isadoc/html/rvm.html>
#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum MInstruction {
    /// Format: `mul rd, rs1, rs2`
    ///
    /// Description: performs an 32-bit 32-bit multiplication of signed rs1
    /// by signed rs2 and places the lower 32 bits in the destination register.
    /// Implementation: `x[rd] = x[rs1] * x[rs2]`
    #[default]
    Mul, // mul
    /// Format: `mulh rd, rs1, rs2`
    ///
    /// Description: performs an 32-bit 32-bit multiplication of signed rs1 by
    /// signed rs2 and places the upper 32 bits in the destination register.
    /// Implementation: `x[rd] = (x[rs1] * x[rs2]) >> 32`
    Mulh, // mulh
    /// Format: `mulhsu rd, rs1, rs2`
    ///
    /// Description: performs an 32-bit 32-bit multiplication of signed rs1 by
    /// unsigned rs2 and places the upper 32 bits in the destination register.
    /// Implementation: `x[rd] = (x[rs1] * x[rs2]) >> 32`
    Mulhsu, // mulhsu
    /// Format: `mulhu rd, rs1, rs2`
    ///
    /// Description: performs an 32-bit 32-bit multiplication of unsigned rs1 by
    /// unsigned rs2 and places the upper 32 bits in the destination register.
    /// Implementation: `x[rd] = (x[rs1] * x[rs2]) >> 32`
    Mulhu, // mulhu
    /// Format: `div rd, rs1, rs2`
    ///
    /// Description: perform an 32 bits by 32 bits signed integer division of
    /// rs1 by rs2, rounding towards zero
    /// Implementation: `x[rd] = x[rs1] /s x[rs2]`
    Div, // div
    /// Format: `divu rd, rs1, rs2`
    ///
    /// Description: performs an 32 bits by 32 bits unsigned integer division of
    /// rs1 by rs2, rounding towards zero.
    /// Implementation: `x[rd] = x[rs1] /u x[rs2]`
    Divu, // divu
    /// Format: `rem rd, rs1, rs2`
    ///
    /// Description: performs an 32 bits by 32 bits signed integer reminder of
    /// rs1 by rs2.
    /// Implementation: `x[rd] = x[rs1] %s x[rs2]`
    Rem, // rem
    /// Format: `remu rd, rs1, rs2`
    ///
    /// Description: performs an 32 bits by 32 bits unsigned integer reminder of
    /// rs1 by rs2.
    /// Implementation: `x[rd] = x[rs1] %u x[rs2]`
    Remu, // remu
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
            Instruction::SyscallType(_) => {
                let mut iter_contents = Vec::with_capacity(SyscallInstruction::COUNT);
                for syscall in SyscallInstruction::iter() {
                    iter_contents.push(Instruction::SyscallType(syscall));
                }
                iter_contents.into_iter()
            }
            Instruction::MType(_) => {
                let mut iter_contents = Vec::with_capacity(MInstruction::COUNT);
                for mtype in MInstruction::iter() {
                    iter_contents.push(Instruction::MType(mtype));
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
            Instruction::SyscallType(_syscall) => write!(f, "ecall"),
            Instruction::MType(mtype) => write!(f, "{}", mtype),
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
            IInstruction::JumpAndLinkRegister => write!(f, "jalr"),
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
            SBInstruction::BranchGreaterThanEqual => write!(f, "bge"),
            SBInstruction::BranchLessThanUnsigned => write!(f, "bltu"),
            SBInstruction::BranchGreaterThanEqualUnsigned => write!(f, "bgeu"),
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
        }
    }
}

impl std::fmt::Display for MInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MInstruction::Mul => write!(f, "mul"),
            MInstruction::Mulh => write!(f, "mulh"),
            MInstruction::Mulhsu => write!(f, "mulhsu"),
            MInstruction::Mulhu => write!(f, "mulhu"),
            MInstruction::Div => write!(f, "div"),
            MInstruction::Divu => write!(f, "divu"),
            MInstruction::Rem => write!(f, "rem"),
            MInstruction::Remu => write!(f, "remu"),
        }
    }
}

pub trait InterpreterEnv {
    /// A position can be seen as an indexed variable
    type Position;

    /// Allocate a new abstract variable for the current step.
    /// The variable can be used to store temporary values.
    /// The variables are "freed" after each step/instruction.
    /// The variable allocation can be seen as an allocation on a stack that is
    /// popped after each step execution.
    /// At the moment, [crate::interpreters::riscv32im::SCRATCH_SIZE]
    /// elements can be allocated. If more temporary variables are required for
    /// an instruction, increase the value
    /// [crate::interpreters::riscv32im::SCRATCH_SIZE]
    fn alloc_scratch(&mut self) -> Self::Position;

    fn alloc_scratch_inverse(&mut self) -> Self::Position;

    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::fmt::Debug
        + Zero
        + One;

    // Returns the variable in the current row corresponding to a given column alias.
    fn variable(&self, column: Self::Position) -> Self::Variable;

    /// Add a constraint to the proof system, asserting that
    /// `assert_equals_zero` is 0.
    fn add_constraint(&mut self, assert_equals_zero: Self::Variable);

    /// Activate the selector for the given instruction.
    fn activate_selector(&mut self, selector: Instruction);

    /// Check that the witness value in `assert_equals_zero` is 0; otherwise abort.
    fn check_is_zero(assert_equals_zero: &Self::Variable);

    /// Assert that the value `assert_equals_zero` is 0, and add a constraint in the proof system.
    fn assert_is_zero(&mut self, assert_equals_zero: Self::Variable) {
        Self::check_is_zero(&assert_equals_zero);
        self.add_constraint(assert_equals_zero);
    }

    /// Check that the witness values in `x` and `y` are equal; otherwise abort.
    fn check_equal(x: &Self::Variable, y: &Self::Variable);

    /// Assert that the values `x` and `y` are equal, and add a constraint in the proof system.
    fn assert_equal(&mut self, x: Self::Variable, y: Self::Variable) {
        // NB: We use a different function to give a better error message for debugging.
        Self::check_equal(&x, &y);
        self.add_constraint(x - y);
    }

    /// Assert that the value `x` is boolean, and add a constraint in the proof system.
    fn assert_boolean(&mut self, x: &Self::Variable);

    fn add_lookup(&mut self, lookup: Lookup<Self::Variable>);

    fn instruction_counter(&self) -> Self::Variable;

    fn increase_instruction_counter(&mut self);

    /// Fetch the value of the general purpose register with index `idx` and store it in local
    /// position `output`.
    ///
    /// # Safety
    ///
    /// No lookups or other constraints are added as part of this operation. The caller must
    /// manually add the lookups for this operation.
    unsafe fn fetch_register(
        &mut self,
        idx: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable;

    /// Set the general purpose register with index `idx` to `value` if `if_is_true` is true.
    ///
    /// # Safety
    ///
    /// No lookups or other constraints are added as part of this operation. The caller must
    /// manually add the lookups for this operation.
    unsafe fn push_register_if(
        &mut self,
        idx: &Self::Variable,
        value: Self::Variable,
        if_is_true: &Self::Variable,
    );

    /// Set the general purpose register with index `idx` to `value`.
    ///
    /// # Safety
    ///
    /// No lookups or other constraints are added as part of this operation. The caller must
    /// manually add the lookups for this operation.
    unsafe fn push_register(&mut self, idx: &Self::Variable, value: Self::Variable) {
        self.push_register_if(idx, value, &Self::constant(1))
    }

    /// Fetch the last 'access index' for the general purpose register with index `idx`, and store
    /// it in local position `output`.
    ///
    /// # Safety
    ///
    /// No lookups or other constraints are added as part of this operation. The caller must
    /// manually add the lookups for this operation.
    unsafe fn fetch_register_access(
        &mut self,
        idx: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable;

    /// Set the last 'access index' for the general purpose register with index `idx` to `value` if
    /// `if_is_true` is true.
    ///
    /// # Safety
    ///
    /// No lookups or other constraints are added as part of this operation. The caller must
    /// manually add the lookups for this operation.
    unsafe fn push_register_access_if(
        &mut self,
        idx: &Self::Variable,
        value: Self::Variable,
        if_is_true: &Self::Variable,
    );

    /// Set the last 'access index' for the general purpose register with index `idx` to `value`.
    ///
    /// # Safety
    ///
    /// No lookups or other constraints are added as part of this operation. The caller must
    /// manually add the lookups for this operation.
    unsafe fn push_register_access(&mut self, idx: &Self::Variable, value: Self::Variable) {
        self.push_register_access_if(idx, value, &Self::constant(1))
    }

    /// Access the general purpose register with index `idx`, adding constraints asserting that the
    /// old value was `old_value` and that the new value will be `new_value`, if `if_is_true` is
    /// true.
    ///
    /// # Safety
    ///
    /// Callers of this function must manually update the registers if required, this function will
    /// only update the access counter.
    unsafe fn access_register_if(
        &mut self,
        idx: &Self::Variable,
        old_value: &Self::Variable,
        new_value: &Self::Variable,
        if_is_true: &Self::Variable,
    ) {
        let last_accessed = {
            let last_accessed_location = self.alloc_scratch();
            unsafe { self.fetch_register_access(idx, last_accessed_location) }
        };
        let instruction_counter = self.instruction_counter();
        let elapsed_time = instruction_counter.clone() - last_accessed.clone();
        let new_accessed = {
            // Here, we write as if the register had been written *at the start of the next
            // instruction*. This ensures that we can't 'time travel' within this
            // instruction, and claim to read the value that we're about to write!
            instruction_counter + Self::constant(1)
            // A register should allow multiple accesses to the same register within the same instruction.
            // In order to allow this, we always increase the instruction counter by 1.
        };
        unsafe { self.push_register_access_if(idx, new_accessed.clone(), if_is_true) };
        self.add_lookup(Lookup::write_if(
            if_is_true.clone(),
            LookupTableIDs::RegisterLookup,
            vec![idx.clone(), last_accessed, old_value.clone()],
        ));
        self.add_lookup(Lookup::read_if(
            if_is_true.clone(),
            LookupTableIDs::RegisterLookup,
            vec![idx.clone(), new_accessed, new_value.clone()],
        ));
        self.range_check64(&elapsed_time);

        // Update instruction counter after accessing a register.
        self.increase_instruction_counter();
    }

    fn read_register(&mut self, idx: &Self::Variable) -> Self::Variable {
        let value = {
            let value_location = self.alloc_scratch();
            unsafe { self.fetch_register(idx, value_location) }
        };
        unsafe {
            self.access_register(idx, &value, &value);
        };
        value
    }

    /// Access the general purpose register with index `idx`, adding constraints asserting that the
    /// old value was `old_value` and that the new value will be `new_value`.
    ///
    /// # Safety
    ///
    /// Callers of this function must manually update the registers if required, this function will
    /// only update the access counter.
    unsafe fn access_register(
        &mut self,
        idx: &Self::Variable,
        old_value: &Self::Variable,
        new_value: &Self::Variable,
    ) {
        self.access_register_if(idx, old_value, new_value, &Self::constant(1))
    }

    fn write_register_if(
        &mut self,
        idx: &Self::Variable,
        new_value: Self::Variable,
        if_is_true: &Self::Variable,
    ) {
        let old_value = {
            let value_location = self.alloc_scratch();
            unsafe { self.fetch_register(idx, value_location) }
        };
        // Ensure that we only write 0 to the 0 register.
        let actual_new_value = {
            let idx_is_zero = self.is_zero(idx);
            let pos = self.alloc_scratch();
            self.copy(&((Self::constant(1) - idx_is_zero) * new_value), pos)
        };
        unsafe {
            self.access_register_if(idx, &old_value, &actual_new_value, if_is_true);
        };
        unsafe {
            self.push_register_if(idx, actual_new_value, if_is_true);
        };
    }

    fn write_register(&mut self, idx: &Self::Variable, new_value: Self::Variable) {
        self.write_register_if(idx, new_value, &Self::constant(1))
    }

    /// Fetch the memory value at address `addr` and store it in local position `output`.
    ///
    /// # Safety
    ///
    /// No lookups or other constraints are added as part of this operation. The caller must
    /// manually add the lookups for this memory operation.
    unsafe fn fetch_memory(
        &mut self,
        addr: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable;

    /// Set the memory value at address `addr` to `value`.
    ///
    /// # Safety
    ///
    /// No lookups or other constraints are added as part of this operation. The caller must
    /// manually add the lookups for this memory operation.
    unsafe fn push_memory(&mut self, addr: &Self::Variable, value: Self::Variable);

    /// Fetch the last 'access index' that the memory at address `addr` was written at, and store
    /// it in local position `output`.
    ///
    /// # Safety
    ///
    /// No lookups or other constraints are added as part of this operation. The caller must
    /// manually add the lookups for this memory operation.
    unsafe fn fetch_memory_access(
        &mut self,
        addr: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable;

    /// Set the last 'access index' for the memory at address `addr` to `value`.
    ///
    /// # Safety
    ///
    /// No lookups or other constraints are added as part of this operation. The caller must
    /// manually add the lookups for this memory operation.
    unsafe fn push_memory_access(&mut self, addr: &Self::Variable, value: Self::Variable);

    /// Access the memory address `addr`, adding constraints asserting that the old value was
    /// `old_value` and that the new value will be `new_value`.
    ///
    /// # Safety
    ///
    /// Callers of this function must manually update the memory if required, this function will
    /// only update the access counter.
    unsafe fn access_memory(
        &mut self,
        addr: &Self::Variable,
        old_value: &Self::Variable,
        new_value: &Self::Variable,
    ) {
        let last_accessed = {
            let last_accessed_location = self.alloc_scratch();
            unsafe { self.fetch_memory_access(addr, last_accessed_location) }
        };
        let instruction_counter = self.instruction_counter();
        let elapsed_time = instruction_counter.clone() - last_accessed.clone();
        let new_accessed = {
            // Here, we write as if the memory had been written *at the start of the next
            // instruction*. This ensures that we can't 'time travel' within this
            // instruction, and claim to read the value that we're about to write!
            instruction_counter + Self::constant(1)
        };
        unsafe { self.push_memory_access(addr, new_accessed.clone()) };
        self.add_lookup(Lookup::write_one(
            LookupTableIDs::MemoryLookup,
            vec![addr.clone(), last_accessed, old_value.clone()],
        ));
        self.add_lookup(Lookup::read_one(
            LookupTableIDs::MemoryLookup,
            vec![addr.clone(), new_accessed, new_value.clone()],
        ));
        self.range_check64(&elapsed_time);

        // Update instruction counter after accessing a memory address.
        self.increase_instruction_counter();
    }

    fn read_memory(&mut self, addr: &Self::Variable) -> Self::Variable {
        let value = {
            let value_location = self.alloc_scratch();
            unsafe { self.fetch_memory(addr, value_location) }
        };
        unsafe {
            self.access_memory(addr, &value, &value);
        };
        value
    }

    fn write_memory(&mut self, addr: &Self::Variable, new_value: Self::Variable) {
        let old_value = {
            let value_location = self.alloc_scratch();
            unsafe { self.fetch_memory(addr, value_location) }
        };
        unsafe {
            self.access_memory(addr, &old_value, &new_value);
        };
        unsafe {
            self.push_memory(addr, new_value);
        };
    }

    /// Adds a lookup to the RangeCheck16Lookup table
    fn lookup_16bits(&mut self, value: &Self::Variable) {
        self.add_lookup(Lookup::read_one(
            LookupTableIDs::RangeCheck16Lookup,
            vec![value.clone()],
        ));
    }

    /// Range checks with 2 lookups to the RangeCheck16Lookup table that a value
    /// is at most 2^`bits`-1  (bits <= 16).
    fn range_check16(&mut self, value: &Self::Variable, bits: u32) {
        assert!(bits <= 16);
        // 0 <= value < 2^bits
        // First, check lowerbound: 0 <= value < 2^16
        self.lookup_16bits(value);
        // Second, check upperbound: value + 2^16 - 2^bits < 2^16
        self.lookup_16bits(&(value.clone() + Self::constant(1 << 16) - Self::constant(1 << bits)));
    }

    /// Adds a lookup to the ByteLookup table
    fn lookup_8bits(&mut self, value: &Self::Variable) {
        self.add_lookup(Lookup::read_one(
            LookupTableIDs::ByteLookup,
            vec![value.clone()],
        ));
    }

    /// Range checks with 2 lookups to the ByteLookup table that a value
    /// is at most 2^`bits`-1  (bits <= 8).
    fn range_check8(&mut self, value: &Self::Variable, bits: u32) {
        assert!(bits <= 8);
        // 0 <= value < 2^bits
        // First, check lowerbound: 0 <= value < 2^8
        self.lookup_8bits(value);
        // Second, check upperbound: value + 2^8 - 2^bits < 2^8
        self.lookup_8bits(&(value.clone() + Self::constant(1 << 8) - Self::constant(1 << bits)));
    }

    /// Adds a lookup to the AtMost4Lookup table
    fn lookup_2bits(&mut self, value: &Self::Variable) {
        self.add_lookup(Lookup::read_one(
            LookupTableIDs::AtMost4Lookup,
            vec![value.clone()],
        ));
    }

    fn range_check64(&mut self, _value: &Self::Variable) {
        // TODO
    }

    fn set_instruction_pointer(&mut self, ip: Self::Variable) {
        let idx = Self::constant(REGISTER_CURRENT_IP as u32);
        let new_accessed = self.instruction_counter() + Self::constant(1);
        unsafe {
            self.push_register_access(&idx, new_accessed.clone());
        }
        unsafe {
            self.push_register(&idx, ip.clone());
        }
        self.add_lookup(Lookup::read_one(
            LookupTableIDs::RegisterLookup,
            vec![idx, new_accessed, ip],
        ));
    }

    fn get_instruction_pointer(&mut self) -> Self::Variable {
        let idx = Self::constant(REGISTER_CURRENT_IP as u32);
        let ip = {
            let value_location = self.alloc_scratch();
            unsafe { self.fetch_register(&idx, value_location) }
        };
        self.add_lookup(Lookup::write_one(
            LookupTableIDs::RegisterLookup,
            vec![idx, self.instruction_counter(), ip.clone()],
        ));
        ip
    }

    fn set_next_instruction_pointer(&mut self, ip: Self::Variable) {
        let idx = Self::constant(REGISTER_NEXT_IP as u32);
        let new_accessed = self.instruction_counter() + Self::constant(1);
        unsafe {
            self.push_register_access(&idx, new_accessed.clone());
        }
        unsafe {
            self.push_register(&idx, ip.clone());
        }
        self.add_lookup(Lookup::read_one(
            LookupTableIDs::RegisterLookup,
            vec![idx, new_accessed, ip],
        ));
    }

    fn get_next_instruction_pointer(&mut self) -> Self::Variable {
        let idx = Self::constant(REGISTER_NEXT_IP as u32);
        let ip = {
            let value_location = self.alloc_scratch();
            unsafe { self.fetch_register(&idx, value_location) }
        };
        self.add_lookup(Lookup::write_one(
            LookupTableIDs::RegisterLookup,
            vec![idx, self.instruction_counter(), ip.clone()],
        ));
        ip
    }

    fn constant(x: u32) -> Self::Variable;

    /// Extract the bits from the variable `x` between `highest_bit` and `lowest_bit`, and store
    /// the result in `position`.
    /// `lowest_bit` becomes the least-significant bit of the resulting value.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned value; callers must assert the relationship with
    /// the source variable `x` and that the returned value fits in `highest_bit - lowest_bit`
    /// bits.
    ///
    /// Do not call this function with highest_bit - lowest_bit >= 32.
    // TODO: embed the range check in the function when highest_bit - lowest_bit <= 16?
    unsafe fn bitmask(
        &mut self,
        x: &Self::Variable,
        highest_bit: u32,
        lowest_bit: u32,
        position: Self::Position,
    ) -> Self::Variable;

    /// Return the result of shifting `x` by `by`, storing the result in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned value; callers must assert the relationship with
    /// the source variable `x` and the shift amount `by`.
    unsafe fn shift_left(
        &mut self,
        x: &Self::Variable,
        by: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Return the result of shifting `x` by `by`, storing the result in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned value; callers must assert the relationship with
    /// the source variable `x` and the shift amount `by`.
    unsafe fn shift_right(
        &mut self,
        x: &Self::Variable,
        by: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Return the result of shifting `x` by `by`, storing the result in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned value; callers must assert the relationship with
    /// the source variable `x` and the shift amount `by`.
    unsafe fn shift_right_arithmetic(
        &mut self,
        x: &Self::Variable,
        by: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Returns 1 if `x` is 0, or 0 otherwise, storing the result in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned value; callers must assert the relationship with
    /// `x`.
    unsafe fn test_zero(&mut self, x: &Self::Variable, position: Self::Position) -> Self::Variable;

    fn is_zero(&mut self, x: &Self::Variable) -> Self::Variable;

    /// Returns 1 if `x` is equal to `y`, or 0 otherwise, storing the result in `position`.
    fn equal(&mut self, x: &Self::Variable, y: &Self::Variable) -> Self::Variable;

    /// Returns 1 if `x < y` as unsigned integers, or 0 otherwise, storing the result in
    /// `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned value; callers must assert that the value
    /// correctly represents the relationship between `x` and `y`
    unsafe fn test_less_than(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Returns 1 if `x < y` as signed integers, or 0 otherwise, storing the result in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned value; callers must assert that the value
    /// correctly represents the relationship between `x` and `y`
    unsafe fn test_less_than_signed(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Returns `x or y`, storing the result in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned value; callers must manually add constraints to
    /// ensure that it is correctly constructed.
    unsafe fn and_witness(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Returns `x or y`, storing the result in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned value; callers must manually add constraints to
    /// ensure that it is correctly constructed.
    unsafe fn or_witness(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Returns `x nor y`, storing the result in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned value; callers must manually add constraints to
    /// ensure that it is correctly constructed.
    unsafe fn nor_witness(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Returns `x xor y`, storing the result in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned value; callers must manually add constraints to
    /// ensure that it is correctly constructed.
    unsafe fn xor_witness(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Returns `x + y` and the overflow bit, storing the results in `position_out` and
    /// `position_overflow` respectively.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned values; callers must manually add constraints to
    /// ensure that they are correctly constructed.
    unsafe fn add_witness(
        &mut self,
        y: &Self::Variable,
        x: &Self::Variable,
        out_position: Self::Position,
        overflow_position: Self::Position,
    ) -> (Self::Variable, Self::Variable);

    /// Returns `x + y` and the underflow bit, storing the results in `position_out` and
    /// `position_underflow` respectively.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned values; callers must manually add constraints to
    /// ensure that they are correctly constructed.
    unsafe fn sub_witness(
        &mut self,
        y: &Self::Variable,
        x: &Self::Variable,
        out_position: Self::Position,
        underflow_position: Self::Position,
    ) -> (Self::Variable, Self::Variable);

    /// Returns `x * y`, where `x` and `y` are treated as integers, storing the result in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned value; callers must manually add constraints to
    /// ensure that it is correctly constructed.
    unsafe fn mul_signed_witness(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Returns `((x * y) >> 32`, storing the results in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned values; callers must manually add constraints to
    /// ensure that the pair of returned values correspond to the given values `x` and `y`, and
    /// that they fall within the desired range.
    unsafe fn mul_hi_signed(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Returns `(x * y) & ((1 << 32) - 1))`, storing the results in `position`
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned values; callers must manually add constraints to
    /// ensure that the pair of returned values correspond to the given values `x` and `y`, and
    /// that they fall within the desired range.
    unsafe fn mul_lo_signed(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Returns `((x * y) >> 32`, storing the results in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned values; callers must manually add constraints to
    /// ensure that the pair of returned values correspond to the given values `x` and `y`, and
    /// that they fall within the desired range.
    unsafe fn mul_hi(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Returns `(x * y) & ((1 << 32) - 1))`, storing the results in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned values; callers must manually add constraints to
    /// ensure that the pair of returned values correspond to the given values `x` and `y`, and
    /// that they fall within the desired range.
    unsafe fn mul_lo(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Returns `((x * y) >> 32`, storing the results in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned values; callers must manually add constraints to
    /// ensure that the pair of returned values correspond to the given values `x` and `y`, and
    /// that they fall within the desired range.
    unsafe fn mul_hi_signed_unsigned(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Returns `x / y`, storing the results in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned values; callers must manually add constraints to
    /// ensure that the pair of returned values correspond to the given values `x` and `y`, and
    /// that they fall within the desired range.
    ///
    /// Division by zero will create a panic! exception. The RISC-V
    /// specification leaves the case unspecified, and therefore we prefer to
    /// forbid this case while building the witness.
    unsafe fn div_signed(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Returns `x % y`, storing the results in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned values; callers must manually add constraints to
    /// ensure that the pair of returned values correspond to the given values `x` and `y`, and
    /// that they fall within the desired range.
    unsafe fn mod_signed(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Returns `x / y`, storing the results in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned values; callers must manually add constraints to
    /// ensure that the pair of returned values correspond to the given values `x` and `y`, and
    /// that they fall within the desired range.
    ///
    /// Division by zero will create a panic! exception. The RISC-V
    /// specification leaves the case unspecified, and therefore we prefer to
    /// forbid this case while building the witness.
    unsafe fn div(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Returns `x % y`, storing the results in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned values; callers must manually add constraints to
    /// ensure that the pair of returned values correspond to the given values `x` and `y`, and
    /// that they fall within the desired range.
    unsafe fn mod_unsigned(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Returns the number of leading 0s in `x`, storing the result in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned value; callers must manually add constraints to
    /// ensure that it is correctly constructed.
    unsafe fn count_leading_zeros(
        &mut self,
        x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    /// Returns the number of leading 1s in `x`, storing the result in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned value; callers must manually add constraints to
    /// ensure that it is correctly constructed.
    unsafe fn count_leading_ones(
        &mut self,
        x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    fn copy(&mut self, x: &Self::Variable, position: Self::Position) -> Self::Variable;

    /// Increases the heap pointer by `by_amount` if `if_is_true` is `1`, and returns the previous
    /// value of the heap pointer.
    fn increase_heap_pointer(
        &mut self,
        by_amount: &Self::Variable,
        if_is_true: &Self::Variable,
    ) -> Self::Variable {
        let idx = Self::constant(REGISTER_HEAP_POINTER as u32);
        let old_ptr = {
            let value_location = self.alloc_scratch();
            unsafe { self.fetch_register(&idx, value_location) }
        };
        let new_ptr = old_ptr.clone() + by_amount.clone();
        unsafe {
            self.access_register_if(&idx, &old_ptr, &new_ptr, if_is_true);
        };
        unsafe {
            self.push_register_if(&idx, new_ptr, if_is_true);
        };
        old_ptr
    }

    fn set_halted(&mut self, flag: Self::Variable);

    /// Given a variable `x`, this function extends it to a signed integer of
    /// `bitlength` bits.
    fn sign_extend(&mut self, x: &Self::Variable, bitlength: u32) -> Self::Variable {
        assert!(bitlength <= 32);
        // FIXME: Constrain `high_bit`
        let high_bit = {
            let pos = self.alloc_scratch();
            unsafe { self.bitmask(x, bitlength, bitlength - 1, pos) }
        };
        // Casting in u64 for special case of bitlength = 0 to avoid overflow.
        // No condition for constant time execution.
        // Decomposing the steps for readability.
        let v: u64 = (1u64 << (32 - bitlength)) - 1;
        let v: u64 = v << bitlength;
        let v: u32 = v as u32;
        high_bit * Self::constant(v) + x.clone()
    }

    fn report_exit(&mut self, exit_code: &Self::Variable);

    fn reset(&mut self);
}

pub fn interpret_instruction<Env: InterpreterEnv>(env: &mut Env, instr: Instruction) {
    env.activate_selector(instr);
    match instr {
        Instruction::RType(rtype) => interpret_rtype(env, rtype),
        Instruction::IType(itype) => interpret_itype(env, itype),
        Instruction::SType(stype) => interpret_stype(env, stype),
        Instruction::SBType(sbtype) => interpret_sbtype(env, sbtype),
        Instruction::UType(utype) => interpret_utype(env, utype),
        Instruction::UJType(ujtype) => interpret_ujtype(env, ujtype),
        Instruction::SyscallType(syscall) => interpret_syscall(env, syscall),
        Instruction::MType(mtype) => interpret_mtype(env, mtype),
    }
}

/// Interpret an R-type instruction.
/// The encoding of an R-type instruction is as follows:
/// ```text
/// | 31               25 | 24      20 | 19     15 | 14        12 | 11    7 | 6      0 |
/// | funct5 & funct 2    |     rs2    |    rs1    |    funct3    |    rd   |  opcode  |
/// ```
/// Following the documentation found
/// [here](https://www.cs.cornell.edu/courses/cs3410/2024fa/assignments/cpusim/riscv-instructions.pdf)
pub fn interpret_rtype<Env: InterpreterEnv>(env: &mut Env, instr: RInstruction) {
    let instruction_pointer = env.get_instruction_pointer();
    let next_instruction_pointer = env.get_next_instruction_pointer();

    let instruction = {
        let v0 = env.read_memory(&instruction_pointer);
        let v1 = env.read_memory(&(instruction_pointer.clone() + Env::constant(1)));
        let v2 = env.read_memory(&(instruction_pointer.clone() + Env::constant(2)));
        let v3 = env.read_memory(&(instruction_pointer.clone() + Env::constant(3)));
        (v3 * Env::constant(1 << 24))
            + (v2 * Env::constant(1 << 16))
            + (v1 * Env::constant(1 << 8))
            + v0
    };

    // FIXME: constrain the opcode to match the instruction given as a parameter
    let opcode = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 7, 0, pos) }
    };
    env.range_check8(&opcode, 7);

    let rd = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 12, 7, pos) }
    };
    env.range_check8(&rd, 5);

    let funct3 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 15, 12, pos) }
    };
    env.range_check8(&funct3, 3);

    let rs1 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 20, 15, pos) }
    };
    env.range_check8(&rs1, 5);

    let rs2 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 25, 20, pos) }
    };
    env.range_check8(&rs2, 5);

    let funct2 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 27, 25, pos) }
    };
    env.range_check8(&funct2, 2);

    let funct5 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 32, 27, pos) }
    };
    env.range_check8(&funct5, 5);

    // Check correctness of decomposition
    env.add_constraint(
        instruction
    - (opcode.clone() * Env::constant(1 << 0))    // opcode at bits 0-6
    - (rd.clone() * Env::constant(1 << 7))        // rd at bits 7-11
    - (funct3.clone() * Env::constant(1 << 12))   // funct3 at bits 12-14
    - (rs1.clone() * Env::constant(1 << 15))      // rs1 at bits 15-19
    - (rs2.clone() * Env::constant(1 << 20))      // rs2 at bits 20-24
    - (funct2.clone() * Env::constant(1 << 25))   // funct2 at bits 25-26
    - (funct5.clone() * Env::constant(1 << 27)), // funct5 at bits 27-31
    );

    match instr {
        RInstruction::Add => {
            // add: x[rd] = x[rs1] + x[rs2]
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let local_rd = {
                let overflow_scratch = env.alloc_scratch();
                let rd_scratch = env.alloc_scratch();
                let (local_rd, _overflow) = unsafe {
                    env.add_witness(&local_rs1, &local_rs2, rd_scratch, overflow_scratch)
                };
                local_rd
            };
            env.write_register(&rd, local_rd);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::Sub => {
            /* sub: x[rd] = x[rs1] - x[rs2] */
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let local_rd = {
                let underflow_scratch = env.alloc_scratch();
                let rd_scratch = env.alloc_scratch();
                let (local_rd, _underflow) = unsafe {
                    env.sub_witness(&local_rs1, &local_rs2, rd_scratch, underflow_scratch)
                };
                local_rd
            };
            env.write_register(&rd, local_rd);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::ShiftLeftLogical => {
            /* sll: x[rd] = x[rs1] << x[rs2] */
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let local_rd = {
                let rd_scratch = env.alloc_scratch();
                unsafe { env.shift_left(&local_rs1, &local_rs2, rd_scratch) }
            };
            env.write_register(&rd, local_rd);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::SetLessThan => {
            /* slt: x[rd] = (x[rs1] < x[rs2]) ? 1 : 0 */
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let local_rd = {
                let rd_scratch = env.alloc_scratch();
                unsafe { env.test_less_than_signed(&local_rs1, &local_rs2, rd_scratch) }
            };
            env.write_register(&rd, local_rd);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::SetLessThanUnsigned => {
            /* sltu: x[rd] = (x[rs1] < (u)x[rs2]) ? 1 : 0 */
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let local_rd = {
                let pos = env.alloc_scratch();
                unsafe { env.test_less_than(&local_rs1, &local_rs2, pos) }
            };
            env.write_register(&rd, local_rd);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::Xor => {
            /* xor: x[rd] = x[rs1] ^ x[rs2] */
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let local_rd = {
                let pos = env.alloc_scratch();
                unsafe { env.xor_witness(&local_rs1, &local_rs2, pos) }
            };
            env.write_register(&rd, local_rd);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::ShiftRightLogical => {
            /* srl: x[rd] = x[rs1] >> x[rs2] */
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let local_rd = {
                let pos = env.alloc_scratch();
                unsafe { env.shift_right(&local_rs1, &local_rs2, pos) }
            };
            env.write_register(&rd, local_rd);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::ShiftRightArithmetic => {
            /* sra: x[rd] = x[rs1] >> x[rs2] */
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let local_rd = {
                let pos = env.alloc_scratch();
                unsafe { env.shift_right_arithmetic(&local_rs1, &local_rs2, pos) }
            };
            env.write_register(&rd, local_rd);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::Or => {
            /* or: x[rd] = x[rs1] | x[rs2] */
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let local_rd = {
                let pos = env.alloc_scratch();
                unsafe { env.or_witness(&local_rs1, &local_rs2, pos) }
            };
            env.write_register(&rd, local_rd);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::And => {
            /* and: x[rd] = x[rs1] & x[rs2] */
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let local_rd = {
                let pos = env.alloc_scratch();
                unsafe { env.and_witness(&local_rs1, &local_rs2, pos) }
            };
            env.write_register(&rd, local_rd);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::Fence => {
            unimplemented!("Fence")
        }
        RInstruction::FenceI => {
            unimplemented!("FenceI")
        }
    };
}

/// Interpret an I-type instruction.
/// The encoding of an I-type instruction is as follows:
/// ```text
/// | 31     20 | 19     15 | 14    12 | 11    7 | 6      0 |
/// | immediate |    rs1    |  funct3  |    rd   |  opcode  |
/// ```
/// Following the documentation found
/// [here](https://www.cs.cornell.edu/courses/cs3410/2024fa/assignments/cpusim/riscv-instructions.pdf)
pub fn interpret_itype<Env: InterpreterEnv>(env: &mut Env, instr: IInstruction) {
    let instruction_pointer = env.get_instruction_pointer();
    let next_instruction_pointer = env.get_next_instruction_pointer();

    let instruction = {
        let v0 = env.read_memory(&instruction_pointer);
        let v1 = env.read_memory(&(instruction_pointer.clone() + Env::constant(1)));
        let v2 = env.read_memory(&(instruction_pointer.clone() + Env::constant(2)));
        let v3 = env.read_memory(&(instruction_pointer.clone() + Env::constant(3)));
        (v3 * Env::constant(1 << 24))
            + (v2 * Env::constant(1 << 16))
            + (v1 * Env::constant(1 << 8))
            + v0
    };

    let opcode = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 7, 0, pos) }
    };
    env.range_check8(&opcode, 7);

    let rd = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 12, 7, pos) }
    };
    env.range_check8(&rd, 5);

    let funct3 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 15, 12, pos) }
    };
    env.range_check8(&funct3, 3);

    let rs1 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 20, 15, pos) }
    };
    env.range_check8(&rs1, 5);

    let imm = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 32, 20, pos) }
    };

    env.range_check16(&imm, 12);

    let shamt = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&imm, 5, 0, pos) }
    };
    env.range_check8(&shamt, 5);

    let imm_header = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&imm, 12, 5, pos) }
    };
    env.range_check8(&imm_header, 7);

    // check the correctness of the immediate and shamt
    env.add_constraint(imm.clone() - (imm_header.clone() * Env::constant(1 << 5)) - shamt.clone());

    // check correctness of decomposition
    env.add_constraint(
        instruction
            - (opcode.clone() * Env::constant(1 << 0))    // opcode at bits 0-6
            - (rd.clone() * Env::constant(1 << 7))        // rd at bits 7-11
            - (funct3.clone() * Env::constant(1 << 12))   // funct3 at bits 12-14
            - (rs1.clone() * Env::constant(1 << 15))      // rs1 at bits 15-19
            - (imm.clone() * Env::constant(1 << 20)), // imm at bits 20-32
    );

    match instr {
        IInstruction::LoadByte => {
            // lb:  x[rd] = sext(M[x[rs1] + sext(offset)][7:0])
            let local_rs1 = env.read_register(&rs1);
            let local_imm = env.sign_extend(&imm, 12);
            let address = {
                let address_scratch = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (address, _overflow) = unsafe {
                    env.add_witness(&local_rs1, &local_imm, address_scratch, overflow_scratch)
                };
                address
            };
            // Add a range check here for address
            let value = env.read_memory(&address);
            let value = env.sign_extend(&value, 8);
            env.write_register(&rd, value);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::LoadHalf => {
            // lh:  x[rd] = sext(M[x[rs1] + sext(offset)][15:0])
            let local_rs1 = env.read_register(&rs1);
            let local_imm = env.sign_extend(&imm, 12);
            let address = {
                let address_scratch = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (address, _overflow) = unsafe {
                    env.add_witness(&local_rs1, &local_imm, address_scratch, overflow_scratch)
                };
                address
            };
            // Add a range check here for address
            let v0 = env.read_memory(&address);
            let v1 = env.read_memory(&(address.clone() + Env::constant(1)));
            let value = (v0 * Env::constant(1 << 8)) + v1;
            let value = env.sign_extend(&value, 16);
            env.write_register(&rd, value);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::LoadWord => {
            // lw:  x[rd] = sext(M[x[rs1] + sext(offset)][31:0])
            let base = env.read_register(&rs1);
            let offset = env.sign_extend(&imm, 12);
            let address = {
                let address_scratch = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (address, _overflow) =
                    unsafe { env.add_witness(&base, &offset, address_scratch, overflow_scratch) };
                address
            };
            // Add a range check here for address
            let v0 = env.read_memory(&address);
            let v1 = env.read_memory(&(address.clone() + Env::constant(1)));
            let v2 = env.read_memory(&(address.clone() + Env::constant(2)));
            let v3 = env.read_memory(&(address.clone() + Env::constant(3)));
            let value = (v0 * Env::constant(1 << 24))
                + (v1 * Env::constant(1 << 16))
                + (v2 * Env::constant(1 << 8))
                + v3;
            let value = env.sign_extend(&value, 32);
            env.write_register(&rd, value);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::LoadByteUnsigned => {
            //lbu: x[rd] = M[x[rs1] + sext(offset)][7:0]
            let local_rs1 = env.read_register(&rs1);
            let local_imm = env.sign_extend(&imm, 12);
            let address = {
                let address_scratch = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (address, _overflow) = unsafe {
                    env.add_witness(&local_rs1, &local_imm, address_scratch, overflow_scratch)
                };
                address
            };
            // lhu: Add a range check here for address
            let value = env.read_memory(&address);
            env.write_register(&rd, value);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::LoadHalfUnsigned => {
            // lhu: x[rd] = M[x[rs1] + sext(offset)][15:0]
            let local_rs1 = env.read_register(&rs1);
            let local_imm = env.sign_extend(&imm, 12);
            let address = {
                let address_scratch = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (address, _overflow) = unsafe {
                    env.add_witness(&local_rs1, &local_imm, address_scratch, overflow_scratch)
                };
                address
            };
            // Add a range check here for address
            let v0 = env.read_memory(&address);
            let v1 = env.read_memory(&(address.clone() + Env::constant(1)));
            let value = (v0 * Env::constant(1 << 8)) + v1;
            env.write_register(&rd, value);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::ShiftLeftLogicalImmediate => {
            // slli: x[rd] = x[rs1] << shamt
            let local_rs1 = env.read_register(&rs1);

            let local_rd = {
                let pos = env.alloc_scratch();
                unsafe { env.shift_left(&local_rs1, &shamt.clone(), pos) }
            };

            env.write_register(&rd, local_rd);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::ShiftRightLogicalImmediate => {
            // srli: x[rd] = x[rs1] >> shamt
            let local_rs1 = env.read_register(&rs1);
            let local_rd = {
                let pos = env.alloc_scratch();
                unsafe { env.shift_right(&local_rs1, &shamt, pos) }
            };
            env.write_register(&rd, local_rd);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::ShiftRightArithmeticImmediate => {
            // srai: x[rd] = x[rs1] >> shamt
            let local_rs1 = env.read_register(&rs1);

            let local_rd = {
                let pos = env.alloc_scratch();
                unsafe { env.shift_right_arithmetic(&local_rs1, &shamt, pos) }
            };
            env.write_register(&rd, local_rd);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::SetLessThanImmediate => {
            // slti: x[rd] = (x[rs1] < sext(immediate)) ? 1 : 0
            let local_rs1 = env.read_register(&rs1);
            let local_imm = env.sign_extend(&imm, 12);
            let local_rd = {
                let pos = env.alloc_scratch();
                unsafe { env.test_less_than_signed(&local_rs1, &local_imm, pos) }
            };
            env.write_register(&rd, local_rd);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::SetLessThanImmediateUnsigned => {
            // sltiu: x[rd] = (x[rs1] < (u)sext(immediate)) ? 1 : 0
            let local_rs1 = env.read_register(&rs1);
            let local_imm = env.sign_extend(&imm, 12);
            let local_rd = {
                let pos = env.alloc_scratch();
                unsafe { env.test_less_than(&local_rs1, &local_imm, pos) }
            };
            env.write_register(&rd, local_rd);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::AddImmediate => {
            // addi: x[rd] = x[rs1] + sext(immediate)
            let local_rs1 = env.read_register(&(rs1.clone()));
            let local_imm = env.sign_extend(&imm, 12);
            let local_rd = {
                let overflow_scratch = env.alloc_scratch();
                let rd_scratch = env.alloc_scratch();
                let (local_rd, _overflow) = unsafe {
                    env.add_witness(&local_rs1, &local_imm, rd_scratch, overflow_scratch)
                };
                local_rd
            };
            env.write_register(&rd, local_rd);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::XorImmediate => {
            // xori: x[rd] = x[rs1] ^ sext(immediate)
            let local_rs1 = env.read_register(&rs1);
            let local_imm = env.sign_extend(&imm, 12);
            let local_rd = {
                let rd_scratch = env.alloc_scratch();
                unsafe { env.xor_witness(&local_rs1, &local_imm, rd_scratch) }
            };
            env.write_register(&rd, local_rd);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::OrImmediate => {
            // ori: x[rd] = x[rs1] | sext(immediate)
            let local_rs1 = env.read_register(&rs1);
            let local_imm = env.sign_extend(&imm, 12);
            let local_rd = {
                let rd_scratch = env.alloc_scratch();
                unsafe { env.or_witness(&local_rs1, &local_imm, rd_scratch) }
            };
            env.write_register(&rd, local_rd);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::AndImmediate => {
            // andi: x[rd] = x[rs1] & sext(immediate)
            let local_rs1 = env.read_register(&rs1);
            let local_imm = env.sign_extend(&imm, 12);
            let local_rd = {
                let rd_scratch = env.alloc_scratch();
                unsafe { env.and_witness(&local_rs1, &local_imm, rd_scratch) }
            };
            env.write_register(&rd, local_rd);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::JumpAndLinkRegister => {
            let addr = env.read_register(&rs1);
            // jalr:
            //  t  = pc+4;
            //  pc = (x[rs1] + sext(offset)) & ∼1; <- NOT NOW
            //  pc = (x[rs1] + sext(offset)); <- PLEASE FIXME
            //  x[rd] = t
            let offset = env.sign_extend(&imm, 12);
            let new_addr = {
                let res_scratch = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (res, _overflow) =
                    unsafe { env.add_witness(&addr, &offset, res_scratch, overflow_scratch) };
                res
            };
            env.write_register(&rd, next_instruction_pointer.clone());
            env.set_instruction_pointer(new_addr.clone());
            env.set_next_instruction_pointer(new_addr.clone() + Env::constant(4u32));
        }
    };
}

/// Interpret an S-type instruction.
/// The encoding of an S-type instruction is as follows:
/// ```text
/// | 31     25 | 24      20 | 19     15 | 14        12 | 11    7 | 6      0 |
/// | immediate |     rs2    |    rs1    |    funct3    |    imm  |  opcode  |
/// ```
/// Following the documentation found
/// [here](https://www.cs.cornell.edu/courses/cs3410/2024fa/assignments/cpusim/riscv-instructions.pdf)
pub fn interpret_stype<Env: InterpreterEnv>(env: &mut Env, instr: SInstruction) {
    /* fetch instruction pointer from the program state */
    let instruction_pointer = env.get_instruction_pointer();
    /* compute the next instruction ptr and add one, as well record raml lookup */
    let next_instruction_pointer = env.get_next_instruction_pointer();
    /* read instruction from ip address */
    let instruction = {
        let v0 = env.read_memory(&instruction_pointer);
        let v1 = env.read_memory(&(instruction_pointer.clone() + Env::constant(1)));
        let v2 = env.read_memory(&(instruction_pointer.clone() + Env::constant(2)));
        let v3 = env.read_memory(&(instruction_pointer.clone() + Env::constant(3)));
        (v3 * Env::constant(1 << 24))
            + (v2 * Env::constant(1 << 16))
            + (v1 * Env::constant(1 << 8))
            + v0
    };

    /* fetch opcode from instruction bit 0 - 6 for a total len of 7 */
    let opcode = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 7, 0, pos) }
    };
    /* verify opcode is 7 bits */
    env.range_check8(&opcode, 7);

    let imm0_4 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 12, 7, pos) }
        // bytes 7-11
    };
    env.range_check8(&imm0_4, 5);
    let funct3 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 15, 12, pos) }
    };
    env.range_check8(&funct3, 3);

    let rs1 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 20, 15, pos) }
    };
    env.range_check8(&rs1, 5);
    let rs2 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 25, 20, pos) }
    };
    env.range_check8(&rs2, 5);

    let imm5_11 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 32, 25, pos) }
        // bytes 25-31
    };
    env.range_check8(&imm5_11, 7);

    // check correctness of decomposition of S type function
    env.add_constraint(
        instruction
         - (opcode.clone() * Env::constant(1 << 0))    // opcode at bits 0-6
         - (imm0_4.clone() * Env::constant(1 << 7))    // imm0_4 at bits 7-11
         - (funct3.clone() * Env::constant(1 << 12))   // funct3 at bits 12-14
         - (rs1.clone() * Env::constant(1 << 15))      // rs1 at bits 15-19
         - (rs2.clone() * Env::constant(1 << 20))      // rs2 at bits 20-24
         - (imm5_11.clone() * Env::constant(1 << 25)), // imm5_11 at bits 25-31
    );

    let local_rs1 = env.read_register(&rs1);
    let local_imm0_4 = env.sign_extend(&imm0_4, 5);
    let local_imm5_11 = env.sign_extend(&imm5_11, 7);
    let local_imm0_11 = {
        let pos = env.alloc_scratch();
        let shift_pos = env.alloc_scratch();
        let shifted_imm5_11 =
            unsafe { env.shift_left(&local_imm5_11, &Env::constant(5), shift_pos) };
        let local_imm0_11 = unsafe { env.or_witness(&shifted_imm5_11, &local_imm0_4, pos) };
        env.sign_extend(&local_imm0_11, 11)
    };
    let address = {
        let address_scratch = env.alloc_scratch();
        let overflow_scratch = env.alloc_scratch();
        let (address, _overflow) = unsafe {
            env.add_witness(
                &local_rs1,
                &local_imm0_11,
                address_scratch,
                overflow_scratch,
            )
        };
        address
    };
    let local_rs2 = env.read_register(&rs2);

    match instr {
        SInstruction::StoreByte => {
            // sb: M[x[rs1] + sext(offset)] = x[rs2][7:0]
            let v0 = {
                let value_scratch = env.alloc_scratch();
                unsafe { env.bitmask(&local_rs2, 8, 0, value_scratch) }
            };

            env.lookup_8bits(&v0);
            env.write_memory(&address, v0);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        SInstruction::StoreHalf => {
            // sh: M[x[rs1] + sext(offset)] = x[rs2][15:0]
            let [v0, v1] = [
                {
                    let value_scratch = env.alloc_scratch();
                    unsafe { env.bitmask(&local_rs2, 8, 0, value_scratch) }
                },
                {
                    let value_scratch = env.alloc_scratch();
                    unsafe { env.bitmask(&local_rs2, 16, 8, value_scratch) }
                },
            ];

            env.lookup_8bits(&v0);
            env.lookup_8bits(&v1);

            env.write_memory(&address, v0);
            env.write_memory(&(address.clone() + Env::constant(1u32)), v1);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        SInstruction::StoreWord => {
            // sw: M[x[rs1] + sext(offset)] = x[rs2][31:0]
            let [v0, v1, v2, v3] = [
                {
                    let value_scratch = env.alloc_scratch();
                    unsafe { env.bitmask(&local_rs2, 32, 24, value_scratch) }
                },
                {
                    let value_scratch = env.alloc_scratch();
                    unsafe { env.bitmask(&local_rs2, 24, 16, value_scratch) }
                },
                {
                    let value_scratch = env.alloc_scratch();
                    unsafe { env.bitmask(&local_rs2, 16, 8, value_scratch) }
                },
                {
                    let value_scratch = env.alloc_scratch();
                    unsafe { env.bitmask(&local_rs2, 8, 0, value_scratch) }
                },
            ];

            env.lookup_8bits(&v0);
            env.lookup_8bits(&v1);
            env.lookup_8bits(&v2);
            env.lookup_8bits(&v3);

            env.write_memory(&address, v0);
            env.write_memory(&(address.clone() + Env::constant(1u32)), v1);
            env.write_memory(&(address.clone() + Env::constant(2u32)), v2);
            env.write_memory(&(address.clone() + Env::constant(3u32)), v3);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
    };
}

/// Interpret an SB-type instruction.
/// The encoding of an SB-type instruction is as follows:
/// ```text
/// | 31     25 | 24     20 | 19     15 | 14        12 | 11      7 | 6      0 |
/// |   imm2    |    rs2    |    rs1    |    funct3    |    imm1   |  opcode  |
/// ```
/// Following the documentation found
/// [here](https://www.cs.cornell.edu/courses/cs3410/2024fa/assignments/cpusim/riscv-instructions.pdf)
pub fn interpret_sbtype<Env: InterpreterEnv>(env: &mut Env, instr: SBInstruction) {
    let instruction_pointer = env.get_instruction_pointer();
    let next_instruction_pointer = env.get_next_instruction_pointer();
    let instruction = {
        let v0 = env.read_memory(&instruction_pointer);
        let v1 = env.read_memory(&(instruction_pointer.clone() + Env::constant(1)));
        let v2 = env.read_memory(&(instruction_pointer.clone() + Env::constant(2)));
        let v3 = env.read_memory(&(instruction_pointer.clone() + Env::constant(3)));
        (v3 * Env::constant(1 << 24))
            + (v2 * Env::constant(1 << 16))
            + (v1 * Env::constant(1 << 8))
            + v0
    };
    let opcode = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 7, 0, pos) }
    };

    env.range_check8(&opcode, 7);

    let funct3 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 15, 12, pos) }
    };
    env.range_check8(&funct3, 3);

    let rs1 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 20, 15, pos) }
    };
    env.range_check8(&rs1, 5);

    let rs2 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 25, 20, pos) }
    };
    env.range_check8(&rs2, 5);

    let imm0_12 = {
        let imm11 = {
            let pos = env.alloc_scratch();
            unsafe { env.bitmask(&instruction, 8, 7, pos) }
        };

        env.assert_boolean(&imm11);

        let imm1_4 = {
            let pos = env.alloc_scratch();
            unsafe { env.bitmask(&instruction, 12, 8, pos) }
        };
        env.range_check8(&imm1_4, 4);

        let imm5_10 = {
            let pos = env.alloc_scratch();
            unsafe { env.bitmask(&instruction, 31, 25, pos) }
        };
        env.range_check8(&imm5_10, 6);

        let imm12 = {
            let pos = env.alloc_scratch();
            unsafe { env.bitmask(&instruction, 32, 31, pos) }
        };
        env.assert_boolean(&imm12);

        // check correctness of decomposition of SB type function
        env.add_constraint(
            instruction.clone()
                - (opcode * Env::constant(1 << 0))    // opcode at bits 0-7
                - (imm11.clone() * Env::constant(1 << 7))     // imm11 at bits 8
                - (imm1_4.clone() * Env::constant(1 << 8))    // imm1_4 at bits 9-11
                - (funct3 * Env::constant(1 << 11))   // funct3 at bits 11-14
                - (rs1.clone() * Env::constant(1 << 14))      // rs1 at bits 15-20
                - (rs2.clone() * Env::constant(1 << 19))      // rs2 at bits 20-24
                - (imm5_10.clone() * Env::constant(1 << 24))  // imm5_10 at bits 25-30
                - (imm12.clone() * Env::constant(1 << 31)), // imm12 at bits 31
        );

        (imm12 * Env::constant(1 << 12))
            + (imm11 * Env::constant(1 << 11))
            + (imm5_10 * Env::constant(1 << 5))
            + (imm1_4 * Env::constant(1 << 1))
    };
    // extra bit is because the 0th bit in the immediate is always 0 i.e you cannot jump to an odd address
    let imm0_12 = env.sign_extend(&imm0_12, 13);

    match instr {
        SBInstruction::BranchEq => {
            // beq: if (x[rs1] == x[rs2]) pc += sext(offset)
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);

            let equals = env.equal(&local_rs1, &local_rs2);
            let offset = (Env::constant(1) - equals.clone()) * Env::constant(4) + equals * imm0_12;
            let offset = env.sign_extend(&offset, 12);
            let addr = {
                let res_scratch = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (res, _overflow) = unsafe {
                    env.add_witness(
                        &next_instruction_pointer,
                        &offset,
                        res_scratch,
                        overflow_scratch,
                    )
                };
                // FIXME: Requires a range check
                res
            };
            env.set_instruction_pointer(next_instruction_pointer);
            env.set_next_instruction_pointer(addr);
        }
        SBInstruction::BranchNeq => {
            // bne: if (x[rs1] != x[rs2]) pc += sext(offset)
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);

            let equals = env.equal(&local_rs1, &local_rs2);
            let offset = equals.clone() * Env::constant(4) + (Env::constant(1) - equals) * imm0_12;
            let addr = {
                let res_scratch = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (res, _overflow) = unsafe {
                    env.add_witness(
                        &next_instruction_pointer,
                        &offset,
                        res_scratch,
                        overflow_scratch,
                    )
                };
                // FIXME: Requires a range check
                res
            };
            env.set_instruction_pointer(next_instruction_pointer);
            env.set_next_instruction_pointer(addr);
        }
        SBInstruction::BranchLessThan => {
            // blt: if (x[rs1] < x[rs2]) pc += sext(offset)
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);

            let less_than = {
                let rd_scratch = env.alloc_scratch();
                unsafe { env.test_less_than_signed(&local_rs1, &local_rs2, rd_scratch) }
            };
            let offset = (less_than.clone()) * imm0_12
                + (Env::constant(1) - less_than.clone()) * Env::constant(4);

            let addr = {
                let res_scratch = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (res, _overflow) = unsafe {
                    env.add_witness(
                        &next_instruction_pointer,
                        &offset,
                        res_scratch,
                        overflow_scratch,
                    )
                };
                // FIXME: Requires a range check
                res
            };
            env.set_instruction_pointer(next_instruction_pointer);
            env.set_next_instruction_pointer(addr);
        }
        SBInstruction::BranchGreaterThanEqual => {
            // bge: if (x[rs1] >= x[rs2]) pc += sext(offset)
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);

            let less_than = {
                let rd_scratch = env.alloc_scratch();
                unsafe { env.test_less_than_signed(&local_rs1, &local_rs2, rd_scratch) }
            };

            let offset =
                less_than.clone() * Env::constant(4) + (Env::constant(1) - less_than) * imm0_12;
            // greater than equal is the negation of less than
            let addr = {
                let res_scratch = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (res, _overflow) = unsafe {
                    env.add_witness(
                        &next_instruction_pointer,
                        &offset,
                        res_scratch,
                        overflow_scratch,
                    )
                };
                // FIXME: Requires a range check
                res
            };
            env.set_instruction_pointer(next_instruction_pointer);
            env.set_next_instruction_pointer(addr);
        }
        SBInstruction::BranchLessThanUnsigned => {
            // bltu: if (x[rs1] <u x[rs2]) pc += sext(offset)
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);

            let less_than = {
                let rd_scratch = env.alloc_scratch();
                unsafe { env.test_less_than(&local_rs1, &local_rs2, rd_scratch) }
            };

            let offset = (Env::constant(1) - less_than.clone()) * Env::constant(4)
                + less_than.clone() * imm0_12;

            let addr = {
                let res_scratch = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (res, _overflow) = unsafe {
                    env.add_witness(&instruction_pointer, &offset, res_scratch, overflow_scratch)
                };
                // FIXME: Requires a range check
                res
            };

            env.set_instruction_pointer(next_instruction_pointer);
            env.set_next_instruction_pointer(addr);
        }
        SBInstruction::BranchGreaterThanEqualUnsigned => {
            // bgeu: if (x[rs1] >=u x[rs2]) pc += sext(offset)
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);

            let rd_scratch = env.alloc_scratch();
            let less_than = unsafe { env.test_less_than(&local_rs1, &local_rs2, rd_scratch) };
            let offset =
                less_than.clone() * Env::constant(4) + (Env::constant(1) - less_than) * imm0_12;

            // greater than equal is the negation of less than
            let addr = {
                let res_scratch = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (res, _overflow) = unsafe {
                    env.add_witness(&instruction_pointer, &offset, res_scratch, overflow_scratch)
                };
                res
            };

            env.set_instruction_pointer(next_instruction_pointer);
            env.set_next_instruction_pointer(addr);
        }
    };
}

/// Interpret an U-type instruction.
/// The encoding of an U-type instruction is as follows:
/// ```text
/// | 31     12 | 11    7 | 6      0 |
/// | immediate |    rd   |  opcode  |
/// ```
/// Following the documentation found
/// [here](https://www.cs.cornell.edu/courses/cs3410/2024fa/assignments/cpusim/riscv-instructions.pdf)
pub fn interpret_utype<Env: InterpreterEnv>(env: &mut Env, instr: UInstruction) {
    let instruction_pointer = env.get_instruction_pointer();
    let next_instruction_pointer = env.get_next_instruction_pointer();

    let instruction = {
        let v0 = env.read_memory(&instruction_pointer);
        let v1 = env.read_memory(&(instruction_pointer.clone() + Env::constant(1)));
        let v2 = env.read_memory(&(instruction_pointer.clone() + Env::constant(2)));
        let v3 = env.read_memory(&(instruction_pointer.clone() + Env::constant(3)));
        (v3 * Env::constant(1 << 24))
            + (v2 * Env::constant(1 << 16))
            + (v1 * Env::constant(1 << 8))
            + v0
    };

    let opcode = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 7, 0, pos) }
    };
    env.range_check8(&opcode, 7);

    let rd = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 12, 7, pos) }
    };
    env.range_check8(&rd, 5);

    let imm = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 32, 12, pos) }
    };
    // FIXME: rangecheck

    // check correctness of decomposition of U type function
    env.add_constraint(
        instruction
            - (opcode.clone() * Env::constant(1 << 0))    // opcode at bits 0-6
            - (rd.clone() * Env::constant(1 << 7))        // rd at bits 7-11
            - (imm.clone() * Env::constant(1 << 12)), // imm at bits 12-31
    );

    match instr {
        UInstruction::LoadUpperImmediate => {
            // lui: x[rd] = sext(immediate[31:12] << 12)
            let local_imm = {
                let shifted_imm = {
                    let pos = env.alloc_scratch();
                    unsafe { env.shift_left(&imm, &Env::constant(12), pos) }
                };
                env.sign_extend(&shifted_imm, 32)
            };
            env.write_register(&rd, local_imm);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        UInstruction::AddUpperImmediate => {
            // auipc: x[rd] = pc + sext(immediate[31:12] << 12)
            let local_imm = {
                let pos = env.alloc_scratch();
                let shifted_imm = unsafe { env.shift_left(&imm, &Env::constant(12), pos) };
                env.sign_extend(&shifted_imm, 32)
            };
            let local_pc = instruction_pointer.clone();
            let (local_rd, _) = {
                let pos = env.alloc_scratch();
                let overflow_pos = env.alloc_scratch();
                unsafe { env.add_witness(&local_pc, &local_imm, pos, overflow_pos) }
            };
            env.write_register(&rd, local_rd);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
    };
}

/// Interpret an UJ-type instruction.
/// The encoding of an UJ-type instruction is as follows:
/// ```text
/// | 31                12  | 11    7 | 6      0 |
/// | imm[20|10:1|11|19:12] |    rd   |  opcode  |
/// ```
/// Following the documentation found
/// [here](https://www.cs.cornell.edu/courses/cs3410/2024fa/assignments/cpusim/riscv-instructions.pdf)
///
/// The interpretation of the immediate is as follow:
/// ```text
/// imm_20    = instruction[31]
/// imm_10_1  = instruction[30..21]
/// imm_11    = instruction[20]
/// imm_19_12 = instruction[19..12]
///
/// imm = imm_20    << 19   +
///       imm_19_12 << 11   +
///       imm_11    << 10   +
///       imm_10_1
///
/// # The immediate is then sign-extended. The sign-extension is in the bit imm20
/// imm = imm << 1
/// ```
pub fn interpret_ujtype<Env: InterpreterEnv>(env: &mut Env, instr: UJInstruction) {
    let instruction_pointer = env.get_instruction_pointer();
    let next_instruction_pointer = env.get_next_instruction_pointer();

    let instruction = {
        let v0 = env.read_memory(&instruction_pointer);
        let v1 = env.read_memory(&(instruction_pointer.clone() + Env::constant(1)));
        let v2 = env.read_memory(&(instruction_pointer.clone() + Env::constant(2)));
        let v3 = env.read_memory(&(instruction_pointer.clone() + Env::constant(3)));
        (v3 * Env::constant(1 << 24))
            + (v2 * Env::constant(1 << 16))
            + (v1 * Env::constant(1 << 8))
            + v0
    };

    let opcode = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 7, 0, pos) }
    };
    env.range_check8(&opcode, 7);

    let rd = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 12, 7, pos) }
    };
    env.range_check8(&rd, 5);

    let imm20 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 32, 31, pos) }
    };
    env.assert_boolean(&imm20);

    let imm10_1 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 31, 21, pos) }
    };
    env.range_check16(&imm10_1, 10);

    let imm11 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 21, 20, pos) }
    };
    env.assert_boolean(&imm11);

    let imm19_12 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 20, 12, pos) }
    };
    env.range_check8(&imm19_12, 8);

    let offset = {
        imm10_1.clone() * Env::constant(1 << 1)
            + imm11.clone() * Env::constant(1 << 11)
            + imm19_12.clone() * Env::constant(1 << 12)
            + imm20.clone() * Env::constant(1 << 20)
    };

    // FIXME: check correctness of decomposition

    match instr {
        UJInstruction::JumpAndLink => {
            let offset = env.sign_extend(&offset, 21);
            let new_addr = {
                let res_scratch = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (res, _overflow) = unsafe {
                    env.add_witness(&instruction_pointer, &offset, res_scratch, overflow_scratch)
                };
                res
            };
            env.write_register(&rd, next_instruction_pointer.clone());
            env.set_instruction_pointer(new_addr.clone());
            env.set_next_instruction_pointer(new_addr + Env::constant(4u32));
        }
    }
}

pub fn interpret_syscall<Env: InterpreterEnv>(env: &mut Env, _instr: SyscallInstruction) {
    // FIXME: check if it is syscall success. There is only one syscall atm
    env.set_halted(Env::constant(1));
}

/// Interpret an M-type instruction.
/// The encoding of an M-type instruction is as follows:
/// ```text
/// | 31     27 | 26    25 | 24     20 | 19     15 | 14        12 | 11    7 | 6      0 |
/// |   00000   |    01    |    rs2    |    rs1    |    funct3    |    rd   |  opcode  |
/// ```
/// Following the documentation found
/// [here](https://www.cs.cornell.edu/courses/cs3410/2024fa/assignments/cpusim/riscv-instructions.pdf)
pub fn interpret_mtype<Env: InterpreterEnv>(env: &mut Env, instr: MInstruction) {
    let instruction_pointer = env.get_instruction_pointer();
    let next_instruction_pointer = env.get_next_instruction_pointer();

    let instruction = {
        let v0 = env.read_memory(&instruction_pointer);
        let v1 = env.read_memory(&(instruction_pointer.clone() + Env::constant(1)));
        let v2 = env.read_memory(&(instruction_pointer.clone() + Env::constant(2)));
        let v3 = env.read_memory(&(instruction_pointer.clone() + Env::constant(3)));
        (v3 * Env::constant(1 << 24))
            + (v2 * Env::constant(1 << 16))
            + (v1 * Env::constant(1 << 8))
            + v0
    };

    let opcode = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 7, 0, pos) }
    };
    env.range_check8(&opcode, 7);

    let rd = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 12, 7, pos) }
    };
    env.range_check8(&rd, 5);

    let funct3 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 15, 12, pos) }
    };
    env.range_check8(&funct3, 3);

    let rs1 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 20, 15, pos) }
    };
    env.range_check8(&rs1, 5);

    let rs2 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 25, 20, pos) }
    };
    env.range_check8(&rs2, 5);

    let funct2 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 27, 25, pos) }
    };
    // FIXME: check it is equal to 01?
    env.range_check8(&funct2, 2);

    let funct5 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 32, 27, pos) }
    };
    // FIXME: check it is equal to 00000?
    env.range_check8(&funct5, 5);

    // Check decomposition of M type instruction
    env.add_constraint(
        instruction
            - (opcode.clone() * Env::constant(1 << 0))    // opcode at bits 0-6
            - (rd.clone() * Env::constant(1 << 7))        // rd at bits 7-11
            - (funct3.clone() * Env::constant(1 << 12))   // funct3 at bits 12-14
            - (rs1.clone() * Env::constant(1 << 15))      // rs1 at bits 15-19
            - (rs2.clone() * Env::constant(1 << 20))      // rs2 at bits 20-24
            - (funct2.clone() * Env::constant(1 << 25))   // funct2 at bits 25-26
            - (funct5.clone() * Env::constant(1 << 27)), // funct5 at bits 27-31
    );

    match instr {
        MInstruction::Mul => {
            // x[rd] = x[rs1] * x[rs2]
            let rs1 = env.read_register(&rs1);
            let rs2 = env.read_register(&rs2);
            // FIXME: constrain
            let res = {
                let pos = env.alloc_scratch();
                unsafe { env.mul_lo_signed(&rs1, &rs2, pos) }
            };
            env.write_register(&rd, res);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        MInstruction::Mulh => {
            // x[rd] = (signed(x[rs1]) * signed(x[rs2])) >> 32
            let rs1 = env.read_register(&rs1);
            let rs2 = env.read_register(&rs2);
            // FIXME: constrain
            let res = {
                let pos = env.alloc_scratch();
                unsafe { env.mul_hi_signed(&rs1, &rs2, pos) }
            };
            env.write_register(&rd, res);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        MInstruction::Mulhsu => {
            // x[rd] = (signed(x[rs1]) * x[rs2]) >> 32
            let rs1 = env.read_register(&rs1);
            let rs2 = env.read_register(&rs2);
            // FIXME: constrain
            let res = {
                let pos = env.alloc_scratch();
                unsafe { env.mul_hi_signed_unsigned(&rs1, &rs2, pos) }
            };
            env.write_register(&rd, res);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        MInstruction::Mulhu => {
            // x[rd] = (x[rs1] * x[rs2]) >> 32
            let rs1 = env.read_register(&rs1);
            let rs2 = env.read_register(&rs2);
            // FIXME: constrain
            let res = {
                let pos = env.alloc_scratch();
                unsafe { env.mul_hi(&rs1, &rs2, pos) }
            };
            env.write_register(&rd, res);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        MInstruction::Div => {
            // x[rd] = signed(x[rs1]) / signed(x[rs2])
            let rs1 = env.read_register(&rs1);
            let rs2 = env.read_register(&rs2);
            // FIXME: constrain
            let res = {
                let pos = env.alloc_scratch();
                unsafe { env.div_signed(&rs1, &rs2, pos) }
            };
            env.write_register(&rd, res);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        MInstruction::Divu => {
            // x[rd] = x[rs1] / x[rs2]
            let rs1 = env.read_register(&rs1);
            let rs2 = env.read_register(&rs2);
            // FIXME: constrain
            let res = {
                let pos = env.alloc_scratch();
                unsafe { env.div(&rs1, &rs2, pos) }
            };
            env.write_register(&rd, res);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        MInstruction::Rem => {
            // x[rd] = signed(x[rs1]) % signed(x[rs2])
            let rs1 = env.read_register(&rs1);
            let rs2 = env.read_register(&rs2);
            // FIXME: constrain
            let res = {
                let pos = env.alloc_scratch();
                unsafe { env.mod_signed(&rs1, &rs2, pos) }
            };
            env.write_register(&rd, res);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        MInstruction::Remu => {
            // x[rd] = x[rs1] % x[rs2]
            let rs1 = env.read_register(&rs1);
            let rs2 = env.read_register(&rs2);
            // FIXME: constrain
            let res = {
                let pos = env.alloc_scratch();
                unsafe { env.mod_unsigned(&rs1, &rs2, pos) }
            };
            env.write_register(&rd, res);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
    }
}
