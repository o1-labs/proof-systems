use serde::{Deserialize, Serialize};
use std::iter::IntoIterator;
use std::ops::{Index, IndexMut};
use strum::IntoEnumIterator;
use strum_macros::{EnumCount, EnumIter};
use ark_ff::Zero;
use std::array;

use crate::lookup::{Lookup, TableID};

pub const FD_STDIN: u32 = 0;
pub const FD_STDOUT: u32 = 1;
pub const FD_STDERR: u32 = 2;
pub const FD_HINT_READ: u32 = 3;
pub const FD_HINT_WRITE: u32 = 4;
pub const FD_PREIMAGE_READ: u32 = 5;
pub const FD_PREIMAGE_WRITE: u32 = 6;

// https://inst.eecs.berkeley.edu/~cs61c/resources/MIPS_help.html
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Instruction {
    RType(RTypeInstruction),
    JType(JTypeInstruction),
    IType(ITypeInstruction),
}

// TODO(dw): use num_traits/num_derive to assign an integer value and have a
// decoding/encoding functions.
// It will remove the need of the decoding/encoding function below.
#[derive(Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter)]
pub enum RTypeInstruction {
    ShiftLeftLogical,             // sll
    ShiftRightLogical,            // srl
    ShiftRightArithmetic,         // sra
    ShiftLeftLogicalVariable,     // sllv
    ShiftRightLogicalVariable,    // srlv
    ShiftRightArithmeticVariable, // srav
    JumpRegister,                 // jr
    JumpAndLinkRegister,          // jalr
    SyscallMmap,                  // syscall (Mmap)
    SyscallExitGroup,             // syscall (ExitGroup)
    SyscallReadPreimage,          // syscall (Read 5)
    SyscallReadOther,             // syscall (Read ?)
    SyscallWriteHint,             // syscall (Write 4)
    SyscallWritePreimage,         // syscall (Write 6)
    SyscallWriteOther,            // syscall (Write ?)
    SyscallFcntl,                 // syscall (Fcntl)
    SyscallOther,                 // syscall (Brk, Clone, ?)
    MoveZero,                     // movz - FIXME: documented as "MIPS32 removed in Release 6"
    MoveNonZero,                  // movn - FIXME: documented as "MIPS32 removed in Release 6"
    Sync,                         // sync
    MoveFromHi,                   // mfhi
    MoveToHi,                     // mthi
    MoveFromLo,                   // mflo
    MoveToLo,                     // mtlo
    Multiply,                     // mult
    MultiplyUnsigned,             // multu
    Div,                          // div
    DivUnsigned,                  // divu
    Add,                          // add
    AddUnsigned,                  // addu
    Sub,                          // sub
    SubUnsigned,                  // subu
    And,                          // and
    Or,                           // or
    Xor,                          // xor
    Nor,                          // nor
    SetLessThan,                  // slt
    SetLessThanUnsigned,          // sltu
    MultiplyToRegister,           // mul
    CountLeadingOnes,             // clo
    CountLeadingZeros,            // clz
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter)]
pub enum JTypeInstruction {
    Jump,        // j
    JumpAndLink, // jal
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter)]
pub enum ITypeInstruction {
    BranchEq,                     // beq
    BranchNeq,                    // bne
    BranchLeqZero,                // blez
    BranchGtZero,                 // bgtz
    AddImmediate,                 // addi
    AddImmediateUnsigned,         // addiu
    SetLessThanImmediate,         // slti
    SetLessThanImmediateUnsigned, // sltiu
    AndImmediate,                 // andi
    OrImmediate,                  // ori
    XorImmediate,                 // xori
    LoadUpperImmediate,           // lui
    LoadImmediate,                // li
    Load8,                        // lb
    Load16,                       // lh
    Load32,                       // lw
    Load8Unsigned,                // lbu
    Load16Unsigned,               // lhu
    LoadWordLeft,                 // lwl
    LoadWordRight,                // lwr
    Store8,                       // sb
    Store16,                      // sh
    Store32,                      // sw
    StoreWordLeft,                // swl
    StoreWordRight,               // swr
}

// InstructionSelectors
#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
pub struct InstructionSelectors<T> {
    pub r_type: RTypeInstructionSelectors<T>,
    pub j_type: JTypeInstructionSelectors<T>,
    pub i_type: ITypeInstructionSelectors<T>,
}

impl<A> Index<Instruction> for InstructionSelectors<A> {
    type Output = A;

    fn index(&self, idx: Instruction) -> &Self::Output {
        match idx {
            Instruction::RType(instr) => &self.r_type[instr],
            Instruction::JType(instr) => &self.j_type[instr],
            Instruction::IType(instr) => &self.i_type[instr],
        }
    }
}

impl<A> IndexMut<Instruction> for InstructionSelectors<A> {
    fn index_mut(&mut self, idx: Instruction) -> &mut Self::Output {
        match idx {
            Instruction::RType(instr) => &mut self.r_type[instr],
            Instruction::JType(instr) => &mut self.j_type[instr],
            Instruction::IType(instr) => &mut self.i_type[instr],
        }
    }
}

impl<A> InstructionSelectors<A> {
    pub fn as_ref(&self) -> InstructionSelectors<&A> {
        InstructionSelectors {
            r_type: self.r_type.as_ref(),
            j_type: self.j_type.as_ref(),
            i_type: self.i_type.as_ref(),
        }
    }

    pub fn as_mut(&mut self) -> InstructionSelectors<&mut A> {
        InstructionSelectors {
            r_type: self.r_type.as_mut(),
            j_type: self.j_type.as_mut(),
            i_type: self.i_type.as_mut(),
        }
    }

    pub fn map<B, F: FnMut(A) -> B>(self, mut f: F) -> InstructionSelectors<B> {
        let InstructionSelectors {
            r_type,
            j_type,
            i_type,
        } = self;
        InstructionSelectors {
            r_type: r_type.map(&mut f),
            j_type: j_type.map(&mut f),
            i_type: i_type.map(&mut f),
        }
    }
}

impl<A> IntoIterator for InstructionSelectors<A> {
    type Item = A;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let InstructionSelectors {
            r_type,
            j_type,
            i_type,
        } = self;
        // Could be more efficient than copying. However, it is relatively
        // small. It is negligeable.
        let mut r_type: Vec<A> = r_type.into_iter().collect();
        let j_type: Vec<A> = j_type.into_iter().collect();
        let i_type: Vec<A> = i_type.into_iter().collect();
        r_type.extend(j_type);
        r_type.extend(i_type);
        r_type.into_iter()
    }
}

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
pub struct RTypeInstructionSelectors<T> {
    pub shift_left_logical: T,
    pub shift_right_logical: T,
    pub shift_right_arithmetic: T,
    pub shift_left_logical_variable: T,
    pub shift_right_logical_variable: T,
    pub shift_right_arithmetic_variable: T,
    pub jump_register: T,
    pub jump_and_link_register: T,
    pub syscall: T,
    pub move_zero: T,
    pub move_non_zero: T,
    pub sync: T,
    pub move_from_hi: T,
    pub move_to_hi: T,
    pub move_from_lo: T,
    pub move_to_lo: T,
    pub multiply: T,
    pub multiply_unsigned: T,
    pub div: T,
    pub div_unsigned: T,
    pub add: T,
    pub add_unsigned: T,
    pub sub: T,
    pub sub_unsigned: T,
    pub and: T,
    pub or: T,
    pub xor: T,
    pub nor: T,
    pub set_less_than: T,
    pub set_less_than_unsigned: T,
    pub multiply_to_register: T,
    pub count_leading_ones: T,
    pub count_leading_zeros: T,
}

impl<A> Index<RTypeInstruction> for RTypeInstructionSelectors<A> {
    type Output = A;

    fn index(&self, index: RTypeInstruction) -> &Self::Output {
        match index {
            RTypeInstruction::ShiftLeftLogical => &self.shift_left_logical,
            RTypeInstruction::ShiftRightLogical => &self.shift_right_logical,
            RTypeInstruction::ShiftRightArithmetic => &self.shift_right_arithmetic,
            RTypeInstruction::ShiftLeftLogicalVariable => &self.shift_left_logical_variable,
            RTypeInstruction::ShiftRightLogicalVariable => &self.shift_right_logical_variable,
            RTypeInstruction::ShiftRightArithmeticVariable => &self.shift_right_arithmetic_variable,
            RTypeInstruction::JumpRegister => &self.jump_register,
            RTypeInstruction::JumpAndLinkRegister => &self.jump_and_link_register,
            // FIXME: Am I understanding correctly that we need to map the
            // actual MIPS instruction? Maybe not. It is used in the proof with
            // InstructionSelectors
            RTypeInstruction::SyscallMmap => &self.syscall,
            RTypeInstruction::SyscallExitGroup => &self.syscall,
            RTypeInstruction::SyscallReadPreimage => &self.syscall,
            RTypeInstruction::SyscallReadOther => &self.syscall,
            RTypeInstruction::SyscallWriteHint => &self.syscall,
            RTypeInstruction::SyscallWritePreimage => &self.syscall,
            RTypeInstruction::SyscallWriteOther => &self.syscall,
            RTypeInstruction::SyscallFcntl => &self.syscall,
            RTypeInstruction::SyscallOther => &self.syscall,
            RTypeInstruction::MoveZero => &self.move_zero,
            RTypeInstruction::MoveNonZero => &self.move_non_zero,
            RTypeInstruction::Sync => &self.sync,
            RTypeInstruction::MoveFromHi => &self.move_from_hi,
            RTypeInstruction::MoveToHi => &self.move_to_hi,
            RTypeInstruction::MoveFromLo => &self.move_from_lo,
            RTypeInstruction::MoveToLo => &self.move_to_lo,
            RTypeInstruction::Multiply => &self.multiply,
            RTypeInstruction::MultiplyUnsigned => &self.multiply_unsigned,
            RTypeInstruction::Div => &self.div,
            RTypeInstruction::DivUnsigned => &self.div_unsigned,
            RTypeInstruction::Add => &self.add,
            RTypeInstruction::AddUnsigned => &self.add_unsigned,
            RTypeInstruction::Sub => &self.sub,
            RTypeInstruction::SubUnsigned => &self.sub_unsigned,
            RTypeInstruction::And => &self.and,
            RTypeInstruction::Or => &self.or,
            RTypeInstruction::Xor => &self.xor,
            RTypeInstruction::Nor => &self.nor,
            RTypeInstruction::SetLessThan => &self.set_less_than,
            RTypeInstruction::SetLessThanUnsigned => &self.set_less_than_unsigned,
            RTypeInstruction::MultiplyToRegister => &self.multiply_to_register,
            RTypeInstruction::CountLeadingOnes => &self.count_leading_ones,
            RTypeInstruction::CountLeadingZeros => &self.count_leading_zeros,
        }
    }
}

impl<A> IndexMut<RTypeInstruction> for RTypeInstructionSelectors<A> {
    fn index_mut(&mut self, index: RTypeInstruction) -> &mut Self::Output {
        match index {
            RTypeInstruction::ShiftLeftLogical => &mut self.shift_left_logical,
            RTypeInstruction::ShiftRightLogical => &mut self.shift_right_logical,
            RTypeInstruction::ShiftRightArithmetic => &mut self.shift_right_arithmetic,
            RTypeInstruction::ShiftLeftLogicalVariable => &mut self.shift_left_logical_variable,
            RTypeInstruction::ShiftRightLogicalVariable => &mut self.shift_right_logical_variable,
            RTypeInstruction::ShiftRightArithmeticVariable => {
                &mut self.shift_right_arithmetic_variable
            }
            RTypeInstruction::JumpRegister => &mut self.jump_register,
            RTypeInstruction::JumpAndLinkRegister => &mut self.jump_and_link_register,
            RTypeInstruction::SyscallMmap => &mut self.syscall,
            RTypeInstruction::SyscallExitGroup => &mut self.syscall,
            RTypeInstruction::SyscallReadPreimage => &mut self.syscall,
            RTypeInstruction::SyscallReadOther => &mut self.syscall,
            RTypeInstruction::SyscallWriteHint => &mut self.syscall,
            RTypeInstruction::SyscallWritePreimage => &mut self.syscall,
            RTypeInstruction::SyscallWriteOther => &mut self.syscall,
            RTypeInstruction::SyscallFcntl => &mut self.syscall,
            RTypeInstruction::SyscallOther => &mut self.syscall,
            RTypeInstruction::MoveZero => &mut self.move_zero,
            RTypeInstruction::MoveNonZero => &mut self.move_non_zero,
            RTypeInstruction::Sync => &mut self.sync,
            RTypeInstruction::MoveFromHi => &mut self.move_from_hi,
            RTypeInstruction::MoveToHi => &mut self.move_to_hi,
            RTypeInstruction::MoveFromLo => &mut self.move_from_lo,
            RTypeInstruction::MoveToLo => &mut self.move_to_lo,
            RTypeInstruction::Multiply => &mut self.multiply,
            RTypeInstruction::MultiplyUnsigned => &mut self.multiply_unsigned,
            RTypeInstruction::Div => &mut self.div,
            RTypeInstruction::DivUnsigned => &mut self.div_unsigned,
            RTypeInstruction::Add => &mut self.add,
            RTypeInstruction::AddUnsigned => &mut self.add_unsigned,
            RTypeInstruction::Sub => &mut self.sub,
            RTypeInstruction::SubUnsigned => &mut self.sub_unsigned,
            RTypeInstruction::And => &mut self.and,
            RTypeInstruction::Or => &mut self.or,
            RTypeInstruction::Xor => &mut self.xor,
            RTypeInstruction::Nor => &mut self.nor,
            RTypeInstruction::SetLessThan => &mut self.set_less_than,
            RTypeInstruction::SetLessThanUnsigned => &mut self.set_less_than_unsigned,
            RTypeInstruction::MultiplyToRegister => &mut self.multiply_to_register,
            RTypeInstruction::CountLeadingOnes => &mut self.count_leading_ones,
            RTypeInstruction::CountLeadingZeros => &mut self.count_leading_zeros,
        }
    }
}

impl<A> RTypeInstructionSelectors<A> {
    pub fn as_ref(&self) -> RTypeInstructionSelectors<&A> {
        RTypeInstructionSelectors {
            shift_left_logical: &self.shift_left_logical,
            shift_right_logical: &self.shift_right_logical,
            shift_right_arithmetic: &self.shift_right_arithmetic,
            shift_left_logical_variable: &self.shift_left_logical_variable,
            shift_right_logical_variable: &self.shift_right_logical_variable,
            shift_right_arithmetic_variable: &self.shift_right_arithmetic_variable,
            jump_register: &self.jump_register,
            jump_and_link_register: &self.jump_and_link_register,
            syscall: &self.syscall,
            move_zero: &self.move_zero,
            move_non_zero: &self.move_non_zero,
            sync: &self.sync,
            move_from_hi: &self.move_from_hi,
            move_to_hi: &self.move_to_hi,
            move_from_lo: &self.move_from_lo,
            move_to_lo: &self.move_to_lo,
            multiply: &self.multiply,
            multiply_unsigned: &self.multiply_unsigned,
            div: &self.div,
            div_unsigned: &self.div_unsigned,
            add: &self.add,
            add_unsigned: &self.add_unsigned,
            sub: &self.sub,
            sub_unsigned: &self.sub_unsigned,
            and: &self.and,
            or: &self.or,
            xor: &self.xor,
            nor: &self.nor,
            set_less_than: &self.set_less_than,
            set_less_than_unsigned: &self.set_less_than_unsigned,
            multiply_to_register: &self.multiply_to_register,
            count_leading_ones: &self.count_leading_ones,
            count_leading_zeros: &self.count_leading_zeros,
        }
    }

    pub fn as_mut(&mut self) -> RTypeInstructionSelectors<&mut A> {
        RTypeInstructionSelectors {
            shift_left_logical: &mut self.shift_left_logical,
            shift_right_logical: &mut self.shift_right_logical,
            shift_right_arithmetic: &mut self.shift_right_arithmetic,
            shift_left_logical_variable: &mut self.shift_left_logical_variable,
            shift_right_logical_variable: &mut self.shift_right_logical_variable,
            shift_right_arithmetic_variable: &mut self.shift_right_arithmetic_variable,
            jump_register: &mut self.jump_register,
            jump_and_link_register: &mut self.jump_and_link_register,
            syscall: &mut self.syscall,
            move_zero: &mut self.move_zero,
            move_non_zero: &mut self.move_non_zero,
            sync: &mut self.sync,
            move_from_hi: &mut self.move_from_hi,
            move_to_hi: &mut self.move_to_hi,
            move_from_lo: &mut self.move_from_lo,
            move_to_lo: &mut self.move_to_lo,
            multiply: &mut self.multiply,
            multiply_unsigned: &mut self.multiply_unsigned,
            div: &mut self.div,
            div_unsigned: &mut self.div_unsigned,
            add: &mut self.add,
            add_unsigned: &mut self.add_unsigned,
            sub: &mut self.sub,
            sub_unsigned: &mut self.sub_unsigned,
            and: &mut self.and,
            or: &mut self.or,
            xor: &mut self.xor,
            nor: &mut self.nor,
            set_less_than: &mut self.set_less_than,
            set_less_than_unsigned: &mut self.set_less_than_unsigned,
            multiply_to_register: &mut self.multiply_to_register,
            count_leading_ones: &mut self.count_leading_ones,
            count_leading_zeros: &mut self.count_leading_zeros,
        }
    }

    pub fn map<B, F: FnMut(A) -> B>(self, mut f: F) -> RTypeInstructionSelectors<B> {
        let RTypeInstructionSelectors {
            shift_left_logical,
            shift_right_logical,
            shift_right_arithmetic,
            shift_left_logical_variable,
            shift_right_logical_variable,
            shift_right_arithmetic_variable,
            jump_register,
            jump_and_link_register,
            syscall,
            move_zero,
            move_non_zero,
            sync,
            move_from_hi,
            move_to_hi,
            move_from_lo,
            move_to_lo,
            multiply,
            multiply_unsigned,
            div,
            div_unsigned,
            add,
            add_unsigned,
            sub,
            sub_unsigned,
            and,
            or,
            xor,
            nor,
            set_less_than,
            set_less_than_unsigned,
            multiply_to_register,
            count_leading_ones,
            count_leading_zeros,
        } = self;
        RTypeInstructionSelectors {
            shift_left_logical: f(shift_left_logical),
            shift_right_logical: f(shift_right_logical),
            shift_right_arithmetic: f(shift_right_arithmetic),
            shift_left_logical_variable: f(shift_left_logical_variable),
            shift_right_logical_variable: f(shift_right_logical_variable),
            shift_right_arithmetic_variable: f(shift_right_arithmetic_variable),
            jump_register: f(jump_register),
            jump_and_link_register: f(jump_and_link_register),
            syscall: f(syscall),
            move_zero: f(move_zero),
            move_non_zero: f(move_non_zero),
            sync: f(sync),
            move_from_hi: f(move_from_hi),
            move_to_hi: f(move_to_hi),
            move_from_lo: f(move_from_lo),
            move_to_lo: f(move_to_lo),
            multiply: f(multiply),
            multiply_unsigned: f(multiply_unsigned),
            div: f(div),
            div_unsigned: f(div_unsigned),
            add: f(add),
            add_unsigned: f(add_unsigned),
            sub: f(sub),
            sub_unsigned: f(sub_unsigned),
            and: f(and),
            or: f(or),
            xor: f(xor),
            nor: f(nor),
            set_less_than: f(set_less_than),
            set_less_than_unsigned: f(set_less_than_unsigned),
            multiply_to_register: f(multiply_to_register),
            count_leading_ones: f(count_leading_ones),
            count_leading_zeros: f(count_leading_zeros),
        }
    }
}

impl<A> IntoIterator for RTypeInstructionSelectors<A> {
    type Item = A;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let RTypeInstructionSelectors {
            shift_left_logical,
            shift_right_logical,
            shift_right_arithmetic,
            shift_left_logical_variable,
            shift_right_logical_variable,
            shift_right_arithmetic_variable,
            jump_register,
            jump_and_link_register,
            syscall,
            move_zero,
            move_non_zero,
            sync,
            move_from_hi,
            move_to_hi,
            move_from_lo,
            move_to_lo,
            multiply,
            multiply_unsigned,
            div,
            div_unsigned,
            add,
            add_unsigned,
            sub,
            sub_unsigned,
            and,
            or,
            xor,
            nor,
            set_less_than,
            set_less_than_unsigned,
            multiply_to_register,
            count_leading_ones,
            count_leading_zeros,
        } = self;
        vec![
            shift_left_logical,
            shift_right_logical,
            shift_right_arithmetic,
            shift_left_logical_variable,
            shift_right_logical_variable,
            shift_right_arithmetic_variable,
            jump_register,
            jump_and_link_register,
            syscall,
            move_zero,
            move_non_zero,
            sync,
            move_from_hi,
            move_to_hi,
            move_from_lo,
            move_to_lo,
            multiply,
            multiply_unsigned,
            div,
            div_unsigned,
            add,
            add_unsigned,
            sub,
            sub_unsigned,
            and,
            or,
            xor,
            nor,
            set_less_than,
            set_less_than_unsigned,
            multiply_to_register,
            count_leading_ones,
            count_leading_zeros,
        ]
        .into_iter()
    }
}

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
pub struct JTypeInstructionSelectors<T> {
    pub jump: T,
    pub jump_and_link: T,
}

impl<A> Index<JTypeInstruction> for JTypeInstructionSelectors<A> {
    type Output = A;

    fn index(&self, index: JTypeInstruction) -> &Self::Output {
        match index {
            JTypeInstruction::Jump => &self.jump,
            JTypeInstruction::JumpAndLink => &self.jump_and_link,
        }
    }
}

impl<A> IndexMut<JTypeInstruction> for JTypeInstructionSelectors<A> {
    fn index_mut(&mut self, index: JTypeInstruction) -> &mut Self::Output {
        match index {
            JTypeInstruction::Jump => &mut self.jump,
            JTypeInstruction::JumpAndLink => &mut self.jump_and_link,
        }
    }
}

impl<A> JTypeInstructionSelectors<A> {
    pub fn as_ref(&self) -> JTypeInstructionSelectors<&A> {
        JTypeInstructionSelectors {
            jump: &self.jump,
            jump_and_link: &self.jump_and_link,
        }
    }

    pub fn as_mut(&mut self) -> JTypeInstructionSelectors<&mut A> {
        JTypeInstructionSelectors {
            jump: &mut self.jump,
            jump_and_link: &mut self.jump_and_link,
        }
    }

    pub fn map<B, F: FnMut(A) -> B>(self, mut f: F) -> JTypeInstructionSelectors<B> {
        let JTypeInstructionSelectors {
            jump,
            jump_and_link,
        } = self;
        JTypeInstructionSelectors {
            jump: f(jump),
            jump_and_link: f(jump_and_link),
        }
    }
}

impl<A> IntoIterator for JTypeInstructionSelectors<A> {
    type Item = A;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let JTypeInstructionSelectors {
            jump,
            jump_and_link,
        } = self;
        vec![jump, jump_and_link].into_iter()
    }
}

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
pub struct ITypeInstructionSelectors<T> {
    pub branch_eq: T,
    pub branch_neq: T,
    pub branch_leq_zero: T,
    pub branch_gt_zero: T,
    pub add_immediate: T,
    pub add_unsigned_immediate: T,
    pub set_less_than_immediate: T,
    pub set_less_than_unsigned_immediate: T,
    pub and_immediate: T,
    pub or_immediate: T,
    pub xor_immediate: T,
    pub load_immediate: T,
    pub load_upper_immediate: T,
    pub load_8: T,
    pub load_16: T,
    pub load_32: T,
    pub load_8_unsigned: T,
    pub load_16_unsigned: T,
    pub load_word_left: T,
    pub load_word_right: T,
    pub store_8: T,
    pub store_16: T,
    pub store_32: T,
    pub store_word_left: T,
    pub store_word_right: T,
}

impl<A> Index<ITypeInstruction> for ITypeInstructionSelectors<A> {
    type Output = A;

    fn index(&self, index: ITypeInstruction) -> &Self::Output {
        match index {
            ITypeInstruction::BranchEq => &self.branch_eq,
            ITypeInstruction::BranchNeq => &self.branch_neq,
            ITypeInstruction::BranchLeqZero => &self.branch_leq_zero,
            ITypeInstruction::BranchGtZero => &self.branch_gt_zero,
            ITypeInstruction::AddImmediate => &self.add_immediate,
            ITypeInstruction::AddImmediateUnsigned => &self.add_unsigned_immediate,
            ITypeInstruction::SetLessThanImmediate => &self.set_less_than_immediate,
            ITypeInstruction::SetLessThanImmediateUnsigned => {
                &self.set_less_than_unsigned_immediate
            }
            ITypeInstruction::AndImmediate => &self.and_immediate,
            ITypeInstruction::OrImmediate => &self.or_immediate,
            ITypeInstruction::XorImmediate => &self.xor_immediate,
            ITypeInstruction::LoadImmediate => &self.load_immediate,
            ITypeInstruction::LoadUpperImmediate => &self.load_upper_immediate,
            ITypeInstruction::Load8 => &self.load_8,
            ITypeInstruction::Load16 => &self.load_16,
            ITypeInstruction::Load32 => &self.load_32,
            ITypeInstruction::Load8Unsigned => &self.load_8_unsigned,
            ITypeInstruction::Load16Unsigned => &self.load_16_unsigned,
            ITypeInstruction::LoadWordLeft => &self.load_word_left,
            ITypeInstruction::LoadWordRight => &self.load_word_right,
            ITypeInstruction::Store8 => &self.store_8,
            ITypeInstruction::Store16 => &self.store_16,
            ITypeInstruction::Store32 => &self.store_32,
            ITypeInstruction::StoreWordLeft => &self.load_word_left,
            ITypeInstruction::StoreWordRight => &self.load_word_right,
        }
    }
}

impl<A> IndexMut<ITypeInstruction> for ITypeInstructionSelectors<A> {
    fn index_mut(&mut self, index: ITypeInstruction) -> &mut Self::Output {
        match index {
            ITypeInstruction::BranchEq => &mut self.branch_eq,
            ITypeInstruction::BranchNeq => &mut self.branch_neq,
            ITypeInstruction::BranchLeqZero => &mut self.branch_leq_zero,
            ITypeInstruction::BranchGtZero => &mut self.branch_gt_zero,
            ITypeInstruction::AddImmediate => &mut self.add_immediate,
            ITypeInstruction::AddImmediateUnsigned => &mut self.add_unsigned_immediate,
            ITypeInstruction::SetLessThanImmediate => &mut self.set_less_than_immediate,
            ITypeInstruction::SetLessThanImmediateUnsigned => {
                &mut self.set_less_than_unsigned_immediate
            }
            ITypeInstruction::AndImmediate => &mut self.and_immediate,
            ITypeInstruction::OrImmediate => &mut self.or_immediate,
            ITypeInstruction::XorImmediate => &mut self.xor_immediate,
            ITypeInstruction::LoadImmediate => &mut self.load_immediate,
            ITypeInstruction::LoadUpperImmediate => &mut self.load_upper_immediate,
            ITypeInstruction::Load8 => &mut self.load_8,
            ITypeInstruction::Load16 => &mut self.load_16,
            ITypeInstruction::Load32 => &mut self.load_32,
            ITypeInstruction::Load8Unsigned => &mut self.load_8_unsigned,
            ITypeInstruction::Load16Unsigned => &mut self.load_16_unsigned,
            ITypeInstruction::LoadWordLeft => &mut self.load_word_left,
            ITypeInstruction::LoadWordRight => &mut self.load_word_right,
            ITypeInstruction::Store8 => &mut self.store_8,
            ITypeInstruction::Store16 => &mut self.store_16,
            ITypeInstruction::Store32 => &mut self.store_32,
            ITypeInstruction::StoreWordLeft => &mut self.store_word_left,
            ITypeInstruction::StoreWordRight => &mut self.store_word_right,
        }
    }
}

impl<A> ITypeInstructionSelectors<A> {
    pub fn as_ref(&self) -> ITypeInstructionSelectors<&A> {
        ITypeInstructionSelectors {
            branch_eq: &self.branch_eq,
            branch_neq: &self.branch_neq,
            branch_leq_zero: &self.branch_leq_zero,
            branch_gt_zero: &self.branch_gt_zero,
            add_immediate: &self.add_immediate,
            add_unsigned_immediate: &self.add_unsigned_immediate,
            set_less_than_immediate: &self.set_less_than_immediate,
            set_less_than_unsigned_immediate: &self.set_less_than_unsigned_immediate,
            and_immediate: &self.and_immediate,
            or_immediate: &self.or_immediate,
            xor_immediate: &self.xor_immediate,
            load_immediate: &self.load_immediate,
            load_upper_immediate: &self.load_upper_immediate,
            load_8: &self.load_8,
            load_16: &self.load_16,
            load_32: &self.load_32,
            load_8_unsigned: &self.load_8_unsigned,
            load_16_unsigned: &self.load_16_unsigned,
            load_word_left: &self.load_word_left,
            load_word_right: &self.load_word_right,
            store_8: &self.store_8,
            store_16: &self.store_16,
            store_32: &self.store_32,
            store_word_left: &self.store_word_left,
            store_word_right: &self.store_word_right,
        }
    }

    pub fn as_mut(&mut self) -> ITypeInstructionSelectors<&mut A> {
        ITypeInstructionSelectors {
            branch_eq: &mut self.branch_eq,
            branch_neq: &mut self.branch_neq,
            branch_leq_zero: &mut self.branch_leq_zero,
            branch_gt_zero: &mut self.branch_gt_zero,
            add_immediate: &mut self.add_immediate,
            add_unsigned_immediate: &mut self.add_unsigned_immediate,
            set_less_than_immediate: &mut self.set_less_than_immediate,
            set_less_than_unsigned_immediate: &mut self.set_less_than_unsigned_immediate,
            and_immediate: &mut self.and_immediate,
            or_immediate: &mut self.or_immediate,
            xor_immediate: &mut self.xor_immediate,
            load_immediate: &mut self.load_immediate,
            load_upper_immediate: &mut self.load_upper_immediate,
            load_8: &mut self.load_8,
            load_16: &mut self.load_16,
            load_32: &mut self.load_32,
            load_8_unsigned: &mut self.load_8_unsigned,
            load_16_unsigned: &mut self.load_16_unsigned,
            load_word_left: &mut self.load_word_left,
            load_word_right: &mut self.load_word_right,
            store_8: &mut self.store_8,
            store_16: &mut self.store_16,
            store_32: &mut self.store_32,
            store_word_left: &mut self.store_word_left,
            store_word_right: &mut self.store_word_right,
        }
    }

    pub fn map<B, F: FnMut(A) -> B>(self, mut f: F) -> ITypeInstructionSelectors<B> {
        let ITypeInstructionSelectors {
            branch_eq,
            branch_neq,
            branch_leq_zero,
            branch_gt_zero,
            add_immediate,
            add_unsigned_immediate,
            set_less_than_immediate,
            set_less_than_unsigned_immediate,
            and_immediate,
            or_immediate,
            xor_immediate,
            load_immediate,
            load_upper_immediate,
            load_8,
            load_16,
            load_32,
            load_8_unsigned,
            load_16_unsigned,
            load_word_left,
            load_word_right,
            store_8,
            store_16,
            store_32,
            store_word_left,
            store_word_right,
        } = self;
        ITypeInstructionSelectors {
            branch_eq: f(branch_eq),
            branch_neq: f(branch_neq),
            branch_leq_zero: f(branch_leq_zero),
            branch_gt_zero: f(branch_gt_zero),
            add_immediate: f(add_immediate),
            add_unsigned_immediate: f(add_unsigned_immediate),
            set_less_than_immediate: f(set_less_than_immediate),
            set_less_than_unsigned_immediate: f(set_less_than_unsigned_immediate),
            and_immediate: f(and_immediate),
            or_immediate: f(or_immediate),
            xor_immediate: f(xor_immediate),
            load_immediate: f(load_immediate),
            load_upper_immediate: f(load_upper_immediate),
            load_8: f(load_8),
            load_16: f(load_16),
            load_32: f(load_32),
            load_8_unsigned: f(load_8_unsigned),
            load_16_unsigned: f(load_16_unsigned),
            load_word_left: f(load_word_left),
            load_word_right: f(load_word_right),
            store_8: f(store_8),
            store_16: f(store_16),
            store_32: f(store_32),
            store_word_left: f(store_word_left),
            store_word_right: f(store_word_right),
        }
    }
}

impl<A> IntoIterator for ITypeInstructionSelectors<A> {
    type Item = A;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let ITypeInstructionSelectors {
            branch_eq,
            branch_neq,
            branch_leq_zero,
            branch_gt_zero,
            add_immediate,
            add_unsigned_immediate,
            set_less_than_immediate,
            set_less_than_unsigned_immediate,
            and_immediate,
            or_immediate,
            xor_immediate,
            load_immediate,
            load_upper_immediate,
            load_8,
            load_16,
            load_32,
            load_8_unsigned,
            load_16_unsigned,
            load_word_left,
            load_word_right,
            store_8,
            store_16,
            store_32,
            store_word_left,
            store_word_right,
        } = self;
        vec![
            branch_eq,
            branch_neq,
            branch_leq_zero,
            branch_gt_zero,
            add_immediate,
            add_unsigned_immediate,
            set_less_than_immediate,
            set_less_than_unsigned_immediate,
            and_immediate,
            or_immediate,
            xor_immediate,
            load_immediate,
            load_upper_immediate,
            load_8,
            load_16,
            load_32,
            load_8_unsigned,
            load_16_unsigned,
            load_word_left,
            load_word_right,
            store_8,
            store_16,
            store_32,
            store_word_left,
            store_word_right,
        ]
        .into_iter()
    }
}

impl IntoEnumIterator for Instruction {
    // The underlying type is inexpressible, due to the function types :|
    type Iterator = Box<dyn Iterator<Item = Self>>;
    fn iter() -> Self::Iterator {
        Box::new(
            RTypeInstruction::iter()
                .map(&Instruction::RType)
                .chain(JTypeInstruction::iter().map(&Instruction::JType))
                .chain(ITypeInstruction::iter().map(&Instruction::IType)),
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter)]
pub enum InstructionPart {
    OpCode,
    RS,
    RT,
    RD,
    Shamt,
    Funct,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct InstructionParts<T> {
    pub op_code: T,
    pub rs: T,
    pub rt: T,
    pub rd: T,
    pub shamt: T,
    pub funct: T,
}

impl<A> Index<InstructionPart> for InstructionParts<A> {
    type Output = A;

    fn index(&self, index: InstructionPart) -> &Self::Output {
        match index {
            InstructionPart::OpCode => &self.op_code,
            InstructionPart::RS => &self.rs,
            InstructionPart::RT => &self.rt,
            InstructionPart::RD => &self.rd,
            InstructionPart::Shamt => &self.shamt,
            InstructionPart::Funct => &self.funct,
        }
    }
}

impl<A> IndexMut<InstructionPart> for InstructionParts<A> {
    fn index_mut(&mut self, index: InstructionPart) -> &mut Self::Output {
        match index {
            InstructionPart::OpCode => &mut self.op_code,
            InstructionPart::RS => &mut self.rs,
            InstructionPart::RT => &mut self.rt,
            InstructionPart::RD => &mut self.rd,
            InstructionPart::Shamt => &mut self.shamt,
            InstructionPart::Funct => &mut self.funct,
        }
    }
}

impl<A> InstructionParts<A> {
    pub fn as_ref(&self) -> InstructionParts<&A> {
        InstructionParts {
            op_code: &self.op_code,
            rs: &self.rs,
            rt: &self.rt,
            rd: &self.rd,
            shamt: &self.shamt,
            funct: &self.funct,
        }
    }

    pub fn as_mut(&mut self) -> InstructionParts<&mut A> {
        InstructionParts {
            op_code: &mut self.op_code,
            rs: &mut self.rs,
            rt: &mut self.rt,
            rd: &mut self.rd,
            shamt: &mut self.shamt,
            funct: &mut self.funct,
        }
    }

    pub fn map<B, F: FnMut(A) -> B>(self, mut f: F) -> InstructionParts<B> {
        let InstructionParts {
            op_code,
            rs,
            rt,
            rd,
            shamt,
            funct,
        } = self;
        InstructionParts {
            op_code: f(op_code),
            rs: f(rs),
            rt: f(rt),
            rd: f(rd),
            shamt: f(shamt),
            funct: f(funct),
        }
    }
}

impl<A> IntoIterator for InstructionParts<A> {
    type Item = A;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let InstructionParts {
            op_code,
            rs,
            rt,
            rd,
            shamt,
            funct,
        } = self;
        vec![op_code, rs, rt, rd, shamt, funct].into_iter()
    }
}

// TODO(dw): see comment above regarding RTypeInstruction definition. Use
// num_trait/num_derive instead.
pub fn encode_rtype(instr: RTypeInstruction) -> (u32, u32) {
    let funct = match instr {
        RTypeInstruction::ShiftLeftLogical => 0,
        RTypeInstruction::ShiftRightLogical => 2,
        RTypeInstruction::ShiftRightArithmetic => 3,
        RTypeInstruction::ShiftLeftLogicalVariable => 4,
        RTypeInstruction::ShiftRightLogicalVariable => 6,
        RTypeInstruction::ShiftRightArithmeticVariable => 7,
        RTypeInstruction::JumpRegister => 8,
        RTypeInstruction::JumpAndLinkRegister => 9,
        RTypeInstruction::Syscall => 12,
        RTypeInstruction::MoveFromHi => 16,
        RTypeInstruction::MoveToHi => 17,
        RTypeInstruction::MoveFromLo => 18,
        RTypeInstruction::MoveToLo => 19,
        RTypeInstruction::Multiply => 24,
        RTypeInstruction::MultiplyUnsigned => 25,
        RTypeInstruction::Div => 26,
        RTypeInstruction::DivUnsigned => 27,
        RTypeInstruction::Add => 32,
        RTypeInstruction::AddUnsigned => 33,
        RTypeInstruction::Sub => 34,
        RTypeInstruction::SubUnsigned => 35,
        RTypeInstruction::And => 36,
        RTypeInstruction::Or => 37,
        RTypeInstruction::Xor => 38,
        RTypeInstruction::Nor => 39,
        RTypeInstruction::SetLessThan => 42,
        RTypeInstruction::SetLessThanUnsigned => 43,
    };
    (0, funct)
}

pub fn decode_rtype((instr, funct): (u32, u32)) -> Option<RTypeInstruction> {
    if instr != 0 {
        return None;
    }
    let instruction = match funct {
        0 => RTypeInstruction::ShiftLeftLogical,
        2 => RTypeInstruction::ShiftRightLogical,
        3 => RTypeInstruction::ShiftRightArithmetic,
        4 => RTypeInstruction::ShiftLeftLogicalVariable,
        6 => RTypeInstruction::ShiftRightLogicalVariable,
        7 => RTypeInstruction::ShiftRightArithmeticVariable,
        8 => RTypeInstruction::JumpRegister,
        9 => RTypeInstruction::JumpAndLinkRegister,
        12 => RTypeInstruction::Syscall,
        16 => RTypeInstruction::MoveFromHi,
        17 => RTypeInstruction::MoveToHi,
        18 => RTypeInstruction::MoveFromLo,
        19 => RTypeInstruction::MoveToLo,
        24 => RTypeInstruction::Multiply,
        25 => RTypeInstruction::MultiplyUnsigned,
        26 => RTypeInstruction::Div,
        27 => RTypeInstruction::DivUnsigned,
        32 => RTypeInstruction::Add,
        33 => RTypeInstruction::AddUnsigned,
        34 => RTypeInstruction::Sub,
        35 => RTypeInstruction::SubUnsigned,
        36 => RTypeInstruction::And,
        37 => RTypeInstruction::Or,
        38 => RTypeInstruction::Xor,
        39 => RTypeInstruction::Nor,
        42 => RTypeInstruction::SetLessThan,
        43 => RTypeInstruction::SetLessThanUnsigned,
        _ => return None,
    };
    Some(instruction)
}

pub fn encode_jtype(instr: JTypeInstruction) -> u32 {
    match instr {
        JTypeInstruction::Jump => 2,
        JTypeInstruction::JumpAndLink => 3,
    }
}

pub fn decode_jtype(instr: u32) -> Option<JTypeInstruction> {
    match instr {
        2 => Some(JTypeInstruction::Jump),
        3 => Some(JTypeInstruction::JumpAndLink),
        _ => None,
    }
}

pub fn encode_itype(instr: ITypeInstruction) -> u32 {
    match instr {
        ITypeInstruction::BranchEq => 4,
        ITypeInstruction::BranchNeq => 5,
        ITypeInstruction::BranchLeqZero => 6,
        ITypeInstruction::BranchGtZero => 7,
        ITypeInstruction::AddImmediate => 8,
        ITypeInstruction::AddImmediateUnsigned => 9,
        ITypeInstruction::SetLessThanImmediate => 10,
        ITypeInstruction::SetLessThanImmediateUnsigned => 11,
        ITypeInstruction::AndImmediate => 12,
        ITypeInstruction::OrImmediate => 13,
        ITypeInstruction::XorImmediate => 14,
        ITypeInstruction::LoadImmediate => 15,
        ITypeInstruction::Load8 => 32,
        ITypeInstruction::Load16 => 33,
        ITypeInstruction::Load32 => 34,
        ITypeInstruction::Load8Unsigned => 36,
        ITypeInstruction::Load16Unsigned => 37,
        ITypeInstruction::Store8 => 40,
        ITypeInstruction::Store16 => 41,
        ITypeInstruction::Store32 => 43,
        // TODO(dw)
        _ => unimplemented!("FIXME"),
    }
}

pub fn decode_itype(instr: u32) -> Option<ITypeInstruction> {
    let instruction = match instr {
        4 => ITypeInstruction::BranchEq,
        5 => ITypeInstruction::BranchNeq,
        6 => ITypeInstruction::BranchLeqZero,
        7 => ITypeInstruction::BranchGtZero,
        8 => ITypeInstruction::AddImmediate,
        9 => ITypeInstruction::AddImmediateUnsigned,
        10 => ITypeInstruction::SetLessThanImmediate,
        11 => ITypeInstruction::SetLessThanImmediateUnsigned,
        12 => ITypeInstruction::AndImmediate,
        13 => ITypeInstruction::OrImmediate,
        14 => ITypeInstruction::XorImmediate,
        15 => ITypeInstruction::LoadImmediate,
        32 => ITypeInstruction::Load8,
        33 => ITypeInstruction::Load16,
        34 => ITypeInstruction::Load32,
        36 => ITypeInstruction::Load8Unsigned,
        37 => ITypeInstruction::Load16Unsigned,
        40 => ITypeInstruction::Store8,
        41 => ITypeInstruction::Store16,
        43 => ITypeInstruction::Store32,
        _ => return None,
    };
    Some(instruction)
}

pub fn encode_selector(instr: Instruction) -> (u32, Option<u32>) {
    match instr {
        Instruction::RType(instr) => {
            let (opcode, funct) = encode_rtype(instr);
            (opcode, Some(funct))
        }
        Instruction::JType(instr) => (encode_jtype(instr), None),
        Instruction::IType(instr) => (encode_itype(instr), None),
    }
}

pub fn decode_selector((instr, funct): (u32, u32)) -> Option<Instruction> {
    if let Some(rtype) = decode_rtype((instr, funct)) {
        return Some(Instruction::RType(rtype));
    }
    if let Some(jtype) = decode_jtype(instr) {
        return Some(Instruction::JType(jtype));
    }
    if let Some(itype) = decode_itype(instr) {
        return Some(Instruction::IType(itype));
    }
    None
}

pub fn decode(instruction: u32) -> Option<Instruction> {
    println!("Instr {:#x}", instruction);
    let instr = instruction >> 26;
    let funct = instruction & ((1 << 6) - 1);
    decode_selector((instr, funct))
}

// Imported as it.
pub trait InstructionEnvironment {
    type Column;
    type Variable: std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + Clone;
    type Fp: std::ops::Neg<Output = Self::Fp> + PartialEq;

    fn current_row(&self) -> Self::Variable;

    fn constant(x: u32) -> Self::Variable;

    fn to_fp(x: Self::Variable) -> Self::Fp;

    fn v0_register_idx() -> Self::Variable {
        Self::constant(2)
    }

    fn v1_register_idx() -> Self::Variable {
        Self::constant(3)
    }

    fn a0_register_idx() -> Self::Variable {
        Self::constant(4)
    }

    fn a1_register_idx() -> Self::Variable {
        Self::constant(5)
    }

    fn a2_register_idx() -> Self::Variable {
        Self::constant(6)
    }

    fn a3_register_idx() -> Self::Variable {
        Self::constant(7)
    }

    fn hi_register_idx() -> Self::Variable {
        Self::constant(32)
    }

    fn lo_register_idx() -> Self::Variable {
        Self::constant(33)
    }

    // File descriptors
    fn stdin_fd() -> Self::Variable {
        Self::constant(0)
    }

    fn stdout_fd() -> Self::Variable {
        Self::constant(1)
    }

    fn stderr_fd() -> Self::Variable {
        Self::constant(2)
    }

    fn hint_read_fd() -> Self::Variable {
        Self::constant(3)
    }

    fn hint_write_fd() -> Self::Variable {
        Self::constant(4)
    }

    fn preimage_oracle_read_fd() -> Self::Variable {
        Self::constant(5)
    }

    fn preimage_oracle_write_fd() -> Self::Variable {
        Self::constant(6)
    }

    // Syscall values
    // TODO: move into an enum
    fn syscall_sysmmap_value() -> Self::Variable {
        Self::constant(4090)
    }

    fn syscall_sysbrk_value() -> Self::Variable {
        Self::constant(4045)
    }

    fn syscall_sysclone_value() -> Self::Variable {
        Self::constant(4120)
    }

    fn syscall_exit_group_value() -> Self::Variable {
        Self::constant(4246)
    }

    // FIXME: REMOVEME, it is for foo.mips to work
    fn syscall_exit_group_value_foo() -> Self::Variable {
        Self::constant(10)
    }

    fn syscall_read_value() -> Self::Variable {
        Self::constant(4003)
    }

    fn syscall_write_value() -> Self::Variable {
        Self::constant(4004)
    }

    fn syscall_sysfcntl_value() -> Self::Variable {
        Self::constant(4055)
    }

    fn instruction_pointer(&self) -> Self::Variable;

    fn set_instruction_pointer(&mut self, ip: &Self::Variable);

    fn halted(&self) -> Self::Variable;

    fn set_halted(&mut self, value: &Self::Variable);

    fn memory_accessible(
        &mut self,
        is_enabled: &Self::Variable,
        column: Self::Column,
        addresses: Vec<&Self::Variable>,
    ) -> Self::Variable;

    fn read_memory(
        &mut self,
        output: Self::Column,
        address: &Self::Variable,
        accessible: &Self::Variable,
    ) -> Self::Variable;

    fn get_register_value(
        &mut self,
        register_idx: &Self::Variable,
        output_value: Self::Column,
    ) -> Self::Variable;

    fn set_register_value(&mut self, register_idx: &Self::Variable, value: &Self::Variable);

    fn last_register_write(
        &mut self,
        register_idx: &Self::Variable,
        output_last_write: Self::Column,
    ) -> Self::Variable;

    fn set_last_register_write(
        &mut self,
        register_idx: &Self::Variable,
        last_write: &Self::Variable,
    );

    fn fetch_register(
        &mut self,
        register_idx: &Self::Variable,
        output_value: Self::Column,
        output_last_write: Self::Column,
    ) -> (Self::Variable, Self::Variable) {
        let value = self.get_register_value(register_idx, output_value);

        let update_row = self.current_row();

        // Insert new values
        self.add_lookup(Lookup {
            numerator: Self::to_fp(Self::constant(1)),
            table_id: Self::to_fp(Self::constant(TableID::Registers as u32)),
            value: vec![
                Self::to_fp(value.clone()),
                Self::to_fp(register_idx.clone()),
                Self::to_fp(update_row.clone()),
            ],
        });

        let last_write = self.last_register_write(&register_idx, output_last_write);
        self.set_last_register_write(&register_idx, &update_row);

        // Remove old values
        self.add_lookup(Lookup {
            numerator: -Self::to_fp(Self::constant(1)),
            table_id: Self::to_fp(Self::constant(TableID::Registers as u32)),
            value: vec![
                Self::to_fp(value.clone()),
                Self::to_fp(register_idx.clone()),
                Self::to_fp(last_write.clone()),
            ],
        });

        (value, last_write)
    }

    fn overwrite_register(
        &mut self,
        register_idx: &Self::Variable,
        value: &Self::Variable,
        output_last_write: Self::Column,
    ) -> Self::Variable {
        let update_row = self.current_row();

        // Insert new values
        self.add_lookup(Lookup {
            numerator: Self::to_fp(Self::constant(1)),
            table_id: Self::to_fp(Self::constant(TableID::Registers as u32)),
            value: vec![
                Self::to_fp(value.clone()),
                Self::to_fp(register_idx.clone()),
                Self::to_fp(update_row.clone()),
            ],
        });

        let output_old_value = self.alloc_scratch();
        let old_value = self.get_register_value(&register_idx, output_old_value);
        self.set_register_value(&register_idx, &value);

        let last_write = self.last_register_write(&register_idx, output_last_write);
        self.set_last_register_write(&register_idx, &update_row);

        // Remove old values
        self.add_lookup(Lookup {
            numerator: -Self::to_fp(Self::constant(1)),
            table_id: Self::to_fp(Self::constant(TableID::Registers as u32)),
            value: vec![
                Self::to_fp(old_value),
                Self::to_fp(register_idx.clone()),
                Self::to_fp(last_write.clone()),
            ],
        });

        last_write
    }

    fn get_memory_value(
        &mut self,
        address: &Self::Variable,
        enabled_if: &Self::Variable,
        output_value: Self::Column,
    ) -> Self::Variable;

    fn set_memory_value(
        &mut self,
        address: &Self::Variable,
        enabled_if: &Self::Variable,
        value: &Self::Variable,
    );

    fn last_memory_write(
        &mut self,
        address: &Self::Variable,
        enabled_if: &Self::Variable,
        output_last_write: Self::Column,
    ) -> Self::Variable;

    fn set_last_memory_write(
        &mut self,
        address: &Self::Variable,
        enabled_if: &Self::Variable,
        last_write: &Self::Variable,
    );

    fn fetch_memory(
        &mut self,
        address: &Self::Variable,
        enabled_if: &Self::Variable,
        output_value: Self::Column,
        output_last_write: Self::Column,
    ) -> (Self::Variable, Self::Variable) {
        let value = self.get_memory_value(address, enabled_if, output_value);

        let update_row = self.current_row();

        // Insert new values
        self.add_lookup(Lookup {
            numerator: Self::to_fp(enabled_if.clone()),
            table_id: Self::to_fp(Self::constant(TableID::Memory as u32)),
            value: vec![
                Self::to_fp(value.clone()),
                Self::to_fp(address.clone()),
                Self::to_fp(update_row.clone()),
            ],
        });

        let last_write = self.last_memory_write(&address, enabled_if, output_last_write);
        self.set_last_memory_write(&address, enabled_if, &update_row);

        // Remove old values
        self.add_lookup(Lookup {
            numerator: -Self::to_fp(enabled_if.clone()),
            table_id: Self::to_fp(Self::constant(TableID::Memory as u32)),
            value: vec![
                Self::to_fp(value.clone()),
                Self::to_fp(address.clone()),
                Self::to_fp(last_write.clone()),
            ],
        });

        (value, last_write)
    }

    fn overwrite_memory(
        &mut self,
        address: &Self::Variable,
        value: &Self::Variable,
        enabled_if: &Self::Variable,
        output_last_write: Self::Column,
    ) -> Self::Variable {
        let update_row = self.current_row();

        // Insert new values
        self.add_lookup(Lookup {
            numerator: Self::to_fp(enabled_if.clone()),
            table_id: Self::to_fp(Self::constant(TableID::Memory as u32)),
            value: vec![
                Self::to_fp(value.clone()),
                Self::to_fp(address.clone()),
                Self::to_fp(update_row.clone()),
            ],
        });

        let output_old_value = self.alloc_scratch();
        let old_value = self.get_memory_value(&address, enabled_if, output_old_value);
        self.set_memory_value(&address, enabled_if, &value);

        let last_write = self.last_memory_write(&address, enabled_if, output_last_write);
        self.set_last_memory_write(&address, enabled_if, &update_row);

        // Remove old values
        self.add_lookup(Lookup {
            numerator: -Self::to_fp(enabled_if.clone()),
            table_id: Self::to_fp(Self::constant(TableID::Memory as u32)),
            value: vec![
                Self::to_fp(old_value),
                Self::to_fp(address.clone()),
                Self::to_fp(last_write.clone()),
            ],
        });

        last_write
    }

    fn instruction_part(&self, part: InstructionPart) -> Self::Variable;

    fn immediate(&self) -> Self::Variable {
        self.instruction_part(InstructionPart::RD) * Self::constant(1 << 11)
            + self.instruction_part(InstructionPart::Shamt) * Self::constant(1 << 6)
            + self.instruction_part(InstructionPart::Funct)
    }

    fn add_lookup(&mut self, lookup: Lookup<Self::Fp>);

    fn increment_range_check_counter(&mut self, value: &Self::Variable);

    fn range_check_16(&mut self, value: &Self::Variable) {
        self.increment_range_check_counter(value);
        self.add_lookup(Lookup {
            numerator: -Self::to_fp(Self::constant(1u32)),
            table_id: Self::to_fp(Self::constant(TableID::RangeCheck16 as u32)),
            value: vec![Self::to_fp(value.clone())],
        });
    }

    fn range_check(&mut self, value: &Self::Variable, shift: u32) {
        if shift < 16 {
            let shift_actual = Self::constant(1 << (16 - shift));
            self.range_check_16(value);
            self.range_check_16(&(value.clone() * shift_actual));
        } else {
            panic!("Unexpected shift: {}", shift)
        }
    }

    fn range_check_1(&mut self, value: &Self::Variable);

    fn range_check_2(&mut self, value: &Self::Variable);

    fn decompose(
        &mut self,
        value: &Self::Variable,
        decomposition_little_endian: Vec<u32>,
        outputs: Vec<Self::Column>,
    ) -> Vec<Self::Variable>;

    fn div_rem(
        &mut self,
        numerator: &Self::Variable,
        denominator: &Self::Variable,
        output_div: Self::Column,
        output_rem: Self::Column,
        output_divide_by_zero: Self::Column,
    ) -> (Self::Variable, Self::Variable, Self::Variable);

    fn and_xor(
        &mut self,
        lhs: &Self::Variable,
        rhs: &Self::Variable,
        output_and: Self::Column,
        output_xor: Self::Column,
    ) -> (Self::Variable, Self::Variable);

    fn alloc_scratch(&mut self) -> Self::Column;

    fn fetch_register_checked(&mut self, register_idx: &Self::Variable) -> Self::Variable {
        let output_register = self.alloc_scratch();
        let output_last_write = self.alloc_scratch();
        let (register, last_write) =
            self.fetch_register(register_idx, output_register, output_last_write);
        self.range_check_16(&(self.current_row() - last_write));
        register
    }

    fn overwrite_register_checked(
        &mut self,
        register_idx: &Self::Variable,
        value: &Self::Variable,
    ) {
        let output_last_write = self.alloc_scratch();
        let last_write = self.overwrite_register(register_idx, value, output_last_write);
        self.range_check_16(&(self.current_row() - last_write));
    }

    fn fetch_memory_checked(
        &mut self,
        address: &Self::Variable,
        enabled_if: &Self::Variable,
    ) -> Self::Variable {
        let output_memory = self.alloc_scratch();
        let output_last_write = self.alloc_scratch();
        let (memory, last_write) =
            self.fetch_memory(&address, enabled_if, output_memory, output_last_write);
        self.range_check_16(&(self.current_row() - last_write));
        memory
    }

    fn overwrite_memory_checked(
        &mut self,
        address: &Self::Variable,
        value: &Self::Variable,
        enabled_if: &Self::Variable,
    ) {
        let output_last_write = self.alloc_scratch();
        let last_write = self.overwrite_memory(address, value, enabled_if, output_last_write);
        self.range_check_16(&(self.current_row() - last_write));
    }

    fn decode(instruction: &Self::Variable) -> Instruction;

    fn assert_(&mut self, value: &Self::Variable);

    fn eq_zero_terms(
        &mut self,
        value: &Self::Variable,
        res_output: Self::Column,
        inv_output: Self::Column,
    ) -> (Self::Variable, Self::Variable);

    fn is_zero(&mut self, value: &Self::Variable) -> Self::Variable {
        let res_output = self.alloc_scratch();
        let inv_output = self.alloc_scratch();
        let (res, inv) = self.eq_zero_terms(value, res_output, inv_output);
        self.assert_(&(inv * value.clone() - (Self::constant(1u32) - res.clone())));
        self.assert_(&(res.clone() * value.clone()));
        res
    }

    fn sign_extend(&mut self, value: &Self::Variable, output: Self::Column) -> Self::Variable;
}

pub fn decode_instruction<Env: InstructionEnvironment>(
    env: &mut Env,
) -> (Instruction, Env::Variable)
where
    Env::Variable: std::fmt::Debug + Zero,
{
    let memory_addrs: [_; 4] = array::from_fn(|i| {
        if i == 0 {
            env.instruction_pointer()
        } else {
            env.instruction_pointer() + Env::constant(i as u32)
        }
    });
    let memory_accessible = {
        let scratch = env.alloc_scratch();
        env.memory_accessible(
            &(Env::constant(1u32) - env.halted()),
            scratch,
            memory_addrs.iter().collect(),
        )
    };
    let may_read = memory_accessible;
    /*
    if !may_read.is_zero() {
        println!("may_read: {:?}", may_read);
    }
    */
    //let may_read = memory_accessible * (Env::constant(1u32) - env.halted());
    let instruction = array::from_fn(|i| env.fetch_memory_checked(&memory_addrs[i], &may_read));

    let instruction = {
        let [i0, i1, i2, i3] = instruction;
        /*
        if !may_read.is_zero() {
            println!("instr: {:?} {:?} {:?} {:?}", i0, i1, i2, i3);
        }
        */
        (Env::constant(1u32 << 24) * i0)
            + (Env::constant(1u32 << 16) * i1)
            + (Env::constant(1u32 << 8) * i2)
            + i3
    };

    (Env::decode(&instruction), instruction)
}


pub fn run_instruction<Env: InstructionEnvironment>(instr: Instruction, env: &mut Env)
where
    Env::Variable: std::fmt::Debug,
{
    use self::{
        ITypeInstruction as IT, Instruction::*, JTypeInstruction as JT, RTypeInstruction as RT,
    };

    match instr {
        RType(RT::ShiftLeftLogical) => (),
        RType(RT::ShiftRightLogical) => (),
        RType(RT::ShiftRightArithmetic) => (),
        RType(RT::ShiftLeftLogicalVariable) => (),
        RType(RT::ShiftRightLogicalVariable) => (),
        RType(RT::ShiftRightArithmeticVariable) => (),
        RType(RT::JumpRegister) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            let decomposition = {
                let scratch = (0..3).map(|_| env.alloc_scratch()).collect();
                env.decompose(&register_rs, vec![16, 14, 2], scratch)
            };
            env.range_check_16(&decomposition[0]);
            env.range_check(&decomposition[1], 14);
            env.range_check_2(&decomposition[2]);
            let is_aligned = env.is_zero(&decomposition[2]);
            // TODO: Don't do this
            let should_halt = Env::constant(1) - is_aligned * (Env::constant(1) - env.halted());
            env.set_halted(&should_halt);
            let halted = env.halted();
            env.set_instruction_pointer(
                &(halted.clone() * register_rs
                    + (Env::constant(1) - halted) * env.instruction_pointer()),
            );
            return;
        }
        RType(RT::JumpAndLinkRegister) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            let rd = env.instruction_part(InstructionPart::RD);
            env.overwrite_register_checked(&rd, &(env.instruction_pointer() + Env::constant(8)));
            let decomposition = {
                let scratch = (0..3).map(|_| env.alloc_scratch()).collect();
                env.decompose(&register_rs, vec![16, 14, 2], scratch)
            };
            env.range_check_16(&decomposition[0]);
            env.range_check(&decomposition[1], 14);
            env.range_check_2(&decomposition[2]);
            let is_aligned = env.is_zero(&decomposition[2]);
            // TODO: Don't do this
            let should_halt = Env::constant(1) - is_aligned * (Env::constant(1) - env.halted());
            env.set_halted(&should_halt);
            let halted = env.halted();
            env.set_instruction_pointer(
                &(halted.clone() * register_rs
                    + (Env::constant(1) - halted) * env.instruction_pointer()),
            );
            return;
        }

        // TODO(dw): implement other syscalls
        RType(RT::SyscallExitGroup) => {
            ()
        }
        RType(RT::SyscallFcntl) => {
            ()
        }
        RType(RT::SyscallOther) => {
            ()
        }
        RType(RT::SyscallReadOther) => {
            ()
        }
        RType(RT::SyscallReadPreimage) => {
            ()
        }
        RType(RT::SyscallWriteHint) => {
            ()
        }
        RType(RT::SyscallWriteOther) => {
            ()
        }
        RType(RT::SyscallWritePreimage) => {
            ()
        }
        RType(RT::SyscallMmap) => {
            // First
            let syscall_number_column = env.alloc_scratch();
            let syscall_number_var =
                env.get_register_value(&Env::v0_register_idx(), syscall_number_column);
            let syscall_number = &Env::to_fp(syscall_number_var);
            // This is not correct, we must transform it in constraints, this is only for the demo!
            // FIXME: halt for foo.mips. This is to have `halted` to true in the logs.
            if syscall_number == &Env::to_fp(Env::syscall_exit_group_value_foo()) {
                // Treat as an effective halt
                env.set_halted(&Env::constant(1u32));
            }
            // OP specific
            else if syscall_number == &Env::to_fp(Env::syscall_exit_group_value()) {
                // Treat as an effective halt
                let a0_register_column = env.alloc_scratch();
                let a0_register_var =
                    env.get_register_value(&Env::a0_register_idx(), a0_register_column);
                env.set_halted(&a0_register_var);
            } else if syscall_number == &Env::to_fp(Env::syscall_sysbrk_value()) {
                // set v0 to 0x400000
                env.overwrite_register_checked(&Env::v0_register_idx(), &Env::constant(0x400000));
                // set a3 to 0
                env.overwrite_register_checked(&Env::a3_register_idx(), &Env::constant(0));
            } else if syscall_number == &Env::to_fp(Env::syscall_sysclone_value()) {
                // set v0 to 1
                env.overwrite_register_checked(&Env::v0_register_idx(), &Env::constant(1));
                // set a3 to 0
                env.overwrite_register_checked(&Env::a3_register_idx(), &Env::constant(0));
            }
            // `sysRead`
            else if syscall_number == &Env::to_fp(Env::syscall_read_value()) {
                let fd_input_column = env.alloc_scratch();
                let fd_input_var = env.get_register_value(&Env::a0_register_idx(), fd_input_column);
                let fd_input = Env::to_fp(fd_input_var);
                let address_column = env.alloc_scratch();
                let _address_var = env.get_register_value(&Env::a1_register_idx(), address_column);
                let nb_bytes_column = env.alloc_scratch();
                let _nb_bytes_var =
                    env.get_register_value(&Env::a3_register_idx(), nb_bytes_column);
                // TODO: only pre-image oracle supported at the moment, without constraint.
                if fd_input == Env::to_fp(Env::stdin_fd()) {
                    // set v0 to the number of written btyes
                    env.overwrite_register_checked(&Env::v0_register_idx(), &Env::constant(0));
                    // set a3 to 0
                    env.overwrite_register_checked(&Env::a3_register_idx(), &Env::constant(0));
                } else if fd_input == Env::to_fp(Env::hint_read_fd()) {
                    // Read nb_bytes
                } else if fd_input == Env::to_fp(Env::preimage_oracle_read_fd()) {
                    // Read nb_bytes
                } else {
                    // set v0 to the number of written btyes
                    env.overwrite_register_checked(
                        &Env::v0_register_idx(),
                        &Env::constant(0xFFffFFff),
                    );
                    // set a3 to 0
                    env.overwrite_register_checked(&Env::a3_register_idx(), &Env::constant(0x09));
                }
            }
            // `sysWrite`
            else if syscall_number == &Env::to_fp(Env::syscall_write_value()) {
                let fd_output_column = env.alloc_scratch();
                let fd_output_var =
                    env.get_register_value(&Env::a0_register_idx(), fd_output_column);
                let fd_output = Env::to_fp(fd_output_var);
                let address_column = env.alloc_scratch();
                let _address_var = env.get_register_value(&Env::a1_register_idx(), address_column);
                let nb_bytes_column = env.alloc_scratch();
                let nb_bytes_var = env.get_register_value(&Env::a3_register_idx(), nb_bytes_column);
                // TODO: only pre-image oracle supported at the moment, without constraint.
                if fd_output == Env::to_fp(Env::stdout_fd()) {
                    // set v0 to the number of written btyes
                    env.overwrite_register_checked(&Env::v0_register_idx(), &nb_bytes_var);
                    // set a3 to 0
                    env.overwrite_register_checked(&Env::a3_register_idx(), &Env::constant(0));
                } else if fd_output == Env::to_fp(Env::stderr_fd()) {
                    // set v0 to the number of written btyes
                    env.overwrite_register_checked(&Env::v0_register_idx(), &nb_bytes_var);
                    // set a3 to 0
                    env.overwrite_register_checked(&Env::a3_register_idx(), &Env::constant(0));
                } else if fd_output == Env::to_fp(Env::hint_write_fd()) {
                    // TODO
                } else if fd_output == Env::to_fp(Env::preimage_oracle_write_fd()) {
                    // TODO
                } else {
                    // set v0 to the number of written btyes
                    env.overwrite_register_checked(
                        &Env::v0_register_idx(),
                        &Env::constant(0xFFffFFff),
                    );
                    // set a3 to 0
                    env.overwrite_register_checked(&Env::a3_register_idx(), &Env::constant(0x09));
                }
            } else {
                // set v0 to 0
                env.overwrite_register_checked(&Env::v0_register_idx(), &Env::constant(0));
                // set a3 to 0
                env.overwrite_register_checked(&Env::a3_register_idx(), &Env::constant(0));
            }
        }
        RType(RT::MoveFromHi) => {
            let register_hi = env.fetch_register_checked(&Env::hi_register_idx());
            let rd = env.instruction_part(InstructionPart::RD);
            env.overwrite_register_checked(&rd, &register_hi);
        }
        RType(RT::MoveToHi) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            env.overwrite_register_checked(&Env::hi_register_idx(), &register_rs);
        }
        RType(RT::MoveFromLo) => {
            let register_lo = env.fetch_register_checked(&Env::lo_register_idx());
            let rd = env.instruction_part(InstructionPart::RD);
            env.overwrite_register_checked(&rd, &register_lo);
        }
        RType(RT::MoveToLo) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            env.overwrite_register_checked(&Env::lo_register_idx(), &register_rs);
        }
        RType(RT::Multiply) => (),
        RType(RT::MultiplyUnsigned) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let rt = env.instruction_part(InstructionPart::RT);
            let register_rs = env.fetch_register_checked(&rs);
            let register_rt = env.fetch_register_checked(&rt);
            let product = register_rs * register_rt;
            let decomposition = {
                let scratch = (0..4).map(|_| env.alloc_scratch()).collect();
                env.decompose(&product, vec![16, 16, 16, 16], scratch)
            };
            env.range_check_16(&decomposition[0]);
            env.range_check_16(&decomposition[1]);
            env.range_check_16(&decomposition[2]);
            env.range_check_16(&decomposition[3]);
            let hi = decomposition[3].clone() * Env::constant(1 << 16) + decomposition[2].clone();
            let lo = decomposition[1].clone() * Env::constant(1 << 16) + decomposition[0].clone();
            env.overwrite_register_checked(&Env::hi_register_idx(), &hi);
            env.overwrite_register_checked(&Env::lo_register_idx(), &lo);
        }
        RType(RT::Div) => (),
        RType(RT::DivUnsigned) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let rt = env.instruction_part(InstructionPart::RT);
            let register_rs = env.fetch_register_checked(&rs);
            let register_rt = env.fetch_register_checked(&rt);
            let (div, rem, divide_by_zero) = {
                let output_div = env.alloc_scratch();
                let output_rem = env.alloc_scratch();
                let output_divide_by_zero = env.alloc_scratch();
                env.div_rem(
                    &register_rs,
                    &register_rt,
                    output_div,
                    output_rem,
                    output_divide_by_zero,
                )
            };
            env.range_check_1(&divide_by_zero);
            let decomposition_div = {
                let scratch = (0..2).map(|_| env.alloc_scratch()).collect();
                env.decompose(&div, vec![16, 16], scratch)
            };
            let decomposition_rem = {
                let scratch = (0..2).map(|_| env.alloc_scratch()).collect();
                env.decompose(&rem, vec![16, 16], scratch)
            };
            env.range_check_16(&decomposition_div[0]);
            env.range_check_16(&decomposition_div[1]);
            env.range_check_16(&decomposition_rem[0]);
            env.range_check_16(&decomposition_rem[1]);
            let hi = decomposition_rem[1].clone() * Env::constant(1 << 16)
                + decomposition_rem[0].clone();
            let lo = decomposition_div[1].clone() * Env::constant(1 << 16)
                + decomposition_div[0].clone();
            env.overwrite_register_checked(&Env::hi_register_idx(), &hi);
            env.overwrite_register_checked(&Env::lo_register_idx(), &lo);
            // TODO: Don't do this
            let should_halt = Env::constant(1)
                - (Env::constant(1) - divide_by_zero) * (Env::constant(1) - env.halted());
            env.set_halted(&should_halt);
        }
        RType(RT::Add) => (),
        RType(RT::AddUnsigned) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let rt = env.instruction_part(InstructionPart::RT);
            let register_rs = env.fetch_register_checked(&rs);
            let register_rt = env.fetch_register_checked(&rt);
            let product = register_rs + register_rt;
            let decomposition = {
                let scratch = (0..3).map(|_| env.alloc_scratch()).collect();
                env.decompose(&product, vec![16, 16, 1], scratch)
            };
            env.range_check_16(&decomposition[0]);
            env.range_check_16(&decomposition[1]);
            env.range_check_1(&decomposition[2]);
            let value =
                decomposition[1].clone() * Env::constant(1 << 16) + decomposition[0].clone();
            let rd = env.instruction_part(InstructionPart::RD);
            env.overwrite_register_checked(&rd, &value);
        }
        RType(RT::Sub) => (),
        RType(RT::SubUnsigned) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let rt = env.instruction_part(InstructionPart::RT);
            let register_rs = env.fetch_register_checked(&rs);
            let register_rt = env.fetch_register_checked(&rt);
            let product = register_rs - register_rt;
            let decomposition = {
                let scratch = (0..3).map(|_| env.alloc_scratch()).collect();
                env.decompose(&product, vec![16, 16, 1], scratch)
            };
            env.range_check_16(&decomposition[0]);
            env.range_check_16(&decomposition[1]);
            env.range_check_1(&decomposition[2]);
            let value =
                decomposition[1].clone() * Env::constant(1 << 16) + decomposition[0].clone();
            let rd = env.instruction_part(InstructionPart::RD);
            env.overwrite_register_checked(&rd, &value);
        }
        RType(RT::And) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let rt = env.instruction_part(InstructionPart::RT);
            let register_rs = env.fetch_register_checked(&rs);
            let register_rt = env.fetch_register_checked(&rt);
            let (and, _xor) = {
                let output_and = env.alloc_scratch();
                let output_xor = env.alloc_scratch();
                env.and_xor(&register_rs, &register_rt, output_and, output_xor)
            };
            let rd = env.instruction_part(InstructionPart::RD);
            env.overwrite_register_checked(&rd, &and);
        }
        RType(RT::Or) => (),
        RType(RT::Xor) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let rt = env.instruction_part(InstructionPart::RT);
            let register_rs = env.fetch_register_checked(&rs);
            let register_rt = env.fetch_register_checked(&rt);
            let (_and, xor) = {
                let output_and = env.alloc_scratch();
                let output_xor = env.alloc_scratch();
                env.and_xor(&register_rs, &register_rt, output_and, output_xor)
            };
            let rd = env.instruction_part(InstructionPart::RD);
            env.overwrite_register_checked(&rd, &xor);
        }
        RType(RT::Nor) => (),
        RType(RT::SetLessThan) => (),
        RType(RT::SetLessThanUnsigned) => (),
        JType(JT::Jump) => return,
        JType(JT::JumpAndLink) => {
            let value = env.instruction_pointer() + Env::constant(8);
            env.overwrite_register_checked(&Env::constant(31), &value);
            return;
        }
        IType(IT::BranchEq) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            let rt = env.instruction_part(InstructionPart::RT);
            let register_rt = env.fetch_register_checked(&rt);
            let equal = env.is_zero(&(register_rs - register_rt));
            let imm = env.immediate();
            let offset = {
                let offset_output = env.alloc_scratch();
                env.sign_extend(&imm, offset_output)
            };
            let ip = env.instruction_pointer();
            env.set_instruction_pointer(
                &(ip + Env::constant(4) + equal * offset * Env::constant(4)),
            );
            return;
        }
        IType(IT::BranchNeq) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            let rt = env.instruction_part(InstructionPart::RT);
            let register_rt = env.fetch_register_checked(&rt);
            let equal = env.is_zero(&(register_rs - register_rt));
            let imm = env.immediate();
            let offset = {
                let offset_output = env.alloc_scratch();
                env.sign_extend(&imm, offset_output)
            };
            let ip = env.instruction_pointer();
            // println!("imm: {:?}", imm);
            // println!("offset: {:?}", offset);
            // println!("equal: {:?}", equal);
            env.set_instruction_pointer(
                &(ip + Env::constant(4) + (Env::constant(1) - equal) * offset * Env::constant(4)),
            );
            return;
        }
        IType(IT::BranchLeqZero) => return,
        IType(IT::BranchGtZero) => return,
        IType(IT::AddImmediate) => (),
        IType(IT::AddImmediateUnsigned) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            let imm = env.immediate();
            let res = register_rs + imm;
            let rt = env.instruction_part(InstructionPart::RT);
            env.overwrite_register_checked(&rt, &res);
        }
        IType(IT::SetLessThanImmediate) => (),
        IType(IT::SetLessThanImmediateUnsigned) => (),
        IType(IT::AndImmediate) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            let imm = env.immediate();
            let (and, _xor) = {
                let output_and = env.alloc_scratch();
                let output_xor = env.alloc_scratch();
                env.and_xor(&register_rs, &imm, output_and, output_xor)
            };
            let rt = env.instruction_part(InstructionPart::RT);
            env.overwrite_register_checked(&rt, &and);
        }
        IType(IT::OrImmediate) => (),
        IType(IT::XorImmediate) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            let imm = env.immediate();
            let (_and, xor) = {
                let output_and = env.alloc_scratch();
                let output_xor = env.alloc_scratch();
                env.and_xor(&register_rs, &imm, output_and, output_xor)
            };
            let rt = env.instruction_part(InstructionPart::RT);
            env.overwrite_register_checked(&rt, &xor);
        }
        IType(IT::LoadImmediate) => {
            let rt = env.instruction_part(InstructionPart::RT);
            let imm = env.immediate();
            env.overwrite_register_checked(&rt, &(imm * Env::constant(1u32 << 16)));
        }
        IType(IT::Load8) => (),
        IType(IT::Load16) => (),
        IType(IT::Load32) => (),
        IType(IT::Load8Unsigned) => (),
        IType(IT::Load16Unsigned) => (),
        IType(IT::Store8) => (),
        IType(IT::Store16) => (),
        IType(IT::Store32) => (),
    };
    let ip = env.instruction_pointer();
    env.set_instruction_pointer(&(ip + Env::constant(4) - env.halted() * Env::constant(4)));
}
