use strum_macros::{EnumCount, EnumIter};
use std::ops::{Index, IndexMut};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;

pub const FD_STDIN: u32 = 0;
pub const FD_STDOUT: u32 = 1;
pub const FD_STDERR: u32 = 2;
pub const FD_HINT_READ: u32 = 3;
pub const FD_HINT_WRITE: u32 = 4;
pub const FD_PREIMAGE_READ: u32 = 5;
pub const FD_PREIMAGE_WRITE: u32 = 6;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Instruction {
    RType(RTypeInstruction),
    JType(JTypeInstruction),
    IType(ITypeInstruction),
}

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
    MoveZero,                     // movz
    MoveNonZero,                  // movn
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
            r_type: r_type.map(|x| f(x)),
            j_type: j_type.map(|x| f(x)),
            i_type: i_type.map(|x| f(x)),
        }
    }

    pub fn into_iter(self) -> impl Iterator<Item = A> {
        let InstructionSelectors {
            r_type,
            j_type,
            i_type,
        } = self;
        r_type
            .into_iter()
            .chain(j_type.into_iter())
            .chain(i_type.into_iter())
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

    pub fn into_iter(self) -> impl Iterator<Item = A> {
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

    pub fn into_iter(self) -> impl Iterator<Item = A> {
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
    pub store_8: T,
    pub store_16: T,
    pub store_32: T,
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
            ITypeInstruction::Store8 => &self.store_8,
            ITypeInstruction::Store16 => &self.store_16,
            ITypeInstruction::Store32 => &self.store_32,
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
            ITypeInstruction::Store8 => &mut self.store_8,
            ITypeInstruction::Store16 => &mut self.store_16,
            ITypeInstruction::Store32 => &mut self.store_32,
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
            store_8: &self.store_8,
            store_16: &self.store_16,
            store_32: &self.store_32,
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
            store_8: &mut self.store_8,
            store_16: &mut self.store_16,
            store_32: &mut self.store_32,
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
            store_8,
            store_16,
            store_32,
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
            store_8: f(store_8),
            store_16: f(store_16),
            store_32: f(store_32),
        }
    }

    pub fn into_iter(self) -> impl Iterator<Item = A> {
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
            store_8,
            store_16,
            store_32,
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
            store_8,
            store_16,
            store_32,
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

// pub fn all_instruction_selectors() -> impl Iterator<Item = Column> {
//     Instruction::iter().map(Column::Instruction)
// }

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

    pub fn into_iter(self) -> impl Iterator<Item = A> {
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
