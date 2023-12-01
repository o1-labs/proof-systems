use serde::{Deserialize, Serialize};
use std::ops::Index;
use log::debug;
use strum_macros::{EnumCount, EnumIter};

pub const FD_STDIN: u32 = 0;
pub const FD_STDOUT: u32 = 1;
pub const FD_STDERR: u32 = 2;
pub const FD_HINT_READ: u32 = 3;
pub const FD_HINT_WRITE: u32 = 4;
pub const FD_PREIMAGE_READ: u32 = 5;
pub const FD_PREIMAGE_WRITE: u32 = 6;

// Source: https://www.doc.ic.ac.uk/lab/secondyear/spim/node10.html
// Reserved for assembler
pub const REGISTER_AT: u32 = 1;
// Argument 0
pub const REGISTER_A0: u32 = 4;
// Argument 1
pub const REGISTER_A1: u32 = 5;
// Argument 2
pub const REGISTER_A2: u32 = 6;
// Argument 3
pub const REGISTER_A3: u32 = 7;
// Temporary (not preserved across call)
pub const REGISTER_T0: u32 = 8;
// Temporary (not preserved across call)
pub const REGISTER_T1: u32 = 9;
// Temporary (not preserved across call)
pub const REGISTER_T2: u32 = 10;
// Temporary (not preserved across call)
pub const REGISTER_T3: u32 = 11;
// Temporary (not preserved across call)
pub const REGISTER_T4: u32 = 12;
// Temporary (not preserved across call)
pub const REGISTER_T5: u32 = 13;
// Temporary (not preserved across call)
pub const REGISTER_T6: u32 = 14;
// Temporary (not preserved across call)
pub const REGISTER_T7: u32 = 15;
// Saved temporary (preserved across call)
pub const REGISTER_S0: u32 = 16;
// Saved temporary (preserved across call)
pub const REGISTER_S1: u32 = 17;
// Saved temporary (preserved across call)
pub const REGISTER_S2: u32 = 18;
// Saved temporary (preserved across call)
pub const REGISTER_S3: u32 = 19;
// Saved temporary (preserved across call)
pub const REGISTER_S4: u32 = 20;
// Saved temporary (preserved across call)
pub const REGISTER_S5: u32 = 21;
// Saved temporary (preserved across call)
pub const REGISTER_S6: u32 = 22;
// Saved temporary (preserved across call)
pub const REGISTER_S7: u32 = 23;
// Temporary (not preserved across call)
pub const REGISTER_T8: u32 = 24;
// Temporary (not preserved across call)
pub const REGISTER_T9: u32 = 25;
// Reserved for OS kernel
pub const REGISTER_K0: u32 = 26;
// Reserved for OS kernel
pub const REGISTER_K1: u32 = 27;
// Pointer to global area
pub const REGISTER_GP: u32 = 28;
// Stack pointer
pub const REGISTER_SP: u32 = 29;
// Frame pointer
pub const REGISTER_FP: u32 = 30;
// Return address (used by function call)
pub const REGISTER_RA: u32 = 31;

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

// To use InstructionParts[OpCode]
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

pub trait InterpreterEnv {
    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<u32, Output = Self::Variable>
        + std::ops::Shl<u32, Output = Self::Variable>
        + std::ops::BitAnd<u32, Output = Self::Variable>
        + std::fmt::Display;

    fn overwrite_register_checked(&mut self, register_idx: &Self::Variable, value: &Self::Variable);

    fn fetch_register_checked(&self, register_idx: &Self::Variable) -> Self::Variable;

    fn fetch_memory(&mut self, addr: &Self::Variable) -> Self::Variable;

    fn set_instruction_pointer(&mut self, ip: Self::Variable);

    fn get_immediate(&self) -> Self::Variable {
        // The immediate value is the last 16bits
        (self.get_instruction_part(InstructionPart::RD) << 11)
            + (self.get_instruction_part(InstructionPart::Shamt) << 6)
            + (self.get_instruction_part(InstructionPart::Funct))
    }

    fn get_instruction_pointer(&self) -> Self::Variable;

    fn get_instruction_part(&self, part: InstructionPart) -> Self::Variable;

    fn constant(x: u32) -> Self::Variable;

    fn set_halted(&mut self, flag: Self::Variable);
}

pub fn interpret_instruction<Env: InterpreterEnv>(env: &mut Env, instr: Instruction) {
    match instr {
        Instruction::RType(instr) => interpret_rtype(env, instr),
        Instruction::JType(instr) => interpret_jtype(env, instr),
        Instruction::IType(instr) => interpret_itype(env, instr),
    }
}

pub fn interpret_rtype<Env: InterpreterEnv>(env: &mut Env, instr: RTypeInstruction) {
    match instr {
        RTypeInstruction::ShiftLeftLogical => (),
        RTypeInstruction::ShiftRightLogical => (),
        RTypeInstruction::ShiftRightArithmetic => (),
        RTypeInstruction::ShiftLeftLogicalVariable => (),
        RTypeInstruction::ShiftRightLogicalVariable => (),
        RTypeInstruction::ShiftRightArithmeticVariable => (),
        RTypeInstruction::JumpRegister => (),
        RTypeInstruction::JumpAndLinkRegister => (),
        RTypeInstruction::SyscallMmap => (),
        RTypeInstruction::SyscallExitGroup => (),
        RTypeInstruction::SyscallReadPreimage => (),
        RTypeInstruction::SyscallReadOther => (),
        RTypeInstruction::SyscallWriteHint => (),
        RTypeInstruction::SyscallWritePreimage => (),
        RTypeInstruction::SyscallWriteOther => (),
        RTypeInstruction::SyscallFcntl => (),
        RTypeInstruction::SyscallOther => (),
        RTypeInstruction::MoveZero => (),
        RTypeInstruction::MoveNonZero => (),
        RTypeInstruction::Sync => (),
        RTypeInstruction::MoveFromHi => (),
        RTypeInstruction::MoveToHi => (),
        RTypeInstruction::MoveFromLo => (),
        RTypeInstruction::MoveToLo => (),
        RTypeInstruction::Multiply => (),
        RTypeInstruction::MultiplyUnsigned => (),
        RTypeInstruction::Div => (),
        RTypeInstruction::DivUnsigned => (),
        RTypeInstruction::Add => (),
        RTypeInstruction::AddUnsigned => (),
        RTypeInstruction::Sub => (),
        RTypeInstruction::SubUnsigned => (),
        RTypeInstruction::And => (),
        RTypeInstruction::Or => (),
        RTypeInstruction::Xor => (),
        RTypeInstruction::Nor => (),
        RTypeInstruction::SetLessThan => (),
        RTypeInstruction::SetLessThanUnsigned => (),
        RTypeInstruction::MultiplyToRegister => (),
        RTypeInstruction::CountLeadingOnes => (),
        RTypeInstruction::CountLeadingZeros => (),
    };
    // TODO: Don't halt.
    env.set_halted(Env::constant(1));
}

pub fn interpret_jtype<Env: InterpreterEnv>(env: &mut Env, instr: JTypeInstruction) {
    match instr {
        JTypeInstruction::Jump => {
            // > The address stored in a j instruction is 26 bits of the address
            // > associated with the specified label. The 26 bits are achieved by
            // > dropping the high-order 4 bits of the address and the low-order 2
            // > bits (which would always be 00, since addresses are always
            // > divisible by 4).
            // Source: https://max.cs.kzoo.edu/cs230/Resources/MIPS/MachineXL/InstructionFormats.html
            let addr = (env.get_instruction_part(InstructionPart::RS) << 21)
                + (env.get_instruction_part(InstructionPart::RT) << 16)
                + (env.get_instruction_part(InstructionPart::RD) << 11)
                + (env.get_instruction_part(InstructionPart::Shamt) << 6)
                + (env.get_instruction_part(InstructionPart::Funct));
            env.set_instruction_pointer(addr * 4);
            // REMOVEME: when all jtype instructions are implemented.
            return;
        }
        JTypeInstruction::JumpAndLink => (),
    };
    // REMOVEME: when all jtype instructions are implemented.
    env.set_halted(Env::constant(1));
}

pub fn interpret_itype<Env: InterpreterEnv>(env: &mut Env, instr: ITypeInstruction) {
    match instr {
        ITypeInstruction::BranchEq => (),
        ITypeInstruction::BranchNeq => (),
        ITypeInstruction::BranchLeqZero => (),
        ITypeInstruction::BranchGtZero => (),
        ITypeInstruction::AddImmediate => {
            let rs = env.get_instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            let imm = env.get_immediate();
            let res = register_rs + imm;
            let rt = env.get_instruction_part(InstructionPart::RT);
            env.overwrite_register_checked(&rt, &res);
            env.set_instruction_pointer(env.get_instruction_pointer() + Env::constant(4u32));
            // TODO: update next_instruction_pointer
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::AddImmediateUnsigned => (),
        ITypeInstruction::SetLessThanImmediate => (),
        ITypeInstruction::SetLessThanImmediateUnsigned => (),
        ITypeInstruction::AndImmediate => (),
        ITypeInstruction::OrImmediate => (),
        ITypeInstruction::XorImmediate => (),
        ITypeInstruction::LoadUpperImmediate => {
            // lui $reg, [most significant 16 bits of immediate]
            let rt = env.get_instruction_part(InstructionPart::RT);
            let immediate_value = env.get_immediate() << 16;
            env.overwrite_register_checked(&rt, &immediate_value);
            env.set_instruction_pointer(env.get_instruction_pointer() + Env::constant(4u32));
            // TODO: update next_instruction_pointer
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::Load8 => (),
        ITypeInstruction::Load16 => (),
        ITypeInstruction::Load32 => {
            let dest = env.get_instruction_part(InstructionPart::RT);
            let addr = env.get_instruction_part(InstructionPart::RS);
            let offset = env.get_immediate();
            let addr_with_offset = addr.clone() + offset.clone();
            debug!("lw {}, {}({})", dest.clone(), offset.clone(), addr.clone());
            let value = env.fetch_memory(&addr_with_offset);
            debug!("Loaded value from {}: {}", addr_with_offset.clone(), value);
            env.overwrite_register_checked(&dest, &value);
            env.set_instruction_pointer(env.get_instruction_pointer() + Env::constant(4u32));
            // TODO: update next_instruction_pointer
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::Load8Unsigned => (),
        ITypeInstruction::Load16Unsigned => (),
        ITypeInstruction::LoadWordLeft => (),
        ITypeInstruction::LoadWordRight => (),
        ITypeInstruction::Store8 => (),
        ITypeInstruction::Store16 => (),
        ITypeInstruction::Store32 => (),
        ITypeInstruction::StoreWordLeft => (),
        ITypeInstruction::StoreWordRight => (),
    };

    // REMOVEME: when all itype instructions are implemented.
    env.set_halted(Env::constant(1))
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::cannon::HostProgram;
    use crate::mips::registers::Registers;
    use crate::mips::witness::{Env, SyscallEnv, SCRATCH_SIZE};
    use crate::preimage_oracle::PreImageOracle;
    use mina_curves::pasta::Fp;

    fn dummy_env() -> Env<Fp> {
        let host_program = Some(HostProgram {
            name: String::from("true"),
            arguments: vec![],
        });
        let dummy_preimage_oracle = PreImageOracle::create(&host_program);
        Env {
            instruction_parts: InstructionParts::default(),
            instruction_counter: 0,
            memory: vec![],
            memory_write_index: vec![],
            registers: Registers::default(),
            registers_write_index: Registers::default(),
            instruction_pointer: 0,
            next_instruction_pointer: 0,
            scratch_state_idx: 0,
            scratch_state: [Fp::from(0); SCRATCH_SIZE],
            halt: true,
            syscall_env: SyscallEnv::default(),
            preimage_oracle: dummy_preimage_oracle,
        }
    }

    #[test]
    fn test_unit_jump_instruction() {
        // We only care about instruction parts and instruction pointer
        let mut dummy_env = dummy_env();
        // Instruction: 0b00001000000000101010011001100111
        // j 173671
        dummy_env.instruction_parts = InstructionParts {
            op_code: 0b000010,
            rs: 0b00000,
            rt: 0b00010,
            rd: 0b10100,
            shamt: 0b11001,
            funct: 0b100111,
        };
        interpret_jtype(&mut dummy_env, JTypeInstruction::Jump);
        assert_eq!(dummy_env.instruction_pointer, 694684);
    }

    #[test]
    fn test_unit_load32_instruction() {
        // We only care about instruction parts and instruction pointer
        let mut dummy_env = dummy_env();
        // Instruction: 0b10001111101001000000000000000000
        // lw $a0, 0
        // a0 = 4
        dummy_env.instruction_parts = InstructionParts {
            op_code: 0b000010,
            rs: 0b11101,
            rt: 0b00100,
            rd: 0b00000,
            shamt: 0b00000,
            funct: 0b000000,
        };
        interpret_itype(&mut dummy_env, ITypeInstruction::Load32);
        assert_eq!(dummy_env.registers[REGISTER_A0 as usize], 0);
    }

    #[test]
    fn test_unit_addi_instruction() {
        // We only care about instruction parts and instruction pointer
        let mut dummy_env = dummy_env();
        // Instruction: 0b10001111101001000000000000000000
        // addi	a1,sp,4
        dummy_env.instruction_parts = InstructionParts {
            op_code: 0b000010,
            rs: 0b11101,
            rt: 0b00101,
            rd: 0b00000,
            shamt: 0b00000,
            funct: 0b000100,
        };
        interpret_itype(&mut dummy_env, ITypeInstruction::AddImmediate);
        assert_eq!(
            dummy_env.registers[REGISTER_A1 as usize],
            dummy_env.registers[REGISTER_SP as usize] + 4
        );
    }

    #[test]
    fn test_unit_lui_instruction() {
        // We only care about instruction parts and instruction pointer
        let mut dummy_env = dummy_env();
        // Instruction: 0b00111100000000010000000000001010
        // lui at, 0xa
        dummy_env.instruction_parts = InstructionParts {
            op_code: 0b000010,
            rs: 0b00000,
            rt: 0b00001,
            rd: 0b00000,
            shamt: 0b00000,
            funct: 0b001010,
        };
        interpret_itype(&mut dummy_env, ITypeInstruction::LoadUpperImmediate);
        assert_eq!(dummy_env.registers[REGISTER_AT as usize], 0xa0000,);
    }
}
