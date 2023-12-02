use log::debug;
use serde::{Deserialize, Serialize};
use std::ops::Index;
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

    // Debug functions
    fn debug_register(v: &Self::Variable) -> String;

    fn debug_signed_16bits_variable(v: &Self::Variable) -> String;

    fn debug_hexa_variable(v: &Self::Variable) -> String;

    fn add_16bits_signed_offset(x: &Self::Variable, v: &Self::Variable) -> Self::Variable;

    fn decompose_32bits_in_8bits_chunks(
        &self,
        value: &Self::Variable,
    ) -> (
        Self::Variable,
        Self::Variable,
        Self::Variable,
        Self::Variable,
    );

    fn overwrite_register_checked(&mut self, register_idx: &Self::Variable, value: &Self::Variable);

    fn fetch_register_checked(&self, register_idx: &Self::Variable) -> Self::Variable;

    // Memory RW
    fn fetch_memory(&mut self, addr: &Self::Variable) -> Self::Variable;

    fn overwrite_memory_checked(&mut self, addr: &Self::Variable, value: &Self::Variable);

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
        RTypeInstruction::JumpRegister => {
            let rs = env.get_instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            debug!("Instr: jr {}", Env::debug_register(&rs));
            // TODO: Check if address is aligned
            env.set_instruction_pointer(register_rs);
            // TODO: update next_instruction_pointer?
            // REMOVEME: when all rtype instructions are implemented.
            return;
        }
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
            let addr = addr * 4;
            debug!("Instr: j {}", Env::debug_hexa_variable(&addr));
            env.set_instruction_pointer(addr);
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
            let rt = env.get_instruction_part(InstructionPart::RT);
            let imm = env.get_immediate();
            debug!(
                "Instr: addi {}, {}, {}",
                Env::debug_register(&rt),
                Env::debug_register(&rs),
                Env::debug_signed_16bits_variable(&imm)
            );
            let vrs = env.fetch_register_checked(&rs);
            let res = Env::add_16bits_signed_offset(&vrs, &imm);
            env.overwrite_register_checked(&rt, &res);
            env.set_instruction_pointer(env.get_instruction_pointer() + Env::constant(4u32));
            // TODO: update next_instruction_pointer
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::AddImmediateUnsigned => {
            let rs = env.get_instruction_part(InstructionPart::RS);
            let rt = env.get_instruction_part(InstructionPart::RT);
            let immediate = env.get_immediate();
            debug!(
                "Instr: addiu {}, {}, {}",
                Env::debug_register(&rt),
                Env::debug_register(&rs),
                immediate
            );
            let register_rs = env.fetch_register_checked(&rs);
            let res = register_rs + immediate;
            env.overwrite_register_checked(&rt, &res);
            env.set_instruction_pointer(env.get_instruction_pointer() + Env::constant(4u32));
            // TODO: update next_instruction_pointer
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::SetLessThanImmediate => (),
        ITypeInstruction::SetLessThanImmediateUnsigned => (),
        ITypeInstruction::AndImmediate => (),
        ITypeInstruction::OrImmediate => (),
        ITypeInstruction::XorImmediate => (),
        ITypeInstruction::LoadUpperImmediate => {
            // lui $reg, [most significant 16 bits of immediate]
            let rt = env.get_instruction_part(InstructionPart::RT);
            let immediate_value = env.get_immediate();
            debug!(
                "Instr: lui {}, {}",
                Env::debug_register(&rt),
                immediate_value
            );
            let immediate_value = immediate_value << 16;
            env.overwrite_register_checked(&rt, &immediate_value);
            env.set_instruction_pointer(env.get_instruction_pointer() + Env::constant(4u32));
            // TODO: update next_instruction_pointer
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::Load8 => (),
        ITypeInstruction::Load16 => (),
        ITypeInstruction::Load32 => {
            // lw: R[rt] <- M[R[rs] + sign_extended_imm]
            //                -------------------------
            //                         address
            //              ----------------------------
            //                        value
            let rt = env.get_instruction_part(InstructionPart::RT);
            let rs = env.get_instruction_part(InstructionPart::RS);
            let r_rs = env.fetch_register_checked(&rs);
            let sign_extended_imm = env.get_immediate();
            debug!(
                "Instr: lw {}, {}({})",
                Env::debug_register(&rt),
                Env::debug_signed_16bits_variable(&sign_extended_imm),
                Env::debug_register(&rs)
            );
            let address = Env::add_16bits_signed_offset(&r_rs, &sign_extended_imm);
            // We load 4 bytes, i.e. one word.
            // We combine the bytes after that
            //           31  24 | 23    16 | 15     8 | 7      0 |
            //             V4   |    V3    |    V2    |    V1    |
            //            addr  | addr + 1 | addr + 2 | addr + 3 |
            let v4 = env.fetch_memory(&address);
            let v3 = env.fetch_memory(&(address.clone() + Env::constant(1)));
            let v2 = env.fetch_memory(&(address.clone() + Env::constant(2)));
            let v1 = env.fetch_memory(&(address.clone() + Env::constant(3)));
            let value = (v4 << 24) + (v3 << 16) + (v2 << 8) + v1;
            debug!(
                "Loaded 32 bits value from address {}: {}",
                Env::debug_hexa_variable(&address.clone()),
                value
            );
            env.overwrite_register_checked(&rt, &value);
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
        ITypeInstruction::Store32 => {
            let reg_src = env.get_instruction_part(InstructionPart::RS);
            let reg_dest = env.get_instruction_part(InstructionPart::RD);
            let offset = env.get_immediate();
            let mem_addr = env.fetch_register_checked(&reg_dest);
            debug!(
                "Fetch address {} in register {}",
                mem_addr,
                Env::debug_register(&reg_src)
            );
            debug!(
                "Instr: sw {}, {}({})",
                Env::debug_register(&reg_dest),
                Env::debug_signed_16bits_variable(&offset),
                Env::debug_register(&reg_src),
            );
            let addr_with_offset = Env::add_16bits_signed_offset(&mem_addr, &offset);
            debug!("Compute offset address: {}", addr_with_offset);
            //           31  24 | 23    16 | 15     8 | 7      0 |
            //             V1   |    V2    |    V3    |    V4    |
            //            addr  | addr + 1 | addr + 2 | addr + 3 |
            let value = env.fetch_register_checked(&reg_src);
            let (v1, v2, v3, v4) = env.decompose_32bits_in_8bits_chunks(&value);
            env.overwrite_memory_checked(&addr_with_offset, &v1);
            env.overwrite_memory_checked(&(addr_with_offset.clone() + Env::constant(1)), &v2);
            env.overwrite_memory_checked(&(addr_with_offset.clone() + Env::constant(2)), &v3);
            env.overwrite_memory_checked(&(addr_with_offset.clone() + Env::constant(3)), &v4);
            env.set_instruction_pointer(env.get_instruction_pointer() + Env::constant(4u32));
            // TODO: update next_instruction_pointer
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::StoreWordLeft => (),
        ITypeInstruction::StoreWordRight => (),
    };

    // REMOVEME: when all itype instructions are implemented.
    env.set_halted(Env::constant(1))
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::cannon::{HostProgram, PAGE_SIZE};
    use crate::mips::registers::Registers;
    use crate::mips::witness::{Env, SyscallEnv, SCRATCH_SIZE};
    use crate::preimage_oracle::PreImageOracle;
    use mina_curves::pasta::Fp;
    use rand::Rng;

    fn dummy_env() -> Env<Fp> {
        let host_program = Some(HostProgram {
            name: String::from("true"),
            arguments: vec![],
        });
        let mut rng = rand::thread_rng();
        let dummy_preimage_oracle = PreImageOracle::create(&host_program);
        Env {
            instruction_parts: InstructionParts::default(),
            instruction_counter: 0,
            // Only 4kb of memory (one PAGE_ADDRESS_SIZE)
            memory: vec![(0, vec![rng.gen(); PAGE_SIZE as usize])],
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
        let mut rng = rand::thread_rng();
        // lw instruction
        let mut dummy_env = dummy_env();
        // Instruction: 0b10001111101001000000000000000000
        // lw $a0, 0(29)
        // a0 = 4
        // Random address in SP
        // Address has only one index
        let addr: u32 = rng.gen_range(0u32..100u32);
        let aligned_addr: u32 = (addr / 4) * 4;
        dummy_env.registers[REGISTER_SP as usize] = aligned_addr;
        let mem = dummy_env.memory[0].clone();
        let mem = mem.1;
        let v0 = mem[aligned_addr as usize];
        let v1 = mem[(aligned_addr + 1) as usize];
        let v2 = mem[(aligned_addr + 2) as usize];
        let v3 = mem[(aligned_addr + 3) as usize];
        let exp_v = ((v0 as u32) << 24) + ((v1 as u32) << 16) + ((v2 as u32) << 8) + (v3 as u32);
        // Set random alue into registers
        dummy_env.instruction_parts = InstructionParts {
            op_code: 0b000010,
            rs: 0b11101,
            rt: 0b00100,
            rd: 0b00000,
            shamt: 0b00000,
            funct: 0b000000,
        };
        interpret_itype(&mut dummy_env, ITypeInstruction::Load32);
        assert_eq!(
            dummy_env.registers.general_purpose[REGISTER_A0 as usize],
            exp_v
        );
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
            dummy_env.registers.general_purpose[REGISTER_A1 as usize],
            dummy_env.registers.general_purpose[REGISTER_SP as usize] + 4
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
        assert_eq!(
            dummy_env.registers.general_purpose[REGISTER_AT as usize],
            0xa0000
        );
    }

    #[test]
    fn test_unit_addiu_instruction() {
        // We only care about instruction parts and instruction pointer
        let mut dummy_env = dummy_env();
        // Instruction: 0b00100100001000010110110011101000
        // lui at, 0xa
        dummy_env.instruction_parts = InstructionParts {
            op_code: 0b001001,
            rs: 0b00001,
            rt: 0b00001,
            rd: 0b01101,
            shamt: 0b10011,
            funct: 0b101000,
        };
        let exp_res = dummy_env.registers[REGISTER_AT as usize] + 27880;
        interpret_itype(&mut dummy_env, ITypeInstruction::AddImmediateUnsigned);
        assert_eq!(
            dummy_env.registers.general_purpose[REGISTER_AT as usize],
            exp_res
        );
    }

    #[test]
    fn test_unit_jr_instruction() {
        // We only care about instruction parts and instruction pointer
        let mut dummy_env = dummy_env();
        dummy_env.instruction_parts = InstructionParts {
            op_code: 0b000000,
            rs: 0b00001,
            rt: 0b00000,
            rd: 0b00000,
            shamt: 0b00000,
            funct: 0b001000,
        };
        interpret_rtype(&mut dummy_env, RTypeInstruction::JumpRegister);
        assert_eq!(
            dummy_env.instruction_pointer,
            dummy_env.registers.general_purpose[REGISTER_AT as usize]
        )
    }
}
