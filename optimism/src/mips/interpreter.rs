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

impl InstructionParts<u32> {
    pub fn decode(instruction: u32) -> Self {
        let op_code = (instruction >> 26) & ((1 << (32 - 26)) - 1);
        let rs = (instruction >> 21) & ((1 << (26 - 21)) - 1);
        let rt = (instruction >> 16) & ((1 << (21 - 16)) - 1);
        let rd = (instruction >> 11) & ((1 << (16 - 11)) - 1);
        let shamt = (instruction >> 6) & ((1 << (11 - 6)) - 1);
        let funct = instruction & ((1 << 6) - 1);
        InstructionParts {
            op_code,
            rs,
            rt,
            rd,
            shamt,
            funct,
        }
    }

    pub fn encode(self) -> u32 {
        (self.op_code << 26)
            | (self.rs << 21)
            | (self.rt << 16)
            | (self.rd << 11)
            | (self.shamt << 6)
            | self.funct
    }
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

#[derive(Copy, Clone, Debug)]
pub enum LookupTable {
    MemoryLookup,
    RegisterLookup,
}

#[derive(Clone, Debug)]
pub struct Lookup<Fp> {
    pub numerator: i32, // FIXME: Bad, sad hack.
    pub table_id: LookupTable,
    pub value: Vec<Fp>,
}

pub trait InterpreterEnv {
    type Position;

    fn alloc_scratch(&mut self) -> Self::Position;

    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::fmt::Debug;

    fn add_lookup(&mut self, lookup: Lookup<Self::Variable>);

    fn instruction_counter(&self) -> Self::Variable;

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

    /// Set the general purpose register with index `idx` to `value`.
    ///
    /// # Safety
    ///
    /// No lookups or other constraints are added as part of this operation. The caller must
    /// manually add the lookups for this operation.
    unsafe fn push_register(&mut self, idx: &Self::Variable, value: Self::Variable);

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

    /// Set the last 'access index' for the general purpose register with index `idx` to `value`.
    ///
    /// # Safety
    ///
    /// No lookups or other constraints are added as part of this operation. The caller must
    /// manually add the lookups for this operation.
    unsafe fn push_register_access(&mut self, idx: &Self::Variable, value: Self::Variable);

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

            // FIXME: A register should allow multiple accesses within the same instruction.

            instruction_counter + Self::constant(1)
        };
        self.add_lookup(Lookup {
            numerator: 1,
            table_id: LookupTable::RegisterLookup,
            value: vec![idx.clone(), last_accessed, old_value.clone()],
        });
        self.add_lookup(Lookup {
            numerator: -1,
            table_id: LookupTable::RegisterLookup,
            value: vec![idx.clone(), new_accessed, new_value.clone()],
        });
        self.range_check64(&elapsed_time);
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

    fn write_register(&mut self, idx: &Self::Variable, new_value: Self::Variable) {
        let old_value = {
            let value_location = self.alloc_scratch();
            unsafe { self.fetch_register(idx, value_location) }
        };
        unsafe {
            self.access_register(idx, &old_value, &new_value);
        };
        unsafe {
            self.push_register(idx, new_value);
        };
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
        self.add_lookup(Lookup {
            numerator: 1,
            table_id: LookupTable::MemoryLookup,
            value: vec![addr.clone(), last_accessed, old_value.clone()],
        });
        self.add_lookup(Lookup {
            numerator: -1,
            table_id: LookupTable::MemoryLookup,
            value: vec![addr.clone(), new_accessed, new_value.clone()],
        });
        self.range_check64(&elapsed_time);
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

    fn range_check64(&mut self, _value: &Self::Variable) {
        // TODO
    }

    fn set_instruction_pointer(&mut self, ip: Self::Variable);

    fn get_instruction_pointer(&self) -> Self::Variable;

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
    unsafe fn bitmask(
        &mut self,
        x: &Self::Variable,
        highest_bit: u32,
        lowest_bit: u32,
        position: Self::Position,
    ) -> Self::Variable;

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
    let instruction = {
        let instruction_pointer = env.get_instruction_pointer();
        let v0 = env.read_memory(&instruction_pointer);
        let v1 = env.read_memory(&(instruction_pointer.clone() + Env::constant(1)));
        let v2 = env.read_memory(&(instruction_pointer.clone() + Env::constant(2)));
        let v3 = env.read_memory(&(instruction_pointer + Env::constant(3)));
        (v0 * Env::constant(1 << 24))
            + (v1 * Env::constant(1 << 16))
            + (v2 * Env::constant(1 << 8))
            + v3
    };
    let _opcode = {
        // FIXME: Requires a range check
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 32, 26, pos) }
    };
    let addr = {
        // FIXME: Requires a range check
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 26, 0, pos) }
    };
    match instr {
        JTypeInstruction::Jump => {
            // > The address stored in a j instruction is 26 bits of the address
            // > associated with the specified label. The 26 bits are achieved by
            // > dropping the high-order 4 bits of the address and the low-order 2
            // > bits (which would always be 00, since addresses are always
            // > divisible by 4).
            // Source: https://max.cs.kzoo.edu/cs230/Resources/MIPS/MachineXL/InstructionFormats.html
            env.set_instruction_pointer(addr * Env::constant(4));
            // REMOVEME: when all jtype instructions are implemented.
            return;
        }
        JTypeInstruction::JumpAndLink => (),
    };
    // REMOVEME: when all jtype instructions are implemented.
    env.set_halted(Env::constant(1));
}

pub fn interpret_itype<Env: InterpreterEnv>(env: &mut Env, instr: ITypeInstruction) {
    let instruction = {
        let instruction_pointer = env.get_instruction_pointer();
        let v0 = env.read_memory(&instruction_pointer);
        let v1 = env.read_memory(&(instruction_pointer.clone() + Env::constant(1)));
        let v2 = env.read_memory(&(instruction_pointer.clone() + Env::constant(2)));
        let v3 = env.read_memory(&(instruction_pointer + Env::constant(3)));
        (v0 * Env::constant(1 << 24))
            + (v1 * Env::constant(1 << 16))
            + (v2 * Env::constant(1 << 8))
            + v3
    };
    let _opcode = {
        // FIXME: Requires a range check
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 32, 26, pos) }
    };
    let rs = {
        // FIXME: Requires a range check
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 26, 21, pos) }
    };
    let rt = {
        // FIXME: Requires a range check
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 21, 16, pos) }
    };
    let immediate = {
        // FIXME: Requires a range check
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 16, 0, pos) }
    };
    match instr {
        ITypeInstruction::BranchEq => (),
        ITypeInstruction::BranchNeq => (),
        ITypeInstruction::BranchLeqZero => (),
        ITypeInstruction::BranchGtZero => (),
        ITypeInstruction::AddImmediate => {
            let register_rs = env.read_register(&rs);
            let res = register_rs + immediate;
            env.write_register(&rt, res);
            env.set_instruction_pointer(env.get_instruction_pointer() + Env::constant(4u32));
            // TODO: update next_instruction_pointer
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::AddImmediateUnsigned => {
            debug!("Fetching register: {:?}", rs);
            let register_rs = env.read_register(&rs);
            let res = register_rs + immediate;
            env.write_register(&rt, res);
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
            let immediate_value = immediate * Env::constant(1 << 16);
            env.write_register(&rt, immediate_value);
            env.set_instruction_pointer(env.get_instruction_pointer() + Env::constant(4u32));
            // TODO: update next_instruction_pointer
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::Load8 => (),
        ITypeInstruction::Load16 => (),
        ITypeInstruction::Load32 => {
            let dest = rt;
            let addr = rs;
            let offset = immediate;
            let addr_with_offset = addr.clone() + offset.clone();
            debug!(
                "lw {:?}, {:?}({:?})",
                dest.clone(),
                offset.clone(),
                addr.clone()
            );
            // We load 4 bytes, i.e. one word.
            let v0 = env.read_memory(&addr_with_offset);
            let v1 = env.read_memory(&(addr_with_offset.clone() + Env::constant(1)));
            let v2 = env.read_memory(&(addr_with_offset.clone() + Env::constant(2)));
            let v3 = env.read_memory(&(addr_with_offset.clone() + Env::constant(3)));
            let value = (v0 * Env::constant(1 << 24))
                + (v1 * Env::constant(1 << 16))
                + (v2 * Env::constant(1 << 8))
                + v3;
            debug!(
                "Loaded 32 bits value from {:?}: {:?}",
                addr_with_offset.clone(),
                value
            );
            env.write_register(&dest, value);
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
            // Only 8kb of memory (two PAGE_ADDRESS_SIZE)
            memory: vec![
                // Read/write memory
                (0, vec![rng.gen(); PAGE_SIZE as usize]),
                // Executable memory
                (1, vec![0; PAGE_SIZE as usize]),
            ],
            memory_write_index: vec![
                // Read/write memory
                (0, vec![0; PAGE_SIZE as usize]),
                // Executable memory
                (1, vec![0; PAGE_SIZE as usize]),
            ],
            registers: Registers::default(),
            registers_write_index: Registers::default(),
            instruction_pointer: PAGE_SIZE,
            next_instruction_pointer: PAGE_SIZE + 4,
            scratch_state_idx: 0,
            scratch_state: [Fp::from(0); SCRATCH_SIZE],
            halt: true,
            syscall_env: SyscallEnv::default(),
            preimage_oracle: dummy_preimage_oracle,
        }
    }

    fn write_instruction(env: &mut Env<Fp>, instruction_parts: InstructionParts<u32>) {
        env.instruction_parts = instruction_parts.clone();
        let instr = instruction_parts.encode();
        env.memory[1].1[0] = ((instr >> 24) & 0xFF) as u8;
        env.memory[1].1[1] = ((instr >> 16) & 0xFF) as u8;
        env.memory[1].1[2] = ((instr >> 8) & 0xFF) as u8;
        env.memory[1].1[3] = ((instr >> 0) & 0xFF) as u8;
    }

    #[test]
    fn test_unit_jump_instruction() {
        // We only care about instruction parts and instruction pointer
        let mut dummy_env = dummy_env();
        // Instruction: 0b00001000000000101010011001100111
        // j 173671
        write_instruction(
            &mut dummy_env,
            InstructionParts {
                op_code: 0b000010,
                rs: 0b00000,
                rt: 0b00010,
                rd: 0b10100,
                shamt: 0b11001,
                funct: 0b100111,
            },
        );
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
        let mem = &dummy_env.memory[0];
        let mem = &mem.1;
        let v0 = mem[aligned_addr as usize];
        let v1 = mem[(aligned_addr + 1) as usize];
        let v2 = mem[(aligned_addr + 2) as usize];
        let v3 = mem[(aligned_addr + 3) as usize];
        let exp_v = ((v0 as u32) << 24) + ((v1 as u32) << 16) + ((v2 as u32) << 8) + (v3 as u32);
        // Set random alue into registers
        write_instruction(
            &mut dummy_env,
            InstructionParts {
                op_code: 0b000010,
                rs: 0b11101,
                rt: 0b00100,
                rd: 0b00000,
                shamt: 0b00000,
                funct: 0b000000,
            },
        );
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
        write_instruction(
            &mut dummy_env,
            InstructionParts {
                op_code: 0b000010,
                rs: 0b11101,
                rt: 0b00101,
                rd: 0b00000,
                shamt: 0b00000,
                funct: 0b000100,
            },
        );
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
        write_instruction(
            &mut dummy_env,
            InstructionParts {
                op_code: 0b000010,
                rs: 0b00000,
                rt: 0b00001,
                rd: 0b00000,
                shamt: 0b00000,
                funct: 0b001010,
            },
        );
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
        write_instruction(
            &mut dummy_env,
            InstructionParts {
                op_code: 0b001001,
                rs: 0b00001,
                rt: 0b00001,
                rd: 0b01101,
                shamt: 0b10011,
                funct: 0b101000,
            },
        );
        let exp_res = dummy_env.registers[REGISTER_AT as usize] + 27880;
        interpret_itype(&mut dummy_env, ITypeInstruction::AddImmediateUnsigned);
        assert_eq!(
            dummy_env.registers.general_purpose[REGISTER_AT as usize],
            exp_res
        );
    }
}
