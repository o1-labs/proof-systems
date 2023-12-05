use crate::mips::registers::{REGISTER_CURRENT_IP, REGISTER_NEXT_IP};
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
    BranchLtZero,                 // bltz
    BranchGeqZero,                // bgez
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
pub enum Sign {
    Pos,
    Neg,
}

#[derive(Copy, Clone, Debug)]
pub struct Signed<T> {
    pub sign: Sign,
    pub magnitude: T,
}

#[derive(Copy, Clone, Debug)]
pub enum LookupTable {
    MemoryLookup,
    RegisterLookup,
}

#[derive(Clone, Debug)]
pub struct Lookup<Fp> {
    pub numerator: Signed<Fp>,
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
            numerator: Signed {
                sign: Sign::Pos,
                magnitude: Self::constant(1),
            },
            table_id: LookupTable::RegisterLookup,
            value: vec![idx.clone(), last_accessed, old_value.clone()],
        });
        self.add_lookup(Lookup {
            numerator: Signed {
                sign: Sign::Neg,
                magnitude: Self::constant(1),
            },
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
            numerator: Signed {
                sign: Sign::Pos,
                magnitude: Self::constant(1),
            },
            table_id: LookupTable::MemoryLookup,
            value: vec![addr.clone(), last_accessed, old_value.clone()],
        });
        self.add_lookup(Lookup {
            numerator: Signed {
                sign: Sign::Neg,
                magnitude: Self::constant(1),
            },
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

    fn set_instruction_pointer(&mut self, ip: Self::Variable) {
        let idx = Self::constant(REGISTER_CURRENT_IP as u32);
        let new_accessed = self.instruction_counter() + Self::constant(1);
        unsafe {
            self.push_register_access(&idx, new_accessed.clone());
        }
        unsafe {
            self.push_register(&idx, ip.clone());
        }
        self.add_lookup(Lookup {
            numerator: Signed {
                sign: Sign::Neg,
                magnitude: Self::constant(1),
            },
            table_id: LookupTable::RegisterLookup,
            value: vec![idx, new_accessed, ip],
        });
    }

    fn get_instruction_pointer(&mut self) -> Self::Variable {
        let idx = Self::constant(REGISTER_CURRENT_IP as u32);
        let ip = {
            let value_location = self.alloc_scratch();
            unsafe { self.fetch_register(&idx, value_location) }
        };
        self.add_lookup(Lookup {
            numerator: Signed {
                sign: Sign::Pos,
                magnitude: Self::constant(1),
            },
            table_id: LookupTable::RegisterLookup,
            value: vec![idx, self.instruction_counter(), ip.clone()],
        });
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
        self.add_lookup(Lookup {
            numerator: Signed {
                sign: Sign::Neg,
                magnitude: Self::constant(1),
            },
            table_id: LookupTable::RegisterLookup,
            value: vec![idx, new_accessed, ip],
        });
    }

    fn get_next_instruction_pointer(&mut self) -> Self::Variable {
        let idx = Self::constant(REGISTER_NEXT_IP as u32);
        let ip = {
            let value_location = self.alloc_scratch();
            unsafe { self.fetch_register(&idx, value_location) }
        };
        self.add_lookup(Lookup {
            numerator: Signed {
                sign: Sign::Pos,
                magnitude: Self::constant(1),
            },
            table_id: LookupTable::RegisterLookup,
            value: vec![idx, self.instruction_counter(), ip.clone()],
        });
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

    fn copy(&mut self, x: &Self::Variable, position: Self::Position) -> Self::Variable;

    fn set_halted(&mut self, flag: Self::Variable);

    fn sign_extend(&mut self, x: &Self::Variable, bitlength: u32) -> Self::Variable {
        // FIXME: Constrain `high_bit`
        let high_bit = {
            let pos = self.alloc_scratch();
            unsafe { self.bitmask(x, bitlength, bitlength - 1, pos) }
        };
        high_bit * Self::constant(((1 << (32 - bitlength)) - 1) << bitlength) + x.clone()
    }
}

pub fn interpret_instruction<Env: InterpreterEnv>(env: &mut Env, instr: Instruction) {
    match instr {
        Instruction::RType(instr) => interpret_rtype(env, instr),
        Instruction::JType(instr) => interpret_jtype(env, instr),
        Instruction::IType(instr) => interpret_itype(env, instr),
    }
}

pub fn interpret_rtype<Env: InterpreterEnv>(env: &mut Env, instr: RTypeInstruction) {
    let instruction_pointer = env.get_instruction_pointer();
    let next_instruction_pointer = env.get_next_instruction_pointer();
    let instruction = {
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
    let rd = {
        // FIXME: Requires a range check
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 16, 11, pos) }
    };
    let shamt = {
        // FIXME: Requires a range check
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 11, 6, pos) }
    };
    let _funct = {
        // FIXME: Requires a range check
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 6, 0, pos) }
    };
    match instr {
        RTypeInstruction::ShiftLeftLogical => {
            let rt = env.read_register(&rt);
            // FIXME: Constrain this value
            let shifted = unsafe {
                let pos = env.alloc_scratch();
                env.shift_left(&rt, &shamt, pos)
            };
            env.write_register(&rd, shifted);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::ShiftRightLogical => {
            let rt = env.read_register(&rt);
            // FIXME: Constrain this value
            let shifted = unsafe {
                let pos = env.alloc_scratch();
                env.shift_right(&rt, &shamt, pos)
            };
            env.write_register(&rd, shifted);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::ShiftRightArithmetic => {
            let rt = env.read_register(&rt);
            // FIXME: Constrain this value
            let shifted = unsafe {
                let pos = env.alloc_scratch();
                env.shift_right(&rt, &shamt, pos)
            };
            env.write_register(&rd, shifted);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::ShiftLeftLogicalVariable => (),
        RTypeInstruction::ShiftRightLogicalVariable => (),
        RTypeInstruction::ShiftRightArithmeticVariable => (),
        RTypeInstruction::JumpRegister => {
            let addr = env.read_register(&rs);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(addr);
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
        RTypeInstruction::SyscallOther => {
            let syscall_num = env.read_register(&Env::constant(2));
            let is_sysbrk = {
                // FIXME: Requires constraints
                let pos = env.alloc_scratch();
                unsafe { env.test_zero(&(syscall_num.clone() - Env::constant(4045)), pos) }
            };
            let is_sysclone = {
                // FIXME: Requires constraints
                let pos = env.alloc_scratch();
                unsafe { env.test_zero(&(syscall_num.clone() - Env::constant(4120)), pos) }
            };
            let v0 = { is_sysbrk * Env::constant(0x40000000) + is_sysclone };
            let v1 = Env::constant(0);
            env.write_register(&Env::constant(2), v0);
            env.write_register(&Env::constant(7), v1);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
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
        RTypeInstruction::Add => {
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            env.write_register(&rd, rs + rt);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::AddUnsigned => {
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            env.write_register(&rd, rs + rt);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::Sub => (),
        RTypeInstruction::SubUnsigned => (),
        RTypeInstruction::And => {
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            let res = {
                // FIXME: Constrain
                let pos = env.alloc_scratch();
                unsafe { env.and_witness(&rs, &rt, pos) }
            };
            env.write_register(&rd, res);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::Or => {
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            let res = {
                // FIXME: Constrain
                let pos = env.alloc_scratch();
                unsafe { env.or_witness(&rs, &rt, pos) }
            };
            env.write_register(&rd, res);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::Xor => {
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            let res = {
                // FIXME: Constrain
                let pos = env.alloc_scratch();
                unsafe { env.xor_witness(&rs, &rt, pos) }
            };
            env.write_register(&rd, res);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::Nor => (),
        RTypeInstruction::SetLessThan => {
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            let res = {
                // FIXME: Constrain
                let pos = env.alloc_scratch();
                unsafe { env.test_less_than_signed(&rs, &rt, pos) }
            };
            env.write_register(&rd, res);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::SetLessThanUnsigned => {
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            let res = {
                // FIXME: Constrain
                let pos = env.alloc_scratch();
                unsafe { env.test_less_than(&rs, &rt, pos) }
            };
            env.write_register(&rd, res);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::MultiplyToRegister => (),
        RTypeInstruction::CountLeadingOnes => (),
        RTypeInstruction::CountLeadingZeros => (),
    };
    // TODO: Don't halt.
    env.set_halted(Env::constant(1));
}

pub fn interpret_jtype<Env: InterpreterEnv>(env: &mut Env, instr: JTypeInstruction) {
    let instruction_pointer = env.get_instruction_pointer();
    let next_instruction_pointer = env.get_next_instruction_pointer();
    let instruction = {
        let v0 = env.read_memory(&instruction_pointer);
        let v1 = env.read_memory(&(instruction_pointer.clone() + Env::constant(1)));
        let v2 = env.read_memory(&(instruction_pointer.clone() + Env::constant(2)));
        let v3 = env.read_memory(&(instruction_pointer.clone() + Env::constant(3)));
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
    let instruction_pointer_high_bits = {
        // FIXME: Requires a range check
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 32, 28, pos) }
    };
    let target_addr =
        (instruction_pointer_high_bits * Env::constant(1 << 28)) + (addr * Env::constant(1 << 2));
    match instr {
        JTypeInstruction::Jump => (),
        JTypeInstruction::JumpAndLink => {
            env.write_register(&Env::constant(31), instruction_pointer + Env::constant(8));
        }
    };
    env.set_instruction_pointer(next_instruction_pointer);
    env.set_next_instruction_pointer(target_addr);
}

pub fn interpret_itype<Env: InterpreterEnv>(env: &mut Env, instr: ITypeInstruction) {
    let instruction_pointer = env.get_instruction_pointer();
    let next_instruction_pointer = env.get_next_instruction_pointer();
    let instruction = {
        let v0 = env.read_memory(&instruction_pointer);
        let v1 = env.read_memory(&(instruction_pointer.clone() + Env::constant(1)));
        let v2 = env.read_memory(&(instruction_pointer.clone() + Env::constant(2)));
        let v3 = env.read_memory(&(instruction_pointer.clone() + Env::constant(3)));
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
        ITypeInstruction::BranchEq => {
            let offset = env.sign_extend(&(immediate * Env::constant(1 << 2)), 18);
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            let equals = {
                // FIXME: Requires constraints
                let pos = env.alloc_scratch();
                unsafe { env.test_zero(&(rs - rt), pos) }
            };
            let offset = (Env::constant(1) - equals.clone()) * Env::constant(4) + equals * offset;
            let addr = {
                let pos = env.alloc_scratch();
                env.copy(&(next_instruction_pointer.clone() + offset), pos)
            };
            env.set_instruction_pointer(next_instruction_pointer);
            env.set_next_instruction_pointer(addr);
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::BranchNeq => {
            let offset = env.sign_extend(&(immediate * Env::constant(1 << 2)), 18);
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            let equals = {
                // FIXME: Requires constraints
                let pos = env.alloc_scratch();
                unsafe { env.test_zero(&(rs - rt), pos) }
            };
            let offset = equals.clone() * Env::constant(4) + (Env::constant(1) - equals) * offset;
            let addr = {
                let pos = env.alloc_scratch();
                env.copy(&(next_instruction_pointer.clone() + offset), pos)
            };
            env.set_instruction_pointer(next_instruction_pointer);
            env.set_next_instruction_pointer(addr);
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::BranchLeqZero => (),
        ITypeInstruction::BranchGtZero => (),
        ITypeInstruction::BranchLtZero => {
            let offset = env.sign_extend(&(immediate * Env::constant(1 << 2)), 18);
            let rs = env.read_register(&rs);
            let less_than = {
                // FIXME: Requires constraints
                let pos = env.alloc_scratch();
                unsafe { env.test_less_than_signed(&rs, &Env::constant(0), pos) }
            };
            let offset =
                less_than.clone() * Env::constant(4) + (Env::constant(1) - less_than) * offset;
            let addr = {
                let pos = env.alloc_scratch();
                env.copy(&(next_instruction_pointer.clone() + offset), pos)
            };
            env.set_instruction_pointer(next_instruction_pointer);
            env.set_next_instruction_pointer(addr);
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::BranchGeqZero => (),
        ITypeInstruction::AddImmediate => {
            let register_rs = env.read_register(&rs);
            let offset = env.sign_extend(&immediate, 16);
            let res = register_rs + offset;
            env.write_register(&rt, res);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::AddImmediateUnsigned => {
            debug!("Fetching register: {:?}", rs);
            let register_rs = env.read_register(&rs);
            let offset = env.sign_extend(&immediate, 16);
            let res = register_rs + offset;
            env.write_register(&rt, res);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::SetLessThanImmediate => {
            let rs = env.read_register(&rs);
            let immediate = env.sign_extend(&immediate, 16);
            let res = {
                // FIXME: Constrain
                let pos = env.alloc_scratch();
                unsafe { env.test_less_than_signed(&rs, &immediate, pos) }
            };
            env.write_register(&rt, res);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        ITypeInstruction::SetLessThanImmediateUnsigned => {
            let rs = env.read_register(&rs);
            let immediate = env.sign_extend(&immediate, 16);
            let res = {
                // FIXME: Constrain
                let pos = env.alloc_scratch();
                unsafe { env.test_less_than(&rs, &immediate, pos) }
            };
            env.write_register(&rt, res);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        ITypeInstruction::AndImmediate => (),
        ITypeInstruction::OrImmediate => (),
        ITypeInstruction::XorImmediate => {
            let rs = env.read_register(&rs);
            let res = {
                // FIXME: Constraint
                let pos = env.alloc_scratch();
                unsafe { env.xor_witness(&rs, &immediate, pos) }
            };
            env.write_register(&rt, res);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::LoadUpperImmediate => {
            // lui $reg, [most significant 16 bits of immediate]
            let immediate_value = immediate * Env::constant(1 << 16);
            env.write_register(&rt, immediate_value);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::Load8 => {
            let base = env.read_register(&rs);
            let dest = rt;
            let offset = env.sign_extend(&immediate, 16);
            let addr = base + offset;
            let v0 = env.read_memory(&addr);
            let value = env.sign_extend(&v0, 8);
            env.write_register(&dest, value);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::Load16 => (),
        ITypeInstruction::Load32 => {
            let base = env.read_register(&rs);
            let dest = rt;
            let offset = env.sign_extend(&immediate, 16);
            let addr = base.clone() + offset.clone();
            debug!(
                "lw {:?}, {:?}({:?})",
                dest.clone(),
                offset.clone(),
                addr.clone()
            );
            // We load 4 bytes, i.e. one word.
            let v0 = env.read_memory(&addr);
            let v1 = env.read_memory(&(addr.clone() + Env::constant(1)));
            let v2 = env.read_memory(&(addr.clone() + Env::constant(2)));
            let v3 = env.read_memory(&(addr.clone() + Env::constant(3)));
            let value = (v0 * Env::constant(1 << 24))
                + (v1 * Env::constant(1 << 16))
                + (v2 * Env::constant(1 << 8))
                + v3;
            debug!("Loaded 32 bits value from {:?}: {:?}", addr.clone(), value);
            env.write_register(&dest, value);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::Load8Unsigned => {
            let base = env.read_register(&rs);
            let dest = rt;
            let offset = env.sign_extend(&immediate, 16);
            let addr = base + offset;
            let v0 = env.read_memory(&addr);
            let value = v0;
            env.write_register(&dest, value);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::Load16Unsigned => {
            let base = env.read_register(&rs);
            let dest = rt;
            let offset = env.sign_extend(&immediate, 16);
            let addr = base.clone() + offset.clone();
            let v0 = env.read_memory(&addr);
            let v1 = env.read_memory(&(addr.clone() + Env::constant(1)));
            let value = v0 * Env::constant(1 << 8) + v1;
            env.write_register(&dest, value);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::LoadWordLeft => (),
        ITypeInstruction::LoadWordRight => (),
        ITypeInstruction::Store8 => {
            let base = env.read_register(&rs);
            let offset = env.sign_extend(&immediate, 16);
            let addr = base.clone() + offset.clone();
            let value = env.read_register(&rt);
            let v0 = {
                // FIXME: Requires a range check
                let pos = env.alloc_scratch();
                unsafe { env.bitmask(&value, 32, 24, pos) }
            };
            env.write_memory(&addr, v0);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        ITypeInstruction::Store16 => (),
        ITypeInstruction::Store32 => {
            let base = env.read_register(&rs);
            let offset = env.sign_extend(&immediate, 16);
            let addr = base.clone() + offset.clone();
            let value = env.read_register(&rt);
            let [v0, v1, v2, v3] = {
                [
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&value, 32, 24, pos) }
                    },
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&value, 24, 16, pos) }
                    },
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&value, 16, 8, pos) }
                    },
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&value, 8, 0, pos) }
                    },
                ]
            };
            env.write_memory(&addr, v0);
            env.write_memory(&(addr.clone() + Env::constant(1)), v1);
            env.write_memory(&(addr.clone() + Env::constant(2)), v2);
            env.write_memory(&(addr.clone() + Env::constant(3)), v3);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        ITypeInstruction::StoreWordLeft => (),
        ITypeInstruction::StoreWordRight => (),
    };

    // REMOVEME: when all itype instructions are implemented.
    env.set_halted(Env::constant(1))
}

pub mod debugging {
    use serde::{Deserialize, Serialize};
    #[derive(Debug, Clone, Copy, Eq, PartialEq, Default, Serialize, Deserialize)]
    pub struct InstructionParts {
        pub op_code: u32,
        pub rs: u32,
        pub rt: u32,
        pub rd: u32,
        pub shamt: u32,
        pub funct: u32,
    }

    impl InstructionParts {
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
}
