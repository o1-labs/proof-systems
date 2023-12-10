use crate::{
    cannon::PAGE_ADDRESS_SIZE,
    mips::registers::{
        REGISTER_CURRENT_IP, REGISTER_HEAP_POINTER, REGISTER_HI, REGISTER_LO, REGISTER_NEXT_IP,
        REGISTER_PREIMAGE_KEY_END,
    },
};
use log::debug;
use strum_macros::{EnumCount, EnumIter};

pub const FD_STDIN: u32 = 0;
pub const FD_STDOUT: u32 = 1;
pub const FD_STDERR: u32 = 2;
pub const FD_HINT_READ: u32 = 3;
pub const FD_HINT_WRITE: u32 = 4;
pub const FD_PREIMAGE_READ: u32 = 5;
pub const FD_PREIMAGE_WRITE: u32 = 6;

pub const SYSCALL_MMAP: u32 = 4090;
pub const SYSCALL_BRK: u32 = 4045;
pub const SYSCALL_CLONE: u32 = 4120;
pub const SYSCALL_EXIT_GROUP: u32 = 4246;
pub const SYSCALL_READ: u32 = 4003;
pub const SYSCALL_WRITE: u32 = 4004;
pub const SYSCALL_FCNTL: u32 = 4055;

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
    SyscallReadHint,              // syscall (Read 3)
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
    Store32Conditional,           // sc
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

    /// Add a constraint to the proof system, asserting that `assert_equals_zero` is 0.
    fn add_constraint(&mut self, assert_equals_zero: Self::Variable);

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

    /// Check that the witness value `x` is a boolean (`0` or `1`); otherwise abort.
    fn check_boolean(x: &Self::Variable);

    /// Assert that the value `x` is boolean, and add a constraint in the proof system.
    fn assert_boolean(&mut self, x: Self::Variable) {
        Self::check_boolean(&x);
        self.add_constraint(x.clone() * x.clone() - x);
    }

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

            // FIXME: A register should allow multiple accesses within the same instruction.

            instruction_counter + Self::constant(1)
        };
        unsafe { self.push_register_access_if(idx, new_accessed.clone(), if_is_true) };
        self.add_lookup(Lookup {
            numerator: Signed {
                sign: Sign::Pos,
                magnitude: if_is_true.clone(),
            },
            table_id: LookupTable::RegisterLookup,
            value: vec![idx.clone(), last_accessed, old_value.clone()],
        });
        self.add_lookup(Lookup {
            numerator: Signed {
                sign: Sign::Neg,
                magnitude: if_is_true.clone(),
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
        //0x4044e00f;
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

    /// Returns `x^(-1)`, or `0` if `x` is `0`, storing the result in `position`.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned value; callers must assert the relationship with
    /// `x`.
    ///
    /// The value returned may be a placeholder; callers should be careful not to depend directly
    /// on the value stored in the variable.
    unsafe fn inverse_or_zero(
        &mut self,
        x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable;

    fn is_zero(&mut self, x: &Self::Variable) -> Self::Variable {
        let res = {
            let pos = self.alloc_scratch();
            unsafe { self.test_zero(x, pos) }
        };
        let x_inv_or_zero = {
            let pos = self.alloc_scratch();
            unsafe { self.inverse_or_zero(x, pos) }
        };
        // If x = 0, then res = 1 and x_inv_or_zero = _
        // If x <> 0, then res = 0 and x_inv_or_zero = x^(-1)
        self.add_constraint(x.clone() * x_inv_or_zero.clone() + res.clone() - Self::constant(1));
        self.add_constraint(x.clone() * res.clone());
        res
    }

    fn equal(&mut self, x: &Self::Variable, y: &Self::Variable) -> Self::Variable {
        self.is_zero(&(x.clone() - y.clone()))
    }

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

    /// Returns `((x * y) >> 32, (x * y) & ((1 << 32) - 1))`, storing the results in `position_hi`
    /// and `position_lo` respectively.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned values; callers must manually add constraints to
    /// ensure that the pair of returned values correspond to the given values `x` and `y`, and
    /// that they fall within the desired range.
    unsafe fn mul_hi_lo_signed(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position_hi: Self::Position,
        position_lo: Self::Position,
    ) -> (Self::Variable, Self::Variable);

    /// Returns `((x * y) >> 32, (x * y) & ((1 << 32) - 1))`, storing the results in `position_hi`
    /// and `position_lo` respectively.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned values; callers must manually add constraints to
    /// ensure that the pair of returned values correspond to the given values `x` and `y`, and
    /// that they fall within the desired range.
    unsafe fn mul_hi_lo(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position_hi: Self::Position,
        position_lo: Self::Position,
    ) -> (Self::Variable, Self::Variable);

    /// Returns `(x / y, x % y)`, storing the results in `position_quotient` and
    /// `position_remainder` respectively.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned values; callers must manually add constraints to
    /// ensure that the pair of returned values correspond to the given values `x` and `y`, and
    /// that they fall within the desired range.
    unsafe fn divmod_signed(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position_quotient: Self::Position,
        position_remainder: Self::Position,
    ) -> (Self::Variable, Self::Variable);

    /// Returns `(x / y, x % y)`, storing the results in `position_quotient` and
    /// `position_remainder` respectively.
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned values; callers must manually add constraints to
    /// ensure that the pair of returned values correspond to the given values `x` and `y`, and
    /// that they fall within the desired range.
    unsafe fn divmod(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position_quotient: Self::Position,
        position_remainder: Self::Position,
    ) -> (Self::Variable, Self::Variable);

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

    fn sign_extend(&mut self, x: &Self::Variable, bitlength: u32) -> Self::Variable {
        // FIXME: Constrain `high_bit`
        let high_bit = {
            let pos = self.alloc_scratch();
            unsafe { self.bitmask(x, bitlength, bitlength - 1, pos) }
        };
        high_bit * Self::constant(((1 << (32 - bitlength)) - 1) << bitlength) + x.clone()
    }

    fn report_raw_write(
        &mut self,
        fd: &Self::Variable,
        addr: &Self::Variable,
        len: &Self::Variable,
    );

    fn report_exit(&mut self, exit_code: &Self::Variable);
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
                env.shift_right_arithmetic(&rt, &shamt, pos)
            };
            env.write_register(&rd, shifted);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::ShiftLeftLogicalVariable => {
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            // FIXME: Constrain this value
            let shifted = unsafe {
                let pos = env.alloc_scratch();
                env.shift_left(&rt, &rs, pos)
            };
            env.write_register(&rd, shifted);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::ShiftRightLogicalVariable => {
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            // FIXME: Constrain this value
            let shifted = unsafe {
                let pos = env.alloc_scratch();
                env.shift_right(&rt, &rs, pos)
            };
            env.write_register(&rd, shifted);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::ShiftRightArithmeticVariable => {
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            // FIXME: Constrain this value
            let shifted = unsafe {
                let pos = env.alloc_scratch();
                env.shift_right_arithmetic(&rt, &rs, pos)
            };
            env.write_register(&rd, shifted);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::JumpRegister => {
            let addr = env.read_register(&rs);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(addr);
            return;
        }
        RTypeInstruction::JumpAndLinkRegister => {
            let addr = env.read_register(&rs);
            env.write_register(&rd, instruction_pointer + Env::constant(8u32));
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(addr);
            return;
        }
        RTypeInstruction::SyscallMmap => {
            let requested_alloc_size = env.read_register(&Env::constant(5));
            let size_in_pages = {
                // FIXME: Requires a range check
                let pos = env.alloc_scratch();
                unsafe { env.bitmask(&requested_alloc_size, 32, PAGE_ADDRESS_SIZE, pos) }
            };
            let requires_extra_page = {
                let remainder = requested_alloc_size
                    - (size_in_pages.clone() * Env::constant(1 << PAGE_ADDRESS_SIZE));
                Env::constant(1) - env.is_zero(&remainder)
            };
            let actual_alloc_size =
                (size_in_pages + requires_extra_page) * Env::constant(1 << PAGE_ADDRESS_SIZE);
            let address = env.read_register(&Env::constant(4));
            let address_is_zero = env.is_zero(&address);
            let old_heap_ptr = env.increase_heap_pointer(&actual_alloc_size, &address_is_zero);
            let return_position = {
                let pos = env.alloc_scratch();
                env.copy(
                    &(address_is_zero.clone() * old_heap_ptr
                        + (Env::constant(1) - address_is_zero) * address),
                    pos,
                )
            };
            env.write_register(&Env::constant(2), return_position);
            env.write_register(&Env::constant(7), Env::constant(0));
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::SyscallExitGroup => {
            let exit_code = env.read_register(&Env::constant(4));
            env.report_exit(&exit_code);
            env.set_halted(Env::constant(1));
            return;
        }
        RTypeInstruction::SyscallReadHint => (),
        RTypeInstruction::SyscallReadPreimage => (),
        RTypeInstruction::SyscallReadOther => {
            let fd_id = env.read_register(&Env::constant(4));
            let mut check_equal = |expected_fd_id: u32| {
                // FIXME: Requires constraints
                let pos = env.alloc_scratch();
                unsafe { env.test_zero(&(fd_id.clone() - Env::constant(expected_fd_id)), pos) }
            };
            let is_stdin = check_equal(FD_STDIN);
            let is_preimage_read = check_equal(FD_PREIMAGE_READ);
            let is_hint_read = check_equal(FD_HINT_READ);

            // FIXME: Should assert that `is_preimage_read` and `is_hint_read` cannot be true here.
            let other_fd = Env::constant(1) - is_stdin - is_preimage_read - is_hint_read;

            // We're either reading stdin, in which case we get `(0, 0)` as desired, or we've hit a
            // bad FD that we reject with EBADF.
            let v0 = other_fd.clone() * Env::constant(0xFFFFFFFF);
            let v1 = other_fd * Env::constant(0x9); // EBADF

            env.write_register(&Env::constant(2), v0);
            env.write_register(&Env::constant(7), v1);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::SyscallWriteHint => (),
        RTypeInstruction::SyscallWritePreimage => {
            let addr = env.read_register(&Env::constant(5));
            let write_length = env.read_register(&Env::constant(6));

            // Cannon assumes that the remaining `byte_length` represents how much remains to be
            // read (i.e. all write calls send the full data in one syscall, and attempt to retry
            // with the rest until there is a success). This also simplifies the implementation
            // here, so we will follow suit.
            let bytes_to_preserve_in_register = {
                // FIXME: Requires a range check
                let pos = env.alloc_scratch();
                unsafe { env.bitmask(&write_length, 2, 0, pos) }
            };
            let register_idx = {
                let registers_left_to_write_after_this = {
                    // FIXME: Requires a range check
                    let pos = env.alloc_scratch();
                    // The virtual register is 32 bits wide, so we can just read 5 bytes. If the
                    // register has an incorrect value, it will be unprovable and we'll fault.
                    unsafe { env.bitmask(&write_length, 5, 2, pos) }
                };
                Env::constant(REGISTER_PREIMAGE_KEY_END as u32) - registers_left_to_write_after_this
            };

            let [r0, r1, r2, r3] = {
                let register_value = {
                    let initial_register_value = env.read_register(&register_idx);

                    // We should clear the register if our offset into the read will replace all of its
                    // bytes.
                    let should_clear_register = env.is_zero(&bytes_to_preserve_in_register);

                    let pos = env.alloc_scratch();
                    env.copy(
                        &((Env::constant(1) - should_clear_register) * initial_register_value),
                        pos,
                    )
                };
                [
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&register_value, 32, 24, pos) }
                    },
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&register_value, 24, 16, pos) }
                    },
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&register_value, 16, 8, pos) }
                    },
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&register_value, 8, 0, pos) }
                    },
                ]
            };

            // We choose our read address so that the bytes we read come aligned with the target
            // bytes in the register, to avoid an expensive bitshift.
            let read_address = addr.clone() - bytes_to_preserve_in_register.clone();

            let m0 = env.read_memory(&read_address);
            let m1 = env.read_memory(&(read_address.clone() + Env::constant(1)));
            let m2 = env.read_memory(&(read_address.clone() + Env::constant(2)));
            let m3 = env.read_memory(&(read_address.clone() + Env::constant(3)));

            // Now, for some complexity. From the perspective of the write operation, we should be
            // reading the `4 - bytes_to_preserve_in_register`. However, to match cannon 1:1, we
            // only want to read the bytes up to the end of the current word.
            let [overwrite_0, overwrite_1, overwrite_2, overwrite_3] = {
                let next_word_addr = {
                    let byte_subaddr = {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&addr, 2, 0, pos) }
                    };
                    addr.clone() + Env::constant(4) - byte_subaddr
                };
                let overwrite_0 = {
                    // We always write the first byte if we're not preserving it, since it will
                    // have been read from `addr`.
                    env.equal(&bytes_to_preserve_in_register, &Env::constant(0))
                };
                let overwrite_1 = {
                    // We write the second byte if:
                    //   we wrote the first byte
                    overwrite_0.clone()
                    //   and this isn't the start of the next word (which implies `overwrite_0`),
                    - env.equal(&(read_address.clone() + Env::constant(1)), &next_word_addr)
                    //   or this byte was read from `addr`
                    + env.equal(&bytes_to_preserve_in_register, &Env::constant(1))
                };
                let overwrite_2 = {
                    // We write the third byte if:
                    //   we wrote the second byte
                    overwrite_1.clone()
                    //   and this isn't the start of the next word (which implies `overwrite_1`),
                    - env.equal(&(read_address.clone() + Env::constant(2)), &next_word_addr)
                    //   or this byte was read from `addr`
                    + env.equal(&bytes_to_preserve_in_register, &Env::constant(2))
                };
                let overwrite_3 = {
                    // We write the fourth byte if:
                    //   we wrote the third byte
                    overwrite_2.clone()
                    //   and this isn't the start of the next word (which implies `overwrite_2`),
                    - env.equal(&(read_address.clone() + Env::constant(3)), &next_word_addr)
                    //   or this byte was read from `addr`
                    + env.equal(&bytes_to_preserve_in_register, &Env::constant(3))
                };
                [overwrite_0, overwrite_1, overwrite_2, overwrite_3]
            };

            let value = {
                let value = ((overwrite_0.clone() * m0 + (Env::constant(1) - overwrite_0) * r0)
                    * Env::constant(1 << 24))
                    + ((overwrite_1.clone() * m1 + (Env::constant(1) - overwrite_1) * r1)
                        * Env::constant(1 << 16))
                    + ((overwrite_2.clone() * m2 + (Env::constant(1) - overwrite_2) * r2)
                        * Env::constant(1 << 8))
                    + (overwrite_3.clone() * m3 + (Env::constant(1) - overwrite_3) * r3);
                let pos = env.alloc_scratch();
                env.copy(&value, pos)
            };
            env.write_register(&register_idx, value);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        RTypeInstruction::SyscallWriteOther => {
            let fd_id = env.read_register(&Env::constant(4));
            let write_length = env.read_register(&Env::constant(6));
            let mut check_equal = |expected_fd_id: u32| {
                // FIXME: Requires constraints
                let pos = env.alloc_scratch();
                unsafe { env.test_zero(&(fd_id.clone() - Env::constant(expected_fd_id)), pos) }
            };
            let is_stdout = check_equal(FD_STDOUT);
            let is_stderr = check_equal(FD_STDERR);
            let is_preimage_write = check_equal(FD_PREIMAGE_WRITE);
            let is_hint_write = check_equal(FD_HINT_WRITE);

            let addr = env.read_register(&Env::constant(5));
            env.report_raw_write(&fd_id, &addr, &write_length);

            // FIXME: Should assert that `is_preimage_write` and `is_hint_write` cannot be true
            // here.
            let known_fd = is_stdout + is_stderr + is_preimage_write + is_hint_write;
            let other_fd = Env::constant(1) - known_fd.clone();

            // We're either reading stdin, in which case we get `(0, 0)` as desired, or we've hit a
            // bad FD that we reject with EBADF.
            let v0 = known_fd * write_length + other_fd.clone() * Env::constant(0xFFFFFFFF);
            let v1 = other_fd * Env::constant(0x9); // EBADF

            env.write_register(&Env::constant(2), v0);
            env.write_register(&Env::constant(7), v1);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::SyscallFcntl => {
            let fd_id = env.read_register(&Env::constant(4));
            let fd_cmd = env.read_register(&Env::constant(5));
            let is_getfl = env.equal(&fd_cmd, &Env::constant(3));
            let is_stdout = env.equal(&fd_id, &Env::constant(FD_STDOUT));
            let is_stderr = env.equal(&fd_id, &Env::constant(FD_STDERR));
            let is_preimage_write = env.equal(&fd_id, &Env::constant(FD_PREIMAGE_WRITE));
            let is_hint_write = env.equal(&fd_id, &Env::constant(FD_HINT_WRITE));
            let is_stdin = env.equal(&fd_id, &Env::constant(FD_STDIN));
            let is_preimage_read = env.equal(&fd_id, &Env::constant(FD_PREIMAGE_READ));
            let is_hint_read = env.equal(&fd_id, &Env::constant(FD_HINT_READ));

            let is_read = is_stdin + is_preimage_read + is_hint_read;
            let is_write = is_stdout + is_stderr + is_preimage_write + is_hint_write;

            let v0 = is_getfl.clone()
                * (is_write.clone()
                    + (Env::constant(1) - is_read.clone() - is_write.clone())
                        * Env::constant(0xFFFFFFFF))
                + (Env::constant(1) - is_getfl.clone()) * Env::constant(0xFFFFFFFF);
            let v1 = is_getfl.clone() * (Env::constant(1) - is_read - is_write.clone()) * Env::constant(0x9) /* EBADF */ + (Env::constant(1) - fd_cmd) * Env::constant(0x16) /* EINVAL */;

            env.write_register(&Env::constant(2), v0);
            env.write_register(&Env::constant(7), v1);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::SyscallOther => {
            let syscall_num = env.read_register(&Env::constant(2));
            let is_sysbrk = env.equal(&syscall_num, &Env::constant(SYSCALL_BRK));
            let is_sysclone = env.equal(&syscall_num, &Env::constant(SYSCALL_CLONE));
            let v0 = { is_sysbrk * Env::constant(0x40000000) + is_sysclone };
            let v1 = Env::constant(0);
            env.write_register(&Env::constant(2), v0);
            env.write_register(&Env::constant(7), v1);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::MoveZero => {
            let rt = env.read_register(&rt);
            let is_zero = env.is_zero(&rt);
            let rs = env.read_register(&rs);
            env.write_register_if(&rd, rs, &is_zero);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::MoveNonZero => {
            let rt = env.read_register(&rt);
            let is_zero = Env::constant(1) - env.is_zero(&rt);
            let rs = env.read_register(&rs);
            env.write_register_if(&rd, rs, &is_zero);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::Sync => {
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::MoveFromHi => {
            let hi = env.read_register(&Env::constant(REGISTER_HI as u32));
            env.write_register(&rd, hi);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::MoveToHi => (),
        RTypeInstruction::MoveFromLo => {
            let lo = env.read_register(&Env::constant(REGISTER_LO as u32));
            env.write_register(&rd, lo);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::MoveToLo => {
            let rs = env.read_register(&rs);
            env.write_register(&Env::constant(REGISTER_LO as u32), rs);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::Multiply => {
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            let (hi, lo) = {
                // Fixme: constrain
                let hi_pos = env.alloc_scratch();
                let lo_pos = env.alloc_scratch();
                unsafe { env.mul_hi_lo_signed(&rs, &rt, hi_pos, lo_pos) }
            };
            env.write_register(&Env::constant(REGISTER_HI as u32), hi);
            env.write_register(&Env::constant(REGISTER_LO as u32), lo);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::MultiplyUnsigned => {
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            let (hi, lo) = {
                // Fixme: constrain
                let hi_pos = env.alloc_scratch();
                let lo_pos = env.alloc_scratch();
                unsafe { env.mul_hi_lo(&rs, &rt, hi_pos, lo_pos) }
            };
            env.write_register(&Env::constant(REGISTER_HI as u32), hi);
            env.write_register(&Env::constant(REGISTER_LO as u32), lo);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::Div => {
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            let (quotient, remainder) = {
                // Fixme: constrain
                let quotient_pos = env.alloc_scratch();
                let remainder_pos = env.alloc_scratch();
                unsafe { env.divmod_signed(&rs, &rt, quotient_pos, remainder_pos) }
            };
            env.write_register(&Env::constant(REGISTER_LO as u32), quotient);
            env.write_register(&Env::constant(REGISTER_HI as u32), remainder);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::DivUnsigned => {
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            let (quotient, remainder) = {
                // Fixme: constrain
                let quotient_pos = env.alloc_scratch();
                let remainder_pos = env.alloc_scratch();
                unsafe { env.divmod(&rs, &rt, quotient_pos, remainder_pos) }
            };
            env.write_register(&Env::constant(REGISTER_LO as u32), quotient);
            env.write_register(&Env::constant(REGISTER_HI as u32), remainder);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
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
        RTypeInstruction::Sub => {
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            env.write_register(&rd, rs - rt);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::SubUnsigned => {
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            env.write_register(&rd, rs - rt);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
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
        RTypeInstruction::Nor => {
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            let res = {
                // FIXME: Constrain
                let pos = env.alloc_scratch();
                unsafe { env.nor_witness(&rs, &rt, pos) }
            };
            env.write_register(&rd, res);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
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
        RTypeInstruction::MultiplyToRegister => {
            let rs = env.read_register(&rs);
            let rt = env.read_register(&rt);
            let res = {
                // FIXME: Constrain
                let pos = env.alloc_scratch();
                unsafe { env.mul_signed_witness(&rs, &rt, pos) }
            };
            env.write_register(&rd, res);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        RTypeInstruction::CountLeadingOnes => (),
        RTypeInstruction::CountLeadingZeros => {
            let rs = env.read_register(&rs);
            let leading_zeros = {
                // FIXME: Constrain
                let pos = env.alloc_scratch();
                unsafe { env.count_leading_zeros(&rs, pos) }
            };
            env.write_register(&rd, leading_zeros);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
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
        unsafe { env.bitmask(&next_instruction_pointer, 32, 28, pos) }
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
            let equals = env.equal(&rs, &rt);
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
            let equals = env.equal(&rs, &rt);
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
        ITypeInstruction::BranchLeqZero => {
            let offset = env.sign_extend(&(immediate * Env::constant(1 << 2)), 18);
            let rs = env.read_register(&rs);
            let less_than_or_equal_to = {
                let greater_than_zero = {
                    // FIXME: Requires constraints
                    let pos = env.alloc_scratch();
                    unsafe { env.test_less_than_signed(&Env::constant(0), &rs, pos) }
                };
                Env::constant(1) - greater_than_zero
            };
            let offset = (Env::constant(1) - less_than_or_equal_to.clone()) * Env::constant(4)
                + less_than_or_equal_to * offset;
            let addr = {
                let pos = env.alloc_scratch();
                env.copy(&(next_instruction_pointer.clone() + offset), pos)
            };
            env.set_instruction_pointer(next_instruction_pointer);
            env.set_next_instruction_pointer(addr);
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::BranchGtZero => {
            let offset = env.sign_extend(&(immediate * Env::constant(1 << 2)), 18);
            let rs = env.read_register(&rs);
            let less_than = {
                // FIXME: Requires constraints
                let pos = env.alloc_scratch();
                unsafe { env.test_less_than_signed(&Env::constant(0), &rs, pos) }
            };
            let offset =
                (Env::constant(1) - less_than.clone()) * Env::constant(4) + less_than * offset;
            let addr = {
                let pos = env.alloc_scratch();
                env.copy(&(next_instruction_pointer.clone() + offset), pos)
            };
            env.set_instruction_pointer(next_instruction_pointer);
            env.set_next_instruction_pointer(addr);
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::BranchLtZero => {
            let offset = env.sign_extend(&(immediate * Env::constant(1 << 2)), 18);
            let rs = env.read_register(&rs);
            let less_than = {
                // FIXME: Requires constraints
                let pos = env.alloc_scratch();
                unsafe { env.test_less_than_signed(&rs, &Env::constant(0), pos) }
            };
            let offset =
                (Env::constant(1) - less_than.clone()) * Env::constant(4) + less_than * offset;
            let addr = {
                let pos = env.alloc_scratch();
                env.copy(&(next_instruction_pointer.clone() + offset), pos)
            };
            env.set_instruction_pointer(next_instruction_pointer);
            env.set_next_instruction_pointer(addr);
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::BranchGeqZero => {
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
        ITypeInstruction::AndImmediate => {
            let rs = env.read_register(&rs);
            let res = {
                // FIXME: Constraint
                let pos = env.alloc_scratch();
                unsafe { env.and_witness(&rs, &immediate, pos) }
            };
            env.write_register(&rt, res);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::OrImmediate => {
            let rs = env.read_register(&rs);
            let res = {
                // FIXME: Constraint
                let pos = env.alloc_scratch();
                unsafe { env.or_witness(&rs, &immediate, pos) }
            };
            env.write_register(&rt, res);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
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
            //let mut pp_reg = |addr, offset| {
            //let addr = addr + Env::constant(offset);
            //let pos = env.alloc_scratch();
            //let access = unsafe { env.fetch_memory_access(&addr, pos) };
            //let pos = env.alloc_scratch();
            //let value = unsafe { env.fetch_memory(&addr, pos) };
            //println!("addr={:?} last_access={:?} value={:?}", addr, access, value);
            //};
            //pp_reg(addr.clone(), 0);
            //pp_reg(addr.clone(), 1);
            //pp_reg(addr.clone(), 2);
            //pp_reg(addr.clone(), 3);
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
            //println!("insn={:?}", env.instruction_counter());
            //println!("value={:?}", value);
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
        ITypeInstruction::LoadWordLeft => {
            //println!("lwl");
            let base = env.read_register(&rs);
            let offset = env.sign_extend(&immediate, 16);
            let addr = base.clone() + offset.clone();

            //println!("base={:?} offset={:?}", base, offset);
            //println!("addr={:?}", addr);

            let byte_subaddr = {
                // FIXME: Requires a range check
                let pos = env.alloc_scratch();
                unsafe { env.bitmask(&addr, 2, 0, pos) }
            };
            //println!("byte_subaddr={:?}", byte_subaddr);

            let overwrite_3 = env.equal(&byte_subaddr, &Env::constant(0));
            let overwrite_2 = env.equal(&byte_subaddr, &Env::constant(1)) + overwrite_3.clone();
            let overwrite_1 = env.equal(&byte_subaddr, &Env::constant(2)) + overwrite_2.clone();
            let overwrite_0 = env.equal(&byte_subaddr, &Env::constant(3)) + overwrite_1.clone();
            //println!(
            //"o0={:?} o1={:?} o2={:?} o3={:?}",
            //overwrite_0, overwrite_1, overwrite_2, overwrite_3
            //);

            //let mut pp_reg = |addr, offset| {
            /*let addr = addr + Env::constant(offset);
            let pos = env.alloc_scratch();
            let val = unsafe { env.fetch_memory_access(&addr, pos) };
            println!("addr={:?} last_access={:?}", addr, val);*/
            //};

            //pp_reg(addr.clone(), 0);
            //pp_reg(addr.clone(), 1);
            //pp_reg(addr.clone(), 2);
            //pp_reg(addr.clone(), 3);

            let m0 = env.read_memory(&addr);
            let m1 = env.read_memory(&(addr.clone() + Env::constant(1)));
            let m2 = env.read_memory(&(addr.clone() + Env::constant(2)));
            let m3 = env.read_memory(&(addr.clone() + Env::constant(3)));
            //println!("m0={:?} m1={:?} m2={:?} m3={:?}", m0, m1, m2, m3);

            let [r0, r1, r2, r3] = {
                let initial_register_value = env.read_register(&rt);
                [
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&initial_register_value, 32, 24, pos) }
                    },
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&initial_register_value, 24, 16, pos) }
                    },
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&initial_register_value, 16, 8, pos) }
                    },
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&initial_register_value, 8, 0, pos) }
                    },
                ]
            };
            //println!("r0={:?} r1={:?} r2={:?} r3={:?}", r0, r1, r2, r3);

            //println!(
            //"v0={:?} v1={:?} v2={:?} v3={:?}",
            //(overwrite_0.clone() * m0.clone()
            //+ (Env::constant(1) - overwrite_0.clone()) * r0.clone()),
            //(overwrite_1.clone() * m1.clone()
            //+ (Env::constant(1) - overwrite_1.clone()) * r1.clone()),
            //(overwrite_2.clone() * m2.clone()
            //+ (Env::constant(1) - overwrite_2.clone()) * r2.clone()),
            //(overwrite_3.clone() * m3.clone()
            //+ (Env::constant(1) - overwrite_3.clone()) * r3.clone()),
            //);
            let value = {
                let value = ((overwrite_0.clone() * m0 + (Env::constant(1) - overwrite_0) * r0)
                    * Env::constant(1 << 24))
                    + ((overwrite_1.clone() * m1 + (Env::constant(1) - overwrite_1) * r1)
                        * Env::constant(1 << 16))
                    + ((overwrite_2.clone() * m2 + (Env::constant(1) - overwrite_2) * r2)
                        * Env::constant(1 << 8))
                    + (overwrite_3.clone() * m3 + (Env::constant(1) - overwrite_3) * r3);
                let pos = env.alloc_scratch();
                env.copy(&value, pos)
            };
            //println!("v={:?}", value);
            env.write_register(&rt, value);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::LoadWordRight => {
            //println!("lwr");
            let base = env.read_register(&rs);
            let offset = env.sign_extend(&immediate, 16);
            let addr = base.clone() + offset.clone();

            //println!("base={:?} offset={:?}", base, offset);
            //println!("addr={:?}", addr);

            let byte_subaddr = {
                // FIXME: Requires a range check
                let pos = env.alloc_scratch();
                unsafe { env.bitmask(&addr, 2, 0, pos) }
            };
            //println!("byte_subaddr={:?}", byte_subaddr);

            let overwrite_0 = env.equal(&byte_subaddr, &Env::constant(3));
            let overwrite_1 = env.equal(&byte_subaddr, &Env::constant(2)) + overwrite_0.clone();
            let overwrite_2 = env.equal(&byte_subaddr, &Env::constant(1)) + overwrite_1.clone();
            let overwrite_3 = env.equal(&byte_subaddr, &Env::constant(0)) + overwrite_2.clone();
            //println!(
            //"o0={:?} o1={:?} o2={:?} o3={:?}",
            //overwrite_0, overwrite_1, overwrite_2, overwrite_3
            //);


            // The `-3` here feels odd, but simulates the `<< 24` in cannon, and matches the
            // behavior defined in the spec.
            // See e.g. 'MIPS IV Instruction Set' Rev 3.2, Table A-31 for reference.
            let m0 = env.read_memory(&(addr.clone() - Env::constant(3)));
            let m1 = env.read_memory(&(addr.clone() - Env::constant(2)));
            let m2 = env.read_memory(&(addr.clone() - Env::constant(1)));
            let m3 = env.read_memory(&addr);
            //println!("m0={:?} m1={:?} m2={:?} m3={:?}", m0, m1, m2, m3);

            let [r0, r1, r2, r3] = {
                let initial_register_value = env.read_register(&rt);
                [
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&initial_register_value, 32, 24, pos) }
                    },
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&initial_register_value, 24, 16, pos) }
                    },
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&initial_register_value, 16, 8, pos) }
                    },
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&initial_register_value, 8, 0, pos) }
                    },
                ]
            };
            //println!("r0={:?} r1={:?} r2={:?} r3={:?}", r0, r1, r2, r3);

            //println!(
            //"v0={:?} v1={:?} v2={:?} v3={:?}",
            //(overwrite_0.clone() * m0.clone()
            //+ (Env::constant(1) - overwrite_0.clone()) * r0.clone()),
            //(overwrite_1.clone() * m1.clone()
            //+ (Env::constant(1) - overwrite_1.clone()) * r1.clone()),
            //(overwrite_2.clone() * m2.clone()
            //+ (Env::constant(1) - overwrite_2.clone()) * r2.clone()),
            //(overwrite_3.clone() * m3.clone()
            //+ (Env::constant(1) - overwrite_3.clone()) * r3.clone()),
            //);

            let value = {
                let value = ((overwrite_0.clone() * m0 + (Env::constant(1) - overwrite_0) * r0)
                    * Env::constant(1 << 24))
                    + ((overwrite_1.clone() * m1 + (Env::constant(1) - overwrite_1) * r1)
                        * Env::constant(1 << 16))
                    + ((overwrite_2.clone() * m2 + (Env::constant(1) - overwrite_2) * r2)
                        * Env::constant(1 << 8))
                    + (overwrite_3.clone() * m3 + (Env::constant(1) - overwrite_3) * r3);
                let pos = env.alloc_scratch();
                env.copy(&value, pos)
            };
            //println!("v={:?}", value);
            env.write_register(&rt, value);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::Store8 => {
            let base = env.read_register(&rs);
            let offset = env.sign_extend(&immediate, 16);
            let addr = base.clone() + offset.clone();
            let value = env.read_register(&rt);
            let v0 = {
                // FIXME: Requires a range check
                let pos = env.alloc_scratch();
                unsafe { env.bitmask(&value, 8, 0, pos) }
            };
            env.write_memory(&addr, v0);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        ITypeInstruction::Store16 => {
            let base = env.read_register(&rs);
            let offset = env.sign_extend(&immediate, 16);
            let addr = base.clone() + offset.clone();
            let value = env.read_register(&rt);
            let [v0, v1] = {
                [
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
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
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
            //println!("addr={:?} v0={:?} v1={:?} v2={:?} v3={:?}", addr, v0, v1, v2, v3);
            env.write_memory(&addr, v0);
            env.write_memory(&(addr.clone() + Env::constant(1)), v1);
            env.write_memory(&(addr.clone() + Env::constant(2)), v2);
            env.write_memory(&(addr.clone() + Env::constant(3)), v3);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        ITypeInstruction::Store32Conditional => {
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
            // Write status flag.
            env.write_register(&rt, Env::constant(1));
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            return;
        }
        ITypeInstruction::StoreWordLeft => {
            //println!("swl");
            let base = env.read_register(&rs);
            let offset = env.sign_extend(&immediate, 16);
            let addr = base.clone() + offset.clone();

            //println!("base={:?} offset={:?}", base, offset);
            //println!("addr={:?}", addr);

            let byte_subaddr = {
                // FIXME: Requires a range check
                let pos = env.alloc_scratch();
                unsafe { env.bitmask(&addr, 2, 0, pos) }
            };
            //println!("byte_subaddr={:?}", byte_subaddr);

            let overwrite_3 = env.equal(&byte_subaddr, &Env::constant(0));
            let overwrite_2 = env.equal(&byte_subaddr, &Env::constant(1)) + overwrite_3.clone();
            let overwrite_1 = env.equal(&byte_subaddr, &Env::constant(2)) + overwrite_2.clone();
            let overwrite_0 = env.equal(&byte_subaddr, &Env::constant(3)) + overwrite_1.clone();
            //println!(
            //"o0={:?} o1={:?} o2={:?} o3={:?}",
            //overwrite_0, overwrite_1, overwrite_2, overwrite_3
            //);

            //let mut pp_reg = |addr, offset| {
            //let addr = addr + Env::constant(offset);
            //let pos = env.alloc_scratch();
            //let access = unsafe { env.fetch_memory_access(&addr, pos) };
            //let pos = env.alloc_scratch();
            //let value = unsafe { env.fetch_memory(&addr, pos) };
            //println!("addr={:?} last_access={:?} value={:?}", addr, access, value);
            //};

            //pp_reg(addr.clone() - byte_subaddr.clone(), 0);
            //pp_reg(addr.clone() - byte_subaddr.clone(), 1);
            //pp_reg(addr.clone() - byte_subaddr.clone(), 2);
            //pp_reg(addr.clone() - byte_subaddr.clone(), 3);

            //pp_reg(addr.clone(), 0);
            //pp_reg(addr.clone(), 1);
            //pp_reg(addr.clone(), 2);
            //pp_reg(addr.clone(), 3);

            let m0 = env.read_memory(&addr);
            let m1 = env.read_memory(&(addr.clone() + Env::constant(1)));
            let m2 = env.read_memory(&(addr.clone() + Env::constant(2)));
            let m3 = env.read_memory(&(addr.clone() + Env::constant(3)));
            //println!("m0={:?} m1={:?} m2={:?} m3={:?}", m0, m1, m2, m3);

            let [r0, r1, r2, r3] = {
                let initial_register_value = env.read_register(&rt);
                [
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&initial_register_value, 32, 24, pos) }
                    },
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&initial_register_value, 24, 16, pos) }
                    },
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&initial_register_value, 16, 8, pos) }
                    },
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&initial_register_value, 8, 0, pos) }
                    },
                ]
            };
            //println!("r0={:?} r1={:?} r2={:?} r3={:?}", r0, r1, r2, r3);

            let v0 = {
                let pos = env.alloc_scratch();
                env.copy(
                    &(overwrite_0.clone() * r0 + (Env::constant(1) - overwrite_0) * m0),
                    pos,
                )
            };
            let v1 = {
                let pos = env.alloc_scratch();
                env.copy(
                    &(overwrite_1.clone() * r1 + (Env::constant(1) - overwrite_1) * m1),
                    pos,
                )
            };
            let v2 = {
                let pos = env.alloc_scratch();
                env.copy(
                    &(overwrite_2.clone() * r2 + (Env::constant(1) - overwrite_2) * m2),
                    pos,
                )
            };
            let v3 = {
                let pos = env.alloc_scratch();
                env.copy(
                    &(overwrite_3.clone() * r3 + (Env::constant(1) - overwrite_3) * m3),
                    pos,
                )
            };
            //println!("write_addr={:?}", addr.clone());
            //println!("v0={:?} v1={:?} v2={:?} v3={:?}", v0, v1, v2, v3);

            env.write_memory(&addr, v0);
            env.write_memory(&(addr.clone() + Env::constant(1)), v1);
            env.write_memory(&(addr.clone() + Env::constant(2)), v2);
            env.write_memory(&(addr.clone() + Env::constant(3)), v3);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
        ITypeInstruction::StoreWordRight => {
            //println!("swr");
            let base = env.read_register(&rs);
            let offset = env.sign_extend(&immediate, 16);
            let addr = base.clone() + offset.clone();

            //println!("base={:?} offset={:?}", base, offset);
            //println!("addr={:?}", addr);

            let byte_subaddr = {
                // FIXME: Requires a range check
                let pos = env.alloc_scratch();
                unsafe { env.bitmask(&addr, 2, 0, pos) }
            };
            //println!("byte_subaddr={:?}", byte_subaddr);

            let overwrite_0 = env.equal(&byte_subaddr, &Env::constant(3));
            let overwrite_1 = env.equal(&byte_subaddr, &Env::constant(2)) + overwrite_0.clone();
            let overwrite_2 = env.equal(&byte_subaddr, &Env::constant(1)) + overwrite_1.clone();
            let overwrite_3 = env.equal(&byte_subaddr, &Env::constant(0)) + overwrite_2.clone();
            //println!(
            //"o0={:?} o1={:?} o2={:?} o3={:?}",
            //overwrite_0, overwrite_1, overwrite_2, overwrite_3
            //);

            // The `-3` here feels odd, but simulates the `<< 24` in cannon, and matches the
            // behavior defined in the spec.
            // See e.g. 'MIPS IV Instruction Set' Rev 3.2, Table A-31 for reference.
            let m0 = env.read_memory(&(addr.clone() - Env::constant(3)));
            let m1 = env.read_memory(&(addr.clone() - Env::constant(2)));
            let m2 = env.read_memory(&(addr.clone() - Env::constant(1)));
            let m3 = env.read_memory(&addr);
            //println!("m0={:?} m1={:?} m2={:?} m3={:?}", m0, m1, m2, m3);

            let [r0, r1, r2, r3] = {
                let initial_register_value = env.read_register(&rt);
                [
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&initial_register_value, 32, 24, pos) }
                    },
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&initial_register_value, 24, 16, pos) }
                    },
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&initial_register_value, 16, 8, pos) }
                    },
                    {
                        // FIXME: Requires a range check
                        let pos = env.alloc_scratch();
                        unsafe { env.bitmask(&initial_register_value, 8, 0, pos) }
                    },
                ]
            };
            //println!("r0={:?} r1={:?} r2={:?} r3={:?}", r0, r1, r2, r3);

            let v0 = {
                let pos = env.alloc_scratch();
                env.copy(
                    &(overwrite_0.clone() * r0 + (Env::constant(1) - overwrite_0) * m0),
                    pos,
                )
            };
            let v1 = {
                let pos = env.alloc_scratch();
                env.copy(
                    &(overwrite_1.clone() * r1 + (Env::constant(1) - overwrite_1) * m1),
                    pos,
                )
            };
            let v2 = {
                let pos = env.alloc_scratch();
                env.copy(
                    &(overwrite_2.clone() * r2 + (Env::constant(1) - overwrite_2) * m2),
                    pos,
                )
            };
            let v3 = {
                let pos = env.alloc_scratch();
                env.copy(
                    &(overwrite_3.clone() * r3 + (Env::constant(1) - overwrite_3) * m3),
                    pos,
                )
            };
            //println!("write_addr={:?}", addr.clone() - Env::constant(3));
            //println!("v0={:?} v1={:?} v2={:?} v3={:?}", v0, v1, v2, v3);

            env.write_memory(&(addr.clone() - Env::constant(3)), v0);
            env.write_memory(&(addr.clone() - Env::constant(2)), v1);
            env.write_memory(&(addr.clone() - Env::constant(1)), v2);
            env.write_memory(&(addr.clone() - Env::constant(0)), v3);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            // REMOVEME: when all itype instructions are implemented.
            return;
        }
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
