use strum::{EnumCount, IntoEnumIterator};
use strum_macros::{EnumCount, EnumIter};

use crate::lookups::{Lookup, LookupTableIDs};
use ark_ff::{One, Zero};

use super::registers::{REGISTER_CURRENT_IP, REGISTER_HEAP_POINTER, REGISTER_NEXT_IP};

#[derive(Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Hash, Ord, PartialOrd)]
pub enum Instruction {
    RType(RInstruction),
    IType(IInstruction),
    SType(SInstruction),
    SBType(SBInstruction),
    UType(UInstruction),
    UJType(UJInstruction),
    SyscallType(SyscallInstruction),
}

// See https://www.cs.cornell.edu/courses/cs3410/2024fa/assignments/cpusim/riscv-instructions.pdf for the order
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
    XorImmediate, // xori
    OrImmediate,  // ori
    AndImmediate, // andi

    JumpAndLinkRegister, // jalr
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
    BranchNeq,                      // bne
    BranchLessThan,                 // blt
    BranchGreaterThanEqual,         // bge
    BranchLessThanUnsigned,         // bltu
    BranchGreaterThanEqualUnsigned, // bgeu
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
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum SyscallInstruction {
    #[default]
    SyscallSuccess,
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
            Instruction::SyscallType(_) => write!(f, "ecall"),
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

pub trait InterpreterEnv {
    /// A position can be seen as an indexed variable
    type Position;

    /// Allocate a new abstract variable for the current step.
    /// The variable can be used to store temporary values.
    /// The variables are "freed" after each step/instruction.
    /// The variable allocation can be seen as an allocation on a stack that is
    /// popped after each step execution.
    /// At the moment, [crate::interpreters::riscv32i::SCRATCH_SIZE]
    /// elements can be allocated. If more temporary variables are required for
    /// an instruction, increase the value
    /// [crate::interpreters::riscv32i::SCRATCH_SIZE]
    fn alloc_scratch(&mut self) -> Self::Position;

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

    /// Check that the witness value `x` is a boolean (`0` or `1`); otherwise abort.
    fn check_boolean(x: &Self::Variable);

    /// Assert that the value `x` is boolean, and add a constraint in the proof system.
    fn assert_boolean(&mut self, x: Self::Variable) {
        Self::check_boolean(&x);
        self.add_constraint(x.clone() * x.clone() - x);
    }

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

    /// Range checks with 1 lookup to the AtMost4Lookup table 0 <= value < 4
    fn range_check2(&mut self, value: &Self::Variable) {
        self.lookup_2bits(value);
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
        // If x = 0, then res = 1 and x_inv_or_zero = 0
        // If x <> 0, then res = 0 and x_inv_or_zero = x^(-1)
        self.add_constraint(x.clone() * x_inv_or_zero.clone() + res.clone() - Self::constant(1));
        self.add_constraint(x.clone() * res.clone());
        res
    }

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

    /// Given a variable x, this function extends it to a signed integer of
    /// bitlength bits.
    fn sign_extend(&mut self, x: &Self::Variable, bitlength: u32) -> Self::Variable {
        // FIXME: Constrain high_bit
        let high_bit = {
            let pos = self.alloc_scratch();
            unsafe { self.bitmask(x, bitlength, bitlength - 1, pos) }
        };
        high_bit * Self::constant(((1 << (32 - bitlength)) - 1) << bitlength) + x.clone()
    }

    fn report_exit(&mut self, exit_code: &Self::Variable);

    /// Reset the environment to handle the next instruction
    fn reset(&mut self);
}

pub fn interpret_instruction<Env: InterpreterEnv>(env: &mut Env, instr: Instruction) {
    env.activate_selector(instr);

    /* https://msyksphinz-self.github.io/riscv-isadoc/html/rvi.html */
    /* as a general note each inst has an equation description, each operation in the equation needs a witness inst */
    println!("Interpreting instruction {:?}", instr);
    match instr {
        Instruction::RType(rtype) => interpret_rtype(env, rtype),
        Instruction::IType(itype) => interpret_itype(env, itype),
        Instruction::SType(stype) => interpret_stype(env, stype),
        Instruction::SBType(sbtype) => interpret_sbtype(env, sbtype),
        Instruction::UType(utype) => interpret_utype(env, utype),
        Instruction::UJType(ujtype) => interpret_ujtype(env, ujtype),
        Instruction::SyscallType(syscalltype) => interpret_syscall(env, syscalltype),
    }
}

pub fn interpret_syscall<Env: InterpreterEnv>(env: &mut Env, _instr: SyscallInstruction) {
    // FIXME: check if it is syscall success. There is only one syscall atm
    env.set_halted(Env::constant(1));
}

pub fn interpret_rtype<Env: InterpreterEnv>(env: &mut Env, instr: RInstruction) {
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
    println!("opcode: {:?}", opcode);

    /* decode and parse bits from the full 32 bit instruction in accordance with the Rtype riscV spec
    https://www.cs.cornell.edu/courses/cs3410/2024fa/assignments/cpusim/riscv-instructions.pdf
     */
    let rd = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 12, 7, pos) }
    };
    env.range_check8(&rd, 5);
    println!("rd: {:?}", rd);

    let funct3 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 15, 12, pos) }
    };
    env.range_check8(&funct3, 3);
    println!("funct3: {:?}", funct3);

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

    // Check correctness of decomposition for R-type instruction
    env.add_constraint(
        instruction
    - (opcode.clone() * Env::constant(1 << 0))    // opcode at bits 0-6
    - (rd.clone() * Env::constant(1 << 7))        // rd at bits 7-11
    - (funct3.clone() * Env::constant(1 << 12))   // funct3 at bits 12-14
    - (rs1.clone() * Env::constant(1 << 15))      // rs1 at bits 15-19
    - (rs2.clone() * Env::constant(1 << 20))      // rs2 at bits 20-24
    - (funct2.clone() * Env::constant(1 << 25))   // funct7 at bits 25-26
    - (funct5.clone() * Env::constant(1 << 27)), // funct5 at bits 27-31
    );

    // XLEN = 32
    match instr {
        RInstruction::Add => {
            /* add: x[rd] = x[rs1] + x[rs2] */
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let overflow_scratch = env.alloc_scratch();
            let rd_scratch = env.alloc_scratch();
            let local_rd = unsafe {
                let (local_rd, _overflow) =
                    env.add_witness(&local_rs1, &local_rs2, rd_scratch, overflow_scratch);
                local_rd
            };
            // FIXME range check result is 32 bits
            env.write_register(&rd, local_rd);

            // range check result is 32 bits
            // env.range_check32(&x_rd, 32);
            // TODO implement range_check 32
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::Sub => {
            /* sub: x[rd] = x[rs1] - x[rs2] */
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let underflow_scratch = env.alloc_scratch();
            let rd_scratch = env.alloc_scratch();
            let local_rd = unsafe {
                let (local_rd, _underflow) =
                    env.sub_witness(&local_rs1, &local_rs2, rd_scratch, underflow_scratch);
                local_rd
            };
            env.write_register(&rd, local_rd);

            // range check result is 32 bits
            // env.range_check32(&x_rd, 32);
            // TODO implement range_check 32
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::ShiftLeftLogical => {
            /* sll: x[rd] = x[rs1] << x[rs2] */
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let rd_scratch = env.alloc_scratch();
            let local_rd = unsafe { env.shift_left(&local_rs1, &local_rs2, rd_scratch) };
            env.write_register(&rd, local_rd);

            // range check result is 32 bits
            // env.range_check32(&x_rd, 32);
            // TODO implement range_check 32
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::SetLessThan => {
            /* slt: x[rd] = (x[rs1] < x[rs2]) ? 1 : 0 */
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let rd_scratch = env.alloc_scratch();
            let local_rd = unsafe { env.test_less_than_signed(&local_rs1, &local_rs2, rd_scratch) };
            env.write_register(&rd, local_rd);
            // range check result is 32 bits
            // env.range_check32(&x_rd, 32);
            // TODO implement range_check 32
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::SetLessThanUnsigned => {
            /* sltu: x[rd] = (x[rs1] < (u)x[rs2]) ? 1 : 0 */
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let rd_scratch = env.alloc_scratch();
            let local_rd = unsafe { env.test_less_than(&local_rs1, &local_rs2, rd_scratch) };
            env.write_register(&rd, local_rd);
            // range check result is 32 bits
            // env.range_check32(&x_rd, 32);
            // TODO implement range_check 32
            // we should constrain x[rs2] to be unsigned here
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::Xor => {
            /* xor: x[rd] = x[rs1] ^ x[rs2] */
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let rd_scratch = env.alloc_scratch();
            let local_rd = unsafe { env.xor_witness(&local_rs1, &local_rs2, rd_scratch) };
            env.write_register(&rd, local_rd);
            // range check result is 32 bits
            // env.range_check32(&x_rd, 32);
            // TODO implement range_check 32
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::ShiftRightLogical => {
            /* srl: x[rd] = x[rs1] >> x[rs2] */
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let rd_scratch = env.alloc_scratch();
            let local_rd = unsafe { env.shift_right(&local_rs1, &local_rs2, rd_scratch) };
            env.write_register(&rd, local_rd);
            // range check result is 32 bits
            // env.range_check32(&x_rd, 32);
            // TODO implement range_check 32
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::ShiftRightArithmetic => {
            /* sra: x[rd] = x[rs1] >> x[rs2] */
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let rd_scratch = env.alloc_scratch();
            let local_rd =
                unsafe { env.shift_right_arithmetic(&local_rs1, &local_rs2, rd_scratch) };
            env.write_register(&rd, local_rd);
            // range check result is 32 bits
            // env.range_check32(&x_rd, 32);
            // TODO implement range_check 32
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::Or => {
            /* or: x[rd] = x[rs1] | x[rs2] */
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let rd_scratch = env.alloc_scratch();
            let local_rd = unsafe { env.or_witness(&local_rs1, &local_rs2, rd_scratch) };
            env.write_register(&rd, local_rd);
            // range check result is 32 bits
            // env.range_check32(&x_rd, 32);
            // TODO implement range_check 32
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::And => {
            /* and: x[rd] = x[rs1] & x[rs2] */
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);
            let rd_scratch = env.alloc_scratch();
            let local_rd = unsafe { env.and_witness(&local_rs1, &local_rs2, rd_scratch) };
            env.write_register(&rd, local_rd);
            // range check result is 32 bits
            // env.range_check32(&x_rd, 32);
            // TODO implement range_check 32
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        RInstruction::Fence => {
            /* fence: no-op */
            // https://msyksphinz-self.github.io/riscv-isadoc/html/rvi.html#fence
            // need to understand IO device in o1 vm
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
            // Fence(Store, Fetch)
        }
        RInstruction::FenceI => {
            /* fence.i: no-op */
            // https://msyksphinz-self.github.io/riscv-isadoc/html/rvi.html#fence-i
            // need to understand IO device in o1 vm
            // t = CSRs[csr]; CSRs[csr] = x[rs1]; x[rd] = t
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
    };
}

pub fn interpret_itype<Env: InterpreterEnv>(env: &mut Env, instr: IInstruction) {
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

    println!("finished parsing iinstruction");
    //print out the instruction
    println!("instruction in the interpreter: {:?}", instruction);

    /* fetch opcode from instruction bit 0 - 6 for a total len of 7 */
    let opcode = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 7, 0, pos) }
    };
    /* verify opcode is 7 bits */
    env.range_check8(&opcode, 7);
    // print out the opcode
    println!("opcode: {:?}", opcode);

    /* decode and parse bits from the full 32 bit instruction in accordance with the Rtype riscV spec
    https://www.cs.cornell.edu/courses/cs3410/2024fa/assignments/cpusim/riscv-instructions.pdf
     */
    let rd = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 12, 7, pos) }
    };
    env.range_check8(&rd, 5);
    // print out rd
    println!("rd: {:?}", rd);

    let funct3 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 15, 12, pos) }
    };
    env.range_check8(&funct3, 3);
    // print out funct3
    println!("funct3: {:?}", funct3);

    let rs1 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 20, 15, pos) }
    };
    env.range_check8(&rs1, 5);
    // print out rs1
    println!("rs1: {:?}", rs1.clone());

    let imm = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 32, 20, pos) }
    };

    env.range_check16(&imm, 12);
    println!("imm: {:?}", imm);

    // check correctness of decomposition of I type function
    /*
    env.add_constraint(
        instruction
        - (opcode.clone() * Env::constant(1 << 0))    // opcode at bits 0-6
        - (rd.clone() * Env::constant(1 << 6))        // rd at bits 7-11
        - (funct3.clone() * Env::constant(1 << 11))   // funct3 at bits 12-14
        - (rs1.clone() * Env::constant(1 << 14))      // rs1 at bits 15-19
        - (imm.clone() * Env::constant(1 << 19)), // imm at bits 20-31
    );
    */

    // print out the immediate and the opcode
    println!("imm: {:?}", imm);
    println!("opcode: {:?}", opcode);

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
        // FIXME(dw): investigate?
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
            let shamt = {
                let pos = env.alloc_scratch();
                unsafe { env.bitmask(&imm, 4, 0, pos) }
            };
            // parse shamt from imm as 20-24 of instruction and 0-4 wrt to imm
            let rd_scratch = env.alloc_scratch();
            let local_rd = unsafe { env.shift_left(&local_rs1, &shamt, rd_scratch) };

            env.write_register(&rd, local_rd);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::ShiftRightLogicalImmediate => {
            // srli: x[rd] = x[rs1] >> shamt
            let local_rs1 = env.read_register(&rs1);
            let shamt = {
                let pos = env.alloc_scratch();
                unsafe { env.bitmask(&imm, 4, 0, pos) }
            };
            // parse shamt from imm as 20-24 of instruction and 0-4 wrt to imm
            let rd_scratch = env.alloc_scratch();
            let local_rd = unsafe { env.shift_right(&local_rs1, &shamt, rd_scratch) };
            env.write_register(&rd, local_rd);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::ShiftRightArithmeticImmediate => {
            // srai: x[rd] = x[rs1] >> shamt
            let local_rs1 = env.read_register(&rs1);
            let shamt = {
                let pos = env.alloc_scratch();
                unsafe { env.bitmask(&imm, 4, 0, pos) }
            };
            // parse shamt from imm as 20-24 of instruction and 0-4 wrt to imm
            // sign extend shamt for arithmetic shift
            let shamt = env.sign_extend(&shamt, 4);

            let rd_scratch = env.alloc_scratch();
            let local_rd = unsafe { env.shift_right_arithmetic(&local_rs1, &shamt, rd_scratch) };
            env.write_register(&rd, local_rd);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::SetLessThanImmediate => {
            // slti: x[rd] = (x[rs1] < sext(immediate)) ? 1 : 0
            let local_rs1 = env.read_register(&rs1);
            let local_imm = env.sign_extend(&imm, 12);
            let rd_scratch = env.alloc_scratch();
            let local_rd = unsafe { env.test_less_than_signed(&local_rs1, &local_imm, rd_scratch) };
            env.write_register(&rd, local_rd);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::SetLessThanImmediateUnsigned => {
            // sltiu: x[rd] = (x[rs1] < (u)sext(immediate)) ? 1 : 0
            let local_rs1 = env.read_register(&rs1);
            let local_imm = env.sign_extend(&imm, 12);
            let rd_scratch = env.alloc_scratch();
            let local_rd = unsafe { env.test_less_than(&local_rs1, &local_imm, rd_scratch) };
            env.write_register(&rd, local_rd);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::AddImmediate => {
            // addi: x[rd] = x[rs1] + sext(immediate)
            let local_rs1 = env.read_register(&(rs1.clone()));
            let local_imm = env.sign_extend(&imm, 12);
            let overflow_scratch = env.alloc_scratch();
            let rd_scratch = env.alloc_scratch();
            let local_rd = unsafe {
                let (local_rd, _overflow) =
                    env.add_witness(&local_rs1, &local_imm, rd_scratch, overflow_scratch);
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
            let rd_scratch = env.alloc_scratch();
            let local_rd = unsafe { env.xor_witness(&local_rs1, &local_imm, rd_scratch) };
            env.write_register(&rd, local_rd);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::OrImmediate => {
            // ori: x[rd] = x[rs1] | sext(immediate)
            let local_rs1 = env.read_register(&rs1);
            let local_imm = env.sign_extend(&imm, 12);
            let rd_scratch = env.alloc_scratch();
            let local_rd = unsafe { env.or_witness(&local_rs1, &local_imm, rd_scratch) };
            env.write_register(&rd, local_rd);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::AndImmediate => {
            // andi: x[rd] = x[rs1] & sext(immediate)
            let local_rs1 = env.read_register(&rs1);
            let local_imm = env.sign_extend(&imm, 12);
            let rd_scratch = env.alloc_scratch();
            let local_rd = unsafe { env.and_witness(&local_rs1, &local_imm, rd_scratch) };
            env.write_register(&rd, local_rd);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
        IInstruction::JumpAndLinkRegister => {
            let addr = env.read_register(&rs1);
            println!("Addr: {:?}", addr);
            // jalr:
            //  t  = pc+4;
            //  pc = (x[rs1] + sext(offset)) & ∼1; <- NOT NOW
            //  pc = (x[rs1] + sext(offset)); <- PLEASE FIXME
            //  x[rd] = t
            // copying mips for now to match deugger
            let offset = env.sign_extend(&imm, 12);
            let new_addr = {
                let res_scratch = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (res, _overflow) =
                    unsafe { env.add_witness(&addr, &offset, res_scratch, overflow_scratch) };
                res
            };
            println!("Offset: {:?}", offset);
            env.write_register(&rd, next_instruction_pointer.clone());
            env.set_instruction_pointer(new_addr.clone());
            env.set_next_instruction_pointer(new_addr.clone() + Env::constant(4u32));
        }
    };
}

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
        unsafe { env.bitmask(&instruction, 31, 25, pos) }
        // bytes 25-31
    };
    env.range_check8(&imm5_11, 6);

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
                    unsafe { env.bitmask(&local_rs2, 8, 0, value_scratch) }
                },
                {
                    let value_scratch = env.alloc_scratch();
                    unsafe { env.bitmask(&local_rs2, 16, 8, value_scratch) }
                },
                {
                    let value_scratch = env.alloc_scratch();
                    unsafe { env.bitmask(&local_rs2, 24, 16, value_scratch) }
                },
                {
                    let value_scratch = env.alloc_scratch();
                    unsafe { env.bitmask(&local_rs2, 32, 24, value_scratch) }
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

pub fn interpret_sbtype<Env: InterpreterEnv>(env: &mut Env, instr: SBInstruction) {
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

    let imm11 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 8, 7, pos) }
    };
    env.range_check8(&imm11, 1);

    let imm0_4 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 12, 8, pos) }
    };
    env.range_check8(&imm0_4, 4);

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

    let imm5_10 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 31, 25, pos) }
    };
    env.range_check8(&imm5_10, 6);

    let imm12 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 32, 31, pos) }
    };
    env.range_check8(&imm12, 1);

    // check correctness of decomposition of SB type function
    env.add_constraint(
        instruction
        - (opcode.clone() * Env::constant(1 << 0))    // opcode at bits 0-6
        - (imm11.clone() * Env::constant(1 << 7))     // imm11 at bits 7
        - (imm0_4.clone() * Env::constant(1 << 8))    // imm0_4 at bits 8-11
        - (funct3.clone() * Env::constant(1 << 12))   // funct3 at bits 12-14
        - (rs1.clone() * Env::constant(1 << 15))      // rs1 at bits 15-19
        - (rs2.clone() * Env::constant(1 << 20))      // rs2 at bits 20-24
        - (imm5_10.clone() * Env::constant(1 << 25))  // imm5_10 at bits 25-30
        - (imm12.clone() * Env::constant(1 << 31)), // imm12 at bits 31
    );

    let imm0_10 = {
        let shift_pos = env.alloc_scratch();
        let shifted_imm5_10 = unsafe { env.shift_left(&imm5_10, &Env::constant(5), shift_pos) };

        let pos = env.alloc_scratch();
        let shift_pos = env.alloc_scratch();
        let shifted_imm1_4 = unsafe { env.shift_left(&imm0_4, &Env::constant(1), shift_pos) };
        let imm0_10 = unsafe { env.or_witness(&shifted_imm5_10, &shifted_imm1_4, pos) };
        env.sign_extend(&imm0_10, 13)
    };

    let imm11_12 = {
        let shift_pos = env.alloc_scratch();
        let shifted_imm12 = unsafe { env.shift_left(&imm12, &Env::constant(12), shift_pos) };

        let shift_pos = env.alloc_scratch();
        let shifted_imm11 = unsafe { env.shift_left(&imm11, &Env::constant(11), shift_pos) };

        let pos = env.alloc_scratch();
        let imm11_12 = unsafe { env.or_witness(&shifted_imm12, &shifted_imm11, pos) };
        env.sign_extend(&imm11_12, 13)
    };

    let imm0_12 = {
        let pos = env.alloc_scratch();
        let imm0_12 = unsafe { env.or_witness(&imm11_12, &imm0_10, pos) };
        env.sign_extend(&imm0_12, 13)
    };

    match instr {
        SBInstruction::BranchEq => {
            // beq: if (x[rs1] == x[rs2]) pc += sext(offset)
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);

            let equal = env.equal(&local_rs1, &local_rs2);

            let offset = (equal.clone()) * imm0_12;

            let next_instruction_pointer = {
                let pos = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (next_instruction_pointer, _overflow) = unsafe {
                    env.add_witness(&next_instruction_pointer, &offset, pos, overflow_scratch)
                };
                next_instruction_pointer
            };

            let new_instruction_pointer = {
                let pos = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (new_instruction_pointer, _overflow) = unsafe {
                    env.add_witness(
                        &next_instruction_pointer,
                        &Env::constant(4u32),
                        pos,
                        overflow_scratch,
                    )
                };
                new_instruction_pointer
            };

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(new_instruction_pointer.clone());
        }
        SBInstruction::BranchNeq => {
            // bne: if (x[rs1] != x[rs2]) pc += sext(offset)
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);

            let not_equal = env.equal(&local_rs1, &local_rs2);

            let offset = (Env::constant(1) - not_equal.clone()) * imm0_12;

            let next_instruction_pointer = {
                let pos = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (next_instruction_pointer, _overflow) = unsafe {
                    env.add_witness(&next_instruction_pointer, &offset, pos, overflow_scratch)
                };
                next_instruction_pointer
            };

            let new_instruction_pointer = {
                let pos = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (new_instruction_pointer, _overflow) = unsafe {
                    env.add_witness(
                        &next_instruction_pointer,
                        &Env::constant(4u32),
                        pos,
                        overflow_scratch,
                    )
                };
                new_instruction_pointer
            };

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(new_instruction_pointer.clone());
        }
        SBInstruction::BranchLessThan => {
            // blt: if (x[rs1] < x[rs2]) pc += sext(offset)
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);

            let rd_scratch = env.alloc_scratch();
            let less_than =
                unsafe { env.test_less_than_signed(&local_rs1, &local_rs2, rd_scratch) };

            let offset = (less_than.clone()) * imm0_12;

            let next_instruction_pointer = {
                let pos = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (next_instruction_pointer, _overflow) = unsafe {
                    env.add_witness(&next_instruction_pointer, &offset, pos, overflow_scratch)
                };
                next_instruction_pointer
            };
            let new_instruction_pointer = {
                let pos = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (new_instruction_pointer, _overflow) = unsafe {
                    env.add_witness(
                        &next_instruction_pointer,
                        &Env::constant(4u32),
                        pos,
                        overflow_scratch,
                    )
                };
                new_instruction_pointer
            };

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(new_instruction_pointer.clone());
        }
        SBInstruction::BranchGreaterThanEqual => {
            // bge: if (x[rs1] >= x[rs2]) pc += sext(offset)
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);

            let rd_scratch = env.alloc_scratch();
            let less_than =
                unsafe { env.test_less_than_signed(&local_rs2, &local_rs1, rd_scratch) };

            // greater than equal is the negation of less than
            let offset = (Env::constant(1) - less_than.clone()) * imm0_12;

            let next_instruction_pointer = next_instruction_pointer.clone() + offset.clone();
            let new_instruction_pointer =
                next_instruction_pointer.clone() + offset.clone() + Env::constant(4u32);

            env.set_instruction_pointer(new_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer.clone());
        }
        SBInstruction::BranchLessThanUnsigned => {
            // bltu: if (x[rs1] <u x[rs2]) pc += sext(offset)
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);

            let rd_scratch = env.alloc_scratch();
            let less_than = unsafe { env.test_less_than(&local_rs1, &local_rs2, rd_scratch) };

            let offset = (less_than.clone()) * imm0_12;

            let next_instruction_pointer = {
                let pos = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (next_instruction_pointer, _overflow) = unsafe {
                    env.add_witness(&next_instruction_pointer, &offset, pos, overflow_scratch)
                };
                next_instruction_pointer
            };

            let new_instruction_pointer = {
                let pos = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (new_instruction_pointer, _overflow) = unsafe {
                    env.add_witness(
                        &next_instruction_pointer,
                        &Env::constant(4u32),
                        pos,
                        overflow_scratch,
                    )
                };
                new_instruction_pointer
            };

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(new_instruction_pointer.clone());
        }
        SBInstruction::BranchGreaterThanEqualUnsigned => {
            // bgeu: if (x[rs1] >=u x[rs2]) pc += sext(offset)
            let local_rs1 = env.read_register(&rs1);
            let local_rs2 = env.read_register(&rs2);

            let rd_scratch = env.alloc_scratch();
            let less_than = unsafe { env.test_less_than(&local_rs2, &local_rs1, rd_scratch) };

            // greater than equal is the negation of less than
            let offset = (Env::constant(1) - less_than.clone()) * imm0_12;

            let next_instruction_pointer = {
                let pos = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (next_instruction_pointer, _overflow) = unsafe {
                    env.add_witness(&next_instruction_pointer, &offset, pos, overflow_scratch)
                };
                next_instruction_pointer
            };

            let new_instruction_pointer = {
                let pos = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (new_instruction_pointer, _overflow) = unsafe {
                    env.add_witness(
                        &next_instruction_pointer,
                        &Env::constant(4u32),
                        pos,
                        overflow_scratch,
                    )
                };
                new_instruction_pointer
            };

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(new_instruction_pointer.clone());
        }
    };
}

pub fn interpret_utype<Env: InterpreterEnv>(env: &mut Env, instr: UInstruction) {
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

    let rd = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 12, 7, pos) }
    };

    env.range_check8(&rd, 5);

    let imm = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 32, 12, pos) }
    };

    env.range_check64(&imm); // this is not implemented yet, can also be done with 32

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
                let pos = env.alloc_scratch();
                let shifted_imm = unsafe { env.shift_left(&imm, &Env::constant(12), pos) };
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
            let local_pc = env.get_instruction_pointer();
            let pos = env.alloc_scratch();
            let overflow_pos = env.alloc_scratch();
            let (local_rd, _) =
                unsafe { env.add_witness(&local_pc, &local_imm, pos, overflow_pos) };
            env.write_register(&rd, local_rd);

            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(next_instruction_pointer + Env::constant(4u32));
        }
    }
}

pub fn interpret_ujtype<Env: InterpreterEnv>(env: &mut Env, instr: UJInstruction) {
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

    let rd = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 12, 7, pos) }
    };
    env.range_check8(&rd, 5);

    let imm12_19 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 20, 12, pos) }
    };
    env.range_check8(&imm12_19, 8);

    let imm11 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 21, 20, pos) }
    };
    env.range_check8(&imm11, 1);

    let imm1_10 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 31, 21, pos) }
    };
    env.range_check8(&imm1_10, 10);

    let imm20 = {
        let pos = env.alloc_scratch();
        unsafe { env.bitmask(&instruction, 32, 31, pos) }
    };
    env.range_check8(&imm20, 1);

    // check correctness of decomposition of UJ type function
    env.add_constraint(
        instruction
            - (opcode.clone() * Env::constant(1 << 0))    // opcode at bits 0-6
            - (rd.clone() * Env::constant(1 << 7))        // rd at bits 7-11
            - (imm12_19.clone() * Env::constant(1 << 12)) // imm12_19 at bits 12-19
            - (imm11.clone() * Env::constant(1 << 20))    // imm11 at bits 20
            - (imm1_10.clone() * Env::constant(1 << 21))  // imm1_10 at bits 21-30
            - (imm20.clone() * Env::constant(1 << 31)), // imm20 at bits 31
    );

    // index at 1 because there is no sign bit
    let imm1_11 = {
        let shift_pos = env.alloc_scratch();
        let shifted_imm11 = unsafe { env.shift_left(&imm11, &Env::constant(11), shift_pos) };
        let imm1_11 = env.sign_extend(&shifted_imm11.clone(), 11);

        let shift_pos = env.alloc_scratch();
        let shifted_imm1_10 = unsafe { env.shift_left(&imm1_10, &Env::constant(1), shift_pos) };
        let imm1_10 = env.sign_extend(&shifted_imm1_10, 10);

        let pos = env.alloc_scratch();
        let imm1_11 = unsafe { env.or_witness(&imm1_11, &imm1_10.clone(), pos) };
        env.sign_extend(&imm1_11, 11)
    };

    let imm12_20 = {
        let shift_pos = env.alloc_scratch();
        let shifted_imm12_19 = unsafe { env.shift_left(&imm12_19, &Env::constant(12), shift_pos) };
        let imm12_19 = env.sign_extend(&shifted_imm12_19, 19);

        let shift_pos = env.alloc_scratch();
        let shifted_imm20 = unsafe { env.shift_left(&imm20, &Env::constant(20), shift_pos) };
        let imm20 = env.sign_extend(&shifted_imm20, 20);

        let pos = env.alloc_scratch();
        let imm12_20 = unsafe { env.or_witness(&imm12_19, &imm20, pos) };
        env.sign_extend(&imm12_20, 21)
    };

    let imm1_20 = {
        let pos = env.alloc_scratch();
        let imm12_20 = unsafe { env.shift_left(&imm12_20, &Env::constant(12), pos) };

        let pos = env.alloc_scratch();
        let imm1_20 = unsafe { env.or_witness(&imm1_11, &imm12_20, pos) };
        env.sign_extend(&imm1_20, 32)
    };

    match instr {
        UJInstruction::JumpAndLink => {
            // jal: x[rd] = pc+4; pc += sext(offset)
            let local_pc = env.get_instruction_pointer();
            let local_rd = {
                let pos = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (local_rd, _) = unsafe {
                    env.add_witness(&local_pc, &Env::constant(4u32), pos, overflow_scratch)
                };
                local_rd
            };
            let offset = imm1_20.clone();
            let next_instruction_pointer = {
                let pos = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (next_instruction_pointer, _overflow) = unsafe {
                    env.add_witness(&next_instruction_pointer, &offset, pos, overflow_scratch)
                };
                next_instruction_pointer
            };
            let new_instruction_pointer = {
                let pos = env.alloc_scratch();
                let overflow_scratch = env.alloc_scratch();
                let (new_instruction_pointer, _overflow) = unsafe {
                    env.add_witness(
                        &next_instruction_pointer,
                        &Env::constant(4u32),
                        pos,
                        overflow_scratch,
                    )
                };
                new_instruction_pointer
            };
            env.write_register(&rd, local_rd);
            env.set_instruction_pointer(next_instruction_pointer.clone());
            env.set_next_instruction_pointer(new_instruction_pointer.clone());
        }
    }
}
