use strum_macros::{EnumCount, EnumIter};

use crate::lookups::{Lookup, LookupTableIDs};
use ark_ff::{One, Zero};

use super::registers::{REGISTER_CURRENT_IP, REGISTER_HEAP_POINTER, REGISTER_NEXT_IP};

// FIXME: split in the future in instruction types?
#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum Instruction {
    #[default]
    BranchEq, // beq
    BranchEqZero,  // beqz
    BranchNeq,     // bne
    BranchLeqZero, // blez
    BranchGtZero,  // bgtz
    BranchLtZero,  // bltz
    BranchGeqZero, // bgez

    // Pseudo instruction
    // j offset -> jal x0, offset - Jump
    Jump, // j
    // jal offset -> jal x1, offset - Jump and Link
    JumpAndLink, // jal
    // jr rs -> jalr x0, 0(rs) - Jump Register
    JumpRegister, // jr
    // jalr rs -> jalr x1, 0(rs) - Jump and Link Register
    JumpAndLinkRegister, // jalr
    // jalr x0, 0(x1) - Return from Subroutine
    Return, // ret
    // call x0, offset - Call far-away subroutine
    // auipc x1, offset[31 : 12] + offset[11]
    // jalr x1, offset[11:0](x1)
    Call, // call
    // tail offset -
    // auipc x1, offset[31 : 12] + offset[11]
    Tail,
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

    /// Given a variable `x`, this function extends it to a signed integer of
    /// `bitlength` bits.
    fn sign_extend(&mut self, x: &Self::Variable, bitlength: u32) -> Self::Variable {
        // FIXME: Constrain `high_bit`
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

    // TODO: match on instructions
    unimplemented!("TODO");
}
