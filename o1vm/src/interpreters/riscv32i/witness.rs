// TODO: do we want to be more restrictive and refer to the number of accesses
//       to the SAME register/memory addrss?

use super::{
    column::Column,
    interpreter::{
        self, IInstruction, Instruction, InterpreterEnv, RInstruction, SBInstruction, SInstruction,
        UInstruction, UJInstruction,
    },
    registers::{self, Registers},
    INSTRUCTION_SET_SIZE, PAGE_ADDRESS_MASK, PAGE_ADDRESS_SIZE, PAGE_SIZE, SCRATCH_SIZE,
};
use crate::{cannon::State, lookups::Lookup};
use ark_ff::Field;
use std::array;

/// Maximum number of register accesses per instruction (based on demo)
pub const MAX_NB_REG_ACC: u64 = 7;
/// Maximum number of memory accesses per instruction (based on demo)
pub const MAX_NB_MEM_ACC: u64 = 12;
/// Maximum number of memory or register accesses per instruction
pub const MAX_ACC: u64 = MAX_NB_REG_ACC + MAX_NB_MEM_ACC;

pub const NUM_GLOBAL_LOOKUP_TERMS: usize = 1;
pub const NUM_DECODING_LOOKUP_TERMS: usize = 2;
pub const NUM_INSTRUCTION_LOOKUP_TERMS: usize = 5;
pub const NUM_LOOKUP_TERMS: usize =
    NUM_GLOBAL_LOOKUP_TERMS + NUM_DECODING_LOOKUP_TERMS + NUM_INSTRUCTION_LOOKUP_TERMS;

/// This structure represents the environment the virtual machine state will use
/// to transition. This environment will be used by the interpreter. The virtual
/// machine has access to its internal state and some external memory. In
/// addition to that, it has access to the environment of the Keccak interpreter
/// that is used to verify the preimage requested during the execution.
pub struct Env<Fp> {
    pub instruction_counter: u64,
    pub memory: Vec<(u32, Vec<u8>)>,
    pub last_memory_accesses: [usize; 3],
    pub memory_write_index: Vec<(u32, Vec<u64>)>,
    pub last_memory_write_index_accesses: [usize; 3],
    pub registers: Registers<u32>,
    pub registers_write_index: Registers<u64>,
    pub scratch_state_idx: usize,
    pub scratch_state: [Fp; SCRATCH_SIZE],
    pub halt: bool,
    pub selector: usize,
}

fn fresh_scratch_state<Fp: Field, const N: usize>() -> [Fp; N] {
    array::from_fn(|_| Fp::zero())
}

impl<Fp: Field> InterpreterEnv for Env<Fp> {
    type Position = Column;

    fn alloc_scratch(&mut self) -> Self::Position {
        let scratch_idx = self.scratch_state_idx;
        self.scratch_state_idx += 1;
        Column::ScratchState(scratch_idx)
    }

    type Variable = u64;

    fn variable(&self, _column: Self::Position) -> Self::Variable {
        todo!()
    }

    fn add_constraint(&mut self, _assert_equals_zero: Self::Variable) {
        // No-op for witness
        // Do not assert that _assert_equals_zero is zero here!
        // Some variables may have placeholders that do not faithfully
        // represent the underlying values.
    }

    fn activate_selector(&mut self, instruction: Instruction) {
        self.selector = instruction.into();
    }

    fn check_is_zero(assert_equals_zero: &Self::Variable) {
        assert_eq!(*assert_equals_zero, 0);
    }

    fn check_equal(x: &Self::Variable, y: &Self::Variable) {
        assert_eq!(*x, *y);
    }

    fn check_boolean(x: &Self::Variable) {
        if !(*x == 0 || *x == 1) {
            panic!("The value {} is not a boolean", *x);
        }
    }

    fn add_lookup(&mut self, _lookup: Lookup<Self::Variable>) {
        // No-op, constraints only
        // TODO: keep track of multiplicities of fixed tables here as in Keccak?
    }

    fn instruction_counter(&self) -> Self::Variable {
        self.instruction_counter
    }

    fn increase_instruction_counter(&mut self) {
        self.instruction_counter += 1;
    }

    unsafe fn fetch_register(
        &mut self,
        idx: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable {
        let res = self.registers[*idx as usize] as u64;
        self.write_column(output, res);
        res
    }

    unsafe fn push_register_if(
        &mut self,
        idx: &Self::Variable,
        value: Self::Variable,
        if_is_true: &Self::Variable,
    ) {
        let value: u32 = value.try_into().unwrap();
        if *if_is_true == 1 {
            self.registers[*idx as usize] = value
        } else if *if_is_true == 0 {
            // No-op
        } else {
            panic!("Bad value for flag in push_register: {}", *if_is_true);
        }
    }

    unsafe fn fetch_register_access(
        &mut self,
        idx: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable {
        let res = self.registers_write_index[*idx as usize];
        self.write_column(output, res);
        res
    }

    unsafe fn push_register_access_if(
        &mut self,
        idx: &Self::Variable,
        value: Self::Variable,
        if_is_true: &Self::Variable,
    ) {
        if *if_is_true == 1 {
            self.registers_write_index[*idx as usize] = value
        } else if *if_is_true == 0 {
            // No-op
        } else {
            panic!("Bad value for flag in push_register: {}", *if_is_true);
        }
    }

    unsafe fn fetch_memory(
        &mut self,
        addr: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable {
        let addr: u32 = (*addr).try_into().unwrap();
        let page = addr >> PAGE_ADDRESS_SIZE;
        let page_address = (addr & PAGE_ADDRESS_MASK) as usize;
        let memory_page_idx = self.get_memory_page_index(page);
        let value = self.memory[memory_page_idx].1[page_address];
        self.write_column(output, value.into());
        value.into()
    }

    unsafe fn push_memory(&mut self, addr: &Self::Variable, value: Self::Variable) {
        let addr: u32 = (*addr).try_into().unwrap();
        let page = addr >> PAGE_ADDRESS_SIZE;
        let page_address = (addr & PAGE_ADDRESS_MASK) as usize;
        let memory_page_idx = self.get_memory_page_index(page);
        self.memory[memory_page_idx].1[page_address] =
            value.try_into().expect("push_memory values fit in a u8");
    }

    unsafe fn fetch_memory_access(
        &mut self,
        addr: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable {
        let addr: u32 = (*addr).try_into().unwrap();
        let page = addr >> PAGE_ADDRESS_SIZE;
        let page_address = (addr & PAGE_ADDRESS_MASK) as usize;
        let memory_write_index_page_idx = self.get_memory_access_page_index(page);
        let value = self.memory_write_index[memory_write_index_page_idx].1[page_address];
        self.write_column(output, value);
        value
    }

    unsafe fn push_memory_access(&mut self, addr: &Self::Variable, value: Self::Variable) {
        let addr = *addr as u32;
        let page = addr >> PAGE_ADDRESS_SIZE;
        let page_address = (addr & PAGE_ADDRESS_MASK) as usize;
        let memory_write_index_page_idx = self.get_memory_access_page_index(page);
        self.memory_write_index[memory_write_index_page_idx].1[page_address] = value;
    }

    fn constant(x: u32) -> Self::Variable {
        x as u64
    }

    unsafe fn bitmask(
        &mut self,
        x: &Self::Variable,
        highest_bit: u32,
        lowest_bit: u32,
        position: Self::Position,
    ) -> Self::Variable {
        let x: u32 = (*x).try_into().unwrap();
        let res = (x >> lowest_bit) & ((1 << (highest_bit - lowest_bit)) - 1);
        let res = res as u64;
        self.write_column(position, res);
        res
    }

    unsafe fn shift_left(
        &mut self,
        x: &Self::Variable,
        by: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        let x: u32 = (*x).try_into().unwrap();
        let by: u32 = (*by).try_into().unwrap();
        let res = x << by;
        let res = res as u64;
        self.write_column(position, res);
        res
    }

    unsafe fn shift_right(
        &mut self,
        x: &Self::Variable,
        by: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        let x: u32 = (*x).try_into().unwrap();
        let by: u32 = (*by).try_into().unwrap();
        let res = x >> by;
        let res = res as u64;
        self.write_column(position, res);
        res
    }

    unsafe fn shift_right_arithmetic(
        &mut self,
        x: &Self::Variable,
        by: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        let x: u32 = (*x).try_into().unwrap();
        let by: u32 = (*by).try_into().unwrap();
        let res = ((x as i32) >> by) as u32;
        let res = res as u64;
        self.write_column(position, res);
        res
    }

    unsafe fn test_zero(&mut self, x: &Self::Variable, position: Self::Position) -> Self::Variable {
        let res = if *x == 0 { 1 } else { 0 };
        self.write_column(position, res);
        res
    }

    unsafe fn inverse_or_zero(
        &mut self,
        x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        if *x == 0 {
            self.write_column(position, 0);
            0
        } else {
            self.write_field_column(position, Fp::from(*x).inverse().unwrap());
            1 // Placeholder value
        }
    }

    fn equal(&mut self, x: &Self::Variable, y: &Self::Variable) -> Self::Variable {
        // To avoid subtraction overflow in the witness interpreter for u32
        if x > y {
            self.is_zero(&(*x - *y))
        } else {
            self.is_zero(&(*y - *x))
        }
    }

    unsafe fn test_less_than(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        let x: u32 = (*x).try_into().unwrap();
        let y: u32 = (*y).try_into().unwrap();
        let res = if x < y { 1 } else { 0 };
        let res = res as u64;
        self.write_column(position, res);
        res
    }

    unsafe fn test_less_than_signed(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        let x: u32 = (*x).try_into().unwrap();
        let y: u32 = (*y).try_into().unwrap();
        let res = if (x as i32) < (y as i32) { 1 } else { 0 };
        let res = res as u64;
        self.write_column(position, res);
        res
    }

    unsafe fn and_witness(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        let x: u32 = (*x).try_into().unwrap();
        let y: u32 = (*y).try_into().unwrap();
        let res = x & y;
        let res = res as u64;
        self.write_column(position, res);
        res
    }

    unsafe fn nor_witness(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        let x: u32 = (*x).try_into().unwrap();
        let y: u32 = (*y).try_into().unwrap();
        let res = !(x | y);
        let res = res as u64;
        self.write_column(position, res);
        res
    }

    unsafe fn or_witness(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        let x: u32 = (*x).try_into().unwrap();
        let y: u32 = (*y).try_into().unwrap();
        let res = x | y;
        let res = res as u64;
        self.write_column(position, res);
        res
    }

    unsafe fn xor_witness(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        let x: u32 = (*x).try_into().unwrap();
        let y: u32 = (*y).try_into().unwrap();
        let res = x ^ y;
        let res = res as u64;
        self.write_column(position, res);
        res
    }

    unsafe fn add_witness(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        out_position: Self::Position,
        overflow_position: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        let x: u32 = (*x).try_into().unwrap();
        let y: u32 = (*y).try_into().unwrap();
        // https://doc.rust-lang.org/std/primitive.u32.html#method.overflowing_add
        let res = x.overflowing_add(y);
        let (res_, overflow) = (res.0 as u64, res.1 as u64);
        self.write_column(out_position, res_);
        self.write_column(overflow_position, overflow);
        (res_, overflow)
    }

    unsafe fn sub_witness(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        out_position: Self::Position,
        underflow_position: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        let x: u32 = (*x).try_into().unwrap();
        let y: u32 = (*y).try_into().unwrap();
        // https://doc.rust-lang.org/std/primitive.u32.html#method.overflowing_sub
        let res = x.overflowing_sub(y);
        let (res_, underflow) = (res.0 as u64, res.1 as u64);
        self.write_column(out_position, res_);
        self.write_column(underflow_position, underflow);
        (res_, underflow)
    }

    unsafe fn mul_signed_witness(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        let x: u32 = (*x).try_into().unwrap();
        let y: u32 = (*y).try_into().unwrap();
        let res = ((x as i32) * (y as i32)) as u32;
        let res = res as u64;
        self.write_column(position, res);
        res
    }

    unsafe fn mul_hi_lo_signed(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position_hi: Self::Position,
        position_lo: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        let x: u32 = (*x).try_into().unwrap();
        let y: u32 = (*y).try_into().unwrap();
        let mul = (((x as i32) as i64) * ((y as i32) as i64)) as u64;
        let hi = (mul >> 32) as u32;
        let lo = (mul & ((1 << 32) - 1)) as u32;
        let hi = hi as u64;
        let lo = lo as u64;
        self.write_column(position_hi, hi);
        self.write_column(position_lo, lo);
        (hi, lo)
    }

    unsafe fn mul_hi_lo(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position_hi: Self::Position,
        position_lo: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        let x: u32 = (*x).try_into().unwrap();
        let y: u32 = (*y).try_into().unwrap();
        let mul = (x as u64) * (y as u64);
        let hi = (mul >> 32) as u32;
        let lo = (mul & ((1 << 32) - 1)) as u32;
        let hi = hi as u64;
        let lo = lo as u64;
        self.write_column(position_hi, hi);
        self.write_column(position_lo, lo);
        (hi, lo)
    }

    unsafe fn divmod_signed(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position_quotient: Self::Position,
        position_remainder: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        let x: u32 = (*x).try_into().unwrap();
        let y: u32 = (*y).try_into().unwrap();
        let q = ((x as i32) / (y as i32)) as u32;
        let r = ((x as i32) % (y as i32)) as u32;
        let q = q as u64;
        let r = r as u64;
        self.write_column(position_quotient, q);
        self.write_column(position_remainder, r);
        (q, r)
    }

    unsafe fn divmod(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        position_quotient: Self::Position,
        position_remainder: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        let x: u32 = (*x).try_into().unwrap();
        let y: u32 = (*y).try_into().unwrap();
        let q = x / y;
        let r = x % y;
        let q = q as u64;
        let r = r as u64;
        self.write_column(position_quotient, q);
        self.write_column(position_remainder, r);
        (q, r)
    }

    unsafe fn count_leading_zeros(
        &mut self,
        x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        let x: u32 = (*x).try_into().unwrap();
        let res = x.leading_zeros();
        let res = res as u64;
        self.write_column(position, res);
        res
    }

    unsafe fn count_leading_ones(
        &mut self,
        x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        let x: u32 = (*x).try_into().unwrap();
        let res = x.leading_ones();
        let res = res as u64;
        self.write_column(position, res);
        res
    }

    fn copy(&mut self, x: &Self::Variable, position: Self::Position) -> Self::Variable {
        self.write_column(position, *x);
        *x
    }

    fn set_halted(&mut self, flag: Self::Variable) {
        if flag == 0 {
            self.halt = false
        } else if flag == 1 {
            self.halt = true
        } else {
            panic!("Bad value for flag in set_halted: {}", flag);
        }
    }

    fn report_exit(&mut self, exit_code: &Self::Variable) {
        println!(
            "Exited with code {} at step {}",
            *exit_code,
            self.normalized_instruction_counter()
        );
    }

    fn reset(&mut self) {
        self.scratch_state_idx = 0;
        self.scratch_state = fresh_scratch_state();
        self.selector = INSTRUCTION_SET_SIZE;
    }
}

impl<Fp: Field> Env<Fp> {
    pub fn create(page_size: usize, state: State) -> Self {
        let initial_instruction_pointer = state.pc;
        let next_instruction_pointer = state.next_pc;

        let selector = INSTRUCTION_SET_SIZE;

        let mut initial_memory: Vec<(u32, Vec<u8>)> = state
            .memory
            .into_iter()
            // Check that the conversion from page data is correct
            .map(|page| (page.index, page.data))
            .collect();

        for (_address, initial_memory) in initial_memory.iter_mut() {
            initial_memory.extend((0..(page_size - initial_memory.len())).map(|_| 0u8));
            assert_eq!(initial_memory.len(), page_size);
        }

        let memory_offsets = initial_memory
            .iter()
            .map(|(offset, _)| *offset)
            .collect::<Vec<_>>();

        let initial_registers = {
            Registers {
                general_purpose: state.registers,
                current_instruction_pointer: initial_instruction_pointer,
                next_instruction_pointer,
                heap_pointer: state.heap,
            }
        };

        let mut registers = initial_registers.clone();
        registers[2] = 0x408004e0;
        // set the stack pointer to the top of the stack

        Env {
            instruction_counter: state.step,
            memory: initial_memory.clone(),
            last_memory_accesses: [0usize; 3],
            memory_write_index: memory_offsets
                .iter()
                .map(|offset| (*offset, vec![0u64; page_size]))
                .collect(),
            last_memory_write_index_accesses: [0usize; 3],
            registers: registers,
            registers_write_index: Registers::default(),
            scratch_state_idx: 0,
            scratch_state: fresh_scratch_state(),
            halt: state.exited,
            selector,
        }
    }

    pub fn next_instruction_counter(&self) -> u64 {
        (self.normalized_instruction_counter() + 1) * MAX_ACC
    }

    pub fn decode_instruction(&mut self) -> (Instruction, u32) {
        /* https://www.cs.cornell.edu/courses/cs3410/2024fa/assignments/cpusim/riscv-instructions.pdf */
        let instruction =
            ((self.get_memory_direct(self.registers.current_instruction_pointer) as u32) << 24)
                | ((self.get_memory_direct(self.registers.current_instruction_pointer + 1) as u32)
                    << 16)
                | ((self.get_memory_direct(self.registers.current_instruction_pointer + 2) as u32)
                    << 8)
                | (self.get_memory_direct(self.registers.current_instruction_pointer + 3) as u32);
        println!(
            "Decoding instruction at address {:b} with value {:b}, with opcode",
            self.registers.current_instruction_pointer, instruction
        );
        let instruction = instruction.to_be(); // convert to big endian for more straightforward decoding
        println!(
            "Decoding instruction at address {:b} with value {:b}, with opcode",
            self.registers.current_instruction_pointer, instruction
        );

        let opcode = {
            match instruction & 0b1111111 // bits 0-6
            {
                0b0110111 => Instruction::UType(UInstruction::LoadUpperImmediate),
                0b0010111 => Instruction::UType(UInstruction::AddUpperImmediate),
                0b1101111 => Instruction::UJType(UJInstruction::JumpAndLink),
                0b1100011 =>
                match (instruction >> 12) & 0x7 // bits 12-14 for func3
                {
                    0b000 => Instruction::SBType(SBInstruction::BranchEq),
                    0b001 => Instruction::SBType(SBInstruction::BranchNeq),
                    0b100 => Instruction::SBType(SBInstruction::BranchLessThan),
                    0b101 => Instruction::SBType(SBInstruction::BranchGreaterThanEqual),
                    0b110 => Instruction::SBType(SBInstruction::BranchLessThanUnsigned),
                    0b111 => Instruction::SBType(SBInstruction::BranchGreaterThanEqualUnsigned),
                    _ => panic!("Unknown SBType instruction with full inst {}", instruction),
                },
                0b1100111 => Instruction::IType(IInstruction::JumpAndLinkRegister),
                0b0000011 =>
                match (instruction >> 12) & 0x7 // bits 12-14 for func3
                {
                    0b000 => Instruction::IType(IInstruction::LoadByte),
                    0b001 => Instruction::IType(IInstruction::LoadHalf),
                    0b010 => Instruction::IType(IInstruction::LoadWord),
                    0b100 => Instruction::IType(IInstruction::LoadByteUnsigned),
                    0b101 => Instruction::IType(IInstruction::LoadHalfUnsigned),
                    _ => panic!("Unknown IType instruction with full inst {}", instruction),
                },
                0b0100011 =>
                match (instruction >> 12) & 0x7 // bits 12-14 for func3
                {
                    0b000 => Instruction::SType(SInstruction::StoreByte),
                    0b001 => Instruction::SType(SInstruction::StoreHalf),
                    0b010 => Instruction::SType(SInstruction::StoreWord),
                    _ => panic!("Unknown SType instruction with full inst {}", instruction),
                },
                0b0010011 =>
                match (instruction >> 12) & 0x7 // bits 12-14 for func3
                {
                    0b000 => Instruction::IType(IInstruction::AddImmediate),
                    0b010 => Instruction::IType(IInstruction::SetLessThanImmediate),
                    0b011 => Instruction::IType(IInstruction::SetLessThanImmediateUnsigned),
                    0b100 => Instruction::IType(IInstruction::XorImmediate),
                    0b110 => Instruction::IType(IInstruction::OrImmediate),
                    0b111 => Instruction::IType(IInstruction::AndImmediate),
                    0b001 => Instruction::IType(IInstruction::ShiftLeftLogicalImmediate),
                    0b101 =>
                    match (instruction >> 30) & 0x1 // bit 30 in simm component of IType
                    {
                    0b0 => Instruction::IType(IInstruction::ShiftRightLogicalImmediate),
                    0b1 => Instruction::IType(IInstruction::ShiftRightArithmeticImmediate),
                    _ => panic!("Unknown IType in shift right instructions with full inst {}", instruction),
                    },
                    _ => panic!("Unknown IType instruction with full inst {}", instruction),
                },
                0b0110011 =>
                match (instruction >> 12) & 0x7 // bits 12-14 for func3
                {
                    0b000 =>
                    match (instruction >> 30) & 0x1 // bit 30 of funct5 component in RType
                    {
                    0b0 => Instruction::RType(RInstruction::Add),
                    0b1 => Instruction::RType(RInstruction::Sub),
                     _ => panic!("Unknown RType in add/sub instructions with full inst {}", instruction),
                    },
                    0b001 => Instruction::RType(RInstruction::ShiftLeftLogical),
                    0b010 => Instruction::RType(RInstruction::SetLessThan),
                    0b011 => Instruction::RType(RInstruction::SetLessThanUnsigned),
                    0b100 => Instruction::RType(RInstruction::Xor),
                    0b101 =>
                    match (instruction >> 30) & 0x1 // bit 30 of funct5 component in RType
                    {
                        0b0 => Instruction::RType(RInstruction::ShiftRightLogical),
                        0b1 => Instruction::RType(RInstruction::ShiftRightArithmetic),
                        _ => panic!("Unknown RType in shift right instructions with full inst {}", instruction),
                    },
                    0b110 => Instruction::RType(RInstruction::Or),
                    0b111 => Instruction::RType(RInstruction::And),
                    _ => panic!("Unknown RType 0110011 instruction with full inst {}", instruction),
                },
                0b0001111 =>
                match (instruction >> 12) & 0x7 // bits 12-14 for func3
                {
                    0b000 => Instruction::RType(RInstruction::Fence),
                    0b001 => Instruction::RType(RInstruction::FenceI),
                    _ => panic!("Unknown RType 0001111 (Fence) instruction with full inst {}", instruction),
                },
                _ => panic!("Unknown instruction with full inst {:b}, and opcode {:b}", instruction, instruction & 0b1111111),
            }
        };
        // display the opcode
        println!(
            "Decoded instruction {:?} with opcode {:?}",
            instruction, opcode
        );
        (opcode, instruction)
    }

    /// Execute a single step in the RISCV32i program
    pub fn step(&mut self) -> Instruction {
        self.reset_scratch_state();
        println!("Before decode");
        let (opcode, _instruction) = self.decode_instruction();
        println!("After decode");

        interpreter::interpret_instruction(self, opcode);

        println!("Before ic set");
        self.instruction_counter = self.next_instruction_counter();
        println!("After ic set");

        // Integer division by MAX_ACC to obtain the actual instruction count
        if self.halt {
            println!(
                "Halted at step={} instruction={:?}",
                self.normalized_instruction_counter(),
                opcode
            );
        }
        opcode
    }

    pub fn reset_scratch_state(&mut self) {
        self.scratch_state_idx = 0;
        self.scratch_state = fresh_scratch_state();
        self.selector = INSTRUCTION_SET_SIZE;
    }

    pub fn write_column(&mut self, column: Column, value: u64) {
        self.write_field_column(column, value.into())
    }

    pub fn write_field_column(&mut self, column: Column, value: Fp) {
        match column {
            Column::ScratchState(idx) => self.scratch_state[idx] = value,
            Column::InstructionCounter => panic!("Cannot overwrite the column {:?}", column),
            Column::Error => {
                panic!("Overriding the error is not yet implemented, but it should be")
            }
            Column::Selector(s) => self.selector = s,
        }
    }

    pub fn update_last_memory_access(&mut self, i: usize) {
        let [i_0, i_1, _] = self.last_memory_accesses;
        self.last_memory_accesses = [i, i_0, i_1]
    }

    pub fn get_memory_page_index(&mut self, page: u32) -> usize {
        for &i in self.last_memory_accesses.iter() {
            if self.memory_write_index[i].0 == page {
                return i;
            }
        }
        for (i, (page_index, _memory)) in self.memory.iter_mut().enumerate() {
            if *page_index == page {
                self.update_last_memory_access(i);
                return i;
            }
        }

        // Memory not found; dynamically allocate
        let memory = vec![0u8; PAGE_SIZE as usize];
        self.memory.push((page, memory));
        let i = self.memory.len() - 1;
        self.update_last_memory_access(i);
        i
    }

    pub fn update_last_memory_write_index_access(&mut self, i: usize) {
        let [i_0, i_1, _] = self.last_memory_write_index_accesses;
        self.last_memory_write_index_accesses = [i, i_0, i_1]
    }

    pub fn get_memory_access_page_index(&mut self, page: u32) -> usize {
        for &i in self.last_memory_write_index_accesses.iter() {
            if self.memory_write_index[i].0 == page {
                return i;
            }
        }
        for (i, (page_index, _memory_write_index)) in self.memory_write_index.iter_mut().enumerate()
        {
            if *page_index == page {
                self.update_last_memory_write_index_access(i);
                return i;
            }
        }

        // Memory not found; dynamically allocate
        let memory_write_index = vec![0u64; PAGE_SIZE as usize];
        self.memory_write_index.push((page, memory_write_index));
        let i = self.memory_write_index.len() - 1;
        self.update_last_memory_write_index_access(i);
        i
    }

    pub fn get_memory_direct(&mut self, addr: u32) -> u8 {
        let page = addr >> PAGE_ADDRESS_SIZE;
        let page_address = (addr & PAGE_ADDRESS_MASK) as usize;
        let memory_idx = self.get_memory_page_index(page);
        self.memory[memory_idx].1[page_address]
    }

    /// The actual number of instructions executed results from dividing the
    /// instruction counter by MAX_ACC (floor).
    ///
    /// NOTE: actually, in practice it will be less than that, as there is no
    ///       single instruction that performs all of them.
    pub fn normalized_instruction_counter(&self) -> u64 {
        self.instruction_counter / MAX_ACC
    }
}
