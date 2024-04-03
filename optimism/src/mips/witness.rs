use crate::{
    cannon::{
        Hint, Meta, Page, Start, State, StepFrequency, VmConfiguration, PAGE_ADDRESS_MASK,
        PAGE_ADDRESS_SIZE, PAGE_SIZE,
    },
    keccak::environment::KeccakEnv,
    lookups::Lookup,
    mips::{
        column::{
            Column, MIPS_BYTES_READ_OFFSET, MIPS_CHUNK_BYTES_LENGTH, MIPS_HASH_COUNTER_OFFSET,
            MIPS_HAS_N_BYTES_OFFSET, MIPS_IS_SYSCALL_OFFSET, MIPS_PREIMAGE_BYTES_OFFSET,
            MIPS_PREIMAGE_LEFT_OFFSET, MIPS_READING_PREIMAGE_OFFSET,
        },
        interpreter::{
            self, ITypeInstruction, Instruction, InterpreterEnv, JTypeInstruction, RTypeInstruction,
        },
        registers::Registers,
    },
    preimage_oracle::PreImageOracle,
};
use ark_ff::{Field, One, Zero};
use core::panic;
use log::{debug, info};
use std::{
    array,
    fs::File,
    io::{BufWriter, Write},
};

pub const NUM_GLOBAL_LOOKUP_TERMS: usize = 1;
pub const NUM_DECODING_LOOKUP_TERMS: usize = 2;
pub const NUM_INSTRUCTION_LOOKUP_TERMS: usize = 5;
pub const NUM_LOOKUP_TERMS: usize =
    NUM_GLOBAL_LOOKUP_TERMS + NUM_DECODING_LOOKUP_TERMS + NUM_INSTRUCTION_LOOKUP_TERMS;
// TODO: Delete and use a vector instead
// TODO: Check if now that we have split the inverse columns, we can have fewer of these
pub const SCRATCH_SIZE: usize = 93; // MIPS + hash_counter + is_syscall + bytes_read + bytes_left + bytes + has_n_bytes + reading_preimage
/// Maximum number of register accesses that can happen per instruction.
pub const INVERSE_SIZE: usize = 9;

#[derive(Clone, Default)]
pub struct SyscallEnv {
    pub last_hint: Option<Vec<u8>>,
}

impl SyscallEnv {
    pub fn create(state: &State) -> Self {
        SyscallEnv {
            last_hint: state.last_hint.clone(),
        }
    }
}

/// This structure represents the environment the virtual machine state will use
/// to transition. This environment will be used by the interpreter.
/// The virtual machine has access to its internal state and some external memory.
/// In addition to that, it has access to the environment of the Keccak
/// interpreter that is used to verify the preimage requested during the
/// execution.
pub struct Env<Fp> {
    pub instruction_counter: u64,
    pub memory: Vec<(u32, Vec<u8>)>,
    pub last_memory_accesses: [usize; 3],
    pub memory_write_index: Vec<(u32, Vec<u64>)>,
    pub last_memory_write_index_accesses: [usize; 3],
    pub registers: Registers<u32>,
    pub registers_write_index: Registers<u64>,
    pub scratch_state_idx: usize,
    /// Index of the inverse columns in the current step
    pub inverse_state_idx: usize,
    pub scratch_state: [u64; SCRATCH_SIZE],
    pub inverse_state: [u64; INVERSE_SIZE],
    pub halt: bool,
    pub syscall_env: SyscallEnv,
    pub preimage_oracle: PreImageOracle,
    pub preimage: Option<Vec<u8>>,
    pub preimage_bytes_read: u64,
    pub preimage_key: Option<[u8; 32]>,
    pub keccak_env: Option<KeccakEnv<Fp>>,
    pub hash_counter: u64,
}

fn fresh_scratch_state<const N: usize>() -> [u64; N] {
    array::from_fn(|_| 0)
}

fn fresh_inverse_state<const N: usize>() -> [u64; N] {
    // So that we won't try to invert the zero value
    array::from_fn(|_| 1)
}

const KUNIT: usize = 1024; // a kunit of memory is 1024 things (bytes, kilobytes, ...)
const PREFIXES: &str = "KMGTPE"; // prefixes for memory quantities KiB, MiB, GiB, ...

// Create a human-readable string representation of the memory size
fn memory_size(total: usize) -> String {
    if total < KUNIT {
        format!("{total} B")
    } else {
        // Compute the index in the prefixes string above
        let mut idx = 0;
        let mut d = KUNIT;
        let mut n = total / KUNIT;

        while n >= KUNIT {
            d *= KUNIT;
            idx += 1;
            n /= KUNIT;
        }

        let value = total as f64 / d as f64;

        let prefix =
        ////////////////////////////////////////////////////////////////////////////
        // Famous last words: 1023 exabytes ought to be enough for anybody        //
        //                                                                        //
        // Corollary: unwrap() below shouldn't fail                               //
        //                                                                        //
        // The maximum representation for usize corresponds to 16 exabytes anyway //
        ////////////////////////////////////////////////////////////////////////////
            PREFIXES.chars().nth(idx).unwrap();

        format!("{:.1} {}iB", value, prefix)
    }
}

impl<Fp: Field> InterpreterEnv for Env<Fp> {
    type Position = Column;

    fn alloc_scratch(&mut self) -> Self::Position {
        let scratch_idx = self.scratch_state_idx;
        self.scratch_state_idx += 1;
        Column::ScratchState(scratch_idx)
    }

    fn alloc_inverse_or_scratch(&mut self, x: &Self::Variable) -> Self::Position {
        if *x == 0 {
            self.alloc_scratch()
        } else {
            let inverse_idx = self.inverse_state_idx;
            self.inverse_state_idx += 1;
            Column::InverseState(inverse_idx)
        }
    }

    type Variable = u64;

    fn add_constraint(&mut self, _assert_equals_zero: Self::Variable) {
        // No-op for witness
        // Do not assert that _assert_equals_zero is zero here! Some variables may have
        // placeholders that do not faithfully represent the underlying values.
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
    }

    fn instruction_counter(&self) -> Self::Variable {
        self.instruction_counter
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
            // TODO: batch inverse before folding
            // By default, we write the value to be inverted at the end
            self.write_column(position, *x);
            1 // Placeholder value
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
        let u64_res = x + y;
        let x: u32 = (*x).try_into().unwrap();
        let y: u32 = (*y).try_into().unwrap();
        let u32_res = x + y;
        let u32_res = u32_res as u64;
        let overflows = if u32_res == u64_res { 0u64 } else { 1u64 };
        self.write_column(out_position, u32_res);
        self.write_column(overflow_position, overflows);
        (u32_res, overflows)
    }

    unsafe fn sub_witness(
        &mut self,
        x: &Self::Variable,
        y: &Self::Variable,
        out_position: Self::Position,
        underflow_position: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        let u64_res = x - y;
        let x: u32 = (*x).try_into().unwrap();
        let y: u32 = (*y).try_into().unwrap();
        let u32_res = x - y;
        let u32_res = u32_res as u64;
        let underflows = if u32_res == u64_res { 0u64 } else { 1u64 };
        self.write_column(out_position, u32_res);
        self.write_column(underflow_position, underflows);
        (u32_res, underflows)
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
            *exit_code, self.instruction_counter
        );
    }

    fn request_preimage_write(
        &mut self,
        addr: &Self::Variable,
        len: &Self::Variable,
        pos: Self::Position,
    ) -> Self::Variable {
        // This is a syscall row, otherwise is zero
        self.write_column(Column::ScratchState(MIPS_IS_SYSCALL_OFFSET), 1);

        if self.registers.preimage_offset == 0 {
            let mut preimage_key = [0u8; 32];
            for i in 0..8 {
                let bytes = u32::to_be_bytes(self.registers.preimage_key[i]);
                for j in 0..4 {
                    preimage_key[4 * i + j] = bytes[j]
                }
            }
            let preimage = self.preimage_oracle.get_preimage(preimage_key).get();
            self.preimage = Some(preimage.clone());
            self.preimage_key = Some(preimage_key);

            // Initialize bytes left to read from preimage length
            self.write_column(
                Column::ScratchState(MIPS_PREIMAGE_LEFT_OFFSET),
                preimage.len() as u64,
            );
        }

        const LENGTH_SIZE: usize = 8;

        let preimage = self
            .preimage
            .as_ref()
            .expect("to have a preimage if we're requesting it at a non-zero offset");
        let preimage_len = preimage.len();
        let preimage_offset = self.registers.preimage_offset as u64;

        let max_read_len =
            std::cmp::min(preimage_offset + len, (preimage_len + LENGTH_SIZE) as u64)
                - preimage_offset;
        // We read at most 4 bytes, ensuring that we respect word alignment.
        let actual_read_len = std::cmp::min(max_read_len, 4 - (addr & 3));
        // This variable will contain the amount of bytes read which belong to the actual preimage
        let mut preimage_read_len = 0;
        for i in 0..actual_read_len {
            let idx = (preimage_offset + i) as usize;
            // The first 8 bytes of the read preimage are the preimage length, followed by the body
            // of the preimage
            if idx < LENGTH_SIZE {
                self.write_column(Column::ScratchState(MIPS_READING_PREIMAGE_OFFSET), 0);
                let length_byte = u64::to_be_bytes(preimage_len as u64)[idx];
                unsafe {
                    self.push_memory(&(*addr + i), length_byte as u64);
                    self.push_memory_access(&(*addr + i), self.instruction_counter + 1);
                }
            } else {
                preimage_read_len += 1; // At most, it will be actual_read_len
                self.write_column(Column::ScratchState(MIPS_READING_PREIMAGE_OFFSET), 1);
                // This should really be handled by the keccak oracle.
                let preimage_byte = self.preimage.as_ref().unwrap()[idx - LENGTH_SIZE];
                // Write the individual byte to the witness
                self.write_column(
                    Column::ScratchState(MIPS_PREIMAGE_BYTES_OFFSET + i as usize),
                    preimage_byte as u64,
                );
                unsafe {
                    self.push_memory(&(*addr + i), preimage_byte as u64);
                    self.push_memory_access(&(*addr + i), self.instruction_counter + 1);
                }
            }
        }
        self.write_column(pos, actual_read_len);

        // Update the flags to count how many bytes are contained at least
        for i in 0..MIPS_CHUNK_BYTES_LENGTH {
            if preimage_read_len > i as u64 {
                self.write_column(Column::ScratchState(MIPS_HAS_N_BYTES_OFFSET + i), 1);
            }
        }

        // Update the total number of preimage bytes read so far
        self.preimage_bytes_read += preimage_read_len;
        self.write_column(
            Column::ScratchState(MIPS_BYTES_READ_OFFSET),
            self.preimage_bytes_read,
        );

        // Update how many bytes are left to be read
        self.write_column(
            Column::ScratchState(MIPS_PREIMAGE_LEFT_OFFSET),
            (preimage_len as u64) - self.preimage_bytes_read,
        );

        // If we've read the entire preimage, trigger Keccak workflow
        if self.preimage_bytes_read == preimage_len as u64 {
            debug!("Preimage has been read entirely, triggering Keccak process");
            self.keccak_env = Some(KeccakEnv::<Fp>::new(
                self.hash_counter,
                self.preimage.as_ref().unwrap(),
            ));

            // COMMUNICATION CHANNEL: only on constraint side

            // Update hash counter column
            self.write_column(
                Column::ScratchState(MIPS_HASH_COUNTER_OFFSET),
                self.hash_counter,
            );
            // Number of preimage bytes left to be read should be zero at this point

            // Reset environment
            self.preimage_bytes_read = 0;
            self.preimage_key = None;
            self.hash_counter += 1;

            // Reset PreimageCounter column will be done in the next call
        }
        actual_read_len
    }

    fn request_hint_write(&mut self, addr: &Self::Variable, len: &Self::Variable) {
        let mut last_hint = match std::mem::take(&mut self.syscall_env.last_hint) {
            Some(mut last_hint) => {
                last_hint.reserve(*len as usize);
                last_hint
            }
            None => Vec::with_capacity(*len as usize),
        };

        // This should really be handled by the keccak oracle.
        for i in 0..*len {
            // Push memory access
            unsafe { self.push_memory_access(&(*addr + i), self.instruction_counter + 1) };
            // Fetch the value without allocating witness columns
            let value = {
                let addr: u32 = (*addr).try_into().unwrap();
                let page = addr >> PAGE_ADDRESS_SIZE;
                let page_address = (addr & PAGE_ADDRESS_MASK) as usize;
                let memory_page_idx = self.get_memory_page_index(page);
                self.memory[memory_page_idx].1[page_address]
            };
            last_hint.push(value);
        }

        let len = last_hint.len();
        let mut idx = 0;

        while idx + 4 <= len {
            let hint_len = u32::from_be_bytes(last_hint[idx..idx + 4].try_into().unwrap()) as usize;
            idx += 4;
            if idx + hint_len <= len {
                let hint = last_hint[idx..idx + hint_len].to_vec();
                idx += hint_len;
                self.preimage_oracle.hint(Hint::create(hint));
            }
        }

        let remaining = last_hint[idx..len].to_vec();

        self.syscall_env.last_hint = Some(remaining);
    }
}

impl<Fp: Field> Env<Fp> {
    pub fn create(page_size: usize, state: State, preimage_oracle: PreImageOracle) -> Self {
        let initial_instruction_pointer = state.pc;
        let next_instruction_pointer = state.next_pc;

        let syscall_env = SyscallEnv::create(&state);

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
            let preimage_key = {
                let mut preimage_key = [0u32; 8];
                for (i, preimage_key_word) in preimage_key.iter_mut().enumerate() {
                    *preimage_key_word = u32::from_be_bytes(
                        state.preimage_key[i * 4..(i + 1) * 4].try_into().unwrap(),
                    )
                }
                preimage_key
            };
            Registers {
                lo: state.lo,
                hi: state.hi,
                general_purpose: state.registers,
                current_instruction_pointer: initial_instruction_pointer,
                next_instruction_pointer,
                heap_pointer: state.heap,
                preimage_key,
                preimage_offset: state.preimage_offset,
            }
        };

        Env {
            instruction_counter: state.step,
            memory: initial_memory.clone(),
            last_memory_accesses: [0usize; 3],
            memory_write_index: memory_offsets
                .iter()
                .map(|offset| (*offset, vec![0u64; page_size]))
                .collect(),
            last_memory_write_index_accesses: [0usize; 3],
            registers: initial_registers.clone(),
            registers_write_index: Registers::default(),
            scratch_state_idx: 0,
            inverse_state_idx: 0,
            scratch_state: fresh_scratch_state(),
            inverse_state: fresh_inverse_state(),
            halt: state.exited,
            syscall_env,
            preimage_oracle,
            preimage: state.preimage,
            preimage_bytes_read: 0,
            preimage_key: None,
            keccak_env: None,
            hash_counter: 0,
        }
    }

    pub fn reset_scratch_state(&mut self) {
        self.scratch_state_idx = 0;
        self.scratch_state = fresh_scratch_state();
    }

    pub fn reset_inverse_state(&mut self) {
        self.inverse_state_idx = 0;
        self.inverse_state = fresh_inverse_state();
    }

    pub fn write_column(&mut self, column: Column, value: u64) {
        match column {
            Column::ScratchState(idx) => self.scratch_state[idx] = value,
            Column::InverseState(idx) => {
                // So that we won't try to invert the zero value
                assert_ne!(value, 0);
                self.inverse_state[idx] = value
            }
            Column::InstructionCounter => panic!("Cannot overwrite the column {:?}", column),
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

    pub fn decode_instruction(&mut self) -> (Instruction, u32) {
        let instruction =
            ((self.get_memory_direct(self.registers.current_instruction_pointer) as u32) << 24)
                | ((self.get_memory_direct(self.registers.current_instruction_pointer + 1) as u32)
                    << 16)
                | ((self.get_memory_direct(self.registers.current_instruction_pointer + 2) as u32)
                    << 8)
                | (self.get_memory_direct(self.registers.current_instruction_pointer + 3) as u32);
        let opcode = {
            match instruction >> 26 {
                0x00 => match instruction & 0x3F {
                    0x00 => Instruction::RType(RTypeInstruction::ShiftLeftLogical),
                    0x02 => Instruction::RType(RTypeInstruction::ShiftRightLogical),
                    0x03 => Instruction::RType(RTypeInstruction::ShiftRightArithmetic),
                    0x04 => Instruction::RType(RTypeInstruction::ShiftLeftLogicalVariable),
                    0x06 => Instruction::RType(RTypeInstruction::ShiftRightLogicalVariable),
                    0x07 => Instruction::RType(RTypeInstruction::ShiftRightArithmeticVariable),
                    0x08 => Instruction::RType(RTypeInstruction::JumpRegister),
                    0x09 => Instruction::RType(RTypeInstruction::JumpAndLinkRegister),
                    0x0a => Instruction::RType(RTypeInstruction::MoveZero),
                    0x0b => Instruction::RType(RTypeInstruction::MoveNonZero),
                    0x0c => match self.registers.general_purpose[2] {
                        4090 => Instruction::RType(RTypeInstruction::SyscallMmap),
                        4045 => {
                            // sysBrk
                            Instruction::RType(RTypeInstruction::SyscallOther)
                        }
                        4120 => {
                            // sysClone
                            Instruction::RType(RTypeInstruction::SyscallOther)
                        }
                        4246 => Instruction::RType(RTypeInstruction::SyscallExitGroup),
                        4003 => match self.registers.general_purpose[4] {
                            interpreter::FD_HINT_READ => {
                                Instruction::RType(RTypeInstruction::SyscallReadHint)
                            }
                            interpreter::FD_PREIMAGE_READ => {
                                Instruction::RType(RTypeInstruction::SyscallReadPreimage)
                            }
                            _ => Instruction::RType(RTypeInstruction::SyscallReadOther),
                        },
                        4004 => match self.registers.general_purpose[4] {
                            interpreter::FD_PREIMAGE_WRITE => {
                                Instruction::RType(RTypeInstruction::SyscallWritePreimage)
                            }
                            interpreter::FD_HINT_WRITE => {
                                Instruction::RType(RTypeInstruction::SyscallWriteHint)
                            }
                            _ => Instruction::RType(RTypeInstruction::SyscallWriteOther),
                        },
                        4055 => Instruction::RType(RTypeInstruction::SyscallFcntl),
                        _ => {
                            // NB: This has well-defined behavior. Don't panic!
                            Instruction::RType(RTypeInstruction::SyscallOther)
                        }
                    },
                    0x0f => Instruction::RType(RTypeInstruction::Sync),
                    0x10 => Instruction::RType(RTypeInstruction::MoveFromHi),
                    0x11 => Instruction::RType(RTypeInstruction::MoveToHi),
                    0x12 => Instruction::RType(RTypeInstruction::MoveFromLo),
                    0x13 => Instruction::RType(RTypeInstruction::MoveToLo),
                    0x18 => Instruction::RType(RTypeInstruction::Multiply),
                    0x19 => Instruction::RType(RTypeInstruction::MultiplyUnsigned),
                    0x1a => Instruction::RType(RTypeInstruction::Div),
                    0x1b => Instruction::RType(RTypeInstruction::DivUnsigned),
                    0x20 => Instruction::RType(RTypeInstruction::Add),
                    0x21 => Instruction::RType(RTypeInstruction::AddUnsigned),
                    0x22 => Instruction::RType(RTypeInstruction::Sub),
                    0x23 => Instruction::RType(RTypeInstruction::SubUnsigned),
                    0x24 => Instruction::RType(RTypeInstruction::And),
                    0x25 => Instruction::RType(RTypeInstruction::Or),
                    0x26 => Instruction::RType(RTypeInstruction::Xor),
                    0x27 => Instruction::RType(RTypeInstruction::Nor),
                    0x2a => Instruction::RType(RTypeInstruction::SetLessThan),
                    0x2b => Instruction::RType(RTypeInstruction::SetLessThanUnsigned),
                    _ => {
                        panic!("Unhandled instruction {:#X}", instruction)
                    }
                },
                0x01 => {
                    // RegImm instructions
                    match (instruction >> 16) & 0x1F {
                        0x0 => Instruction::IType(ITypeInstruction::BranchLtZero),
                        0x1 => Instruction::IType(ITypeInstruction::BranchGeqZero),
                        _ => panic!("Unhandled instruction {:#X}", instruction),
                    }
                }
                0x02 => Instruction::JType(JTypeInstruction::Jump),
                0x03 => Instruction::JType(JTypeInstruction::JumpAndLink),
                0x04 => Instruction::IType(ITypeInstruction::BranchEq),
                0x05 => Instruction::IType(ITypeInstruction::BranchNeq),
                0x06 => Instruction::IType(ITypeInstruction::BranchLeqZero),
                0x07 => Instruction::IType(ITypeInstruction::BranchGtZero),
                0x08 => Instruction::IType(ITypeInstruction::AddImmediate),
                0x09 => Instruction::IType(ITypeInstruction::AddImmediateUnsigned),
                0x0A => Instruction::IType(ITypeInstruction::SetLessThanImmediate),
                0x0B => Instruction::IType(ITypeInstruction::SetLessThanImmediateUnsigned),
                0x0C => Instruction::IType(ITypeInstruction::AndImmediate),
                0x0D => Instruction::IType(ITypeInstruction::OrImmediate),
                0x0E => Instruction::IType(ITypeInstruction::XorImmediate),
                0x0F => Instruction::IType(ITypeInstruction::LoadUpperImmediate),
                0x1C => match instruction & 0x3F {
                    0x02 => Instruction::RType(RTypeInstruction::MultiplyToRegister),
                    0x20 => Instruction::RType(RTypeInstruction::CountLeadingZeros),
                    0x21 => Instruction::RType(RTypeInstruction::CountLeadingOnes),
                    _ => panic!("Unhandled instruction {:#X}", instruction),
                },
                0x20 => Instruction::IType(ITypeInstruction::Load8),
                0x21 => Instruction::IType(ITypeInstruction::Load16),
                0x22 => Instruction::IType(ITypeInstruction::LoadWordLeft),
                0x23 => Instruction::IType(ITypeInstruction::Load32),
                0x24 => Instruction::IType(ITypeInstruction::Load8Unsigned),
                0x25 => Instruction::IType(ITypeInstruction::Load16Unsigned),
                0x26 => Instruction::IType(ITypeInstruction::LoadWordRight),
                0x28 => Instruction::IType(ITypeInstruction::Store8),
                0x29 => Instruction::IType(ITypeInstruction::Store16),
                0x2a => Instruction::IType(ITypeInstruction::StoreWordLeft),
                0x2b => Instruction::IType(ITypeInstruction::Store32),
                0x2e => Instruction::IType(ITypeInstruction::StoreWordRight),
                0x30 => {
                    // Note: This is ll (LoadLinked), but we're only simulating a single processor.
                    Instruction::IType(ITypeInstruction::Load32)
                }
                0x38 => {
                    // Note: This is sc (StoreConditional), but we're only simulating a single processor.
                    Instruction::IType(ITypeInstruction::Store32Conditional)
                }
                _ => {
                    panic!("Unhandled instruction {:#X}", instruction)
                }
            }
        };
        (opcode, instruction)
    }

    pub fn step(&mut self, config: &VmConfiguration, metadata: &Meta, start: &Start) {
        self.reset_scratch_state();
        self.reset_inverse_state();
        let (opcode, _instruction) = self.decode_instruction();

        self.pp_info(&config.info_at, metadata, start);
        self.snapshot_state_at(&config.snapshot_state_at);

        // Force stops at given iteration
        if self.should_trigger_at(&config.stop_at) {
            self.halt = true;
            println!(
                "Halted as requested at step={} instruction={:?}",
                self.instruction_counter, opcode
            );
            return;
        }

        interpreter::interpret_instruction(self, opcode);

        self.instruction_counter += 1;

        if self.halt {
            println!(
                "Halted at step={} instruction={:?}",
                self.instruction_counter, opcode
            );
        }
    }

    fn should_trigger_at(&self, at: &StepFrequency) -> bool {
        let m: u64 = self.instruction_counter;
        match at {
            StepFrequency::Never => false,
            StepFrequency::Always => true,
            StepFrequency::Exactly(n) => *n == m,
            StepFrequency::Every(n) => m % *n == 0,
            StepFrequency::Range(lo, hi_opt) => {
                m >= *lo && (hi_opt.is_none() || m < hi_opt.unwrap())
            }
        }
    }

    // Compute memory usage
    fn memory_usage(&self) -> String {
        let total = self.memory.len() * PAGE_SIZE as usize;
        memory_size(total)
    }

    fn page_address(&self) -> (u32, usize) {
        let address = self.registers.current_instruction_pointer;
        let page = address >> PAGE_ADDRESS_SIZE;
        let page_address = (address & PAGE_ADDRESS_MASK) as usize;
        (page, page_address)
    }

    fn get_opcode(&mut self) -> Option<u32> {
        let (page_id, page_address) = self.page_address();
        for (page_index, memory) in self.memory.iter() {
            if page_id == *page_index {
                let memory_slice: [u8; 4] = memory[page_address..page_address + 4]
                    .try_into()
                    .expect("Couldn't read 4 bytes at given address");
                return Some(u32::from_be_bytes(memory_slice));
            }
        }
        None
    }

    fn snapshot_state_at(&mut self, at: &StepFrequency) {
        if self.should_trigger_at(at) {
            let filename = format!("snapshot-state-{}.json", self.instruction_counter);
            let file = File::create(filename.clone()).expect("Impossible to open file");
            let mut writer = BufWriter::new(file);
            let mut preimage_key = [0u8; 32];
            for i in 0..8 {
                let bytes = u32::to_be_bytes(self.registers.preimage_key[i]);
                for j in 0..4 {
                    preimage_key[4 * i + j] = bytes[j]
                }
            }
            let memory = self
                .memory
                .clone()
                .into_iter()
                .map(|(idx, data)| Page { index: idx, data })
                .collect();
            let s: State = State {
                pc: self.registers.current_instruction_pointer,
                next_pc: self.registers.next_instruction_pointer,
                step: self.instruction_counter,
                registers: self.registers.general_purpose,
                lo: self.registers.lo,
                hi: self.registers.hi,
                heap: self.registers.heap_pointer,
                // FIXME: it should be the exit code. We do not keep it in the witness atm
                exit: if self.halt { 1 } else { 0 },
                last_hint: self.syscall_env.last_hint.clone(),
                exited: self.halt,
                preimage_offset: self.registers.preimage_offset,
                preimage_key,
                memory,
                preimage: self.preimage.clone(),
            };
            let _ = serde_json::to_writer(&mut writer, &s);
            info!(
                "Snapshot state in {}, step {}",
                filename, self.instruction_counter
            );
            writer.flush().expect("Flush writer failing")
        }
    }

    fn pp_info(&mut self, at: &StepFrequency, meta: &Meta, start: &Start) {
        if self.should_trigger_at(at) {
            let elapsed = start.time.elapsed();
            let step = self.instruction_counter;
            let pc = self.registers.current_instruction_pointer;

            // Get the 32-bits opcode
            let insn = self.get_opcode().unwrap();

            // Approximate instruction per seconds
            let how_many_steps = step as usize - start.step;
            let ips = how_many_steps as f64 / elapsed.as_secs() as f64;

            let pages = self.memory.len();

            let mem = self.memory_usage();
            let name = meta
                .find_address_symbol(pc)
                .unwrap_or_else(|| "n/a".to_string());

            info!(
                "processing step={} pc={:010x} insn={:010x} ips={:.2} pages={} mem={} name={}",
                step, pc, insn, ips, pages, mem, name
            );
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_memory_size() {
        assert_eq!(memory_size(1023_usize), "1023 B");
        assert_eq!(memory_size(1024_usize), "1.0 KiB");
        assert_eq!(memory_size(1024 * 1024_usize), "1.0 MiB");
        assert_eq!(memory_size(2100 * 1024 * 1024_usize), "2.1 GiB");
        assert_eq!(memory_size(std::usize::MAX), "16.0 EiB");
    }
}
