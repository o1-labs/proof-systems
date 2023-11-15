use crate::mips::{
    cannon::State,
    columns::{
        Column, InstructionPart, InstructionParts, InstructionSelector, InstructionSelectors,
        LookupCounter, LookupCounters, NUM_DECODING_LOOKUP_TERMS, NUM_GLOBAL_LOOKUP_TERMS,
        NUM_INSTRUCTION_LOOKUP_TERMS, NUM_LOOKUP_TERMS, SCRATCH_SIZE,
    },
    instructions::{self, decoding::decode, InstructionEnvironment},
    registers::{Registers, NUM_REGISTERS},
};
use ark_ff::Field;
use rand::{rngs::StdRng, SeedableRng};
use std::array;
use strum::IntoEnumIterator;

pub const CODE_PAGE: u32 = 0x400000;
pub const DATA_PAGE: u32 = 0x410000;

#[derive(Clone, Debug)]
pub struct Lookup<Fp> {
    pub numerator: Fp,
    pub table_id: Fp,
    pub value: Vec<Fp>,
}

impl<Fp: std::fmt::Display> std::fmt::Display for Lookup<Fp> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "numerator: {}\ntable_id: {}\nvalue:\n[\n",
            self.numerator, self.table_id
        )?;
        for value in self.value.iter() {
            write!(formatter, "\t{}\n", value)?;
        }
        write!(formatter, "]")?;
        Ok(())
    }
}

pub enum TableID {
    Registers,
    Memory,
    RangeCheck16,
    Sparse,
}

pub trait GlobalLookupEnvironment {
    type Fp: From<u64>
        + std::ops::Neg<Output = Self::Fp>
        + std::ops::Add<Self::Fp, Output = Self::Fp>;

    fn initial_memory(&self, idx: usize) -> Self::Fp;
    fn final_memory(&self, idx: usize) -> Self::Fp;
    fn final_memory_write_index(&self, idx: usize) -> Self::Fp;
    fn memory_offset(&self, idx: usize) -> Self::Fp;

    fn initial_registers(&self) -> Self::Fp;
    fn final_registers(&self) -> Self::Fp;
    fn final_registers_write_index(&self) -> Self::Fp;

    fn lookup_counters(&self, col: LookupCounter) -> Self::Fp;

    fn row_number(&self) -> Self::Fp;

    fn add_lookup(&mut self, lookup: Lookup<Self::Fp>);
}

struct GlobalLookupEnv<Fp> {
    // Memory
    initial_memory: Vec<u8>,
    final_memory: Vec<u8>,
    final_memory_write_index: Vec<usize>,
    memory_offset: Vec<u32>,
    // Registers
    initial_registers: u32,
    final_registers: u32,
    final_registers_write_index: usize,
    // Current row
    row_number: usize,
    lookups: Vec<Lookup<Fp>>,
    lookup_counters: LookupCounters<usize>,
}

impl<Fp: From<u64> + std::ops::Neg<Output = Fp> + std::ops::Add<Fp, Output = Fp>>
    GlobalLookupEnvironment for GlobalLookupEnv<Fp>
{
    type Fp = Fp;

    fn initial_memory(&self, idx: usize) -> Self::Fp {
        Fp::from(self.initial_memory[idx] as u64)
    }
    fn final_memory(&self, idx: usize) -> Self::Fp {
        Fp::from(self.final_memory[idx] as u64)
    }
    fn final_memory_write_index(&self, idx: usize) -> Self::Fp {
        Fp::from(self.final_memory_write_index[idx] as u64)
    }
    fn memory_offset(&self, idx: usize) -> Self::Fp {
        Fp::from(self.memory_offset[idx] as u64)
    }

    fn initial_registers(&self) -> Self::Fp {
        Fp::from(self.initial_registers as u64)
    }
    fn final_registers(&self) -> Self::Fp {
        Fp::from(self.final_registers as u64)
    }
    fn final_registers_write_index(&self) -> Self::Fp {
        Fp::from(self.final_registers_write_index as u64)
    }

    fn lookup_counters(&self, col: LookupCounter) -> Self::Fp {
        Fp::from(self.lookup_counters[col] as u64)
    }

    fn row_number(&self) -> Self::Fp {
        Fp::from(self.row_number as u64)
    }

    fn add_lookup(&mut self, lookup: Lookup<Self::Fp>) {
        self.lookups.push(lookup)
    }
}

pub fn memory_lookups<Env: GlobalLookupEnvironment>(env: &mut Env, memory_idx: usize) {
    env.add_lookup(Lookup {
        numerator: Env::Fp::from(1u64),
        table_id: Env::Fp::from(TableID::Memory as u64),
        value: vec![
            env.initial_memory(memory_idx),
            env.row_number() + env.memory_offset(memory_idx),
        ],
    });
    env.add_lookup(Lookup {
        numerator: -Env::Fp::from(1u64),
        table_id: Env::Fp::from(TableID::Memory as u64),
        value: vec![
            env.final_memory(memory_idx),
            env.row_number() + env.memory_offset(memory_idx),
            env.final_memory_write_index(memory_idx),
        ],
    });
}

pub fn registers_lookups<Env: GlobalLookupEnvironment>(env: &mut Env) {
    env.add_lookup(Lookup {
        numerator: Env::Fp::from(1u64),
        table_id: Env::Fp::from(TableID::Registers as u64),
        value: vec![env.initial_registers(), env.row_number()],
    });
    env.add_lookup(Lookup {
        numerator: -Env::Fp::from(1u64),
        table_id: Env::Fp::from(TableID::Registers as u64),
        value: vec![
            env.final_registers(),
            env.row_number(),
            env.final_registers_write_index(),
        ],
    });
}

pub fn range_check_16_lookups<Env: GlobalLookupEnvironment>(env: &mut Env) {
    env.add_lookup(Lookup {
        numerator: env.lookup_counters(LookupCounter::Counter),
        table_id: Env::Fp::from(TableID::RangeCheck16 as u64),
        value: vec![env.row_number()],
    });
}

#[derive(Clone)]
struct SyscallEnv {
    heap: u32, // Heap pointer (actually unused in Cannon as of [2023-10-18])
    preimage_offset: u32,
    preimage_key: Vec<u8>,
    last_hint: Option<Vec<u8>>,
}

fn syscall_env_of_state(state: State) -> SyscallEnv {
    SyscallEnv {
        heap: state.heap,
        preimage_key: state.preimage_key.as_bytes().to_vec(), // Might not be correct
        preimage_offset: state.preimage_offset,
        last_hint: state.last_hint,
    }
}

#[derive(Clone)]
struct Env<Fp> {
    instruction_counter: usize,
    memory: Vec<(u32, Vec<u8>)>,
    memory_write_index: Vec<(u32, Vec<usize>)>,
    registers: Registers<u32>,
    registers_write_index: Registers<usize>,
    instruction_parts: InstructionParts<u32>,
    lookup_terms: [Vec<Lookup<Fp>>; NUM_DECODING_LOOKUP_TERMS + NUM_INSTRUCTION_LOOKUP_TERMS],
    lookup_terms_idx: usize,
    instruction_pointer: u32,
    scratch_state_idx: usize,
    scratch_state: [Fp; SCRATCH_SIZE],
    lookup_counters: LookupCounters<Vec<usize>>,
    halt: bool,
    syscall_env: SyscallEnv,
}

impl<Fp: Field> Env<Fp> {
    fn write_column(&mut self, column: Column, value: u64) {
        match column {
            Column::ScratchState(idx) => self.scratch_state[idx] = Fp::from(value as u64),
            _ => panic!("Unexpected column"),
        }
    }

    fn write_column_field(&mut self, column: Column, value: Fp) {
        match column {
            Column::ScratchState(idx) => self.scratch_state[idx] = value,
            _ => panic!("Unexpected column"),
        }
    }
}

impl<Fp: Field> InstructionEnvironment for Env<Fp> {
    type Column = Column;
    type Variable = u64;
    type Fp = Fp;

    fn current_row(&self) -> Self::Variable {
        self.instruction_counter as u64
    }

    fn constant(x: u32) -> Self::Variable {
        x as u64
    }

    fn to_fp(x: Self::Variable) -> Self::Fp {
        Fp::from(x as u64)
    }

    fn instruction_pointer(&self) -> Self::Variable {
        self.instruction_pointer as u64
    }

    fn set_instruction_pointer(&mut self, ip: &Self::Variable) {
        self.instruction_pointer = *ip as u32
    }

    fn halted(&self) -> Self::Variable {
        if self.halt {
            1u64
        } else {
            0u64
        }
    }

    fn set_halted(&mut self, value: &Self::Variable) {
        let old = self.halt;
        self.halt = {
            if *value == 0 {
                assert_eq!(old, false);
                false
            } else if *value == 1 {
                true
            } else {
                panic!("Invalid halt flag")
            }
        }
    }

    fn memory_accessible(
        &mut self,
        is_enabled: &Self::Variable,
        column: Self::Column,
        addresses: Vec<&Self::Variable>,
    ) -> Self::Variable {
        let value = (|| {
            if *is_enabled == 0 {
                return 0;
            }
            for address in addresses.into_iter() {
                let res = (|| {
                    for (offset, memory) in self.memory.iter_mut() {
                        let offset = *offset as u64;
                        if offset <= *address && *address < offset + (memory.len() as u64) {
                            return 1 as u64;
                        }
                    }
                    0
                })();
                if res == 0 {
                    return 0;
                }
            }
            1
        })();
        self.write_column(column, value);
        value
    }

    fn read_memory(
        &mut self,
        output: Self::Column,
        address: &Self::Variable,
        accessible: &Self::Variable,
    ) -> Self::Variable {
        let res = if *accessible != 0u64 {
            for (offset, memory) in self.memory.iter_mut() {
                let offset = *offset as u64;
                if offset <= *address && *address < offset + (memory.len() as u64) {
                    return memory[(*address - offset) as usize] as u64;
                }
            }
            panic!("Could not access address")
        } else {
            0u64
        };
        self.write_column(output, res);
        res
    }

    fn increment_range_check_counter(&mut self, value: &Self::Variable) {
        self.lookup_counters.counter[*value as usize] += 1;
    }

    fn range_check_1(&mut self, value: &Self::Variable) {
        // For debugging, delete
        if *value != 0 && *value != 1 {
            panic!("range_check_1 failed: {}", value)
        }
    }

    fn range_check_2(&mut self, value: &Self::Variable) {
        // For debugging, delete
        if *value != 0 && *value != 1 && *value != 2 && *value != 3 {
            panic!("range_check_1 failed: {}", value)
        }
    }

    fn add_lookup(&mut self, lookup: Lookup<Self::Fp>) {
        let curr_count = self.lookup_terms[self.lookup_terms_idx].len();
        if self.lookup_terms_idx < NUM_DECODING_LOOKUP_TERMS {
            if curr_count >= 7 {
                self.lookup_terms_idx += 1
            }
        } else {
            if curr_count >= 6 {
                self.lookup_terms_idx += 1
            }
        }
        self.lookup_terms[self.lookup_terms_idx].push(lookup)
    }

    fn get_register_value(
        &mut self,
        register_idx: &Self::Variable,
        output_value: Self::Column,
    ) -> Self::Variable {
        let value = self.registers[*register_idx as usize] as u64;

        self.write_column(output_value, value);

        value
    }

    fn set_register_value(&mut self, register_idx: &Self::Variable, value: &Self::Variable) {
        self.registers[*register_idx as usize] = *value as u32;
    }

    fn last_register_write(
        &mut self,
        register_idx: &Self::Variable,
        output_last_write: Self::Column,
    ) -> Self::Variable {
        let last_write = self.registers_write_index[*register_idx as usize] as u64;
        self.write_column(output_last_write, last_write);
        last_write
    }

    fn set_last_register_write(
        &mut self,
        register_idx: &Self::Variable,
        last_write: &Self::Variable,
    ) {
        self.registers_write_index[*register_idx as usize] = *last_write as usize;
    }

    fn get_memory_value(
        &mut self,
        address: &Self::Variable,
        enabled_if: &Self::Variable,
        output_value: Self::Column,
    ) -> Self::Variable {
        if *enabled_if == 1 {
            let value = (|| {
                for (offset, memory) in self.memory.iter_mut() {
                    let offset = *offset as u64;
                    if offset <= *address && *address < offset + (memory.len() as u64) {
                        return memory[(*address - offset) as usize] as u64;
                    }
                }
                panic!("Could not access address")
            })();

            self.write_column(output_value, value);

            value
        } else if *enabled_if == 0 {
            0
        } else {
            panic!("Unexpected enabled_if: {}", enabled_if)
        }
    }

    fn set_memory_value(
        &mut self,
        address: &Self::Variable,
        enabled_if: &Self::Variable,
        value: &Self::Variable,
    ) {
        if *enabled_if == 1 {
            for (offset, memory) in self.memory.iter_mut() {
                let offset = *offset as u64;
                if offset <= *address && *address < offset + (memory.len() as u64) {
                    memory[(*address - offset) as usize] = *value as u8;
                }
            }
        } else if *enabled_if != 0 {
            panic!("Unexpected enabled_if: {}", enabled_if)
        }
    }

    fn last_memory_write(
        &mut self,
        address: &Self::Variable,
        enabled_if: &Self::Variable,
        output_last_write: Self::Column,
    ) -> Self::Variable {
        if *enabled_if == 1 {
            let last_write = (|| {
                for (offset, memory_write_index) in self.memory_write_index.iter_mut() {
                    let offset = *offset as u64;
                    if offset <= *address && *address < offset + (memory_write_index.len() as u64) {
                        return memory_write_index[(*address - offset) as usize] as u64;
                    }
                }
                panic!("Could not access address")
            })();
            self.write_column(output_last_write, last_write);
            last_write
        } else if *enabled_if == 0 {
            0
        } else {
            panic!("Unexpected enabled_if: {}", enabled_if)
        }
    }

    fn set_last_memory_write(
        &mut self,
        address: &Self::Variable,
        enabled_if: &Self::Variable,
        last_write: &Self::Variable,
    ) {
        if *enabled_if == 1 {
            for (offset, memory_write_index) in self.memory_write_index.iter_mut() {
                let offset = *offset as u64;
                if offset <= *address && *address < offset + (memory_write_index.len() as u64) {
                    memory_write_index[(*address - offset) as usize] = *last_write as usize;
                }
            }
        } else if *enabled_if != 0 {
            panic!("Unexpected enabled_if: {}", enabled_if)
        }
    }

    fn instruction_part(&self, part: InstructionPart) -> Self::Variable {
        self.instruction_parts[part] as u64
    }

    fn decompose(
        &mut self,
        value: &Self::Variable,
        decomposition_little_endian: Vec<u32>,
        outputs: Vec<Self::Column>,
    ) -> Vec<Self::Variable> {
        let mut value = *value;
        let mut res = Vec::with_capacity(decomposition_little_endian.len());
        for (amount, output) in decomposition_little_endian
            .into_iter()
            .zip(outputs.into_iter())
        {
            let mask = (1 << amount) - 1;
            let output_value = value & mask;
            self.write_column(output, output_value);
            res.push(output_value);
            value >>= amount;
        }
        res
    }

    fn div_rem(
        &mut self,
        numerator: &Self::Variable,
        denominator: &Self::Variable,
        output_div: Self::Column,
        output_rem: Self::Column,
        output_divide_by_zero: Self::Column,
    ) -> (Self::Variable, Self::Variable, Self::Variable) {
        let (div, rem, divide_by_zero) = if *denominator != 0 {
            (numerator / denominator, numerator % denominator, 0)
        } else {
            (0, 0, 1)
        };
        self.write_column(output_div, div);
        self.write_column(output_rem, rem);
        self.write_column(output_divide_by_zero, divide_by_zero);
        (div, rem, divide_by_zero)
    }

    fn and_xor(
        &mut self,
        lhs: &Self::Variable,
        rhs: &Self::Variable,
        output_and: Self::Column,
        output_xor: Self::Column,
    ) -> (Self::Variable, Self::Variable) {
        let and = *lhs & *rhs;
        let xor = *lhs ^ *rhs;
        self.write_column(output_and, and);
        self.write_column(output_xor, xor);
        (and, xor)
    }

    fn alloc_scratch(&mut self) -> Self::Column {
        let scratch_idx = self.scratch_state_idx;
        self.scratch_state_idx += 1;
        Column::ScratchState(scratch_idx)
    }

    fn decode(instruction: &Self::Variable) -> Option<InstructionSelector> {
        decode(*instruction as u32)
    }

    fn assert_(&mut self, _value: &Self::Variable) {
        // TODO when hack below is fixed
    }

    fn eq_zero_terms(
        &mut self,
        value: &Self::Variable,
        res_output: Self::Column,
        inv_output: Self::Column,
    ) -> (Self::Variable, Self::Variable) {
        if *value == 0 {
            self.write_column(res_output, 1);
            self.write_column_field(inv_output, Fp::zero());
            (1, 0)
        } else {
            self.write_column(res_output, 0);
            self.write_column_field(inv_output, Fp::from(*value as u64).inverse().unwrap());
            // HACK
            (0, 0)
        }
    }

    fn sign_extend(&mut self, value: &Self::Variable, output: Self::Column) -> Self::Variable {
        let extended_value = ((((*value as u16) as i16) as i32) as u32) as u64;
        // println!("Sign extended {:#0x} to {:#0x}", value, extended_value);
        let _diff = extended_value - *value;
        let sign_value = i32::abs(extended_value as i32);
        // println!("diff:{:#0x}", diff);
        // println!("sign_value:{:#0x}", sign_value);
        self.write_column_field(output, -Fp::from(sign_value as u64));
        extended_value
    }
}

pub struct Witness<Fp> {
    pub instruction_parts: InstructionParts<Vec<u32>>,
    pub instruction_selectors: InstructionSelectors<Vec<bool>>,
    pub initial_registers: Registers<u32>,
    pub final_registers: Registers<u32>,
    pub final_registers_write_index: Registers<usize>,
    pub initial_memory: Vec<(u32, Vec<u8>)>,
    pub final_memory: Vec<(u32, Vec<u8>)>,
    pub final_memory_write_index: Vec<(u32, Vec<usize>)>,
    pub lookups: Vec<[Vec<Lookup<Fp>>; NUM_LOOKUP_TERMS]>,
    pub instruction_pointers: Vec<u32>,
    pub scratch_states: Vec<[Fp; SCRATCH_SIZE]>,
    pub lookup_counters: LookupCounters<Vec<usize>>,
    pub halt: Vec<bool>,
}

impl<Fp: Field> Witness<Fp> {
    pub fn create(d1_size: usize, state: State) -> Self {
        let initial_instruction_pointer = state.pc;

        let mut initial_memory: Vec<(u32, Vec<u8>)> = state
            .memory
            .iter()
            // Check that the conversion from page data is correct
            .map(|page| (page.index, page.data.as_bytes().to_vec()))
            .collect();

        // Pad memory to d1_size with 0s
        for (_address, initial_memory) in initial_memory.iter_mut() {
            initial_memory.extend((0..(d1_size - initial_memory.len())).map(|_| 0u8));
            assert_eq!(initial_memory.len(), d1_size);
        }

        let memory_offsets = initial_memory
            .iter()
            .map(|(offset, _)| *offset)
            .collect::<Vec<_>>();

        let initial_registers = Registers {
            lo: state.lo,
            hi: state.hi,
            general_purpose: state.registers,
        };

        let mut instruction_pointers = Vec::with_capacity(d1_size);
        // println!(
        //     "initial instruction pointer: {:#0x}",
        //     initial_instruction_pointer
        // );
        instruction_pointers.push(initial_instruction_pointer);

        let _rng = &mut StdRng::from_seed([0; 32]);

        let mut instruction_parts = InstructionParts::default().map(|()| vec![0; d1_size]);
        let mut instruction_selectors =
            InstructionSelectors::default().map(|()| vec![false; d1_size]);
        let all_opcodes = crate::mips::columns::all_instruction_selectors()
            .map(|col| match col {
                crate::mips::columns::Column::InstructionSelector(sel) => sel,
                _ => unreachable!(),
            })
            .collect::<Vec<_>>();
        let mut lookups = Vec::with_capacity(d1_size);
        let mut scratch_states = Vec::with_capacity(d1_size);
        let mut halt = Vec::with_capacity(d1_size);

        let fresh_lookup_terms = || array::from_fn(|_| vec![]);
        let fresh_scratch_state = || array::from_fn(|_| Fp::zero());

        println! {"Creating initial environment"};
        let mut env = Env {
            instruction_counter: state.step as usize,
            lookup_terms: fresh_lookup_terms(),
            lookup_terms_idx: 0,
            memory: initial_memory.clone(),
            memory_write_index: memory_offsets
                .iter()
                .map(|offset| (*offset, vec![0usize; d1_size]))
                .collect(),
            registers: initial_registers.clone(),
            registers_write_index: Registers::default(),
            instruction_parts: InstructionParts::default(),
            instruction_pointer: initial_instruction_pointer,
            scratch_state_idx: 0,
            scratch_state: fresh_scratch_state(),
            lookup_counters: LookupCounters::default().map(|()| vec![0; d1_size]),
            halt: state.exited,
            syscall_env: syscall_env_of_state(state),
        };

        // For debugging; delete
        let mut instruction_pointer_old = initial_instruction_pointer + 1;

        halt.push(env.halt);

        /*
        for (i, (_, rest)) in env.memory.iter().enumerate() {
            for (j, mem) in rest.iter().enumerate() {
                if !mem.is_zero() {
                    println!("i: {}, j: {}, mem: {}", i, j, mem);
                }
            }
        }
        */

        // NB: -1 here to stop the instruction outputs from wrapping back around to the first row.
        for i in 0..d1_size - 1 {
            println!("Instruction {i}");

            env.instruction_counter = i;
            env.lookup_terms = fresh_lookup_terms();
            env.scratch_state = fresh_scratch_state();
            env.lookup_terms_idx = 0;
            env.scratch_state_idx = 0;

            // Read the memory for the instruction
            let (opcode, instruction) = instructions::decode_instruction(&mut env);

            if env.instruction_pointer != instruction_pointer_old
                && opcode
                    != Some(InstructionSelector::RType(
                        crate::mips::columns::RTypeInstruction::ShiftLeftLogical,
                    ))
            {
                instruction_pointer_old = env.instruction_pointer;
                // println!("IP: {:?}, Opcode: {:?}", env.instruction_pointer, opcode);
            }

            /*// Choose a random opcode
            let rand_opcode_index =
                rng.sample(rand::distributions::Uniform::new(0, all_opcodes.len()));
            let opcode = all_opcodes[rand_opcode_index];*/
            let opcode = opcode.unwrap_or(all_opcodes[0]);

            instruction_selectors[opcode][i] = true;

            instruction_parts.op_code[i] = ((instruction >> 26) & ((1 << (32 - 26)) - 1)) as u32;
            instruction_parts.rs[i] = ((instruction >> 21) & ((1 << (26 - 21)) - 1)) as u32;
            instruction_parts.rt[i] = ((instruction >> 16) & ((1 << (21 - 16)) - 1)) as u32;
            instruction_parts.rd[i] = ((instruction >> 11) & ((1 << (16 - 11)) - 1)) as u32;
            instruction_parts.shamt[i] = ((instruction >> 6) & ((1 << (11 - 6)) - 1)) as u32;
            instruction_parts.funct[i] = ((instruction >> 0) & ((1 << (6 - 0)) - 1)) as u32;

            /*// Decode the instruction
            let (opcode, funct) = encode_selector(opcode);
            instruction_parts.op_code[i] = opcode;
            if let Some(funct) = funct {
                instruction_parts.funct[i] = funct;
            }

            // Choose some random values for the other parts
            instruction_parts.rs[i] = rng.gen_range(0..1 << 5);
            instruction_parts.rt[i] = rng.gen_range(0..1 << 5);
            instruction_parts.rd[i] = rng.gen_range(0..1 << 5);
            instruction_parts.shamt[i] = rng.gen_range(0..1 << 5);
            if funct.is_none() {
                instruction_parts.funct[i] = rng.gen_range(0..1 << 6);
            }*/

            // Update the environment
            for part in InstructionPart::iter() {
                env.instruction_parts[part] = instruction_parts[part][i];
            }

            // Step the lookup terms
            if env.lookup_terms_idx >= NUM_DECODING_LOOKUP_TERMS {
                panic!("{} > {}", env.lookup_terms_idx, NUM_DECODING_LOOKUP_TERMS);
            }
            env.lookup_terms_idx = NUM_DECODING_LOOKUP_TERMS;

            /*if opcode == InstructionSelector::RType(crate::mips::columns::RTypeInstruction::ShiftLeftLogical) {
                println!("{:#?}", env.lookup_terms);
            }*/

            // Run the instruction
            instructions::run_instruction(opcode, &mut env);

            /*let rand_lookup: u16 = rng.sample(rand::distributions::Uniform::new(0, u16::MAX));
            env.range_check_16(&(rand_lookup as u64));*/

            /*if opcode == InstructionSelector::RType(crate::mips::columns::RTypeInstruction::ShiftLeftLogical) {
                println!("{:#?}", env.lookup_terms);
            }*/

            // Store the lookups
            lookups.push(env.lookup_terms);

            // Store the instruction pointer
            instruction_pointers.push(env.instruction_pointer);

            // Store the scratch state
            scratch_states.push(env.scratch_state);

            // Store the halt state
            halt.push(env.halt);
        }

        lookups.push(fresh_lookup_terms());
        scratch_states.push(fresh_scratch_state());

        let _lookups_count = lookups
            .iter()
            .map(|x| x.iter().map(|x| x.len()).max().unwrap_or(0))
            .max()
            .unwrap();
        // println!("lookups_count: {}", lookups_count);

        // Finalize memory and registers
        let mut full_lookups = Vec::with_capacity(d1_size);
        for (i, lookups) in lookups.into_iter().enumerate() {
            let lookups = array::from_fn(|j| {
                if j < NUM_GLOBAL_LOOKUP_TERMS {
                    // Unconditional lookups
                    let mut env = {
                        let initial_registers = if i < NUM_REGISTERS {
                            initial_registers[i]
                        } else {
                            0
                        };
                        let final_registers = if i < NUM_REGISTERS {
                            env.registers[i]
                        } else {
                            0
                        };
                        let final_registers_write_index = if i < NUM_REGISTERS {
                            env.registers_write_index[i]
                        } else {
                            0
                        };
                        GlobalLookupEnv {
                            initial_memory: initial_memory.iter().map(|(_, col)| col[i]).collect(),
                            final_memory: env.memory.iter().map(|(_, col)| col[i]).collect(),
                            final_memory_write_index: env
                                .memory_write_index
                                .iter()
                                .map(|(_, col)| col[i])
                                .collect(),
                            memory_offset: memory_offsets.clone(),
                            initial_registers,
                            final_registers,
                            final_registers_write_index,
                            lookup_counters: env.lookup_counters.as_ref().map(|x| x[i]),
                            row_number: i,
                            lookups: vec![],
                        }
                    };
                    for i in 0..memory_offsets.len() {
                        memory_lookups(&mut env, i);
                    }
                    registers_lookups(&mut env);
                    range_check_16_lookups(&mut env);
                    env.lookups
                } else {
                    lookups[j - 1].clone()
                }
            });
            full_lookups.push(lookups);
        }

        println!(
            "initial instruction pointer: {:#0x}",
            initial_instruction_pointer
        );
        println!("final instruction pointer: {:#0x}", env.instruction_pointer);
        println!("halted: {:?}", halt[d1_size - 1]);
        println!("initial_registers: {:?}", initial_registers);
        println!("final_registers: {:?}", env.registers);
        // println!("register updates: {:?}", env.registers_write_index);

        Witness {
            instruction_parts,
            instruction_selectors,
            initial_memory,
            final_memory: env.memory,
            final_memory_write_index: env.memory_write_index,
            initial_registers,
            final_registers: env.registers,
            final_registers_write_index: env.registers_write_index,
            lookups: full_lookups,
            instruction_pointers,
            scratch_states,
            lookup_counters: env.lookup_counters,
            halt,
        }
    }
}
