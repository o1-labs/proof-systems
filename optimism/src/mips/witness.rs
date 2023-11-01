use crate::{cannon::State, mips::registers::Registers};
use ark_ff::Field;
use std::array;

pub const NUM_GLOBAL_LOOKUP_TERMS: usize = 1;
pub const NUM_DECODING_LOOKUP_TERMS: usize = 2;
pub const NUM_INSTRUCTION_LOOKUP_TERMS: usize = 5;
pub const NUM_LOOKUP_TERMS: usize =
    NUM_GLOBAL_LOOKUP_TERMS + NUM_DECODING_LOOKUP_TERMS + NUM_INSTRUCTION_LOOKUP_TERMS;
pub const SCRATCH_SIZE: usize = 25;

#[derive(Clone)]
pub struct SyscallEnv {
    pub heap: u32, // Heap pointer (actually unused in Cannon as of [2023-10-18])
    pub preimage_offset: u32,
    pub preimage_key: Vec<u8>,
    pub last_hint: Option<Vec<u8>>,
}

impl SyscallEnv {
    pub fn create(state: &State) -> Self {
        SyscallEnv {
            heap: state.heap,
            preimage_key: state.preimage_key.as_bytes().to_vec(), // Might not be correct
            preimage_offset: state.preimage_offset,
            last_hint: state.last_hint.clone(),
        }
    }
}

#[derive(Clone)]
pub struct Env<Fp> {
    pub instruction_counter: usize,
    pub memory: Vec<(u32, Vec<u8>)>,
    pub memory_write_index: Vec<(u32, Vec<usize>)>,
    pub registers: Registers<u32>,
    pub registers_write_index: Registers<usize>,
    pub instruction_pointer: u32,
    pub scratch_state_idx: usize,
    pub scratch_state: [Fp; SCRATCH_SIZE],
    pub halt: bool,
    pub syscall_env: SyscallEnv,
}

fn fresh_scratch_state<Fp: Field, const N: usize>() -> [Fp; N] {
    array::from_fn(|_| Fp::zero())
}

impl<Fp: Field> Env<Fp> {
    pub fn create(page_size: usize, state: State) -> Self {
        let initial_instruction_pointer = state.pc;

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

        let initial_registers = Registers {
            lo: state.lo,
            hi: state.hi,
            general_purpose: state.registers,
        };

        Env {
            instruction_counter: state.step as usize,
            memory: initial_memory.clone(),
            memory_write_index: memory_offsets
                .iter()
                .map(|offset| (*offset, vec![0usize; page_size]))
                .collect(),
            registers: initial_registers.clone(),
            registers_write_index: Registers::default(),
            instruction_pointer: initial_instruction_pointer,
            scratch_state_idx: 0,
            scratch_state: fresh_scratch_state(),
            halt: state.exited,
            syscall_env,
        }
    }

    pub fn step(&mut self) {
        // TODO
        self.halt = true;
    }
}
