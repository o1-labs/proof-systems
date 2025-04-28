use crate::{
    cannon::{Hint, Preimage, PAGE_ADDRESS_MASK, PAGE_ADDRESS_SIZE, PAGE_SIZE},
    interpreters::mips::{
        interpreter::{debugging::InstructionParts, InterpreterEnv},
        registers::Registers,
        witness::{Env as WEnv, SyscallEnv},
    },
    lookups::FixedLookup,
    preimage_oracle::PreImageOracleT,
};
use rand::{CryptoRng, Rng, RngCore};
use std::{fs, path::PathBuf};

// FIXME: we should parametrize the tests with different fields.
use ark_bn254::Fr as Fp;

use super::column::{SCRATCH_SIZE, SCRATCH_SIZE_INVERSE};

const PAGE_INDEX_EXECUTABLE_MEMORY: u32 = 1;

pub(crate) struct OnDiskPreImageOracle;

impl PreImageOracleT for OnDiskPreImageOracle {
    fn get_preimage(&mut self, key: [u8; 32]) -> Preimage {
        let key_s = hex::encode(key);
        let full_path = format!("resources/tests/0x{key_s}.txt");
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push(full_path);
        let contents = fs::read_to_string(d).expect("Should have been able to read the file");
        // Decode String (ASCII) as Vec<u8> (hexadecimal bytes)
        let bytes = hex::decode(contents)
            .expect("Should have been able to decode the file as hexadecimal bytes");
        Preimage::create(bytes)
    }

    fn hint(&mut self, _hint: Hint) {}
}

pub(crate) fn dummy_env<RNG>(rng: &mut RNG) -> WEnv<Fp, OnDiskPreImageOracle>
where
    RNG: RngCore + CryptoRng,
{
    let dummy_preimage_oracle = OnDiskPreImageOracle;
    let mut env = WEnv {
        // Set it to 2 to run 1 instruction that access registers if
        instruction_counter: 2,
        // Only 8kb of memory (two PAGE_ADDRESS_SIZE)
        memory: vec![
            // Read/write memory
            // Initializing with random data
            (
                0,
                (0..PAGE_SIZE).map(|_| rng.gen_range(0u8..=255)).collect(),
            ),
            // Executable memory. Allocating 4 * 4kB
            (PAGE_INDEX_EXECUTABLE_MEMORY, vec![0; PAGE_SIZE as usize]),
            (
                PAGE_INDEX_EXECUTABLE_MEMORY + 1,
                vec![0; PAGE_SIZE as usize],
            ),
            (
                PAGE_INDEX_EXECUTABLE_MEMORY + 2,
                vec![0; PAGE_SIZE as usize],
            ),
            (
                PAGE_INDEX_EXECUTABLE_MEMORY + 3,
                vec![0; PAGE_SIZE as usize],
            ),
        ],
        last_memory_accesses: [0; 3],
        memory_write_index: vec![
            // Read/write memory
            (0, vec![0; PAGE_SIZE as usize]),
            // Executable memory. Allocating 4 * 4kB
            (PAGE_INDEX_EXECUTABLE_MEMORY, vec![0; PAGE_SIZE as usize]),
            (
                PAGE_INDEX_EXECUTABLE_MEMORY + 1,
                vec![0; PAGE_SIZE as usize],
            ),
            (
                PAGE_INDEX_EXECUTABLE_MEMORY + 2,
                vec![0; PAGE_SIZE as usize],
            ),
            (
                PAGE_INDEX_EXECUTABLE_MEMORY + 3,
                vec![0; PAGE_SIZE as usize],
            ),
        ],
        last_memory_write_index_accesses: [0; 3],
        registers: Registers::default(),
        registers_write_index: Registers::default(),
        scratch_state_idx: 0,
        scratch_state_idx_inverse: 0,
        scratch_state: [Fp::from(0); SCRATCH_SIZE],
        scratch_state_inverse: [Fp::from(0); SCRATCH_SIZE_INVERSE],
        lookup_multiplicities: FixedLookup::<Vec<u64>>::new(),
        lookup_state_idx: 0,
        lookup_state: vec![],
        lookup_arity: vec![],
        selector: crate::interpreters::mips::column::N_MIPS_SEL_COLS,
        halt: false,
        // Keccak related
        syscall_env: SyscallEnv::default(),
        preimage: None,
        preimage_oracle: dummy_preimage_oracle,
        preimage_bytes_read: 0,
        preimage_key: None,
        keccak_env: None,
        hash_counter: 0,
    };
    // Initialize general purpose registers with random values
    for reg in env.registers.general_purpose.iter_mut() {
        *reg = rng.gen_range(0u32..=u32::MAX);
    }
    env.registers.current_instruction_pointer = PAGE_INDEX_EXECUTABLE_MEMORY * PAGE_SIZE;
    env.registers.next_instruction_pointer = env.registers.current_instruction_pointer + 4;
    env
}

// Write the instruction to the location of the instruction pointer.
pub(crate) fn write_instruction(
    env: &mut WEnv<Fp, OnDiskPreImageOracle>,
    instruction_parts: InstructionParts,
) {
    let instr = instruction_parts.encode();
    let instr_pointer: u32 = env.get_instruction_pointer().try_into().unwrap();
    let page = instr_pointer >> PAGE_ADDRESS_SIZE;
    let page_address = (instr_pointer & PAGE_ADDRESS_MASK) as usize;
    env.memory[page as usize].1[page_address] = ((instr >> 24) & 0xFF) as u8;
    env.memory[page as usize].1[page_address + 1] = ((instr >> 16) & 0xFF) as u8;
    env.memory[page as usize].1[page_address + 2] = ((instr >> 8) & 0xFF) as u8;
    env.memory[page as usize].1[page_address + 3] = (instr & 0xFF) as u8;
}
