use super::{registers::Registers, witness::Env, INSTRUCTION_SET_SIZE, PAGE_SIZE, SCRATCH_SIZE};
use crate::interpreters::riscv32im::{
    constraints,
    interpreter::{
        IInstruction, Instruction, MInstruction, RInstruction, SBInstruction, SInstruction,
        SyscallInstruction, UInstruction, UJInstruction,
    },
};
use ark_ff::Zero;
use mina_curves::pasta::Fp;
use rand::{CryptoRng, Rng, RngCore};
use strum::EnumCount;

pub fn dummy_env() -> Env<Fp> {
    Env {
        instruction_counter: 0,
        memory: vec![(0, vec![0; PAGE_SIZE.try_into().unwrap()])],
        last_memory_accesses: [0; 3],
        memory_write_index: vec![(0, vec![0; PAGE_SIZE.try_into().unwrap()])],
        last_memory_write_index_accesses: [0; 3],
        registers: Registers::default(),
        registers_write_index: Registers::default(),
        scratch_state_idx: 0,
        scratch_state: [Fp::zero(); SCRATCH_SIZE],
        halt: false,
        selector: INSTRUCTION_SET_SIZE,
    }
}

pub fn generate_random_add_instruction<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> [u8; 4] {
    let opcode = 0b0110011;
    let rd = rng.gen_range(0..32);
    let funct3 = 0b000;
    let rs1 = rng.gen_range(0..32);
    let rs2 = rng.gen_range(0..32);
    let funct2 = 0b00;
    let funct5 = 0b00000;
    let instruction = opcode
        | (rd << 7)
        | (funct3 << 12)
        | (rs1 << 15)
        | (rs2 << 20)
        | (funct2 << 25)
        | (funct5 << 27);
    [
        instruction as u8,
        (instruction >> 8) as u8,
        (instruction >> 16) as u8,
        (instruction >> 24) as u8,
    ]
}

pub fn generate_random_sub_instruction<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> [u8; 4] {
    let opcode = 0b0110011;
    let rd = rng.gen_range(0..32);
    let funct3 = 0b000;
    let rs1 = rng.gen_range(0..32);
    let rs2 = rng.gen_range(0..32);
    let funct2 = 0b00;
    let funct5 = 0b01000;
    let instruction = opcode
        | (rd << 7)
        | (funct3 << 12)
        | (rs1 << 15)
        | (rs2 << 20)
        | (funct2 << 25)
        | (funct5 << 27);
    [
        instruction as u8,
        (instruction >> 8) as u8,
        (instruction >> 16) as u8,
        (instruction >> 24) as u8,
    ]
}

#[test]
pub fn test_instruction_decoding_add() {
    let mut env: Env<Fp> = dummy_env();
    let mut rng = o1_utils::tests::make_test_rng(None);
    let instruction = generate_random_add_instruction(&mut rng);
    env.memory[0].1[0] = instruction[0];
    env.memory[0].1[1] = instruction[1];
    env.memory[0].1[2] = instruction[2];
    env.memory[0].1[3] = instruction[3];
    let (opcode, _instruction) = env.decode_instruction();
    assert_eq!(opcode, Instruction::RType(RInstruction::Add));
}

#[test]
pub fn test_instruction_decoding_sub() {
    let mut env: Env<Fp> = dummy_env();
    let mut rng = o1_utils::tests::make_test_rng(None);
    let instruction = generate_random_sub_instruction(&mut rng);
    env.memory[0].1[0] = instruction[0];
    env.memory[0].1[1] = instruction[1];
    env.memory[0].1[2] = instruction[2];
    env.memory[0].1[3] = instruction[3];
    let (opcode, _instruction) = env.decode_instruction();
    assert_eq!(opcode, Instruction::RType(RInstruction::Sub));
}

// Sanity check that we have as many selector as we have instructions
#[test]
fn test_regression_selectors_for_instructions() {
    let mips_con_env = constraints::Env::<Fp>::default();
    let constraints = mips_con_env.get_selector_constraints();
    assert_eq!(
        // We substract 1 as we have one boolean check per sel
        // and 1 constraint to check that one and only one
        // sel is activated
        constraints.len() - 1,
        // This should match the list in
        // crate::interpreters::riscv32im::interpreter::Instruction
        RInstruction::COUNT
            + IInstruction::COUNT
            + SInstruction::COUNT
            + SBInstruction::COUNT
            + UInstruction::COUNT
            + UJInstruction::COUNT
            + SyscallInstruction::COUNT
            + MInstruction::COUNT
    );
    // All instructions are degree 1 or 2.
    constraints
        .iter()
        .for_each(|c| assert!(c.degree(1, 0) == 2 || c.degree(1, 0) == 1));
}
