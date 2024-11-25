use super::{registers::Registers, witness::Env, INSTRUCTION_SET_SIZE, PAGE_SIZE, SCRATCH_SIZE};
use crate::interpreters::riscv32im::interpreter::{Instruction, MInstruction, RInstruction};
use ark_ff::Zero;
use mina_curves::pasta::Fp;
use rand::{CryptoRng, Rng, RngCore};

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

pub fn generate_random_sll_instruction<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> [u8; 4] {
    let opcode = 0b0110011;
    let rd = rng.gen_range(0..32);
    let funct3 = 0b001;
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

pub fn generate_random_slt_instruction<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> [u8; 4] {
    let opcode = 0b0110011;
    let rd = rng.gen_range(0..32);
    let funct3 = 0b010;
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

pub fn generate_random_xor_instruction<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> [u8; 4] {
    let opcode = 0b0110011;
    let rd = rng.gen_range(0..32);
    let funct3 = 0b100;
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

pub fn generate_random_sltu_instruction<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> [u8; 4] {
    let opcode = 0b0110011;
    let rd = rng.gen_range(0..32);
    let funct3 = 0b011;
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

pub fn generate_random_srl_instruction<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> [u8; 4] {
    let opcode = 0b0110011;
    let rd = rng.gen_range(0..32);
    let funct3 = 0b101;
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

pub fn generate_random_sra_instruction<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> [u8; 4] {
    let opcode = 0b0110011;
    let rd = rng.gen_range(0..32);
    let funct3 = 0b101;
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

pub fn generate_random_or_instruction<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> [u8; 4] {
    let opcode = 0b0110011;
    let rd = rng.gen_range(0..32);
    let funct3 = 0b110;
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

pub fn generate_random_and_instruction<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> [u8; 4] {
    let opcode = 0b0110011;
    let rd = rng.gen_range(0..32);
    let funct3 = 0b111;
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

pub fn generate_random_mul_instruction<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> [u8; 4] {
    let opcode = 0b0110011;
    let rd = rng.gen_range(0..32);
    let funct3 = 0b000;
    let rs1 = rng.gen_range(0..32);
    let rs2 = rng.gen_range(0..32);
    let funct2 = 0b01;
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

#[test]
pub fn test_instruction_decoding_sll() {
    let mut env: Env<Fp> = dummy_env();
    let mut rng = o1_utils::tests::make_test_rng(None);
    let instruction = generate_random_sll_instruction(&mut rng);
    env.memory[0].1[0] = instruction[0];
    env.memory[0].1[1] = instruction[1];
    env.memory[0].1[2] = instruction[2];
    env.memory[0].1[3] = instruction[3];
    let (opcode, _instruction) = env.decode_instruction();
    assert_eq!(opcode, Instruction::RType(RInstruction::ShiftLeftLogical));
}

#[test]
pub fn test_instruction_decoding_slt() {
    let mut env: Env<Fp> = dummy_env();
    let mut rng = o1_utils::tests::make_test_rng(None);
    let instruction = generate_random_slt_instruction(&mut rng);
    env.memory[0].1[0] = instruction[0];
    env.memory[0].1[1] = instruction[1];
    env.memory[0].1[2] = instruction[2];
    env.memory[0].1[3] = instruction[3];
    let (opcode, _instruction) = env.decode_instruction();
    assert_eq!(opcode, Instruction::RType(RInstruction::SetLessThan));
}

#[test]
pub fn test_instruction_decoding_sltu() {
    let mut env: Env<Fp> = dummy_env();
    let mut rng = o1_utils::tests::make_test_rng(None);
    let instruction = generate_random_sltu_instruction(&mut rng);
    env.memory[0].1[0] = instruction[0];
    env.memory[0].1[1] = instruction[1];
    env.memory[0].1[2] = instruction[2];
    env.memory[0].1[3] = instruction[3];
    let (opcode, _instruction) = env.decode_instruction();
    assert_eq!(
        opcode,
        Instruction::RType(RInstruction::SetLessThanUnsigned)
    );
}

#[test]
pub fn test_instruction_decoding_xor() {
    let mut env: Env<Fp> = dummy_env();
    let mut rng = o1_utils::tests::make_test_rng(None);
    let instruction = generate_random_xor_instruction(&mut rng);
    env.memory[0].1[0] = instruction[0];
    env.memory[0].1[1] = instruction[1];
    env.memory[0].1[2] = instruction[2];
    env.memory[0].1[3] = instruction[3];
    let (opcode, _instruction) = env.decode_instruction();
    assert_eq!(opcode, Instruction::RType(RInstruction::Xor));
}

#[test]
pub fn test_instruction_decoding_srl() {
    let mut env: Env<Fp> = dummy_env();
    let mut rng = o1_utils::tests::make_test_rng(None);
    let instruction = generate_random_srl_instruction(&mut rng);
    env.memory[0].1[0] = instruction[0];
    env.memory[0].1[1] = instruction[1];
    env.memory[0].1[2] = instruction[2];
    env.memory[0].1[3] = instruction[3];
    let (opcode, _instruction) = env.decode_instruction();
    assert_eq!(opcode, Instruction::RType(RInstruction::ShiftRightLogical));
}

#[test]
pub fn test_instruction_decoding_sr1() {
    let mut env: Env<Fp> = dummy_env();
    let mut rng = o1_utils::tests::make_test_rng(None);
    let instruction = generate_random_sra_instruction(&mut rng);
    env.memory[0].1[0] = instruction[0];
    env.memory[0].1[1] = instruction[1];
    env.memory[0].1[2] = instruction[2];
    env.memory[0].1[3] = instruction[3];
    let (opcode, _instruction) = env.decode_instruction();
    assert_eq!(
        opcode,
        Instruction::RType(RInstruction::ShiftRightArithmetic)
    );
}

#[test]
pub fn test_instruction_decoding_or() {
    let mut env: Env<Fp> = dummy_env();
    let mut rng = o1_utils::tests::make_test_rng(None);
    let instruction = generate_random_or_instruction(&mut rng);
    env.memory[0].1[0] = instruction[0];
    env.memory[0].1[1] = instruction[1];
    env.memory[0].1[2] = instruction[2];
    env.memory[0].1[3] = instruction[3];
    let (opcode, _instruction) = env.decode_instruction();
    assert_eq!(opcode, Instruction::RType(RInstruction::Or));
}

#[test]
pub fn test_instruction_decoding_and() {
    let mut env: Env<Fp> = dummy_env();
    let mut rng = o1_utils::tests::make_test_rng(None);
    let instruction = generate_random_and_instruction(&mut rng);
    env.memory[0].1[0] = instruction[0];
    env.memory[0].1[1] = instruction[1];
    env.memory[0].1[2] = instruction[2];
    env.memory[0].1[3] = instruction[3];
    let (opcode, _instruction) = env.decode_instruction();
    assert_eq!(opcode, Instruction::RType(RInstruction::And));
}

#[test]
pub fn test_instruction_decoding_mul() {
    let mut env: Env<Fp> = dummy_env();
    let mut rng = o1_utils::tests::make_test_rng(None);
    let instruction = generate_random_mul_instruction(&mut rng);
    env.memory[0].1[0] = instruction[0];
    env.memory[0].1[1] = instruction[1];
    env.memory[0].1[2] = instruction[2];
    env.memory[0].1[3] = instruction[3];
    let (opcode, _instruction) = env.decode_instruction();
    assert_eq!(opcode, Instruction::MType(MInstruction::Mul));
}
