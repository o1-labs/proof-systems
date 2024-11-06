use mina_curves::pasta::Fp;
use o1vm::interpreters::riscv32i::{
    interpreter::{IInstruction, Instruction, RInstruction},
    witness::Env,
    PAGE_SIZE,
};

#[test]
// This test is used to check that the elf loader is working correctly.
// We must export the code used in this test in a function that can be called by
// the o1vm at load time.
fn test_correctly_parsing_elf() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32i/fibonacci",
    ));
    let state = o1vm::elf_loader::parse_riscv32i(&path).unwrap();
    // This is the output we get by running objdump -d fibonacci
    assert_eq!(state.pc, 69932);

    assert_eq!(state.memory.len(), 1);
    assert_eq!(state.memory[0].index, 17);
}

#[test]
fn test_fibonacci() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32i/fibonacci-7",
    ));
    let state = o1vm::elf_loader::parse_riscv32i(&path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);
    // This is the output we get by running objdump -d fibonacci
    assert_eq!(witness.registers.current_instruction_pointer, 69932);
    assert_eq!(witness.registers.next_instruction_pointer, 69936);

    let first_instruction = witness.step();
    assert_eq!(
        first_instruction,
        Instruction::IType(IInstruction::AddImmediate)
    );
    println!("{:?}", witness.registers);
    assert_eq!(witness.registers.current_instruction_pointer, 69936);
    assert_eq!(witness.registers.next_instruction_pointer, 69940);

    while !witness.halt {
        witness.step();
        println!("Printing register state after instruction execution");
        println!("{:?}", witness.log_register_state());
        println!("-----------------------------------------");
    }

    // let second_instruction = witness.step();
    // println!("Second instruction: {:?}", second_instruction);
    // assert_eq!(
    //     second_instruction,
    //     Instruction::IType(IInstruction::AddImmediate)
    // );
    // assert_eq!(witness.registers.current_instruction_pointer, 69940);
    // assert_eq!(witness.registers.next_instruction_pointer, 69944);
}

#[test]
// Checking an instruction can be converted into a string.
// It is mostly because we would want to use it to debug or write better error
// messages.
fn test_instruction_can_be_converted_into_string() {
    let instruction = Instruction::RType(RInstruction::Add);
    assert_eq!(instruction.to_string(), "add");

    let instruction = Instruction::RType(RInstruction::Sub);
    assert_eq!(instruction.to_string(), "sub");

    let instruction = Instruction::IType(IInstruction::LoadByte);
    assert_eq!(instruction.to_string(), "lb");

    let instruction = Instruction::IType(IInstruction::LoadHalf);
    assert_eq!(instruction.to_string(), "lh");
}

#[test]
fn test_no_action() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32i/no-action",
    ));
    let state = o1vm::elf_loader::parse_riscv32i(&path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);
    // This is the output we get by running objdump -d no-action
    assert_eq!(witness.registers.current_instruction_pointer, 69844);
    assert_eq!(witness.registers.next_instruction_pointer, 69848);

    (0..=7).for_each(|_| {
        let instr = witness.step();
        // li is addi, li is a pseudo instruction
        assert_eq!(instr, Instruction::IType(IInstruction::AddImmediate))
    });
    assert_eq!(witness.registers.general_purpose[10], 0);
    assert_eq!(witness.registers.general_purpose[11], 0);
    assert_eq!(witness.registers.general_purpose[12], 0);
    assert_eq!(witness.registers.general_purpose[13], 0);
    assert_eq!(witness.registers.general_purpose[14], 0);
    assert_eq!(witness.registers.general_purpose[15], 0);
    assert_eq!(witness.registers.general_purpose[16], 0);
    assert_eq!(witness.registers.general_purpose[17], 42);
}
