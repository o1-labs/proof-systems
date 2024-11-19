use mina_curves::pasta::Fp;
use o1vm::interpreters::riscv32im::{
    interpreter::{IInstruction, Instruction, RInstruction},
    witness::Env,
    PAGE_SIZE,
};

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
