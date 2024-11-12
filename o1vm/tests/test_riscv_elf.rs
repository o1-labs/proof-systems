use o1vm::interpreters::riscv32i::
    interpreter::{IInstruction, Instruction, RInstruction};

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