use mina_curves::pasta::Fp;
use o1vm::{
    elf_loader::Architecture,
    interpreters::riscv32im::{
        interpreter::{IInstruction, Instruction, RInstruction},
        registers::RegisterAlias::*,
        witness::Env,
        PAGE_SIZE,
    },
};

#[test]
fn test_registers_indexed_by_alias() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/sll",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    assert_eq!(witness.registers[Ip], 65652);
    assert_eq!(witness.registers[NextIp], 65656);
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
        "resources/programs/riscv32im/bin/no-action",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
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

#[test]
fn test_fibonacci_7() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/fibonacci-7",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);
    // This is the output we get by running objdump -d fibonacci-7
    assert_eq!(witness.registers.current_instruction_pointer, 69932);
    assert_eq!(witness.registers.next_instruction_pointer, 69936);

    while !witness.halt {
        witness.step();
        if witness.registers.current_instruction_pointer == 0x1117c {
            // Fibonacci sequence:
            // 1 1 2 3 5 8 13
            assert_eq!(witness.registers.general_purpose[10], 13);
        }
    }
}

#[test]
fn test_sll() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/sll",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }

    // Expected output of the program
    assert_eq!(witness.registers.general_purpose[5], 1 << 14)
}

#[test]
fn test_addi() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/addi",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }

    assert_eq!(witness.registers[T0], 15);
}

#[test]
fn test_add_1() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/add_1",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }

    assert_eq!(witness.registers[T0], 15);
}

#[test]
fn test_add_2() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/add_2",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }

    assert_eq!(witness.registers[T0], 123); // First number
    assert_eq!(witness.registers[T1], 456); // Second number
    assert_eq!(witness.registers[T2], 789); // Third number
    assert_eq!(witness.registers[T3], 579); // t3 = t0 + t1
    assert_eq!(witness.registers[T4], 1368); // t4 = t3 + t2
    assert_eq!(witness.registers[T5], 912); // t5 = t0 + t2
    assert_eq!(witness.registers[T6], 1368); // t6 = t4 + x0 (Copy t4 to t6)
}

#[test]
fn test_add_overflow() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/add_overflow",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }

    assert_eq!(witness.registers[T0], 0b01111111111111111111111111111111);
    assert_eq!(witness.registers[T1], 0b00000000000000000000000000000001);
    assert_eq!(witness.registers[T2], 0b10000000000000000000000000000000);
    assert_eq!(witness.registers[T3], 0b11111111111111111111111111111111);
    assert_eq!(witness.registers[T4], 0b00000000000000000000000000000000);
}

#[test]
fn test_addi_negative() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/addi_negative",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }

    assert_eq!(witness.registers[T0], 100);
    assert_eq!(witness.registers[T1], 50);
    assert_eq!(witness.registers[T2], (-50_i32) as u32);
    assert_eq!(witness.registers[T3], (-1000_i32) as u32);
    assert_eq!(witness.registers[T4], (-1500_i32) as u32);
}

#[test]
fn test_add_sub_swap() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/add_sub_swap",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }

    assert_eq!(witness.registers[T0], 10);
    assert_eq!(witness.registers[T1], 5);
    assert_eq!(witness.registers[T2], 15);
}

#[test]
fn test_addi_overflow() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/addi_overflow",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }

    assert_eq!(witness.registers[T1], (-2147483648_i32) as u32);
    assert_eq!(witness.registers[T3], 2147483647);
    assert_eq!(witness.registers[T5], 123456789);
}

#[test]
fn test_addi_boundary_immediate() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/addi_boundary_immediate",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }

    assert_eq!(witness.registers[T1], 2147);
    assert_eq!(witness.registers[T3], (-1048_i32) as u32);
}

#[test]
fn test_sub() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/sub",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }

    assert_eq!(witness.registers[T2], 500);
    assert_eq!(witness.registers[T5], (-100_i32) as u32);
}

#[test]
fn test_sub_2() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/sub_2",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }

    assert_eq!(witness.registers[T2], -200_i32 as u32);
    assert_eq!(witness.registers[T5], 150);
}

#[test]
fn test_sub_3() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/sub_3",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }

    assert_eq!(witness.registers[T1], 0);
    assert_eq!(witness.registers[T4], -2147483648_i32 as u32);
}

#[test]
fn test_xor() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/xor",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }

    assert_eq!(witness.registers[T2], 0b0110); // Result: t2 = 0b0110
    assert_eq!(witness.registers[T5], 0b1010); // Result: t5 = 0b1010
    assert_eq!(witness.registers[T1], 0); // Result: t1 = 0
}

#[test]
fn test_and() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/and",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }

    assert_eq!(witness.registers[T2], 0b1000);
    assert_eq!(witness.registers[T5], 0);
    assert_eq!(witness.registers[T1], 0b1010);
}

#[test]
fn test_slt() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/slt",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }

    assert_eq!(witness.registers[T2], 1);
    assert_eq!(witness.registers[T5], 0);
    assert_eq!(witness.registers[T6], 0);
}

#[test]
#[should_panic]
fn test_div_by_zero() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/div_by_zero",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }
}

#[test]
#[should_panic]
fn test_divu_by_zero() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/divu_by_zero",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }
}

#[test]
#[should_panic]
fn test_rem_by_zero() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/rem_by_zero",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }
}

#[test]
#[should_panic]
fn test_remu_by_zero() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/remu_by_zero",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }
}

#[test]
fn test_mul_overflow() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/mul_overflow",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }

    assert_eq!(witness.registers[T2], 276447232);
}

#[test]
fn test_jal() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/jal",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();
    let mut witness = Env::<Fp>::create(PAGE_SIZE.try_into().unwrap(), state);

    while !witness.halt {
        witness.step();
    }

    assert_eq!(witness.registers[T0], 12);
    assert_eq!(witness.registers[T1], 7);
}
