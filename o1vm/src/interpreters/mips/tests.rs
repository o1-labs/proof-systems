// Here live the unit tests for the MIPS instructions
use crate::{
    interpreters::mips::{
        column::{N_MIPS_REL_COLS, N_MIPS_SEL_COLS},
        constraints,
        interpreter::{self, debugging::InstructionParts, InterpreterEnv},
        tests_helpers::*,
        ITypeInstruction, JTypeInstruction, RTypeInstruction, MAXIMUM_DEGREE_CONSTRAINTS,
        TOTAL_NUMBER_OF_CONSTRAINTS,
    },
    preimage_oracle::PreImageOracleT,
    E,
};

use kimchi::o1_utils;
use mina_curves::pasta::Fp;
use rand::Rng;
use strum::{EnumCount, IntoEnumIterator};

use super::Instruction;

pub(crate) fn sign_extend(x: u32, bitlength: u32) -> u32 {
    let high_bit = (x >> (bitlength - 1)) & 1;
    high_bit * (((1 << (32 - bitlength)) - 1) << bitlength) + x
}

pub(crate) fn bitmask(x: u32, highest_bit: u32, lowest_bit: u32) -> u32 {
    let res = (x >> lowest_bit) as u64 & (2u64.pow(highest_bit - lowest_bit) - 1);
    res as u32
}

#[test]
fn test_sext() {
    assert_eq!(sign_extend(0b1001_0110, 16), 0b1001_0110);
    assert_eq!(
        sign_extend(0b1001_0110_0000_0000, 16),
        0b1111_1111_1111_1111_1001_0110_0000_0000
    );
}

#[test]
fn test_bitmask() {
    assert_eq!(bitmask(0xaf, 8, 0), 0xaf);
    assert_eq!(bitmask(0x3671e4cb, 32, 0), 0x3671e4cb);
}

#[test]
fn test_on_disk_preimage_can_read_file() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let mut dummy_env = dummy_env(&mut rng);
    let preimage_key_u8: [u8; 32] = [
        0x02, 0x21, 0x07, 0x30, 0x78, 0x79, 0x25, 0x85, 0x77, 0x23, 0x0c, 0x5a, 0xa2, 0xf9, 0x05,
        0x67, 0xbd, 0xa4, 0x08, 0x77, 0xa7, 0xe8, 0x5d, 0xce, 0xb6, 0xff, 0x1f, 0x37, 0x48, 0x0f,
        0xef, 0x3d,
    ];
    let preimage = dummy_env.preimage_oracle.get_preimage(preimage_key_u8);
    let bytes = preimage.get();
    // Number of bytes inside the corresponding file (preimage)
    assert_eq!(bytes.len(), 358);
}

#[test]
fn test_all_instructions_have_a_usize_representation_smaller_than_the_number_of_selectors() {
    Instruction::iter().for_each(|i| {
        assert!(
            usize::from(i) - N_MIPS_REL_COLS < N_MIPS_SEL_COLS,
            "Instruction {:?} has a usize representation larger than the number of selectors ({})",
            i,
            usize::from(i) - N_MIPS_REL_COLS
        );
    });
}
mod rtype {

    use super::*;
    use crate::interpreters::mips::{interpreter::interpret_rtype, RTypeInstruction};

    #[test]
    fn test_unit_syscall_read_preimage() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        let mut dummy_env = dummy_env(&mut rng);
        // Instruction:  syscall (Read 5)
        // Set preimage key
        let preimage_key = [
            0x02, 0x21, 0x07, 0x30, 0x78, 0x79, 0x25, 0x85, 0x77, 0x23, 0x0c, 0x5a, 0xa2, 0xf9,
            0x05, 0x67, 0xbd, 0xa4, 0x08, 0x77, 0xa7, 0xe8, 0x5d, 0xce, 0xb6, 0xff, 0x1f, 0x37,
            0x48, 0x0f, 0xef, 0x3d,
        ];
        let chunks = preimage_key
            .chunks(4)
            .map(|chunk| {
                ((chunk[0] as u32) << 24)
                    + ((chunk[1] as u32) << 16)
                    + ((chunk[2] as u32) << 8)
                    + (chunk[3] as u32)
            })
            .collect::<Vec<_>>();
        dummy_env.registers.preimage_key = std::array::from_fn(|i| chunks[i]);

        // The whole preimage
        let preimage = dummy_env.preimage_oracle.get_preimage(preimage_key).get();

        // Total number of bytes that need to be processed (includes length)
        let total_length = 8 + preimage.len() as u32;

        // At first, offset is 0

        // Set a random address for register 5 that might not be aligned
        let addr = rng.gen_range(100..200);
        dummy_env.registers[5] = addr;

        // Read oracle until the totality of the preimage is reached
        // NOTE: the termination condition is not
        //       `while dummy_env.preimage_bytes_read < preimage.len()`
        //       because the interpreter sets it back to 0 when the preimage
        //       is read fully and the Keccak process is triggered (meaning
        //       that condition would generate an infinite loop instead)
        while dummy_env.registers.preimage_offset < total_length {
            dummy_env.reset_scratch_state();
            dummy_env.reset_scratch_state_inverse();

            // Set maximum number of bytes to read in this call
            dummy_env.registers[6] = rng.gen_range(1..=4);

            interpret_rtype(&mut dummy_env, RTypeInstruction::SyscallReadPreimage);

            // Update the address to store the next bytes with the offset
            dummy_env.registers[5] = addr + dummy_env.registers.preimage_offset;
        }

        // Number of bytes inside the corresponding file (preimage)
        // This should be the length read from the oracle in the first 8 bytes
        assert_eq!(dummy_env.registers.preimage_offset, total_length);

        // Check the content of memory addresses corresponds to the oracle

        // The first 8 bytes are the length of the preimage
        let length_byte = u64::to_be_bytes(preimage.len() as u64);
        for (i, b) in length_byte.iter().enumerate() {
            assert_eq!(
                dummy_env.memory[0].1[i + addr as usize],
                *b,
                "{}-th length byte does not match",
                i
            );
        }
        // Check that the preimage bytes are stored afterwards in the memory
        for (i, b) in preimage.iter().enumerate() {
            assert_eq!(
                dummy_env.memory[0].1[i + addr as usize + 8],
                *b,
                "{}-th preimage byte does not match",
                i
            );
        }
    }

    #[test]
    fn test_unit_sub_instruction() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        // We only care about instruction parts and instruction pointer
        let mut dummy_env = dummy_env(&mut rng);
        // FIXME: at the moment, we do not support writing and reading into the
        // same register
        // reg_dst <- reg_src - reg_tar
        let reg_src = 1;
        let reg_dst = 2;
        let reg_tar = 3;
        // Instruction: 0b00000000001000100001100000100010 sub $at, $at, $at
        write_instruction(
            &mut dummy_env,
            InstructionParts {
                op_code: 0b000000,
                rs: reg_src as u32, // source register
                rt: reg_tar as u32, // target register
                rd: reg_dst as u32, // destination register
                shamt: 0b00000,
                funct: 0b100010,
            },
        );
        let (exp_res, _underflow) =
            dummy_env.registers[reg_src].overflowing_sub(dummy_env.registers[reg_tar]);
        interpret_rtype(&mut dummy_env, RTypeInstruction::Sub);
        assert_eq!(dummy_env.registers.general_purpose[reg_dst], exp_res);
    }
}

mod itype {
    use super::*;
    use crate::interpreters::mips::{interpreter::interpret_itype, ITypeInstruction};

    #[test]
    fn test_unit_addi_instruction() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        // We only care about instruction parts and instruction pointer
        let mut dummy_env = dummy_env(&mut rng);
        // Instruction: 0b10001111101001000000000000000000 addi a1,sp,4
        write_instruction(
            &mut dummy_env,
            InstructionParts {
                op_code: 0b000010,
                rs: 0b11101,
                rt: 0b00101,
                rd: 0b00000,
                shamt: 0b00000,
                funct: 0b000100,
            },
        );
        interpret_itype(&mut dummy_env, ITypeInstruction::AddImmediate);
        assert_eq!(
            dummy_env.registers.general_purpose[5],
            dummy_env.registers.general_purpose[29] + 4
        );
    }

    #[test]
    fn test_unit_addiu_instruction() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        // We only care about instruction parts and instruction pointer
        let mut dummy_env = dummy_env(&mut rng);
        // FIXME: at the moment, we do not support writing and reading into the
        // same register
        let reg_src = 1;
        let reg_dest = 2;
        // Instruction: 0b00100100001000010110110011101000
        // addiu $at, $at, 27880
        write_instruction(
            &mut dummy_env,
            InstructionParts {
                op_code: 0b001001,
                rs: reg_src,  // source register
                rt: reg_dest, // destination register
                // The rest is the immediate value
                rd: 0b01101,
                shamt: 0b10011,
                funct: 0b101000,
            },
        );
        let exp_res = dummy_env.registers[reg_src as usize] + 27880;
        interpret_itype(&mut dummy_env, ITypeInstruction::AddImmediateUnsigned);
        assert_eq!(
            dummy_env.registers.general_purpose[reg_dest as usize],
            exp_res
        );
    }

    #[test]
    fn test_unit_lui_instruction() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        // We only care about instruction parts and instruction pointer
        let mut dummy_env = dummy_env(&mut rng);
        // Instruction: 0b00111100000000010000000000001010
        // lui at, 0xa
        write_instruction(
            &mut dummy_env,
            InstructionParts {
                op_code: 0b000010,
                rs: 0b00000,
                rt: 0b00001,
                rd: 0b00000,
                shamt: 0b00000,
                funct: 0b001010,
            },
        );
        interpret_itype(&mut dummy_env, ITypeInstruction::LoadUpperImmediate);
        assert_eq!(dummy_env.registers.general_purpose[1], 0xa0000);
    }

    #[test]
    fn test_unit_load16_instruction() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        // lh instruction
        let mut dummy_env = dummy_env(&mut rng);
        // Instruction: 0b100001 11101 00100 00000 00000 000000 lh $a0, 0(29) a0 = 4
        // Random address in SP Address has only one index

        let addr: u32 = rng.gen_range(0u32..100u32);
        let aligned_addr: u32 = (addr / 4) * 4;
        dummy_env.registers[29] = aligned_addr;
        let mem = &dummy_env.memory[0];
        let mem = &mem.1;
        let v0 = mem[aligned_addr as usize];
        let v1 = mem[(aligned_addr + 1) as usize];
        let v = ((v0 as u32) << 8) + (v1 as u32);
        let high_bit = (v >> 15) & 1;
        let exp_v = high_bit * (((1 << 16) - 1) << 16) + v;
        write_instruction(
            &mut dummy_env,
            InstructionParts {
                op_code: 0b100001,
                rs: 0b11101,
                rt: 0b00100,
                rd: 0b00000,
                shamt: 0b00000,
                funct: 0b000000,
            },
        );
        interpret_itype(&mut dummy_env, ITypeInstruction::Load16);
        assert_eq!(dummy_env.registers.general_purpose[4], exp_v);
    }

    #[test]
    fn test_unit_load32_instruction() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        // lw instruction
        let mut dummy_env = dummy_env(&mut rng);
        // Instruction: 0b10001111101001000000000000000000 lw $a0, 0(29) a0 = 4
        // Random address in SP Address has only one index

        let addr: u32 = rng.gen_range(0u32..100u32);
        let aligned_addr: u32 = (addr / 4) * 4;
        dummy_env.registers[29] = aligned_addr;
        let mem = &dummy_env.memory[0];
        let mem = &mem.1;
        let v0 = mem[aligned_addr as usize];
        let v1 = mem[(aligned_addr + 1) as usize];
        let v2 = mem[(aligned_addr + 2) as usize];
        let v3 = mem[(aligned_addr + 3) as usize];
        let exp_v = ((v0 as u32) << 24) + ((v1 as u32) << 16) + ((v2 as u32) << 8) + (v3 as u32);
        write_instruction(
            &mut dummy_env,
            InstructionParts {
                op_code: 0b100011,
                rs: 0b11101,
                rt: 0b00100,
                rd: 0b00000,
                shamt: 0b00000,
                funct: 0b000000,
            },
        );
        interpret_itype(&mut dummy_env, ITypeInstruction::Load32);
        assert_eq!(dummy_env.registers.general_purpose[4], exp_v);
    }
}

#[test]
// Sanity check that we have as many selector as we have instructions
fn test_regression_selectors_for_instructions() {
    let mips_con_env = constraints::Env::<Fp>::default();
    let constraints = mips_con_env.get_selector_constraints();
    assert_eq!(
        // We substract 1 as we have one boolean check per sel
        // and 1 constraint to check that one and only one
        // sel is activated
        constraints.len() - 1,
        // We could use N_MIPS_SEL_COLS, but sanity check in case this value is
        // changed.
        // the +1 is coming from NoOp instruction
        RTypeInstruction::COUNT + JTypeInstruction::COUNT + ITypeInstruction::COUNT + 1
    );
    // All instructions are degree 1 or 2.
    constraints
        .iter()
        .for_each(|c| assert!(c.degree(1, 0) == 2 || c.degree(1, 0) == 1));
}

#[test]
fn test_regression_constraints_with_selectors() {
    let constraints = {
        let mut mips_con_env = constraints::Env::<Fp>::default();
        let mut constraints = Instruction::iter()
            .flat_map(|instr_typ| instr_typ.into_iter())
            .fold(vec![], |mut acc, instr| {
                interpreter::interpret_instruction(&mut mips_con_env, instr);
                let selector = mips_con_env.get_selector();
                let constraints_with_selector: Vec<E<Fp>> = mips_con_env
                    .get_constraints()
                    .into_iter()
                    .map(|c| selector.clone() * c)
                    .collect();
                acc.extend(constraints_with_selector);
                mips_con_env.reset();
                acc
            });
        constraints.extend(mips_con_env.get_selector_constraints());
        constraints
    };

    assert_eq!(constraints.len(), TOTAL_NUMBER_OF_CONSTRAINTS);

    let max_degree = constraints.iter().map(|c| c.degree(1, 0)).max().unwrap();
    assert_eq!(max_degree, MAXIMUM_DEGREE_CONSTRAINTS);
}
