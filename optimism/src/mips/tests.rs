use crate::{
    mips::{
        constraints::Env,
        interpreter::{
            ITypeInstruction::{self, *},
            Instruction::{self, *},
            JTypeInstruction::{self, *},
            RTypeInstruction::{self, *},
        },
        trace::MIPSTrace,
    },
    trace::Tracer,
};
use strum::{EnumCount, IntoEnumIterator};

type Fp = ark_bn254::Fr;

// Manually change the number of constraints if they are modififed in the interpreter
#[test]
fn test_mips_number_constraints() {
    let domain_size = 1 << 8;

    // Initialize the environment and run the interpreter
    let mut constraints_env = Env::<Fp> {
        scratch_state_idx: 0,
        constraints: Vec::new(),
        lookups: Vec::new(),
    };

    // Keep track of the constraints and lookups of the sub-circuits
    let mips_circuit = MIPSTrace::<Fp>::new(domain_size, &mut constraints_env);

    let assert_num_constraints = |instr: &Instruction, num: usize| {
        assert_eq!(mips_circuit.constraints.get(instr).unwrap().len(), num)
    };

    let mut i = 0;
    for instr in Instruction::iter().flat_map(|x| x.into_iter()) {
        match instr {
            RType(rtype) => match rtype {
                JumpRegister | SyscallExitGroup | Sync => assert_num_constraints(&instr, 0),
                ShiftLeftLogical
                | ShiftRightLogical
                | ShiftRightArithmetic
                | ShiftLeftLogicalVariable
                | ShiftRightLogicalVariable
                | ShiftRightArithmeticVariable
                | JumpAndLinkRegister
                | SyscallReadHint
                | MoveFromHi
                | MoveFromLo
                | MoveToLo
                | MoveToHi
                | Add
                | AddUnsigned
                | Sub
                | SubUnsigned
                | And
                | Or
                | Xor
                | Nor
                | SetLessThan
                | SetLessThanUnsigned
                | MultiplyToRegister
                | CountLeadingOnes
                | CountLeadingZeros => assert_num_constraints(&instr, 3),
                MoveZero | MoveNonZero => assert_num_constraints(&instr, 5),
                SyscallReadOther | SyscallWriteHint | SyscallWriteOther | Multiply
                | MultiplyUnsigned | Div | DivUnsigned => assert_num_constraints(&instr, 6),
                SyscallOther => assert_num_constraints(&instr, 10),
                SyscallMmap => assert_num_constraints(&instr, 11),
                SyscallReadPreimage => assert_num_constraints(&instr, 21),
                SyscallFcntl => assert_num_constraints(&instr, 22),
                SyscallWritePreimage => assert_num_constraints(&instr, 30),
            },
            JType(jtype) => match jtype {
                Jump => assert_num_constraints(&instr, 0),
                JumpAndLink => assert_num_constraints(&instr, 3),
            },
            IType(itype) => match itype {
                BranchLeqZero | BranchGtZero | BranchLtZero | BranchGeqZero | Store8 | Store16 => {
                    assert_num_constraints(&instr, 0)
                }
                BranchEq | BranchNeq | Store32 => assert_num_constraints(&instr, 2),
                AddImmediate
                | AddImmediateUnsigned
                | SetLessThanImmediate
                | SetLessThanImmediateUnsigned
                | AndImmediate
                | OrImmediate
                | XorImmediate
                | LoadUpperImmediate
                | Load8
                | Load16
                | Load32
                | Load8Unsigned
                | Load16Unsigned
                | Store32Conditional => assert_num_constraints(&instr, 3),
                LoadWordLeft | LoadWordRight | StoreWordLeft | StoreWordRight => {
                    assert_num_constraints(&instr, 12)
                }
            },
        }
        i += 1;
    }
    assert_eq!(
        i,
        RTypeInstruction::COUNT + JTypeInstruction::COUNT + ITypeInstruction::COUNT
    );
}

mod folding {
    use crate::mips::{
        interpreter::{debugging::InstructionParts, interpret_itype},
        ITypeInstruction,
    };
    use crate::{
        cannon::{HostProgram, PAGE_SIZE},
        mips::{
            // constraints::Env as CEnv,
            registers::Registers,
            witness::{Env as WEnv, SyscallEnv, SCRATCH_SIZE},
        },
        preimage_oracle::PreImageOracle,
    };
    use kimchi::o1_utils;
    use mina_curves::pasta::Fp;
    use rand::{CryptoRng, RngCore};

    const PAGE_INDEX_EXECUTABLE_MEMORY: u32 = 1;

    fn dummy_env<RNG>(_rng: &mut RNG) -> WEnv<Fp>
    where
        RNG: RngCore + CryptoRng,
    {
        let host_program = Some(HostProgram {
            name: String::from("true"),
            arguments: vec![],
        });
        let dummy_preimage_oracle = PreImageOracle::create(&host_program);
        WEnv {
            instruction_counter: 0,
            // Only 8kb of memory (two PAGE_ADDRESS_SIZE)
            memory: vec![
                // Read/write memory
                (0, vec![0; PAGE_SIZE as usize]),
                // Executable memory
                (PAGE_INDEX_EXECUTABLE_MEMORY, vec![0; PAGE_SIZE as usize]),
            ],
            last_memory_accesses: [0; 3],
            memory_write_index: vec![
                // Read/write memory
                (0, vec![0; PAGE_SIZE as usize]),
                // Executable memory
                (PAGE_INDEX_EXECUTABLE_MEMORY, vec![0; PAGE_SIZE as usize]),
            ],
            last_memory_write_index_accesses: [0; 3],
            registers: Registers::default(),
            registers_write_index: Registers::default(),
            scratch_state_idx: 0,
            scratch_state: [Fp::from(0); SCRATCH_SIZE],
            halt: false,
            // Keccak related
            syscall_env: SyscallEnv::default(),
            preimage: None,
            preimage_oracle: dummy_preimage_oracle,
            preimage_bytes_read: 0,
            preimage_key: None,
            keccak_env: None,
            hash_counter: 0,
        }
    }

    // Write the instruction to the second memory page, and first memory
    // location.
    // This is because in the dummy environment, the instruction pointer is
    // always at the first memory location of the second memory page, which is
    // considered as the "executable memory".
    fn write_instruction(env: &mut WEnv<Fp>, instruction_parts: InstructionParts) {
        let instr = instruction_parts.encode();
        env.memory[PAGE_INDEX_EXECUTABLE_MEMORY as usize].1[0] = ((instr >> 24) & 0xFF) as u8;
        env.memory[PAGE_INDEX_EXECUTABLE_MEMORY as usize].1[1] = ((instr >> 16) & 0xFF) as u8;
        env.memory[PAGE_INDEX_EXECUTABLE_MEMORY as usize].1[2] = ((instr >> 8) & 0xFF) as u8;
        env.memory[PAGE_INDEX_EXECUTABLE_MEMORY as usize].1[3] = (instr & 0xFF) as u8;
    }

    #[test]
    fn test_unit_addiu_instruction() {
        let mut rng = o1_utils::tests::make_test_rng();
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
                rs: 0b00001, // source register
                rt: 0b00010, // destination register
                // The rest is the immediate value
                rd: 0b01101,
                shamt: 0b10011,
                funct: 0b101000,
            },
        );
        dummy_env.registers.current_instruction_pointer = PAGE_INDEX_EXECUTABLE_MEMORY * PAGE_SIZE;
        dummy_env.registers.next_instruction_pointer =
            dummy_env.registers.current_instruction_pointer + 4;
        let exp_res = dummy_env.registers[reg_src] + 27880;
        interpret_itype(&mut dummy_env, ITypeInstruction::AddImmediateUnsigned);
        assert_eq!(dummy_env.registers.general_purpose[reg_dest], exp_res);
    }
}
