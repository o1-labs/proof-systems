use crate::{
    mips::{
        constraints::Env,
        interpreter::{
            ITypeInstruction::{self, *},
            Instruction::{self, *},
            JTypeInstruction::{self, *},
            RTypeInstruction::{self, *},
        },
        trace::DecomposedMIPSTrace,
    },
    trace::DecomposableTracer,
};
use strum::{EnumCount, IntoEnumIterator};

type Fp = ark_bn254::Fr;

// Manually change the number of constraints if they are modififed in the
// interpreter
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
    let mips_circuit = DecomposedMIPSTrace::new(domain_size, &mut constraints_env);

    let assert_num_constraints = |instr: &Instruction, num: usize| {
        assert_eq!(
            mips_circuit.trace.get(instr).unwrap().constraints.len(),
            num
        )
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
                SyscallFcntl => assert_num_constraints(&instr, 22),
                SyscallReadPreimage => assert_num_constraints(&instr, 28),
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

// Here live the unit tests for the MIPS instructions
mod unit {
    use super::Fp;
    use crate::{
        cannon::{Hint, Preimage, PAGE_ADDRESS_MASK, PAGE_ADDRESS_SIZE, PAGE_SIZE},
        mips::{
            interpreter::{
                debugging::InstructionParts, interpret_itype, interpret_rtype, InterpreterEnv,
            },
            registers::Registers,
            witness::{Env as WEnv, SyscallEnv, SCRATCH_SIZE},
            ITypeInstruction, RTypeInstruction,
        },
        preimage_oracle::PreImageOracleT,
    };
    use kimchi::o1_utils;
    use rand::{CryptoRng, Rng, RngCore};
    use std::{fs, path::PathBuf};

    const PAGE_INDEX_EXECUTABLE_MEMORY: u32 = 1;

    pub(crate) struct OnDiskPreImageOracle;

    impl PreImageOracleT for OnDiskPreImageOracle {
        fn get_preimage(&mut self, key: [u8; 32]) -> Preimage {
            let key_s = hex::encode(key);
            let full_path = format!("resources/tests/0x{key_s}.txt");
            let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            d.push(full_path);
            let contents = fs::read_to_string(d).expect("Should have been able to read the file");

            Preimage::create(contents.into())
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
            0x02, 0x21, 0x07, 0x30, 0x78, 0x79, 0x25, 0x85, 0x77, 0x23, 0x0c, 0x5a, 0xa2, 0xf9,
            0x05, 0x67, 0xbd, 0xa4, 0x08, 0x77, 0xa7, 0xe8, 0x5d, 0xce, 0xb6, 0xff, 0x1f, 0x37,
            0x48, 0x0f, 0xef, 0x3d,
        ];
        let _preimage = dummy_env.preimage_oracle.get_preimage(preimage_key_u8);
    }
    mod rtype {

        use super::*;

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
            let exp_v =
                ((v0 as u32) << 24) + ((v1 as u32) << 16) + ((v2 as u32) << 8) + (v3 as u32);
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
}

mod folding {
    use super::{
        unit::{dummy_env, write_instruction},
        Fp,
    };
    use crate::{
        folding::{Challenge, FoldingEnvironment, FoldingInstance, FoldingWitness},
        mips::{
            column::N_MIPS_REL_COLS,
            constraints::Env as CEnv,
            interpreter::{debugging::InstructionParts, interpret_itype},
            witness::SCRATCH_SIZE,
            ITypeInstruction,
        },
        trace::Trace,
        BaseSponge, Curve,
    };
    use ark_ff::One;
    use ark_poly::{EvaluationDomain as _, Evaluations, Radix2EvaluationDomain as D};
    use folding::{expressions::FoldingCompatibleExpr, Alphas, FoldingConfig, FoldingScheme};
    use itertools::Itertools;
    use kimchi::{curve::KimchiCurve, o1_utils};
    use kimchi_msm::{columns::Column, witness::Witness};
    use mina_poseidon::FqSponge;
    use poly_commitment::{commitment::absorb_commitment, srs::SRS, PolyComm, SRS as _};
    use rand::{CryptoRng, Rng, RngCore};
    use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};

    pub fn make_random_witness_for_addiu<RNG>(
        domain_size: usize,
        rng: &mut RNG,
    ) -> Witness<N_MIPS_REL_COLS, Vec<Fp>>
    where
        RNG: RngCore + CryptoRng,
    {
        let mut dummy_env = dummy_env(rng);
        let instr = ITypeInstruction::AddImmediateUnsigned;
        let a = std::array::from_fn(|_| Vec::with_capacity(domain_size));
        let mut witness = Witness { cols: Box::new(a) };
        // Building trace for AddImmediateUnsigned
        (0..domain_size).for_each(|_i| {
            // Registers should not conflict because RAMlookup does not support
            // reading from/writing into the same register in the same
            // instruction
            let reg_src = rng.gen_range(0..10);
            let reg_dest = rng.gen_range(10..20);
            // we simulate always the same instruction, with some random values
            // and registers
            write_instruction(
                &mut dummy_env,
                InstructionParts {
                    op_code: 0b001001,
                    rs: reg_src,  // source register
                    rt: reg_dest, // destination register
                    // The rest is the immediate value
                    rd: rng.gen_range(0..32),
                    shamt: rng.gen_range(0..32),
                    funct: rng.gen_range(0..64),
                },
            );
            interpret_itype(&mut dummy_env, instr);

            for j in 0..SCRATCH_SIZE {
                witness.cols[j].push(dummy_env.scratch_state[j]);
            }
            witness.cols[SCRATCH_SIZE].push(Fp::from(dummy_env.instruction_counter));
            witness.cols[SCRATCH_SIZE + 1].push(Fp::from(0));
            dummy_env.instruction_counter += 1;

            dummy_env.reset_scratch_state()
        });
        // sanity check
        witness
            .cols
            .iter()
            .for_each(|x| assert_eq!(x.len(), domain_size));
        witness
    }

    fn build_folding_instance(
        witness: &FoldingWitness<N_MIPS_REL_COLS, Fp>,
        fq_sponge: &mut BaseSponge,
        domain: D<Fp>,
        srs: &SRS<Curve>,
    ) -> FoldingInstance<N_MIPS_REL_COLS, Curve> {
        let commitments: Witness<N_MIPS_REL_COLS, PolyComm<Curve>> = (&witness.witness)
            .into_par_iter()
            .map(|w| srs.commit_evaluations_non_hiding(domain, w))
            .collect();

        // Absorbing commitments
        (&commitments)
            .into_iter()
            .for_each(|c| absorb_commitment(fq_sponge, c));

        let commitments: [Curve; N_MIPS_REL_COLS] = commitments
            .into_iter()
            .map(|c| c.elems[0])
            .collect_vec()
            .try_into()
            .unwrap();

        let beta = fq_sponge.challenge();
        let gamma = fq_sponge.challenge();
        let joint_combiner = fq_sponge.challenge();
        let alpha = fq_sponge.challenge();
        let challenges = [beta, gamma, joint_combiner];
        let alphas = Alphas::new(alpha);
        let blinder = Fp::one();

        FoldingInstance {
            commitments,
            challenges,
            alphas,
            blinder,
        }
    }

    #[test]
    fn test_folding_mips_addiu_constraint() {
        let mut fq_sponge: BaseSponge = FqSponge::new(Curve::other_curve_sponge_params());
        let mut rng = o1_utils::tests::make_test_rng(None);

        let domain_size = 1 << 3;
        let domain: D<Fp> = D::<Fp>::new(domain_size).unwrap();

        let mut srs = SRS::<Curve>::create(domain_size);
        srs.add_lagrange_basis(domain);

        // Generating constraints
        let constraints = {
            // Initialize the environment and run the interpreter
            let mut constraints_env = CEnv::<Fp>::default();
            interpret_itype(&mut constraints_env, ITypeInstruction::AddImmediateUnsigned);
            constraints_env.constraints
        };
        // We have 3 constraints here. We can select only one.
        // println!("Nb of constraints: {:?}", constraints.len());
        //
        // You can select one of the constraints if you want to fold only one
        //
        // constraints
        //      .iter()
        //      .for_each(|constraint|
        //           println!("Degree: {:?}", constraint.degree(1, 0)));
        //
        // Selecting the first constraint for testing
        // let constraints
        //     = vec![constraints.first().unwrap().clone()];

        let witness_one = make_random_witness_for_addiu(domain_size, &mut rng);
        let witness_two = make_random_witness_for_addiu(domain_size, &mut rng);
        // FIXME: run PlonK here to check the it is satisfied.

        // Now, we will fold and use the folding scheme to only prove the
        // aggregation instead of the individual instances

        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        struct MIPSFoldingConfig;

        let trace_one: Trace<N_MIPS_REL_COLS, MIPSFoldingConfig> = Trace {
            domain_size,
            // FIXME: do not use clone
            witness: witness_one.clone(),
            constraints: constraints.clone(),
            lookups: vec![],
        };

        impl FoldingConfig for MIPSFoldingConfig {
            type Column = Column;
            type Selector = ();
            type Challenge = Challenge;
            type Curve = Curve;
            type Srs = SRS<Curve>;
            type Instance = FoldingInstance<N_MIPS_REL_COLS, Curve>;
            type Witness = FoldingWitness<N_MIPS_REL_COLS, Fp>;
            // The structure must a provable Trace. Here we use a single
            // instruction trace
            type Structure = Trace<N_MIPS_REL_COLS, MIPSFoldingConfig>;
            type Env = FoldingEnvironment<
                N_MIPS_REL_COLS,
                MIPSFoldingConfig,
                Trace<N_MIPS_REL_COLS, MIPSFoldingConfig>,
            >;
        }

        let folding_witness_one: FoldingWitness<N_MIPS_REL_COLS, Fp> = {
            let witness_one = (&witness_one)
                .into_par_iter()
                .map(|w| Evaluations::from_vec_and_domain(w.to_vec(), domain))
                .collect();
            FoldingWitness {
                witness: witness_one,
            }
        };

        let folding_witness_two: FoldingWitness<N_MIPS_REL_COLS, Fp> = {
            let witness_two = (&witness_two)
                .into_par_iter()
                .map(|w| Evaluations::from_vec_and_domain(w.to_vec(), domain))
                .collect();
            FoldingWitness {
                witness: witness_two,
            }
        };

        let folding_instance_one =
            build_folding_instance(&folding_witness_one, &mut fq_sponge, domain, &srs);
        let folding_instance_two =
            build_folding_instance(&folding_witness_two, &mut fq_sponge, domain, &srs);

        let folding_compat_constraints: Vec<FoldingCompatibleExpr<MIPSFoldingConfig>> = constraints
            .iter()
            .map(|x| FoldingCompatibleExpr::from(x.clone()))
            .collect::<Vec<_>>();

        let (folding_scheme, _) = FoldingScheme::<MIPSFoldingConfig>::new(
            folding_compat_constraints,
            &srs,
            domain,
            &trace_one,
        );

        let one = (folding_instance_one, folding_witness_one);
        let two = (folding_instance_two, folding_witness_two);
        let (_relaxed_instance, _relatex_witness) = folding_scheme
            .fold_instance_witness_pair(one, two, &mut fq_sponge)
            .pair();

        // FIXME: add IVC
    }
}
