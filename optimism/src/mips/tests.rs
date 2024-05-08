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
    let mips_circuit = MIPSTrace::new(domain_size, &mut constraints_env);

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
    use crate::{
        cannon::{HostProgram, PAGE_ADDRESS_MASK, PAGE_ADDRESS_SIZE, PAGE_SIZE},
        folding::{Challenge, FoldingEnvironment, FoldingInstance, FoldingWitness, ScalarField},
        mips::{
            column::{ColumnAlias as MIPSColumn, MIPS_REL_COLS},
            constraints::Env as CEnv,
            interpreter::{debugging::InstructionParts, interpret_itype, InterpreterEnv},
            registers::Registers,
            witness::{Env as WEnv, SyscallEnv, SCRATCH_SIZE},
            ITypeInstruction,
        },
        preimage_oracle::PreImageOracle,
        BaseSponge, Curve, Fp, DOMAIN_SIZE,
    };
    use ark_poly::{EvaluationDomain as _, Evaluations, Radix2EvaluationDomain as D};
    use folding::{expressions::FoldingCompatibleExpr, Alphas, FoldingConfig, FoldingScheme};
    use itertools::Itertools;
    use kimchi::{curve::KimchiCurve, o1_utils};
    use kimchi_msm::{columns::Column as GenericColumn, witness::Witness};
    use mina_poseidon::FqSponge;
    use poly_commitment::{commitment::absorb_commitment, srs::SRS, PolyComm, SRS as _};
    use rand::{CryptoRng, Rng as _, RngCore};
    use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};

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
        let mut env = WEnv {
            instruction_counter: 0,
            // Only 8kb of memory (two PAGE_ADDRESS_SIZE)
            memory: vec![
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
        env.registers.current_instruction_pointer = PAGE_INDEX_EXECUTABLE_MEMORY * PAGE_SIZE;
        env.registers.next_instruction_pointer = env.registers.current_instruction_pointer + 4;
        env
    }

    // Write the instruction to the location of the instruction pointer.
    fn write_instruction(env: &mut WEnv<Fp>, instruction_parts: InstructionParts) {
        let instr = instruction_parts.encode();
        let instr_pointer: u32 = env.get_instruction_pointer().try_into().unwrap();
        let page = instr_pointer >> PAGE_ADDRESS_SIZE;
        let page_address = (instr_pointer & PAGE_ADDRESS_MASK) as usize;
        env.memory[page as usize].1[page_address] = ((instr >> 24) & 0xFF) as u8;
        env.memory[page as usize].1[page_address + 1] = ((instr >> 16) & 0xFF) as u8;
        env.memory[page as usize].1[page_address + 2] = ((instr >> 8) & 0xFF) as u8;
        env.memory[page as usize].1[page_address + 3] = (instr & 0xFF) as u8;
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

    fn make_random_witness_for_addiu<RNG>(
        domain_size: usize,
        rng: &mut RNG,
    ) -> Witness<MIPS_REL_COLS, Vec<Fp>>
    where
        RNG: RngCore + CryptoRng,
    {
        let mut rng = o1_utils::tests::make_test_rng();
        let mut dummy_env = dummy_env(&mut rng);
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
                    rd: rng.gen(),
                    shamt: rng.gen(),
                    funct: rng.gen(),
                },
            );
            interpret_itype(&mut dummy_env, instr);

            for j in 0..SCRATCH_SIZE {
                witness.cols[j].push(dummy_env.scratch_state[j]);
            }
            witness.cols[SCRATCH_SIZE].push(Fp::from(dummy_env.instruction_counter));
            witness.cols[SCRATCH_SIZE + 1].push(Fp::from(0));

            dummy_env.reset_scratch_state()
        });
        // sanity check
        witness
            .cols
            .iter()
            .for_each(|x| assert_eq!(x.len(), domain_size as usize));
        witness
    }

    fn build_folding_instance(
        witness: &FoldingWitness<MIPS_REL_COLS, Fp>,
        fq_sponge: &mut BaseSponge,
        domain: D<Fp>,
        srs: &SRS<Curve>,
    ) -> FoldingInstance<MIPS_REL_COLS, Curve> {
        let commitments: Witness<MIPS_REL_COLS, PolyComm<Curve>> = (&witness.witness)
            .into_par_iter()
            .map(|w| srs.commit_evaluations_non_hiding(domain, &w))
            .collect();

        // Absorbing commitments
        (&commitments)
            .into_iter()
            .for_each(|c| absorb_commitment(fq_sponge, &c));

        let commitments: [Curve; MIPS_REL_COLS] = commitments
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

        let folding_instance = FoldingInstance {
            commitments,
            challenges,
            alphas,
        };
        folding_instance
    }

    #[test]
    fn test_folding_mips_addiu_constraint() {
        let mut fq_sponge: BaseSponge = FqSponge::new(Curve::other_curve_sponge_params());
        let mut rng = o1_utils::tests::make_test_rng();

        let domain_size = 1 << 3;
        let domain: D<Fp> = D::<Fp>::new(domain_size).unwrap();

        let mut srs = SRS::<Curve>::create(domain_size);
        srs.add_lagrange_basis(domain);

        let witness_one = make_random_witness_for_addiu(domain_size, &mut rng);
        let witness_two = make_random_witness_for_addiu(domain_size, &mut rng);
        // FIXME: run PlonK here to check the it is satisfied.

        // Now, we will fold and use the folding scheme to only prove the
        // aggregation instead of the individual instances

        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        struct MIPSFoldingConfig;

        impl FoldingConfig for MIPSFoldingConfig {
            type Column = MIPSColumn;
            type Selector = ();
            type Challenge = Challenge;
            type Curve = Curve;
            type Srs = SRS<Curve>;
            type Instance = FoldingInstance<MIPS_REL_COLS, Curve>;
            type Witness = FoldingWitness<MIPS_REL_COLS, Fp>;
            // The structure is empty as we don't need to store any additional
            // information that is static for the relation
            type Structure = ();
            type Env = FoldingEnvironment<MIPS_REL_COLS, Curve>;

            fn rows() -> usize {
                DOMAIN_SIZE
            }
        }

        let folding_witness_one: FoldingWitness<MIPS_REL_COLS, Fp> = {
            let witness_one = (&witness_one)
                .into_par_iter()
                .map(|w| Evaluations::from_vec_and_domain(w.to_vec(), domain))
                .collect();
            FoldingWitness {
                witness: witness_one,
            }
        };

        let folding_witness_two: FoldingWitness<MIPS_REL_COLS, Fp> = {
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

        // Generating constraints
        let constraints = {
            // Initialize the environment and run the interpreter
            let mut constraints_env = CEnv::<Fp>::default();
            interpret_itype(&mut constraints_env, ITypeInstruction::AddImmediateUnsigned);
            constraints_env.constraints
        };

        let folding_compat_constraints: Vec<FoldingCompatibleExpr<MIPSFoldingConfig>> = constraints
            .iter()
            .map(|x| FoldingCompatibleExpr::from(x.clone()))
            .collect::<Vec<_>>();

        let (folding_scheme, _) = FoldingScheme::new(folding_compat_constraints, &srs, domain, ());

        let one = (folding_instance_one, folding_witness_one);
        let two = (folding_instance_two, folding_witness_two);
        let _folded = folding_scheme.fold_instance_witness_pair(one, two, &mut fq_sponge);

        // FIXME: add IVC
    }
}
