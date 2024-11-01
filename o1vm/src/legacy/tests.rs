use crate::{
    interpreters::mips::{
        column::N_MIPS_REL_COLS,
        constraints::Env as CEnv,
        interpreter::{debugging::InstructionParts, interpret_itype},
        witness::SCRATCH_SIZE,
        ITypeInstruction,
    },
    legacy::{
        folding::{
            Challenge, DecomposedMIPSTrace, FoldingEnvironment, FoldingInstance, FoldingWitness,
        },
        trace::Trace,
    },
    BaseSponge, Curve,
};

use ark_ff::One;
use ark_poly::{EvaluationDomain as _, Evaluations, Radix2EvaluationDomain as D};
use folding::{expressions::FoldingCompatibleExpr, Alphas, FoldingConfig, FoldingScheme};
use itertools::Itertools;
use kimchi::{curve::KimchiCurve, o1_utils};
use kimchi_msm::{columns::Column, witness::Witness};
use mina_poseidon::FqSponge;
use poly_commitment::{commitment::absorb_commitment, kzg::PairingSRS, PolyComm, SRS as _};
use rand::{CryptoRng, Rng, RngCore};
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};

pub mod mips {
    fn make_random_witness_for_addiu<RNG>(
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
        srs: &PairingSRS<Curve>,
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

    // Manually change the number of constraints if they are modififed in the
    // interpreter
    // FIXME: can be moved up, in interpreters::mips, wihthout using the
    // DecomposedMIPSTrace
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
                    JumpRegister | SyscallExitGroup | Sync => assert_num_constraints(&instr, 1),
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
                    | CountLeadingZeros => assert_num_constraints(&instr, 4),
                    MoveZero | MoveNonZero => assert_num_constraints(&instr, 6),
                    SyscallReadOther | SyscallWriteHint | SyscallWriteOther | Multiply
                    | MultiplyUnsigned | Div | DivUnsigned => assert_num_constraints(&instr, 7),
                    SyscallOther => assert_num_constraints(&instr, 11),
                    SyscallMmap => assert_num_constraints(&instr, 12),
                    SyscallFcntl | SyscallReadPreimage => assert_num_constraints(&instr, 23),
                    // TODO: update SyscallReadPreimage to 31 when using self.equal()
                    SyscallWritePreimage => assert_num_constraints(&instr, 31),
                },
                JType(jtype) => match jtype {
                    Jump => assert_num_constraints(&instr, 1),
                    JumpAndLink => assert_num_constraints(&instr, 4),
                },
                IType(itype) => match itype {
                    BranchLeqZero | BranchGtZero | BranchLtZero | BranchGeqZero | Store8
                    | Store16 => assert_num_constraints(&instr, 1),
                    BranchEq | BranchNeq | Store32 => assert_num_constraints(&instr, 3),
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
                    | Store32Conditional => assert_num_constraints(&instr, 4),
                    LoadWordLeft | LoadWordRight | StoreWordLeft | StoreWordRight => {
                        assert_num_constraints(&instr, 13)
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

    #[test]
    fn test_folding_mips_addiu_constraint() {
        let mut fq_sponge: BaseSponge = FqSponge::new(Curve::other_curve_sponge_params());
        let mut rng = o1_utils::tests::make_test_rng(None);

        let domain_size = 1 << 3;
        let domain: D<Fp> = D::<Fp>::new(domain_size).unwrap();

        let srs = PairingSRS::<Curve>::create(domain_size);
        srs.get_lagrange_basis(domain);

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
            type Srs = PairingSRS<Curve>;
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

pub mod keccak {
    fn create_trace_all_steps(domain_size: usize, rng: &mut StdRng) -> DecomposedKeccakTrace {
        let mut trace = <DecomposedKeccakTrace as DecomposableTracer<KeccakEnv<Fp>>>::new(
            domain_size,
            &mut KeccakEnv::<Fp>::default(),
        );
        {
            // 1 block preimages for Sponge(Absorb(Only)), Round(0), and Sponge(Squeeze)
            for _ in 0..domain_size {
                // random 1-block preimages
                let bytelength = rng.gen_range(0..RATE_IN_BYTES);
                let preimage: Vec<u8> = (0..bytelength).map(|_| rng.gen()).collect();
                // Initialize the environment and run the interpreter
                let mut keccak_env = KeccakEnv::<Fp>::new(0, &preimage);
                while keccak_env.step.is_some() {
                    let step = keccak_env.step.unwrap();
                    // Create the relation witness columns
                    keccak_env.step();
                    match step {
                        Sponge(Absorb(Only)) | Round(0) | Sponge(Squeeze) => {
                            // Add the witness row to the circuit
                            trace.push_row(step, &keccak_env.witness_env.witness.cols);
                        }
                        _ => {}
                    }
                }
            }
            // Check there is no need for padding because we reached domain_size rows for these selectors
            assert!(trace.is_full(Sponge(Absorb(Only))));
            assert!(trace.is_full(Round(0)));
            assert!(trace.is_full(Sponge(Squeeze)));

            // Add the columns of the selectors to the circuit
            trace.set_selector_column::<N_ZKVM_KECCAK_REL_COLS>(Sponge(Absorb(Only)), domain_size);
            trace.set_selector_column::<N_ZKVM_KECCAK_REL_COLS>(Round(0), domain_size);
            trace.set_selector_column::<N_ZKVM_KECCAK_REL_COLS>(Sponge(Squeeze), domain_size);
        }
        {
            // 3 block preimages for Sponge(Absorb(First)), Sponge(Absorb(Middle)), and Sponge(Absorb(Last))
            for _ in 0..domain_size {
                // random 3-block preimages
                let bytelength = rng.gen_range(2 * RATE_IN_BYTES..3 * RATE_IN_BYTES);
                let preimage: Vec<u8> = (0..bytelength).map(|_| rng.gen()).collect();
                // Initialize the environment and run the interpreter
                let mut keccak_env = KeccakEnv::<Fp>::new(0, &preimage);
                while keccak_env.step.is_some() {
                    let step = keccak_env.step.unwrap();
                    // Create the relation witness columns
                    keccak_env.step();
                    match step {
                        Sponge(Absorb(First)) | Sponge(Absorb(Middle)) | Sponge(Absorb(Last)) => {
                            // Add the witness row to the circuit
                            trace.push_row(step, &keccak_env.witness_env.witness.cols);
                        }
                        _ => {}
                    }
                }
            }
            // Check there is no need for padding because we reached domain_size rows for these selectors
            assert!(trace.is_full(Sponge(Absorb(First))));
            assert!(trace.is_full(Sponge(Absorb(Middle))));
            assert!(trace.is_full(Sponge(Absorb(Last))));

            // Add the columns of the selectors to the circuit
            trace.set_selector_column::<N_ZKVM_KECCAK_REL_COLS>(Sponge(Absorb(First)), domain_size);
            trace
                .set_selector_column::<N_ZKVM_KECCAK_REL_COLS>(Sponge(Absorb(Middle)), domain_size);
            trace.set_selector_column::<N_ZKVM_KECCAK_REL_COLS>(Sponge(Absorb(Last)), domain_size);
            trace
        }
    }

    // Prover/Verifier test includidng the Keccak constraints
    #[test]
    fn test_keccak_prover_constraints() {
        // guaranteed to have at least 30MB of stack
        stacker::grow(30 * 1024 * 1024, || {
            let mut rng = o1_utils::tests::make_test_rng(None);
            let domain_size = 1 << 8;

            // Generate 3 blocks of preimage data
            let bytelength = rng.gen_range(2 * RATE_IN_BYTES..RATE_IN_BYTES * 3);
            let preimage: Vec<u8> = (0..bytelength).map(|_| rng.gen()).collect();

            // Initialize the environment and run the interpreter
            let mut keccak_env = KeccakEnv::<Fp>::new(0, &preimage);

            // Keep track of the constraints and lookups of the sub-circuits
            let mut keccak_circuit =
                <DecomposedKeccakTrace as DecomposableTracer<KeccakEnv<Fp>>>::new(
                    domain_size,
                    &mut keccak_env,
                );

            while keccak_env.step.is_some() {
                let step = keccak_env.selector();

                // Run the interpreter, which sets the witness columns
                keccak_env.step();

                // Add the witness row to the circuit
                keccak_circuit.push_row(step, &keccak_env.witness_env.witness.cols);
            }
            keccak_circuit.pad_witnesses();

            for step in Steps::iter().flat_map(|x| x.into_iter()) {
                if keccak_circuit.in_circuit(step) {
                    test_completeness_generic_no_lookups::<
                        N_ZKVM_KECCAK_COLS,
                        N_ZKVM_KECCAK_REL_COLS,
                        N_ZKVM_KECCAK_SEL_COLS,
                        0,
                        _,
                    >(
                        keccak_circuit[step].constraints.clone(),
                        Box::new([]),
                        keccak_circuit[step].witness.clone(),
                        domain_size,
                        &mut rng,
                    );
                }
            }
        });
    }

    fn dummy_constraints() -> BTreeMap<Steps, Vec<FoldingCompatibleExpr<KeccakConfig>>> {
        Steps::iter()
            .flat_map(|x| x.into_iter())
            .map(|step| {
                (
                    step,
                    vec![FoldingCompatibleExpr::<KeccakConfig>::Atom(
                        FoldingCompatibleExprInner::Constant(Fp::zero()),
                    )],
                )
            })
            .collect()
    }

    // (Instance, Witness)
    type KeccakFoldingSide = (
        <KeccakConfig as FoldingConfig>::Instance,
        <KeccakConfig as FoldingConfig>::Witness,
    );

    // (Step, Left, Right)
    type KeccakFoldingPair = (Steps, KeccakFoldingSide, KeccakFoldingSide);

    type KeccakDefaultFqSponge = DefaultFqSponge<ark_bn254::g1::Config, PlonkSpongeConstantsKimchi>;

    #[test]
    fn heavy_test_keccak_folding() {
        use crate::{keccak::folding::KeccakConfig, trace::Foldable, Curve};
        use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
        use folding::{checker::Checker, expressions::FoldingCompatibleExpr};
        use kimchi::curve::KimchiCurve;
        use mina_poseidon::FqSponge;
        use poly_commitment::kzg::PairingSRS;

        // guaranteed to have at least 30MB of stack
        stacker::grow(30 * 1024 * 1024, || {
            let mut rng = o1_utils::tests::make_test_rng(None);
            let domain_size = 1 << 6;

            let domain = D::<Fp>::new(domain_size).unwrap();
            let srs = PairingSRS::<Curve>::create(domain_size);
            srs.get_lagrange_basis(domain);

            // Create sponge
            let mut fq_sponge = BaseSponge::new(Curve::other_curve_sponge_params());

            // Create two instances for each selector to be folded
            let keccak_trace: [DecomposedKeccakTrace; 2] =
                array::from_fn(|_| create_trace_all_steps(domain_size, &mut rng));
            let trace = keccak_trace[0].clone();

            // Store all constraints indexed by Step
            let constraints = <DecomposedKeccakTrace as Foldable<
                N_ZKVM_KECCAK_COLS,
                KeccakConfig,
                BaseSponge,
            >>::folding_constraints(&trace);

            // DEFINITIONS OF FUNCTIONS FOR TESTING PURPOSES

            let check_instance_satisfy_constraints =
                |constraints: &[FoldingCompatibleExpr<KeccakConfig>], side: &KeccakFoldingSide| {
                    let (instance, witness) = side;
                    let checker = Provider::new(instance.clone(), witness.clone());
                    constraints.iter().for_each(|c| {
                        checker.check(c, domain);
                    });
                };

            let check_folding =
                |left: &KeccakFoldingSide,
                 right: &KeccakFoldingSide,
                 constraints: &[FoldingCompatibleExpr<KeccakConfig>],
                 fq_sponge: &mut KeccakDefaultFqSponge| {
                    // Create the folding scheme ignoring selectors
                    let (scheme, final_constraint) =
                        FoldingScheme::<KeccakConfig>::new(constraints.to_vec(), &srs, domain, &());

                    // Fold both sides and check the constraints ignoring the selector columns
                    let fout =
                        scheme.fold_instance_witness_pair(left.clone(), right.clone(), fq_sponge);

                    // We should always have 0 as the degree of the constraints,
                    // without selectors, they are never higher than 2 in Keccak.
                    assert_eq!(scheme.get_number_of_additional_columns(), 0);

                    let checker = ExtendedProvider::new(fout.folded_instance, fout.folded_witness);
                    checker.check(&final_constraint, domain);
                };

            let check_decomposable_folding_pair =
                |step: Option<Steps>,
                 left: &KeccakFoldingSide,
                 right: &KeccakFoldingSide,
                 scheme: &DecomposableFoldingScheme<KeccakConfig>,
                 final_constraint: &FoldingCompatibleExpr<KeccakConfig>,
                 quadri_cols: Option<usize>,
                 fq_sponge: &mut KeccakDefaultFqSponge| {
                    let fout = scheme.fold_instance_witness_pair(
                        left.clone(),
                        right.clone(),
                        step,
                        fq_sponge,
                    );

                    let extra_cols = scheme.get_number_of_additional_columns();
                    if let Some(quadri_cols) = quadri_cols {
                        assert!(extra_cols == quadri_cols);
                    }

                    // Check the constraints on the folded circuit applying selectors
                    let checker = ExtendedProvider::<KeccakConfig>::new(
                        fout.folded_instance,
                        fout.folded_witness,
                    );
                    checker.check(final_constraint, domain);
                };

            let check_decomposable_folding =
                |pair: &KeccakFoldingPair,
                 constraints: BTreeMap<Steps, Vec<FoldingCompatibleExpr<KeccakConfig>>>,
                 common_constraints: Vec<FoldingCompatibleExpr<KeccakConfig>>,
                 quadri_cols: Option<usize>,
                 fq_sponge: &mut KeccakDefaultFqSponge| {
                    let (step, left, right) = pair;
                    let (dec_scheme, dec_final_constraint) =
                        DecomposableFoldingScheme::<KeccakConfig>::new(
                            constraints,
                            common_constraints,
                            &srs,
                            domain,
                            &(),
                        );
                    // Subcase A: Check the folded circuit of decomposable folding ignoring selectors (None)
                    check_decomposable_folding_pair(
                        None,
                        left,
                        right,
                        &dec_scheme,
                        &dec_final_constraint,
                        quadri_cols,
                        fq_sponge,
                    );
                    // Subcase B: Check the folded circuit of decomposable folding applying selectors (Some)
                    check_decomposable_folding_pair(
                        Some(*step),
                        left,
                        right,
                        &dec_scheme,
                        &dec_final_constraint,
                        quadri_cols,
                        fq_sponge,
                    );
                };

            let check_decomposable_folding_mix =
                |steps: (Steps, Steps), fq_sponge: &mut KeccakDefaultFqSponge| {
                    let (dec_scheme, dec_final_constraint) =
                        DecomposableFoldingScheme::<KeccakConfig>::new(
                            constraints.clone(),
                            vec![],
                            &srs,
                            domain,
                            &(),
                        );
                    let left = {
                        let fout = dec_scheme.fold_instance_witness_pair(
                            keccak_trace[0].to_folding_pair(steps.0, fq_sponge, domain, &srs),
                            keccak_trace[1].to_folding_pair(steps.0, fq_sponge, domain, &srs),
                            Some(steps.0),
                            fq_sponge,
                        );
                        let checker = ExtendedProvider::<KeccakConfig>::new(
                            fout.folded_instance,
                            fout.folded_witness,
                        );
                        (checker.instance, checker.witness)
                    };
                    let right = {
                        let fout = dec_scheme.fold_instance_witness_pair(
                            keccak_trace[0].to_folding_pair(steps.1, fq_sponge, domain, &srs),
                            keccak_trace[1].to_folding_pair(steps.1, fq_sponge, domain, &srs),
                            Some(steps.1),
                            fq_sponge,
                        );
                        let checker = ExtendedProvider::<KeccakConfig>::new(
                            fout.folded_instance,
                            fout.folded_witness,
                        );
                        (checker.instance, checker.witness)
                    };
                    let fout = dec_scheme.fold_instance_witness_pair(left, right, None, fq_sponge);
                    let checker = ExtendedProvider::new(fout.folded_instance, fout.folded_witness);
                    checker.check(&dec_final_constraint, domain);
                };

            // HERE STARTS THE TESTING

            // Sanity checks that the number of constraints are as expected for each step
            assert_eq!(constraints[&Sponge(Absorb(First))].len(), 332);
            assert_eq!(constraints[&Sponge(Absorb(Middle))].len(), 232);
            assert_eq!(constraints[&Sponge(Absorb(Last))].len(), 374);
            assert_eq!(constraints[&Sponge(Absorb(Only))].len(), 474);
            assert_eq!(constraints[&Sponge(Squeeze)].len(), 16);
            assert_eq!(constraints[&Round(0)].len(), 389);

            // Total number of Keccak constraints of degree higher than 2 (should be 0)
            let total_deg_higher_2 =
                Steps::iter()
                    .flat_map(|x| x.into_iter())
                    .fold(0, |acc, step| {
                        acc + trace[step]
                            .constraints
                            .iter()
                            .filter(|c| c.degree(1, 0) > 2)
                            .count()
                    });
            assert_eq!(total_deg_higher_2, 0);

            // Check folding constraints of individual steps ignoring selectors
            for step in Steps::iter().flat_map(|x| x.into_iter()) {
                // BTreeMap with constraints of this step
                let mut step_constraints = BTreeMap::new();
                step_constraints.insert(step, constraints[&step].clone());

                // Create sides for folding
                let left = keccak_trace[0].to_folding_pair(step, &mut fq_sponge, domain, &srs);
                let right = keccak_trace[1].to_folding_pair(step, &mut fq_sponge, domain, &srs);

                // CASE 0: Check instances satisfy the constraints, without folding them
                check_instance_satisfy_constraints(&constraints[&step], &left);
                check_instance_satisfy_constraints(&constraints[&step], &right);

                // CASE 1: Check constraints on folded circuit ignoring selectors with `FoldingScheme`
                check_folding(&left, &right, &constraints[&step], &mut fq_sponge);

                // CASE 2: Check that `DecomposableFoldingScheme` works when passing the dummy zero constraint
                //         to each step, and an empty list of common constraints.
                let pair = (step, left, right);
                check_decomposable_folding(
                    &pair,
                    dummy_constraints(),
                    vec![],
                    Some(0),
                    &mut fq_sponge,
                );

                // CASE 3: Using a separate `DecomposableFoldingScheme` for each step, check each step
                //         constraints using a dummy BTreeMap of `vec[0]` per-step constraints and
                //         common constraints set to each selector's constraints.
                check_decomposable_folding(
                    &pair,
                    dummy_constraints(),
                    step_constraints[&step].clone(),
                    Some(0),
                    &mut fq_sponge,
                );

                // CASE 4: Using the same `DecomposableFoldingScheme` for all steps, initialized with a real
                //         BTreeMap of only the current step, and common constraints set to `vec[]`, check
                //         the folded circuit
                check_decomposable_folding(
                    &pair,
                    step_constraints.clone(),
                    vec![],
                    None,
                    &mut fq_sponge,
                );

                // CASE 5: Using the same `DecomposableFoldingScheme` for all steps, initialized with a real
                //         BTreeMap of constraints per-step, and common constraints set to `vec[]`, check
                //         the folded circuit
                check_decomposable_folding(
                    &pair,
                    constraints.clone(),
                    vec![],
                    Some(151),
                    &mut fq_sponge,
                );
            }
            // CASE 6: Fold mixed steps together and check the final constraints
            check_decomposable_folding_mix((Sponge(Absorb(First)), Round(0)), &mut fq_sponge);
        });
    }
}
