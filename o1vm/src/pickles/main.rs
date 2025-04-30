use ark_ff::{One, UniformRand, Zero};
use clap::Parser;
use kimchi::{circuits::domains::EvaluationDomains, curve::KimchiCurve, precomputed_srs::TestSRS};
use log::debug;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use o1vm::{
    cannon::{self, Start, State},
    cli, elf_loader,
    interpreters::mips::{
        column::{N_MIPS_REL_COLS, N_MIPS_SEL_COLS},
        constraints as mips_constraints,
        witness::{self as mips_witness},
        Instruction,
    },
    pickles::{
        lookup_columns::LookupProofInput,
        lookup_env::LookupEnvironment,
        lookup_prover::{lookup_prove_fst_part, lookup_prove_snd_part},
        lookup_verifier::lookup_verify,
        multiplicities_columns::{inverses_constraint, MultiplicitiesProofInput},
        multiplicities_prover::{multiplicitie_prove_fst_part, multiplicities_prove_snd_part},
        multiplicities_verifier::multiplicities_verify,
        proof::ProofInputs,
        prover, verifier,
    },
    preimage_oracle::{NullPreImageOracle, PreImageOracle, PreImageOracleT},
    test_preimage_read, E,
};
use poly_commitment::{commitment::absorb_commitment, ipa::SRS, PolyComm, SRS as _};
use rand::rngs::ThreadRng;
use std::{
    collections::HashSet, fs::File, io::BufReader, path::Path, process::ExitCode, time::Instant,
};

pub fn cannon_main(args: cli::cannon::RunArgs) {
    let mut rng = rand::thread_rng();

    let configuration: cannon::VmConfiguration = args.vm_cfg.into();

    let file =
        File::open(&configuration.input_state_file).expect("Error opening input state file ");

    let reader = BufReader::new(file);
    // Read the JSON contents of the file as an instance of `State`.
    let state: State = serde_json::from_reader(reader).expect("Error reading input state file");
    let state_lookup = state.clone();
    let meta = &configuration.metadata_file.as_ref().map(|f| {
        let meta_file =
            File::open(f).unwrap_or_else(|_| panic!("Could not open metadata file {}", f));
        serde_json::from_reader(BufReader::new(meta_file))
            .unwrap_or_else(|_| panic!("Error deserializing metadata file {}", f))
    });

    // Initialize some data used for statistical computations
    let start = Start::create(state.step as usize);

    let (srs, domain_fp) = match &args.srs_cache {
        Some(cache) => {
            debug!("Loading SRS from cache {}", cache);
            let file_path = Path::new(cache);
            let file = File::open(file_path).expect("Error opening SRS cache file");
            let srs: SRS<Vesta> = {
                // By convention, proof systems serializes a TestSRS with filename 'test_<CURVE_NAME>.srs'.
                // The benefit of using this is you don't waste time verifying the SRS.
                if file_path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("test_")
                {
                    let test_srs: TestSRS<Vesta> = rmp_serde::from_read(&file).unwrap();
                    From::from(test_srs)
                } else {
                    rmp_serde::from_read(&file).unwrap()
                }
            };
            debug!("SRS loaded successfully from cache");
            let domain_fp = EvaluationDomains::<Fp>::create(srs.size()).unwrap();
            (srs, domain_fp)
        }
        None => {
            debug!("No SRS cache provided. Creating SRS from scratch with domain size 2^16");
            let domain_size = 1 << 16;
            let srs = SRS::create(domain_size);
            let domain_fp = EvaluationDomains::<Fp>::create(srs.size()).unwrap();
            srs.get_lagrange_basis(domain_fp.d1);
            debug!("SRS created successfully");
            (srs, domain_fp)
        }
    };

    // Initialize the environments
    let mut mips_wit_env = match configuration.host.clone() {
        Some(host) => {
            let mut po = PreImageOracle::create(host);
            let _child = po.start();
            mips_witness::Env::<Fp, Box<dyn PreImageOracleT>>::create(
                cannon::PAGE_SIZE as usize,
                state,
                Box::new(po),
            )
        }
        None => {
            debug!("No preimage oracle provided 🤞");
            // warning: the null preimage oracle has no data and will crash the program if used
            mips_witness::Env::<Fp, Box<dyn PreImageOracleT>>::create(
                cannon::PAGE_SIZE as usize,
                state,
                Box::new(NullPreImageOracle),
            )
        }
    };
    let mut instruction_set = HashSet::new();
    let domain_size = domain_fp.d1.size as usize;
    let lookup_env = &mut LookupEnvironment::new(&srs, domain_fp);

    let mut curr_proof_inputs: ProofInputs<Vesta> = ProofInputs::new(domain_size);
    // First loop, do the proof without lookup
    while !mips_wit_env.halt {
        let (instr, counter) = mips_wit_env.step(&configuration, meta, &start);
        instruction_set.insert(instr);
        for (scratch, scratch_chunk) in mips_wit_env
            .scratch_state
            .iter()
            .zip(curr_proof_inputs.evaluations.scratch.iter_mut())
        {
            scratch_chunk.push(*scratch);
        }
        for (scratch, scratch_chunk) in mips_wit_env
            .scratch_state_inverse
            .iter()
            .zip(curr_proof_inputs.evaluations.scratch_inverse.iter_mut())
        {
            scratch_chunk.push(*scratch);
        }
        // Lookup state
        {
            let proof_inputs_length = curr_proof_inputs.evaluations.lookup_state.len();
            let environment_length = mips_wit_env.lookup_state.len();
            let lookup_state_size = std::cmp::max(proof_inputs_length, environment_length);
            for idx in 0..lookup_state_size {
                if idx >= environment_length {
                    // We pad with 0s for dummy lookups missing from the environment.
                    curr_proof_inputs.evaluations.lookup_state[idx].push(Fp::zero());
                } else if idx >= proof_inputs_length {
                    // We create a new column filled with 0s in the proof inputs.
                    let mut new_vec =
                        vec![Fp::zero(); curr_proof_inputs.evaluations.instruction_counter.len()];
                    new_vec.push(Fp::from(mips_wit_env.lookup_state[idx]));
                    curr_proof_inputs.evaluations.lookup_state.push(new_vec);
                } else {
                    // Push the value to the column.
                    curr_proof_inputs.evaluations.lookup_state[idx]
                        .push(Fp::from(mips_wit_env.lookup_state[idx]));
                }
            }
        }

        curr_proof_inputs
            .evaluations
            .instruction_counter
            .push(Fp::from(counter as u64));
        // FIXME: Might be another value
        curr_proof_inputs.evaluations.error.push(Fp::rand(&mut rng));

        curr_proof_inputs
            .evaluations
            .selector
            .push(Fp::from((mips_wit_env.selector - N_MIPS_REL_COLS) as u64));

        if curr_proof_inputs.evaluations.instruction_counter.len() == domain_size {
            prove_and_verify(
                domain_fp,
                &srs,
                &mips_constraints::get_constraints(instruction_set),
                curr_proof_inputs,
                &mut rng,
                lookup_env,
            );

            curr_proof_inputs = ProofInputs::new(domain_size);
            instruction_set = HashSet::new();
        }
    }
    if curr_proof_inputs.evaluations.instruction_counter.len() < domain_size {
        debug!("Padding witness for proof generation");
        pad(&mips_wit_env, &mut curr_proof_inputs, &mut rng);
        prove_and_verify(
            domain_fp,
            &srs,
            &mips_constraints::get_constraints(instruction_set),
            curr_proof_inputs,
            &mut rng,
            // FIXME: we use a dummy lookup env here,
            // we do not pad the lookup arg yet
            &mut LookupEnvironment::new(&srs, domain_fp),
        );
    }
    // Second loop, do the lookup delayed argument
    // TODO: use a lighter interpreter specialised for lookups

    // Prepare the sponge
    let sponge = &mut DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
        Vesta::other_curve_sponge_params(),
    );
    lookup_env
        .cms
        .iter()
        .for_each(|cm_list| cm_list.iter().for_each(|cm| absorb_commitment(sponge, cm)));

    // TODO use lookup proof input type, containing the arity
    curr_proof_inputs = ProofInputs::new(domain_size);
    let mut arity: Vec<Vec<usize>> = vec![];
    let mut acc = Fp::zero();

    // Initialize the environments
    let mut mips_wit_env = match configuration.host.clone() {
        Some(host) => {
            let mut po = PreImageOracle::create(host);
            let _child = po.start();
            mips_witness::Env::<Fp, Box<dyn PreImageOracleT>>::create(
                cannon::PAGE_SIZE as usize,
                state_lookup,
                Box::new(po),
            )
        }
        None => {
            debug!("No preimage oracle provided 🤞");
            // warning: the null preimage oracle has no data and will crash the program if used
            mips_witness::Env::<Fp, Box<dyn PreImageOracleT>>::create(
                cannon::PAGE_SIZE as usize,
                state_lookup,
                Box::new(NullPreImageOracle),
            )
        }
    };
    instruction_set = HashSet::new();
    while !mips_wit_env.halt {
        let (instr, _) = mips_wit_env.step(&configuration, meta, &start);
        instruction_set.insert(instr);
        // TODO factorise the addtion of the wit env to the proof input in a seprate function
        // Lookup state
        // TODO factorise padding of lookup in a separate function
        {
            let proof_inputs_length = curr_proof_inputs.evaluations.lookup_state.len();
            let environment_length = mips_wit_env.lookup_state.len();
            let lookup_state_size = std::cmp::max(proof_inputs_length, environment_length);
            for idx in 0..lookup_state_size {
                if idx >= environment_length {
                    // We pad with 0s for dummy lookups missing from the environment.
                    curr_proof_inputs.evaluations.lookup_state[idx].push(Fp::zero());
                } else if idx >= proof_inputs_length {
                    // We create a new column filled with 0s in the proof inputs.
                    let mut new_vec =
                        vec![Fp::zero(); curr_proof_inputs.evaluations.instruction_counter.len()];
                    new_vec.push(Fp::from(mips_wit_env.lookup_state[idx]));
                    curr_proof_inputs.evaluations.lookup_state.push(new_vec);
                } else {
                    // Push the value to the column.
                    curr_proof_inputs.evaluations.lookup_state[idx]
                        .push(Fp::from(mips_wit_env.lookup_state[idx]));
                }
            }
            // TODO: understand why we need to update the instruction counter
            curr_proof_inputs
                .evaluations
                .instruction_counter
                .push(Fp::from(mips_wit_env.instruction_counter));
            arity.push(mips_wit_env.lookup_arity.clone());
            lookup_env.add_multiplicities(mips_wit_env.lookup_multiplicities.clone());
        }

        // TODO add selectors to proof input

        // TODO get rid of this rng creation
        let rng = &mut rand::thread_rng();
        // The padding does not add a lookup column.
        // We do the following to avoid an exception when
        // accessing lookup_state[0]
        let len = if curr_proof_inputs.evaluations.lookup_state.is_empty() {
            0
        } else {
            curr_proof_inputs.evaluations.lookup_state[0].len()
        };
        if len == domain_size {
            acc = lookup_prove_and_verify(
                domain_fp,
                &srs,
                curr_proof_inputs,
                arity,
                rng,
                sponge.clone(),
                acc,
                // TODO O(n) complexity, use a better data structure
                lookup_env.cms.remove(0),
                instruction_set,
            );

            // Reset the env
            instruction_set = HashSet::new();
            curr_proof_inputs = ProofInputs::new(domain_size);
            arity = vec![];
        }
    }
    //TODO pad and do last iteration
    // Substract multiplicities
    // TODO pass a ref to the env to the prover
    let lookup_env = lookup_env.clone();
    let _final_acc =
        multiplicities_prove_and_verify(domain_fp, &srs, lookup_env, &mut rng, sponge.clone(), acc);
}

fn prove_and_verify(
    domain_fp: EvaluationDomains<Fp>,
    srs: &SRS<Vesta>,
    constraints: &[E<Fp>],
    curr_proof_inputs: ProofInputs<Vesta>,
    rng: &mut ThreadRng,
    lookup_env: &mut LookupEnvironment<Vesta>,
) {
    let start_iteration = Instant::now();
    let proof = prover::prove::<
        Vesta,
        DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>,
        DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>,
        _,
    >(domain_fp, srs, curr_proof_inputs, constraints, rng)
    .unwrap();
    debug!(
        "Proof generated in {elapsed} μs",
        elapsed = start_iteration.elapsed().as_micros()
    );
    let start_iteration = Instant::now();
    // update the lookup env
    lookup_env.add_cms(&proof.commitments.lookup_state);
    let verif = verifier::verify::<
        Vesta,
        DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>,
        DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>,
    >(domain_fp, srs, constraints, &proof);
    debug!(
        "Verification done in {elapsed} μs",
        elapsed = start_iteration.elapsed().as_micros()
    );
    assert!(verif);
}

#[allow(clippy::too_many_arguments)]
fn lookup_prove_and_verify(
    domain_fp: EvaluationDomains<Fp>,
    srs: &SRS<Vesta>,
    curr_proof_inputs: ProofInputs<Vesta>,
    arity: Vec<Vec<usize>>,
    rng: &mut ThreadRng,
    mut sponge: DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>,
    acc_init: Fp,
    cm_wires: Vec<PolyComm<Vesta>>,
    instruction_set: HashSet<Instruction>,
) -> Fp {
    let start_iteration = Instant::now();
    // Build the selectors
    let mut dynamicselectors = (0..N_MIPS_SEL_COLS)
        .map(|_| Vec::with_capacity(1 << 16))
        .collect::<Vec<_>>();
    for i in &curr_proof_inputs.evaluations.selector {
        for (j, s) in dynamicselectors.iter_mut().enumerate() {
            s.push(if &Fp::from(j as u64) == i {
                Fp::one()
            } else {
                Fp::zero()
            })
        }
    }
    let sponge_verifier = sponge.clone();
    let beta_challenge = sponge.challenge();
    let gamma_challenge = sponge.challenge();
    let lookup_proof_input = LookupProofInput {
        beta_challenge,
        gamma_challenge,
        dynamicselectors,
        wires: curr_proof_inputs.evaluations.lookup_state,
        arity,
    };
    let (acc_final, state) =
        lookup_prove_fst_part::<Vesta>(&lookup_proof_input, acc_init, domain_fp);
    let constraints = mips_constraints::get_lookup_constraint(
        &domain_fp.d1,
        instruction_set,
        acc_init,
        acc_final,
    );
    let proof = lookup_prove_snd_part::<
        Vesta,
        DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>,
        DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>,
        ThreadRng,
    >(
        lookup_proof_input,
        srs,
        domain_fp,
        sponge,
        &constraints,
        rng,
        cm_wires,
        state,
    );
    debug!(
        "Lookup proof generated in {elapsed} μs",
        elapsed = start_iteration.elapsed().as_micros()
    );
    let start_iteration = Instant::now();
    let verif = lookup_verify::<
        Vesta,
        DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>,
        DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>,
    >(
        beta_challenge,
        gamma_challenge,
        constraints,
        sponge_verifier,
        domain_fp,
        srs,
        &proof,
    );
    assert!(verif);
    debug!(
        "Lookup verification done in {elapsed} μs",
        elapsed = start_iteration.elapsed().as_micros()
    );
    acc_final
}

fn multiplicities_prove_and_verify(
    domain_fp: EvaluationDomains<Fp>,
    srs: &SRS<Vesta>,
    lookup_env: LookupEnvironment<Vesta>,
    rng: &mut ThreadRng,
    mut sponge: DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>,
    acc_init: Fp,
) -> Fp {
    let start_iteration = Instant::now();

    let beta_challenge = sponge.challenge();
    let gamma_challenge = sponge.challenge();
    let sponge_verifier = sponge.clone();
    let proof_input = MultiplicitiesProofInput {
        beta_challenge,
        gamma_challenge,
        multiplicities: lookup_env
            .multiplicities
            .map(|vec| vec.into_iter().map(Fp::from).collect())
            .map(|mut vec: Vec<_>| {
                vec.extend(vec![Fp::zero(); domain_fp.d1.size as usize - vec.len()]);
                vec
            }),
        fixedlookup: lookup_env.tables,
        fixedlookup_transposed: lookup_env.tables_transposed,
        fixedlookupcommitment: lookup_env.tables_comm,
    };
    let (acc_final, state) =
        multiplicitie_prove_fst_part::<Vesta>(&proof_input, acc_init, domain_fp);
    let proof = multiplicities_prove_snd_part::<
        Vesta,
        DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>,
        DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>,
        ThreadRng,
    >(
        proof_input,
        srs,
        domain_fp,
        sponge,
        &inverses_constraint(),
        rng,
        state,
    );
    debug!(
        "Multiplicities proof generated in {elapsed} μs",
        elapsed = start_iteration.elapsed().as_micros()
    );
    let start_iteration = Instant::now();
    let verif = multiplicities_verify::<
        Vesta,
        DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>,
        DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>,
    >(
        beta_challenge,
        gamma_challenge,
        inverses_constraint(),
        sponge_verifier,
        domain_fp,
        srs,
        &proof,
    );
    assert!(verif);
    debug!(
        "Multiplicities verification done in {elapsed} μs",
        elapsed = start_iteration.elapsed().as_micros()
    );
    acc_final
}

fn pad(
    witness_env: &mips_witness::Env<Fp, Box<dyn PreImageOracleT>>,
    curr_proof_inputs: &mut ProofInputs<Vesta>,
    rng: &mut ThreadRng,
) {
    // FIXME, move that code in the witness interpreter of pad
    let zero = Fp::zero();
    // FIXME: Find a better way to get instruction selectors that doesn't
    // reveal internals.
    let pad_selector: Fp = {
        let pad: usize = Instruction::Pad.into();
        Fp::from((pad - N_MIPS_REL_COLS) as u64)
    };
    curr_proof_inputs
        .evaluations
        .scratch
        .iter_mut()
        .for_each(|x| x.resize(x.capacity(), zero));
    curr_proof_inputs
        .evaluations
        .scratch_inverse
        .iter_mut()
        .for_each(|x| x.resize(x.capacity(), zero));
    curr_proof_inputs.evaluations.instruction_counter.resize(
        curr_proof_inputs.evaluations.instruction_counter.capacity(),
        Fp::from(witness_env.instruction_counter),
    );
    curr_proof_inputs
        .evaluations
        .error
        .resize_with(curr_proof_inputs.evaluations.error.capacity(), || {
            Fp::rand(rng)
        });
    curr_proof_inputs.evaluations.selector.resize(
        curr_proof_inputs.evaluations.selector.capacity(),
        pad_selector,
    );
}

fn gen_state_json(arg: cli::cannon::GenStateJsonArgs) -> Result<(), String> {
    let path = Path::new(&arg.input);
    let state = elf_loader::parse_elf(elf_loader::Architecture::Mips, path)?;
    let file = File::create(&arg.output).expect("Error creating output state file");
    serde_json::to_writer_pretty(file, &state).expect("Error writing output state file");
    Ok(())
}

pub fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = cli::Commands::parse();
    match args {
        cli::Commands::Cannon(args) => match args {
            cli::cannon::Cannon::Run(args) => {
                cannon_main(args);
            }
            cli::cannon::Cannon::TestPreimageRead(args) => {
                test_preimage_read::main(args);
            }
            cli::cannon::Cannon::GenStateJson(args) => {
                gen_state_json(args).expect("Error generating state.json");
            }
        },
    }
    ExitCode::SUCCESS
}
