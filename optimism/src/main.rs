use ark_bn254::FrParameters;
use ark_ec::bn::Bn;
use ark_ff::{Fp256, UniformRand, Zero};
use kimchi_optimism::{
    cannon::{self, Meta, Start, State},
    cannon_cli,
    keccak::{
        column::KeccakWitness,
        interpreter::KeccakInterpreter,
        proof::{self as keccak_proof, KeccakProofInputs},
    },
    mips::{proof, witness as mips_witness},
    preimage_oracle::PreImageOracle,
};
use poly_commitment::pairing_proof::PairingProof;
use std::{fs::File, io::BufReader, process::ExitCode};

use kimchi_optimism::DOMAIN_SIZE;
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};

type Fp = ark_bn254::Fr;
type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
type OpeningProof = PairingProof<Bn<ark_bn254::Parameters>>;

pub fn main() -> ExitCode {
    let cli = cannon_cli::main_cli();

    let configuration = cannon_cli::read_configuration(&cli.get_matches());

    let file =
        File::open(&configuration.input_state_file).expect("Error opening input state file ");

    let reader = BufReader::new(file);
    // Read the JSON contents of the file as an instance of `State`.
    let state: State = serde_json::from_reader(reader).expect("Error reading input state file");

    let meta_file = File::open(&configuration.metadata_file).unwrap_or_else(|_| {
        panic!(
            "Could not open metadata file {}",
            &configuration.metadata_file
        )
    });

    let meta: Meta = serde_json::from_reader(BufReader::new(meta_file)).unwrap_or_else(|_| {
        panic!(
            "Error deserializing metadata file {}",
            &configuration.metadata_file
        )
    });

    let mut po = PreImageOracle::create(&configuration.host);
    let _child = po.start();

    // Initialize some data used for statistical computations
    let start = Start::create(state.step as usize);

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let domain_size = DOMAIN_SIZE;

    let domain =
        kimchi::circuits::domains::EvaluationDomains::<ark_bn254::Fr>::create(domain_size).unwrap();

    let srs = {
        // Trusted setup toxic waste
        let x = ark_bn254::Fr::rand(&mut rand::rngs::OsRng);

        let mut srs = poly_commitment::pairing_proof::PairingSRS::create(x, domain_size);
        srs.full_srs.add_lagrange_basis(domain.d1);
        srs
    };

    let mut env = mips_witness::Env::<ark_bn254::Fr>::create(cannon::PAGE_SIZE as usize, state, po);

    let mut folded_witness = proof::ProofInputs::<
        ark_ec::short_weierstrass_jacobian::GroupAffine<ark_bn254::g1::Parameters>,
    >::default();

    let reset_pre_folding_witness = |witness_columns: &mut proof::WitnessColumns<Vec<_>>| {
        let proof::WitnessColumns {
            scratch,
            instruction_counter,
            error,
        } = witness_columns;
        // Resize without deallocating
        scratch.iter_mut().for_each(Vec::clear);
        instruction_counter.clear();
        error.clear();
    };

    let mut current_pre_folding_witness = proof::WitnessColumns {
        scratch: std::array::from_fn(|_| Vec::with_capacity(domain_size)),
        instruction_counter: Vec::with_capacity(domain_size),
        error: Vec::with_capacity(domain_size),
    };

    // The keccak environment is extracted inside the loop

    let mut keccak_folded_witness = KeccakProofInputs::<
        ark_ec::short_weierstrass_jacobian::GroupAffine<ark_bn254::g1::Parameters>,
    >::default();

    let keccak_reset_pre_folding_witness =
        |keccak_columns: &mut KeccakWitness<Vec<Fp256<FrParameters>>>| {
            // Resize without deallocating
            keccak_columns.hash_index.clear();
            keccak_columns.step_index.clear();
            keccak_columns.mode_flags.iter_mut().for_each(Vec::clear);
            keccak_columns.curr.iter_mut().for_each(Vec::clear);
            keccak_columns.next.iter_mut().for_each(Vec::clear);
        };

    let mut keccak_current_pre_folding_witness: KeccakWitness<Vec<Fp256<FrParameters>>> =
        KeccakWitness {
            hash_index: Vec::with_capacity(domain_size),
            step_index: Vec::with_capacity(domain_size),
            mode_flags: std::array::from_fn(|_| Vec::with_capacity(domain_size)),
            curr: std::array::from_fn(|_| Vec::with_capacity(domain_size)),
            next: std::array::from_fn(|_| Vec::with_capacity(domain_size)),
        };

    while !env.halt {
        env.step(&configuration, &meta, &start);

        if let Some(ref mut keccak_env) = env.keccak_env {
            // Run all steps of hash
            while keccak_env.keccak_step.is_some() {
                keccak_env.step();
            }

            // Update the witness with the Keccak step columns before resetting the environment
            // TODO: simplify the contents of the KeccakWitness or create an iterator for it
            keccak_current_pre_folding_witness
                .hash_index
                .push(keccak_env.keccak_witness.hash_index);
            keccak_current_pre_folding_witness
                .step_index
                .push(keccak_env.keccak_witness.step_index);
            for (env_wit, pre_fold_wit) in keccak_env
                .keccak_witness
                .mode_flags
                .iter()
                .zip(keccak_current_pre_folding_witness.mode_flags.iter_mut())
            {
                pre_fold_wit.push(*env_wit);
            }
            for (env_wit, pre_fold_wit) in keccak_env
                .keccak_witness
                .curr
                .iter()
                .zip(keccak_current_pre_folding_witness.curr.iter_mut())
            {
                pre_fold_wit.push(*env_wit);
            }
            for (env_wit, pre_fold_wit) in keccak_env
                .keccak_witness
                .next
                .iter()
                .zip(keccak_current_pre_folding_witness.next.iter_mut())
            {
                pre_fold_wit.push(*env_wit);
            }

            if keccak_current_pre_folding_witness.step_index.len() == DOMAIN_SIZE {
                keccak_proof::fold::<_, OpeningProof, BaseSponge, ScalarSponge>(
                    domain,
                    &srs,
                    &mut keccak_folded_witness,
                    &keccak_current_pre_folding_witness,
                );
                keccak_reset_pre_folding_witness(&mut keccak_current_pre_folding_witness);
            }

            // TODO: create READ lookup tables

            // When the Keccak interpreter is finished, we can reset the environment
            env.keccak_env = None;
        }

        for (scratch, scratch_pre_folding_witness) in env
            .scratch_state
            .iter()
            .zip(current_pre_folding_witness.scratch.iter_mut())
        {
            scratch_pre_folding_witness.push(*scratch);
        }
        current_pre_folding_witness
            .instruction_counter
            .push(ark_bn254::Fr::from(env.instruction_counter));
        // TODO
        current_pre_folding_witness
            .error
            .push(ark_bn254::Fr::rand(&mut rand::rngs::OsRng));
        if current_pre_folding_witness.instruction_counter.len() == DOMAIN_SIZE {
            proof::fold::<_, OpeningProof, BaseSponge, ScalarSponge>(
                domain,
                &srs,
                &mut folded_witness,
                &current_pre_folding_witness,
            );
            reset_pre_folding_witness(&mut current_pre_folding_witness);
        }
    }
    if !current_pre_folding_witness.instruction_counter.is_empty() {
        let remaining = domain_size - current_pre_folding_witness.instruction_counter.len();
        for scratch in current_pre_folding_witness.scratch.iter_mut() {
            scratch.extend((0..remaining).map(|_| ark_bn254::Fr::zero()));
        }
        current_pre_folding_witness
            .instruction_counter
            .extend((0..remaining).map(|_| ark_bn254::Fr::zero()));
        current_pre_folding_witness
            .error
            .extend((0..remaining).map(|_| ark_bn254::Fr::zero()));
        proof::fold::<_, OpeningProof, BaseSponge, ScalarSponge>(
            domain,
            &srs,
            &mut folded_witness,
            &current_pre_folding_witness,
        );
    }

    {
        // MIPS
        let proof =
            proof::prove::<_, OpeningProof, BaseSponge, ScalarSponge>(domain, &srs, folded_witness);
        println!("Generated a proof:\n{:?}", proof);
        let verifies =
            proof::verify::<_, OpeningProof, BaseSponge, ScalarSponge>(domain, &srs, &proof);
        if verifies {
            println!("The MIPS proof verifies")
        } else {
            println!("The MIPS proof doesn't verify")
        }
    }

    {
        // KECCAK
        let keccak_proof = keccak_proof::prove::<_, OpeningProof, BaseSponge, ScalarSponge>(
            domain,
            &srs,
            keccak_folded_witness,
        );
        println!("Generated a proof:\n{:?}", keccak_proof);
        let verifies = keccak_proof::verify::<_, OpeningProof, BaseSponge, ScalarSponge>(
            domain,
            &srs,
            &keccak_proof,
        );
        if verifies {
            println!("The KECCAK proof verifies")
        } else {
            println!("The KECCAK proof doesn't verify")
        }
    }

    // TODO: Logic
    ExitCode::SUCCESS
}
