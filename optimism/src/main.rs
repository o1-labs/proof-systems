use ark_ec::bn::Bn;
<<<<<<< HEAD
use kimchi_optimism::{
    cannon::{self, Meta, Start, State},
    cannon_cli,
=======
use ark_ff::{UniformRand, Zero};
use kimchi_optimism::{
    cannon::{self, Meta, Start, State},
    cannon_cli,
    keccak::interpreter::KeccakInterpreter,
>>>>>>> master
    mips::{proof, witness},
    preimage_oracle::PreImageOracle,
};
use poly_commitment::pairing_proof::PairingProof;
use std::{fs::File, io::BufReader, process::ExitCode};

<<<<<<< HEAD
=======
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

>>>>>>> master
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

<<<<<<< HEAD
    let domain_size = 1 << 15;
=======
    let domain_size = DOMAIN_SIZE;
>>>>>>> master

    let domain =
        kimchi::circuits::domains::EvaluationDomains::<ark_bn254::Fr>::create(domain_size).unwrap();

    let srs = {
<<<<<<< HEAD
        use ark_ff::UniformRand;

=======
>>>>>>> master
        // Trusted setup toxic waste
        let x = ark_bn254::Fr::rand(&mut rand::rngs::OsRng);

        let mut srs = poly_commitment::pairing_proof::PairingSRS::create(x, domain_size);
        srs.full_srs.add_lagrange_basis(domain.d1);
        srs
    };

    let mut env = witness::Env::<ark_bn254::Fr>::create(cannon::PAGE_SIZE as usize, state, po);

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

<<<<<<< HEAD
    use mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi,
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };
    type Fp = ark_bn254::Fr;
    type SpongeParams = PlonkSpongeConstantsKimchi;
    type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;
    type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
    type OpeningProof = PairingProof<Bn<ark_bn254::Parameters>>;

    while !env.halt {
        env.step(&configuration, &meta, &start);
=======
    while !env.halt {
        env.step(&configuration, &meta, &start);

        if let Some(ref mut keccak_env) = env.keccak_env {
            // Run all steps of hash
            while keccak_env.keccak_step.is_some() {
                keccak_env.step();
            }

            // TODO: update the witness with the Keccak step columns before resetting the environment
            // TODO: create READ lookup tables

            // When the Keccak interpreter is finished, we can reset the environment
            env.keccak_env = None;
        }

>>>>>>> master
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
<<<<<<< HEAD
        use ark_ff::UniformRand;
        current_pre_folding_witness
            .error
            .push(ark_bn254::Fr::rand(&mut rand::rngs::OsRng));
        if current_pre_folding_witness.instruction_counter.len() == 1 << 15 {
=======
        current_pre_folding_witness
            .error
            .push(ark_bn254::Fr::rand(&mut rand::rngs::OsRng));
        if current_pre_folding_witness.instruction_counter.len() == DOMAIN_SIZE {
>>>>>>> master
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
<<<<<<< HEAD
        use ark_ff::Zero;
=======
>>>>>>> master
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
        let proof =
            proof::prove::<_, OpeningProof, BaseSponge, ScalarSponge>(domain, &srs, folded_witness);
        println!("Generated a proof:\n{:?}", proof);
        let verifies =
            proof::verify::<_, OpeningProof, BaseSponge, ScalarSponge>(domain, &srs, &proof);
        if verifies {
            println!("The proof verifies")
        } else {
            println!("The proof doesn't verify")
        }
    }

    // TODO: Logic
    ExitCode::SUCCESS
}
