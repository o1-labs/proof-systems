use kimchi_optimism::{
    cannon::{self, Meta, Start, State},
    cannon_cli,
    mips::{proof, witness},
    preimage_oracle::PreImageOracle,
};
use std::{fs::File, io::BufReader, process::ExitCode};

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

    let domain_size = 1 << 15;

    let domain =
        kimchi::circuits::domains::EvaluationDomains::<ark_bn254::Fr>::create(domain_size).unwrap();

    let srs = {
        use ark_ff::UniformRand;

        // Trusted setup toxic waste
        let x = ark_bn254::Fr::rand(&mut rand::rngs::OsRng);

        let mut srs = poly_commitment::pairing_proof::PairingSRS::create(x, domain_size);
        srs.full_srs.add_lagrange_basis(domain.d1);
        srs
    };

    let mut env = witness::Env::<ark_bn254::Fr>::create(cannon::PAGE_SIZE as usize, state, po);

    let mut accumulator = proof::ProofInputs::<
        ark_ec::short_weierstrass_jacobian::GroupAffine<ark_bn254::g1::Parameters>,
    >::new();

    let new_chunk = || proof::WitnessColumns {
        scratch: std::array::from_fn(|_| Vec::with_capacity(domain_size)),
        instruction_counter: Vec::with_capacity(domain_size),
        error: Vec::with_capacity(domain_size),
    };

    let mut current_chunk = new_chunk();

    use mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi,
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };
    type Fp = ark_bn254::Fr;
    type SpongeParams = PlonkSpongeConstantsKimchi;
    type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;
    type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

    while !env.halt {
        env.step(&configuration, &meta, &start);
        for (scratch, scratch_chunk) in env
            .scratch_state
            .iter()
            .zip(current_chunk.scratch.iter_mut())
        {
            scratch_chunk.push(*scratch);
        }
        current_chunk
            .instruction_counter
            .push(ark_bn254::Fr::from(env.instruction_counter as u64));
        // TODO
        use ark_ff::UniformRand;
        current_chunk
            .error
            .push(ark_bn254::Fr::rand(&mut rand::rngs::OsRng));
        if current_chunk.instruction_counter.len() == 1 << 15 {
            proof::fold::<
                _,
                poly_commitment::pairing_proof::PairingProof<ark_ec::bn::Bn<ark_bn254::Parameters>>,
                BaseSponge,
                ScalarSponge,
            >(domain, &srs, &mut accumulator, current_chunk);
            current_chunk = new_chunk();
        }
    }
    if current_chunk.instruction_counter.len() > 0 {
        proof::fold::<
            _,
            poly_commitment::pairing_proof::PairingProof<ark_ec::bn::Bn<ark_bn254::Parameters>>,
            BaseSponge,
            ScalarSponge,
        >(domain, &srs, &mut accumulator, current_chunk);
    }

    {
        let proof = proof::prove::<
            _,
            poly_commitment::pairing_proof::PairingProof<ark_ec::bn::Bn<ark_bn254::Parameters>>,
            BaseSponge,
            ScalarSponge,
        >(domain, &srs, accumulator);
        println!("Generated a proof:\n{:?}", proof);
        let verifies = proof::verify::<
            _,
            poly_commitment::pairing_proof::PairingProof<ark_ec::bn::Bn<ark_bn254::Parameters>>,
            BaseSponge,
            ScalarSponge,
        >(domain, &srs, &proof);
        if verifies {
            println!("The proof verifies")
        } else {
            println!("The proof doesn't verify")
        }
    }

    // TODO: Logic
    ExitCode::SUCCESS
}
