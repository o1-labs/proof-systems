//! Entry point for running zkApps with the Arrabbiata IVC scheme.
//!
//! This binary allows selecting a circuit to fold, specifying the number of
//! iterations, and measuring the performance of the folding scheme.
//!
//! ## Usage
//!
//! ```bash
//! # Run 10 iterations of the squaring circuit with SRS size 2^8
//! cargo run --release -p arrabbiata -- execute --circuit squaring -n 10 --srs-size 8
//!
//! # Run Fibonacci circuit
//! cargo run --release -p arrabbiata -- execute --circuit fibonacci -n 5 --srs-size 8
//!
//! # Run cubic circuit
//! cargo run --release -p arrabbiata -- execute --circuit cubic -n 10 --srs-size 8
//! ```
//!
//! ## Available Circuits
//!
//! - `trivial`: Identity circuit z_{i+1} = z_i
//! - `squaring`: Squaring circuit z_{i+1} = z_i^2
//! - `cubic`: Cubic circuit z_{i+1} = z_i^3 + z_i + 5
//! - `square-cubic`: Composed circuit x -> x^6 + x^2 + 5
//! - `fibonacci`: Fibonacci sequence (x, y) -> (y, x + y)
//! - `counter`: Counter circuit z_{i+1} = z_i + 1
//! - `minroot`: MinRoot VDF computing 5th roots
//! - `hashchain`: Hash chain circuit z_{i+1} = hash(z_i)

use arrabbiata::{
    cli,
    decider::{
        prover::prove,
        verifier::{verify, VerificationKey},
    },
    registry::CircuitRegistry,
    setup::IndexedRelation,
    witness, MIN_SRS_LOG2_SIZE,
};
use clap::Parser;
use log::info;
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
use num_bigint::BigInt;
use std::time::Instant;

pub fn execute(args: cli::ExecuteArgs) {
    let registry = CircuitRegistry::default();

    // Handle --list-circuits flag
    if args.list_circuits {
        println!("Available circuits:\n");
        for (name, info) in registry.circuits() {
            println!("  {}", name);
            println!("    {}", info.description);
            println!(
                "    arity: {}, degree: {}, constraints: {}, rows: {}, min-srs: {}",
                info.arity,
                info.max_degree,
                info.num_constraints,
                info.rows_per_fold,
                info.min_srs_log2_size()
            );
            println!();
        }
        return;
    }

    // Validate circuit name
    if let Err(e) = args.validate_circuit(&registry) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    // These are required unless --list-circuits is used
    let srs_log2_size = args.srs_size.expect("srs-size is required");
    let n_iterations = args.n.expect("n is required");
    let circuit = &args.circuit;

    assert!(
        srs_log2_size >= MIN_SRS_LOG2_SIZE,
        "SRS size must be at least 2^{MIN_SRS_LOG2_SIZE} to support the verifier circuit size"
    );

    info!(
        "Executing circuit '{}' for {} iterations with SRS of size 2^{}",
        circuit, n_iterations, srs_log2_size
    );

    // Setup phase
    let setup_start = Instant::now();
    let indexed_relation = IndexedRelation::new(srs_log2_size);
    let setup_time = setup_start.elapsed();
    info!("Setup completed in {:?}", setup_time);

    // Create environment
    let mut env = witness::Env::<Fp, Fq, Vesta, Pallas>::new(BigInt::from(1u64), indexed_relation);

    // Folding phase
    let fold_start = Instant::now();
    env.fold(n_iterations);
    let fold_time = fold_start.elapsed();
    info!(
        "Folding {} iterations completed in {:?} ({:.2} ms/iteration)",
        n_iterations,
        fold_time,
        fold_time.as_millis() as f64 / n_iterations as f64
    );

    // Prove phase
    let prove_start = Instant::now();
    let proof = prove(&env).expect("Proof generation should succeed");
    let prove_time = prove_start.elapsed();
    info!("Proof generation completed in {:?}", prove_time);

    // Print proof statistics
    info!("Proof statistics:");
    info!("  - Iterations: {}", proof.num_iterations);
    info!("  - Proof size: {} bytes", proof.estimated_size());
    info!(
        "  - E1 witness commitments: {}",
        proof.instance_e1.witness_commitments.len()
    );
    info!(
        "  - E2 witness commitments: {}",
        proof.instance_e2.witness_commitments.len()
    );
    info!(
        "  - E1 cross-term commitments: {}",
        proof.instance_e1.cross_term_commitments.len()
    );
    info!(
        "  - E2 cross-term commitments: {}",
        proof.instance_e2.cross_term_commitments.len()
    );

    // Verify phase
    let verify_start = Instant::now();
    let vk = VerificationKey::from_indexed_relation(&env.indexed_relation);
    let verify_result = verify(&vk, &proof);
    let verify_time = verify_start.elapsed();

    match &verify_result {
        Ok(()) => info!("Verification completed in {:?}: PASSED", verify_time),
        Err(e) => info!(
            "Verification completed in {:?}: FAILED - {}",
            verify_time, e
        ),
    }

    // Total timing summary
    let total_time = setup_time + fold_time + prove_time + verify_time;
    info!("Total execution time: {:?}", total_time);

    // Exit with error if verification failed
    if verify_result.is_err() {
        std::process::exit(1);
    }

    // Note: Regression tests for challenge values are in the integration tests
    // where we can control the SRS seed for reproducibility.
}

pub fn main() {
    // See https://github.com/rust-lang/log
    env_logger::init();

    let args = cli::Commands::parse();
    match args {
        cli::Commands::Execute(args) => execute(args),
    }
}
