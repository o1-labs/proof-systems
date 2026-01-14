//! End-to-end tests for the prover module.
//!
//! These tests verify that:
//! 1. The folding loop runs correctly for multiple iterations
//! 2. The prover can extract accumulated state from the environment
//! 3. Proof size remains constant regardless of iteration count

use arrabbiata::{
    decider::prover::{prove, ProverError},
    setup::IndexedRelation,
    witness::Env,
    MIN_SRS_LOG2_SIZE,
};
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
use num_bigint::BigInt;
use std::time::Instant;

/// Expected proof size in bytes for the current circuit configuration.
/// This is a constant size regardless of the number of iterations (O(1) proof size).
/// Includes: witness commitments, error commitment, cross-term commitments (MAX_DEGREE - 1),
/// and challenge scalars for both curves.
const EXPECTED_PROOF_SIZE: usize = 3112;

/// Test that prover fails with NoIterations error when no iterations have been performed
#[test]
fn test_prover_fails_without_iterations() {
    let indexed_relation = IndexedRelation::new(MIN_SRS_LOG2_SIZE);
    let env: Env<Fp, Fq, Vesta, Pallas> = Env::new(BigInt::from(1u64), indexed_relation);

    // Attempt to prove should fail (no iterations performed)
    let result = prove(&env);
    assert!(
        matches!(result, Err(ProverError::NoIterations)),
        "Expected NoIterations error, got {:?}",
        result
    );
}

/// Test end-to-end folding with a small number of iterations
#[test]
fn test_e2e_folding_5_iterations() {
    let indexed_relation = IndexedRelation::new(MIN_SRS_LOG2_SIZE);
    let mut env: Env<Fp, Fq, Vesta, Pallas> = Env::new(BigInt::from(1u64), indexed_relation);

    // Run 5 folding iterations
    env.fold(5);

    // Prove
    let result = prove(&env);
    assert!(result.is_ok(), "Prove should succeed: {:?}", result);

    let proof = result.unwrap();
    assert_eq!(proof.num_iterations, 5);

    // Verify proof size is constant
    let size = proof.estimated_size();
    assert_eq!(
        size, EXPECTED_PROOF_SIZE,
        "Proof size should be {} bytes, got {}",
        EXPECTED_PROOF_SIZE, size
    );
}

/// Test end-to-end folding with 10 iterations and verify proof structure
#[test]
fn test_e2e_folding_10_iterations_proof_structure() {
    let indexed_relation = IndexedRelation::new(MIN_SRS_LOG2_SIZE);
    let mut env: Env<Fp, Fq, Vesta, Pallas> = Env::new(BigInt::from(1u64), indexed_relation);

    // Run 10 folding iterations
    env.fold(10);

    let proof = prove(&env).expect("Prove should succeed");

    // Verify proof structure
    assert_eq!(proof.num_iterations, 10);
    assert_eq!(
        proof.instance_e1.witness_commitments.len(),
        arrabbiata::NUMBER_OF_COLUMNS
    );
    assert_eq!(
        proof.instance_e2.witness_commitments.len(),
        arrabbiata::NUMBER_OF_COLUMNS
    );

    // Verify proof size is constant
    let size = proof.estimated_size();
    assert_eq!(
        size, EXPECTED_PROOF_SIZE,
        "Proof size should be {} bytes, got {}",
        EXPECTED_PROOF_SIZE, size
    );
}

/// Test that proof size remains constant regardless of iteration count.
/// This is the key property of folding schemes - proof size is O(1) not O(n).
#[test]
fn test_proof_size_is_constant() {
    // Run with 5 iterations
    let indexed_relation_5 = IndexedRelation::new(MIN_SRS_LOG2_SIZE);
    let mut env_5: Env<Fp, Fq, Vesta, Pallas> = Env::new(BigInt::from(1u64), indexed_relation_5);
    env_5.fold(5);
    let proof_5 = prove(&env_5).expect("Prove should succeed for 5 iterations");

    // Run with 10 iterations
    let indexed_relation_10 = IndexedRelation::new(MIN_SRS_LOG2_SIZE);
    let mut env_10: Env<Fp, Fq, Vesta, Pallas> = Env::new(BigInt::from(1u64), indexed_relation_10);
    env_10.fold(10);
    let proof_10 = prove(&env_10).expect("Prove should succeed for 10 iterations");

    let size_5 = proof_5.estimated_size();
    let size_10 = proof_10.estimated_size();

    // Proof sizes must be exactly the same (this is the key property of folding)
    assert_eq!(
        size_5, size_10,
        "Proof sizes must be equal: 5 iterations = {} bytes, 10 iterations = {} bytes",
        size_5, size_10
    );
    assert_eq!(
        size_5, EXPECTED_PROOF_SIZE,
        "Proof size should be {} bytes",
        EXPECTED_PROOF_SIZE
    );
}

/// Full end-to-end test: fold 100 iterations of MinRoot-like computation
/// This tests the scalability of the folding scheme.
///
/// NOTE: This test is marked as ignored by default because it takes ~30+ seconds.
/// Run with: cargo test -p arrabbiata --test prover test_e2e_100_iterations -- --ignored
#[test]
#[ignore]
fn test_e2e_100_iterations() {
    let start = Instant::now();

    let indexed_relation = IndexedRelation::new(MIN_SRS_LOG2_SIZE);
    let mut env: Env<Fp, Fq, Vesta, Pallas> = Env::new(BigInt::from(1u64), indexed_relation);

    // Run 100 folding iterations
    env.fold(100);

    let _setup_time = start.elapsed();

    // Generate proof
    let proof = prove(&env).expect("Prove should succeed");

    // Key assertions:
    // 1. We completed all iterations
    assert_eq!(proof.num_iterations, 100);

    // 2. Proof size is constant regardless of iteration count
    assert_eq!(
        proof.estimated_size(),
        EXPECTED_PROOF_SIZE,
        "Proof should be {} bytes after 100 iterations",
        EXPECTED_PROOF_SIZE
    );

    // 3. Witness commitments have correct count
    assert_eq!(
        proof.instance_e1.witness_commitments.len(),
        arrabbiata::NUMBER_OF_COLUMNS
    );
}
