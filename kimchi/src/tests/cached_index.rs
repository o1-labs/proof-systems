//! Round-trip and prove-then-verify tests for the mmap-backed proving-key
//! cache.

#![cfg(feature = "mmap_cache")]

use crate::{
    cached_prover_index::{read_cache, write_cache, CacheError},
    circuits::{
        gate::{CircuitGate, GateType},
        lookup::tables::LookupTable,
        polynomials::generic::testing::{create_circuit, fill_in_witness},
        wires::{Wire, COLUMNS},
    },
    proof::ProverProof,
    prover_index::testing::{new_index_for_test, new_index_for_test_with_lookups},
    verifier::verify,
};
use ark_ff::Zero;
use ark_poly::EvaluationDomain;
use core::array;
use groupmap::GroupMap;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    pasta::FULL_ROUNDS,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use poly_commitment::{commitment::CommitmentCurve, ipa::OpeningProof, SRS};
use rand::{rngs::StdRng, Rng, SeedableRng};

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams, FULL_ROUNDS>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams, FULL_ROUNDS>;

fn tmpfile(label: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    // Include PID + nanos to avoid collisions across parallel test threads.
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!("kimchi_cached_{label}_{pid}_{nanos}.bin"));
    p
}

/// Round-trips a small proving index through the cache and checks
/// structural equality of every field the cache claims to preserve.
#[test]
fn cached_index_roundtrip_basic_fields() {
    let public = vec![Fp::from(3u8); 5];
    let gates = create_circuit(0, public.len());
    let index = new_index_for_test::<FULL_ROUNDS, Vesta>(gates, public.len());

    let path = tmpfile("roundtrip");
    let id = "test-identifier-0";
    write_cache(id, &index, &path).expect("write_cache");

    let srs = index.srs.clone();
    let restored = read_cache::<FULL_ROUNDS, Vesta, _>(id, &path, srs).expect("read_cache");

    assert_eq!(restored.cs.public, index.cs.public);
    assert_eq!(restored.cs.prev_challenges, index.cs.prev_challenges);
    assert_eq!(restored.cs.zk_rows, index.cs.zk_rows);
    assert_eq!(restored.max_poly_size, index.max_poly_size);
    assert_eq!(restored.cs.domain.d1.size(), index.cs.domain.d1.size());
    assert_eq!(restored.cs.domain.d8.size(), index.cs.domain.d8.size());
    assert_eq!(restored.cs.endo, index.cs.endo);
    assert_eq!(restored.cs.shift, index.cs.shift);
    assert_eq!(restored.cs.sid, index.cs.sid);
    assert_eq!(restored.cs.gates.len(), index.cs.gates.len());
    for (row, (a, b)) in restored.cs.gates.iter().zip(index.cs.gates.iter()).enumerate() {
        assert_eq!(a.typ, b.typ);
        assert_eq!(a.wires, b.wires);
        // coeffs are intentionally dropped; the restored index has empty
        // coeffs except for public rows, which carry `[F::one()]` so the
        // debug-build `index.verify` sanity check still passes.
        if row < index.cs.public {
            assert_eq!(a.coeffs, vec![Fp::from(1u64)]);
        } else {
            assert!(a.coeffs.is_empty());
        }
    }

    // Column evaluations: spot-check the heaviest selector arrays.
    let src = index.column_evaluations.get();
    let dst = restored.column_evaluations.get();
    assert_eq!(
        dst.coefficients8[0].evals, src.coefficients8[0].evals,
        "coefficients8[0] must round-trip exactly"
    );
    assert_eq!(
        dst.generic_selector4.evals, src.generic_selector4.evals,
        "generic_selector4 must round-trip exactly"
    );
    assert_eq!(
        dst.permutation_coefficients8[0].evals,
        src.permutation_coefficients8[0].evals,
        "permutation_coefficients8[0] must round-trip exactly"
    );

    std::fs::remove_file(&path).ok();
}

/// A proof produced from the cached index must verify under the original
/// index's verifier key. This is the real integration test: it asserts
/// the cache preserves enough prover data to emit a valid proof.
#[test]
fn cached_index_prove_then_verify() {
    let public = vec![Fp::from(3u8); 5];
    let gates = create_circuit(0, public.len());
    let mut witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![Fp::zero(); gates.len()]);
    fill_in_witness(0, &mut witness, &public);

    let index = new_index_for_test::<FULL_ROUNDS, Vesta>(gates, public.len());
    let verifier_index = index.verifier_index();

    let path = tmpfile("prove");
    let id = "test-identifier-1";
    write_cache(id, &index, &path).expect("write_cache");

    let srs = index.srs.clone();
    // Drop the original so we prove exclusively from the cached copy.
    drop(index);
    let restored = read_cache::<FULL_ROUNDS, Vesta, _>(id, &path, srs).expect("read_cache");

    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    let proof = ProverProof::create::<BaseSponge, ScalarSponge, _>(
        &group_map,
        witness,
        &[],
        &restored,
        &mut rand::rngs::OsRng,
    )
    .expect("proof creation from cached index");

    verify::<FULL_ROUNDS, Vesta, BaseSponge, ScalarSponge, OpeningProof<Vesta, FULL_ROUNDS>>(
        &group_map,
        &verifier_index,
        &proof,
        &public,
    )
    .expect("verification of proof from cached index");

    std::fs::remove_file(&path).ok();
}

#[test]
fn cached_index_identifier_mismatch_errors() {
    let public = vec![Fp::from(3u8); 5];
    let gates = create_circuit(0, public.len());
    let index = new_index_for_test::<FULL_ROUNDS, Vesta>(gates, public.len());

    let path = tmpfile("idmismatch");
    write_cache("expected-id", &index, &path).unwrap();

    let srs = index.srs.clone();
    let err =
        read_cache::<FULL_ROUNDS, Vesta, _>("different-id", &path, srs).expect_err("should fail");
    assert!(
        matches!(err, CacheError::IdentifierMismatch { .. }),
        "expected IdentifierMismatch, got {err}"
    );

    std::fs::remove_file(&path).ok();
}

/// Lookup-circuit round-trip and prove-then-verify.
///
/// Cache-write used to bail early on any circuit that produced a
/// materialised `LookupConstraintSystem`, leaving lookup circuits
/// without a cache file on disk. This test exercises the full path —
/// write a lookup circuit's proving index, read it back from the cache
/// file, then build and verify a proof using the reconstructed index.
/// A regression where the reader misreconstructs the
/// `LookupConstraintSystem` (missing selector, wrong domain size,
/// swapped field order) will either fail to read, fail to prove, or
/// fail to verify.
#[test]
fn cached_index_lookup_prove_then_verify() {
    // Assemble a tiny lookup circuit: one table of 16 entries (the
    // minimum non-trivial size given pickles/kimchi's zk-row padding),
    // a handful of lookup gates that each read a row out of that table.
    let num_lookups = 32usize;
    let table_size = 16usize;
    let seed: [u8; 32] = [7u8; 32];
    let mut rng = StdRng::from_seed(seed);

    let mut lookup_table_values: Vec<Fp> = (0..table_size).map(|_| rng.gen()).collect();
    // The table with id 0 must contain an all-zeros row.
    lookup_table_values[0] = Fp::zero();
    let lookup_tables = vec![LookupTable {
        id: 0,
        data: vec![
            (0..table_size as u64).map(Fp::from).collect(),
            lookup_table_values.clone(),
        ],
    }];

    let gates: Vec<_> = (0..num_lookups)
        .map(|i| CircuitGate::new(GateType::Lookup, Wire::for_row(i), vec![]))
        .collect();

    // Witness: each lookup row selects a table row and echoes its value
    // in the three triple-lookup cells kimchi's lookup gate consumes.
    let witness = {
        let mut cols: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![Fp::zero(); num_lookups]);
        for row in 0..num_lookups {
            let idx = rng.gen::<usize>() % table_size;
            let value = lookup_table_values[idx];
            // Columns 1/3/5 carry indexes, 2/4/6 carry the looked-up values.
            cols[0][row] = Fp::zero(); // table id 0
            cols[1][row] = Fp::from(idx as u64);
            cols[2][row] = value;
            cols[3][row] = Fp::from(idx as u64);
            cols[4][row] = value;
            cols[5][row] = Fp::from(idx as u64);
            cols[6][row] = value;
        }
        cols
    };

    let index =
        new_index_for_test_with_lookups::<FULL_ROUNDS, Vesta>(
            gates, 0, 0, lookup_tables, None, false, None, false,
        );
    let verifier_index = index.verifier_index();

    // Sanity: the test framework must have produced a materialised
    // LookupConstraintSystem, otherwise we're not actually testing the
    // new cache code path.
    assert!(matches!(
        index.cs.lookup_constraint_system.get(),
        Ok(Some(_))
    ));

    let path = tmpfile("lookup_roundtrip");
    let id = "lookup-test-identifier";
    write_cache(id, &index, &path).expect("write_cache");

    let srs = index.srs.clone();
    drop(index);
    let restored = read_cache::<FULL_ROUNDS, Vesta, _>(id, &path, srs).expect("read_cache");

    // After round-trip we must still have lookup data.
    assert!(matches!(
        restored.cs.lookup_constraint_system.get(),
        Ok(Some(_))
    ));

    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    let proof = ProverProof::create::<BaseSponge, ScalarSponge, _>(
        &group_map,
        witness,
        &[],
        &restored,
        &mut rand::rngs::OsRng,
    )
    .expect("lookup proof creation from cached index");

    verify::<FULL_ROUNDS, Vesta, BaseSponge, ScalarSponge, OpeningProof<Vesta, FULL_ROUNDS>>(
        &group_map,
        &verifier_index,
        &proof,
        &[],
    )
    .expect("lookup proof verification");

    std::fs::remove_file(&path).ok();
}

#[test]
fn cached_index_bad_magic_errors() {
    let path = tmpfile("badmagic");
    std::fs::write(&path, vec![0u8; 1024]).unwrap();
    let srs = std::sync::Arc::new(poly_commitment::ipa::SRS::<Vesta>::create(16));
    let err = read_cache::<FULL_ROUNDS, Vesta, _>("anything", &path, srs).expect_err("should fail");
    assert!(
        matches!(err, CacheError::BadMagic { .. }),
        "expected BadMagic, got {err}"
    );
    std::fs::remove_file(&path).ok();
}
