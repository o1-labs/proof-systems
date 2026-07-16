//! Round-trip and prove-then-verify tests for the mmap-backed proving-key
//! cache.
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
    let public = [Fp::from(3u8); 5];
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
    for (row, (a, b)) in restored
        .cs
        .gates
        .iter()
        .zip(index.cs.gates.iter())
        .enumerate()
    {
        assert_eq!(a.typ, b.typ);
        assert_eq!(a.wires, b.wires);
        // coeffs are preserved verbatim (needed by the debug-build gate check).
        assert_eq!(a.coeffs, b.coeffs, "gate {row} coeffs must round-trip");
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
        dst.permutation_coefficients8[0].evals, src.permutation_coefficients8[0].evals,
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

/// Core stress test for the zero-copy design: populate the cache, load
/// it via `read_cache`, hint the kernel to evict the mapping's pages via
/// `MADV_DONTNEED`, then prove-and-verify. The prover walks every
/// `Evaluations.evals` `Vec<F>` it was handed by the reader; if any of
/// them held an owned copy rather than a slice view into the mmap,
/// eviction wouldn't actually release the memory the test is trying to
/// release. If the wiring is correct, `MADV_DONTNEED` causes page faults
/// on first access, and the prover completes transparently.
#[test]
fn cached_index_prove_after_madv_dontneed() {
    let public = vec![Fp::from(3u8); 5];
    let gates = create_circuit(0, public.len());
    let mut witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![Fp::zero(); gates.len()]);
    fill_in_witness(0, &mut witness, &public);

    let index = new_index_for_test::<FULL_ROUNDS, Vesta>(gates, public.len());
    let verifier_index = index.verifier_index();

    let path = tmpfile("madv_dontneed");
    let id = "madv-test-identifier";
    write_cache(id, &index, &path).expect("write_cache");

    let srs = index.srs.clone();
    drop(index);
    let restored = read_cache::<FULL_ROUNDS, Vesta, _>(id, &path, srs).expect("read_cache");

    // Drop every resident page of the mapping. If the prover truly reads
    // through the mmap, the next access will re-fault the pages from
    // disk; if something accidentally held an owned copy, the "eviction"
    // is silent but the test still passes — the real regression signal
    // here is a crash or a wrong proof.
    restored.madvise_dontneed();

    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    let proof = ProverProof::create::<BaseSponge, ScalarSponge, _>(
        &group_map,
        witness,
        &[],
        &restored,
        &mut rand::rngs::OsRng,
    )
    .expect("proof creation from cached index after MADV_DONTNEED");

    verify::<FULL_ROUNDS, Vesta, BaseSponge, ScalarSponge, OpeningProof<Vesta, FULL_ROUNDS>>(
        &group_map,
        &verifier_index,
        &proof,
        &public,
    )
    .expect("verification of proof from cached index after MADV_DONTNEED");

    std::fs::remove_file(&path).ok();
}

#[test]
fn cached_index_identifier_mismatch_errors() {
    let public = [Fp::from(3u8); 5];
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
        let (table_id_cols, rest) = cols.split_at_mut(1);
        for (row, table_id) in table_id_cols[0].iter_mut().enumerate().take(num_lookups) {
            let idx = rng.gen::<usize>() % table_size;
            let value = lookup_table_values[idx];
            // Columns 1/3/5 carry indexes, 2/4/6 carry the looked-up values.
            *table_id = Fp::zero(); // table id 0
            rest[0][row] = Fp::from(idx as u64);
            rest[1][row] = value;
            rest[2][row] = Fp::from(idx as u64);
            rest[3][row] = value;
            rest[4][row] = Fp::from(idx as u64);
            rest[5][row] = value;
        }
        cols
    };

    let index = new_index_for_test_with_lookups::<FULL_ROUNDS, Vesta>(
        gates,
        0,
        0,
        lookup_tables,
        None,
        false,
        None,
        false,
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

/// Cache writes must surface a lookup-setup failure instead of silently
/// serialising the index as if it had no lookup constraint system.
///
/// With `lazy_mode = true` the `LookupConstraintSystem` is built on first
/// access rather than at index-construction time, so a table error (here an
/// id collision between a from-gate table and an explicitly supplied table
/// with the same id) only surfaces when `write_cache` forces the lazy cache.
/// The buggy behaviour was `Err(_) => None`, which dropped the error and
/// wrote a lookup-free cache file; a later `read_cache` would then hand the
/// prover an index whose lookup argument had silently vanished.
#[test]
fn cached_index_lookup_error_fails_write() {
    use crate::circuits::polynomials::range_check;

    let (_, gates) = CircuitGate::<Fp>::create_multi_range_check(0);
    let index = new_index_for_test_with_lookups::<FULL_ROUNDS, Vesta>(
        gates,
        0,
        0,
        // Same table id (0) as the range-check gates' own from-gate table.
        vec![range_check::gadget::lookup_table()],
        None,
        false,
        None,
        true, // lazy_mode: defer the lookup error to write time
    );

    let path = tmpfile("lookup_error");
    let err = write_cache("lookup-error", &index, &path).expect_err("write_cache should fail");
    assert!(
        matches!(err, CacheError::LookupConstraintSystem(_)),
        "expected LookupConstraintSystem error, got {err}"
    );

    std::fs::remove_file(&path).ok();
}

/// A proof built from a cached index must survive the debug-build gate
/// sanity check (`ProverProof::create` runs `index.verify(..)` under
/// `cfg!(debug_assertions)`). That check calls each gate's `verify()`,
/// which for RangeCheck / Poseidon / foreign-field / xor / rot gates reads
/// `gate.coeffs`. The cache used to drop every gate's coeffs, so this path
/// panicked with an out-of-bounds index on the empty coeff vector for any
/// circuit containing such a gate. (The other tests dodge this because
/// generic gates use `coeffs.get(i).unwrap_or(zero)` and lookup gates don't
/// read coeffs at all.)
///
/// The guarded gate check exists only under `debug_assertions`; the repo's
/// CI test targets all pass `--release`, which compiles it out. Run this
/// test in the dev profile or it exercises nothing:
///
///   cargo test -p kimchi --features mmap_cache cached_index_coeff_gate_prove_from_cache
#[test]
fn cached_index_coeff_gate_prove_from_cache() {
    let (_, gates) = CircuitGate::<Fp>::create_multi_range_check(0);
    // Witness is the length of the (unpadded) circuit; the constraint system
    // pads `cs.gates` up to the domain, so size the witness from the raw gate
    // count, not from `index.cs.gates.len()`.
    let circuit_size = gates.len();
    let index = new_index_for_test_with_lookups::<FULL_ROUNDS, Vesta>(
        gates,
        0,
        0,
        vec![],
        None,
        false,
        None,
        false,
    );
    let verifier_index = index.verifier_index();

    // All-zero witness: 0 is a valid multi-range-check input.
    let witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![Fp::zero(); circuit_size]);

    let path = tmpfile("coeff_gate");
    let id = "coeff-gate-identifier";
    write_cache(id, &index, &path).expect("write_cache");

    let srs = index.srs.clone();
    drop(index);
    let restored = read_cache::<FULL_ROUNDS, Vesta, _>(id, &path, srs).expect("read_cache");

    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    // In a debug build this exercises `index.verify()` -> per-gate coeff reads.
    let proof = ProverProof::create::<BaseSponge, ScalarSponge, _>(
        &group_map,
        witness,
        &[],
        &restored,
        &mut rand::rngs::OsRng,
    )
    .expect("proof creation from cached range-check index");

    verify::<FULL_ROUNDS, Vesta, BaseSponge, ScalarSponge, OpeningProof<Vesta, FULL_ROUNDS>>(
        &group_map,
        &verifier_index,
        &proof,
        &[],
    )
    .expect("verification of proof from cached range-check index");

    std::fs::remove_file(&path).ok();
}

/// A corrupt cache file whose error is only discovered *after* the reader
/// has already built the first mmap-backed `Vec<F>` (here `sid`) must be
/// rejected with a clean `Err`, not abort the process.
///
/// The reader builds `Vec<F>` values via `Vec::from_raw_parts` pointing into
/// the mmap. Those Vecs must never run their destructor (dropping one calls
/// the global allocator on mmap memory → `free(): invalid pointer` abort).
/// The success path parks them in a `ManuallyDrop` index, but an early `?`
/// return after the first Vec is built used to drop it.
///
/// Truncating the file models the ordinary damage mode (interrupted copy,
/// partial write, crashed host): the preamble, section table, and early
/// payload stay intact — so `sid` maps and materialises fine — and the first
/// section whose recorded extent now reaches past end-of-file fails its
/// bounds check while `sid`'s Vec is live. The fix defers all `Vec`
/// construction until every section has been validated, so this returns
/// `Err` instead of aborting.
#[test]
fn cached_index_corrupt_after_first_vec_errors_cleanly() {
    let public = [Fp::from(3u8); 5];
    let gates = create_circuit(0, public.len());
    let index = new_index_for_test::<FULL_ROUNDS, Vesta>(gates, public.len());

    let path = tmpfile("corrupt_after_vec");
    let id = "corrupt-id";
    write_cache(id, &index, &path).expect("write_cache");

    // Cut the file in half: the tail sections are gone.
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.truncate(bytes.len() / 2);
    std::fs::write(&path, &bytes).unwrap();

    let srs = index.srs.clone();
    // Must return Err (previously: SIGABRT from dropping the mmap-backed sid).
    let err = read_cache::<FULL_ROUNDS, Vesta, _>(id, &path, srs).expect_err("should fail");
    assert!(
        matches!(err, CacheError::TruncatedFile),
        "expected TruncatedFile, got {err}"
    );

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
