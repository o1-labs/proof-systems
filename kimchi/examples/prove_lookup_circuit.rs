//! Prove a range-check-heavy circuit, for profiling the prover's lookup path.
//!
//! The benches in this crate build circuits of generic gates only, so they
//! never exercise the joint lookup table, the sorted polynomials or the
//! lookup aggregation.
//!
//! This example builds a circuit of multi-range-check gadgets, which is the
//! shape foreign-field arithmetic produces: every 3-limb value has its 88-bit
//! limbs range-checked, so circuits dominated by foreign-field work are
//! dominated by these gates. They draw on kimchi's fixed 12-bit range check
//! table with several lookups per row, so both the joint lookup table and the
//! sorted polynomials are substantial.
//!
//! Usage:
//!
//! ```text
//! cargo run --release --example prove_lookup_circuit -- [LOG2_ROWS] [PROOFS]
//! ```
//!
//! Defaults to a 2^14 domain and one proof. It prints elapsed time per proof;
//! peak RSS is best measured from outside, e.g. with `/usr/bin/time -v`.
//!
//! Note that below about 2^13 the resulting domain can be larger than asked
//! for, since the fixed 12-bit range check table occupies 4096 rows of its
//! own; the printed setup line reports the domain actually used.

use ark_ff::Zero;
use groupmap::GroupMap;
use kimchi::{
    bench::{BaseSpongeVesta, ScalarSpongeVesta},
    circuits::{gate::CircuitGate, polynomial::COLUMNS, polynomials::range_check},
    proof::ProverProof,
    prover_index::testing::new_index_for_test_with_lookups,
};
use mina_curves::pasta::{Fp, Vesta};
use mina_poseidon::pasta::FULL_ROUNDS;
use poly_commitment::{commitment::CommitmentCurve, ipa::OpeningProof};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::time::Instant;

/// A multi-range-check gadget occupies this many rows.
const ROWS_PER_GADGET: usize = 4;

fn main() {
    let mut args = std::env::args().skip(1);
    let log2_rows: u32 = args
        .next()
        .map_or(14, |s| s.parse().expect("LOG2_ROWS must be an integer"));
    let proofs: usize = args
        .next()
        .map_or(1, |s| s.parse().expect("PROOFS must be an integer"));

    // Fixed seed: the circuit and witness must be identical across runs for a
    // before/after comparison to mean anything.
    let mut rng = StdRng::from_seed([7u8; 32]);

    // Leave room for the zero-knowledge rows.
    let num_gadgets = ((1usize << log2_rows) - 10) / ROWS_PER_GADGET;

    let mut gates = vec![];
    let mut curr_row = 0;
    for _ in 0..num_gadgets {
        CircuitGate::<Fp>::extend_multi_range_check(&mut gates, &mut curr_row);
    }

    // Three 88-bit limbs per gadget, as foreign-field arithmetic produces.
    let mut witness: [Vec<Fp>; COLUMNS] = std::array::from_fn(|_| vec![]);
    for _ in 0..num_gadgets {
        let mut limb = || {
            let hi: u64 = rng.gen::<u64>() >> 40; // 24 bits
            let lo: u64 = rng.gen();
            Fp::from(hi) * Fp::from(1u128 << 64) + Fp::from(lo)
        };
        let (v0, v1, v2) = (limb(), limb(), limb());
        range_check::witness::extend_multi(&mut witness, v0, v1, v2);
    }
    // Pad the witness out to the gate count.
    for col in witness.iter_mut() {
        col.resize(gates.len(), Fp::zero());
    }

    let setup_start = Instant::now();
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
    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    eprintln!(
        "setup: domain 2^{}, {} multi-range-check gadgets ({} rows), {:.2?}",
        index.cs.domain.d1.log_size_of_group,
        num_gadgets,
        curr_row,
        setup_start.elapsed()
    );

    for i in 0..proofs {
        let start = Instant::now();
        let proof: ProverProof<Vesta, OpeningProof<Vesta, FULL_ROUNDS>, FULL_ROUNDS> =
            ProverProof::create::<BaseSpongeVesta, ScalarSpongeVesta, _>(
                &group_map,
                witness.clone(),
                &[],
                &index,
                &mut rand::rngs::OsRng,
            )
            .expect("proving failed");
        eprintln!("proof {}: {:.2?}", i, start.elapsed());
        // Keep the proof alive until after the timer, so it cannot be
        // optimised away.
        std::hint::black_box(&proof);
    }
}
