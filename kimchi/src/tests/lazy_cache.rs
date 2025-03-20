use super::framework::TestFramework;
use crate::circuits::{
    gate::CircuitGate,
    lazy_cache::LazyCache,
    polynomial::COLUMNS,
    polynomials::{generic::GenericGateSpec, xor},
    wires::Wire,
};
use ark_ff::Zero;
use itertools::iterate;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use once_cell::sync::OnceCell;
use rand::Rng;
use serde_json;
use std::{
    array,
    sync::{Arc, Mutex},
};

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

// Unit tests for LazyCache

/// Test creating and getting `LazyCache` values
#[test]
fn test_lazycache() {
    // get
    {
        // Cached variant
        let cache = LazyCache::cache(100);
        assert_eq!(*cache.get(), 100);

        // Lazy variant
        let lazy = LazyCache::lazy(|| {
            let a = 10;
            let b = 20;
            a + b
        });
        assert_eq!(*lazy.get(), 30);
        // Ensure the value is cached and can be accessed multiple times
        assert_eq!(*lazy.get(), 30);
    }

    // function called only once
    {
        let counter = Arc::new(Mutex::new(0));
        let counter_clone = Arc::clone(&counter);

        let cache = LazyCache::lazy(move || {
            let mut count = counter_clone.lock().unwrap();
            *count += 1;
            // counter_clone will be dropped here
            99
        });

        assert_eq!(*cache.get(), 99);
        assert_eq!(*cache.get(), 99); // Ensure cached
        assert_eq!(*counter.lock().unwrap(), 1); // Function was called exactly once
    }
    // clone
    {
        let cache = LazyCache::cache(10);
        let clone = cache.clone();
        assert_eq!(*clone.get(), 10);

        let lazy = LazyCache::lazy(|| 20);
        let clone = lazy.clone();
        assert_eq!(*clone.get(), 20);
    }
    // serde
    {
        let cache = LazyCache::cache(10);
        let serialized = serde_json::to_string(&cache).unwrap();
        let deserialized: LazyCache<i32> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(*deserialized.get(), 10);
    }
    // debug
    {
        let cache = LazyCache::cache(10);
        assert_eq!(format!("{:?}", cache), "Cached(OnceCell(10))");

        let lazy = LazyCache::lazy(|| 20);
        assert_eq!(format!("{:?}", lazy), "Lazy { <function> }");
    }
}

#[test]
#[should_panic(expected = "No function inside LazyCache::Lazy")]
fn test_lazy_panic_when_no_function() {
    let cache: LazyCache<i32> = LazyCache::Lazy {
        computed: OnceCell::new(),
        compute_fn: Arc::new(Mutex::new(None)), // No function set
    };
    let _ = cache.get();
}

#[test]
fn test_lazy_mode_benchmark() {
    let public = vec![Fp::from(1u8); 5];
    let circuit_size = 1 << 16;

    let mut gates_row = iterate(0, |&i| i + 1);
    let mut gates = Vec::with_capacity(circuit_size);
    let mut witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![Fp::zero(); circuit_size]);

    let rng = &mut o1_utils::tests::make_test_rng(None);

    // public input
    for p in public.iter() {
        let r = gates_row.next().unwrap();
        witness[0][r] = *p;
        gates.push(CircuitGate::create_generic_gadget(
            Wire::for_row(r),
            GenericGateSpec::Pub,
            None,
        ));
    }

    let bits = 64;

    while gates.len() < circuit_size - 5 {
        CircuitGate::<Fp>::extend_xor_gadget(&mut gates, bits);

        let input1 = Fp::from(rng.gen_range(0u64..1 << (bits - 1)));
        let input2 = Fp::from(rng.gen_range(0u64..1 << (bits - 1)));

        xor::extend_xor_witness(&mut witness, input1, input2, bits);
    }

    {
        // LAZY CACHE FALSE
        eprintln!("LAZY CACHE: false (default)");
        let gates_ = gates.clone();
        let witness_ = witness.clone();
        let public_ = public.clone();
        TestFramework::<Vesta>::default()
            .gates(gates_)
            .witness(witness_)
            .public_inputs(public_)
            .lazy_mode(false) // optional, default is false
            .setup()
            .prove_and_verify::<BaseSponge, ScalarSponge>()
            .unwrap();
    }

    {
        // LAZY CACHE TRUE
        eprintln!("LAZY CACHE: true");
        TestFramework::<Vesta>::default()
            .gates(gates)
            .witness(witness)
            .public_inputs(public)
            .lazy_mode(true)
            .setup()
            .prove_and_verify::<BaseSponge, ScalarSponge>()
            .unwrap();
    }
}
