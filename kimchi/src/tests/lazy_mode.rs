use super::framework::TestFramework;
use crate::circuits::{
    gate::CircuitGate,
    polynomial::COLUMNS,
    polynomials::{generic::GenericGateSpec, xor},
    wires::Wire,
};
use ark_ff::Zero;
use core::array;
use itertools::iterate;
#[cfg(all(feature = "logs", not(target_arch = "wasm32")))]
use jemallocator::Jemalloc;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use rand::Rng;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;


// Unit tests for LazyCache

#[test]
fn test_lazy_mode_benchmark() {
    #[cfg(all(feature = "logs", not(target_arch = "wasm32")))]
    #[global_allocator]
    static GLOBAL: Jemalloc = Jemalloc;

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
        eprintln!("LAZY MODE: false (default)");
        TestFramework::<Vesta>::default()
            .gates(gates.clone())
            .witness(witness.clone())
            .public_inputs(public.clone())  
            .lazy_mode(false) // optional, default is false
            .with_logs(true)
            .setup()
            .prove_and_verify::<BaseSponge, ScalarSponge>()
            .unwrap();

    }

    {
        // LAZY CACHE TRUE
        eprintln!("LAZY MODE: true");
        TestFramework::<Vesta>::default()
            .gates(gates)
            .witness(witness)
            .public_inputs(public)
            .lazy_mode(true)
            .with_logs(true)
            .setup()
            .prove_and_verify::<BaseSponge, ScalarSponge>()
            .unwrap();
    }
}
