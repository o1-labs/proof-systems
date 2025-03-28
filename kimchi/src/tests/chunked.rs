use super::framework::TestFramework;
use crate::circuits::{
    gate::CircuitGate,
    polynomials::generic::GenericGateSpec,
    wires::{Wire, COLUMNS},
};
use ark_ff::{UniformRand, Zero};
use core::array;
use itertools::iterate;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

fn test_generic_gate_with_srs_override(
    circuit_size_log_2: usize,
    override_srs_size: Option<usize>,
) {
    let public = vec![Fp::from(1u8); 5];
    let circuit_size = (1 << circuit_size_log_2) - 15;

    let mut gates_row = iterate(0, |&i| i + 1);
    let mut gates = Vec::with_capacity(circuit_size);
    let mut witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![Fp::zero(); circuit_size]);

    let rng = &mut rand::rngs::OsRng;

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

    for _ in public.len()..circuit_size {
        let r = gates_row.next().unwrap();

        // First gate
        let g1 = GenericGateSpec::Add {
            left_coeff: None,
            right_coeff: Some(3u32.into()),
            output_coeff: None,
        };
        let g1_l = <Fp as UniformRand>::rand(rng);
        let g1_r = <Fp as UniformRand>::rand(rng);
        let g1_o = g1_l + g1_r * Fp::from(3u32);
        witness[0][r] = g1_l;
        witness[1][r] = g1_r;
        witness[2][r] = g1_o;

        // Second gate
        let g2 = GenericGateSpec::Mul {
            output_coeff: None,
            mul_coeff: Some(2u32.into()),
        };
        let g2_l = <Fp as UniformRand>::rand(rng);
        let g2_r = <Fp as UniformRand>::rand(rng);
        let g2_o = g2_l * g2_r * Fp::from(2u32);
        witness[3][r] = g2_l;
        witness[4][r] = g2_r;
        witness[5][r] = g2_o;
        gates.push(CircuitGate::create_generic_gadget(
            Wire::for_row(r),
            g1,
            Some(g2),
        ));
    }

    // create and verify proof based on the witness
    let framework = TestFramework::<Vesta>::default()
        .gates(gates)
        .witness(witness)
        .public_inputs(public);
    let framework = if let Some(srs_size) = override_srs_size {
        framework.override_srs_size(srs_size)
    } else {
        framework
    };
    framework
        .setup()
        .prove_and_verify::<BaseSponge, ScalarSponge>()
        .unwrap();
}

// Disabled, too slow
/*#[test]
fn test_2_to_20_chunked_generic_gate_pub() {
    test_generic_gate_with_srs_override(20, Some(1 << 16))
}*/

// Disabled, too slow
/*#[test]
fn test_2_to_18_chunked_generic_gate_pub() {
    test_generic_gate_with_srs_override(18, Some(1 << 16))
}*/

#[test]
fn heavy_test_2_to_17_chunked_generic_gate_pub() {
    test_generic_gate_with_srs_override(17, Some(1 << 16))
}

// Disabled; redundant, just for comparison
/*#[test]
fn test_2_to_16_unchunked_generic_gate_pub() {
    test_generic_gate_with_srs_override(16, None)
}*/
