use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::CircuitGate,
        polynomials::rot::{self, RotMode},
        wires::Wire,
    },
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
};

use ark_ff::PrimeField;
use mina_curves::pasta::{Fp, Fq, Pallas, PallasParameters, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use rand::{rngs::StdRng, Rng, SeedableRng};

use super::framework::TestFramework;

type SpongeParams = PlonkSpongeConstantsKimchi;
type VestaBaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type VestaScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
type PallasBaseSponge = DefaultFqSponge<PallasParameters, SpongeParams>;
type PallasScalarSponge = DefaultFrSponge<Fq, SpongeParams>;

const RNG_SEED: [u8; 32] = [
    211, 31, 143, 75, 29, 255, 0, 126, 237, 193, 86, 160, 1, 90, 131, 221, 186, 168, 4, 95, 50, 48,
    89, 29, 13, 250, 215, 172, 130, 24, 164, 162,
];

fn create_test_constraint_system<G: KimchiCurve, EFqSponge, EFrSponge>(
    rot: u32,
    side: RotMode,
) -> ConstraintSystem<G::ScalarField>
where
    G::BaseField: PrimeField,
{
    let (mut next_row, mut gates) = { CircuitGate::<G::ScalarField>::create_rot(0, rot, side) };

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates).build().unwrap()
}

// Function to create a prover and verifier to test the ROT circuit
fn prove_and_verify<G: KimchiCurve, EFqSponge, EFrSponge>()
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let rot = rng.gen_range(1..64);
    // Create
    let (mut next_row, mut gates) =
        CircuitGate::<G::ScalarField>::create_rot(0, rot, RotMode::Left);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    // Create input
    let word = rng.gen_range(0..2u128.pow(64)) as u64;

    // Create witness
    let witness = rot::create_witness(word, rot, RotMode::Left);

    TestFramework::<G>::default()
        .gates(gates)
        .witness(witness)
        .lookup_tables(vec![rot::lookup_table()])
        .setup()
        .prove_and_verify::<EFqSponge, EFrSponge>();
}

#[test]
// End-to-end test
fn test_prove_and_verify() {
    prove_and_verify::<Vesta, VestaBaseSponge, VestaScalarSponge>();
    prove_and_verify::<Pallas, PallasBaseSponge, PallasScalarSponge>();
}

fn test_rot<G: KimchiCurve, EFqSponge, EFrSponge>(word: u64, rot: u32, side: RotMode)
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    let cs = create_test_constraint_system::<G, EFqSponge, EFrSponge>(rot, side);
    let witness = rot::create_witness(word, rot, side);
    for row in 0..=2 {
        assert_eq!(
            cs.gates[row].verify_witness::<G>(
                row,
                &witness,
                &cs,
                &witness[0][0..cs.public].to_vec()
            ),
            Ok(())
        );
    }
    if side == RotMode::Left {
        assert_eq!(G::ScalarField::from(word.rotate_left(rot)), witness[1][1]);
    } else {
        assert_eq!(G::ScalarField::from(word.rotate_right(rot)), witness[1][1]);
    }
}

#[test]
// Test that a random offset between 1 and 63 work as expected, both left and right
fn test_rot_random() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let rot = rng.gen_range(1..=63);
    let word = rng.gen_range(0..2u128.pow(64)) as u64;
    test_rot::<Vesta, VestaBaseSponge, VestaScalarSponge>(word, rot, RotMode::Left);
    test_rot::<Vesta, VestaBaseSponge, VestaScalarSponge>(word, rot, RotMode::Right);
    test_rot::<Pallas, PallasBaseSponge, PallasScalarSponge>(word, rot, RotMode::Left);
    test_rot::<Pallas, PallasBaseSponge, PallasScalarSponge>(word, rot, RotMode::Right);
}
