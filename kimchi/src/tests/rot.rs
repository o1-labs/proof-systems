use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, CircuitGateError, GateType},
        polynomial::COLUMNS,
        polynomials::rot::{self, RotMode},
        wires::Wire,
    },
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
};

use super::framework::TestFramework;
use ark_ec::AffineCurve;
use ark_ff::{One, PrimeField};
use mina_curves::pasta::{Fp, Fq, Pallas, PallasParameters, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use o1_utils::Two;
use rand::{rngs::StdRng, Rng, SeedableRng};

type PallasField = <Pallas as AffineCurve>::BaseField;
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

    assert!(TestFramework::<G>::default()
        .gates(gates)
        .witness(witness)
        .lookup_tables(vec![rot::lookup_table()])
        .setup()
        .prove_and_verify::<EFqSponge, EFrSponge>()
        .is_ok());
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
    let (witness, cs) = setup_rot::<G, EFqSponge, EFrSponge>(word, rot, side);
    for row in 0..=2 {
        assert_eq!(
            cs.gates[row].verify_witness::<G>(row, &witness, &cs, &witness[0][0..cs.public]),
            Ok(())
        );
    }
}

// Creates constraint system and witness for rotation
fn setup_rot<G: KimchiCurve, EFqSponge, EFrSponge>(
    word: u64,
    rot: u32,
    side: RotMode,
) -> (
    [Vec<G::ScalarField>; COLUMNS],
    ConstraintSystem<G::ScalarField>,
)
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    let cs = create_test_constraint_system::<G, EFqSponge, EFrSponge>(rot, side);
    let witness = rot::create_witness(word, rot, side);

    if side == RotMode::Left {
        assert_eq!(G::ScalarField::from(word.rotate_left(rot)), witness[1][1]);
    } else {
        assert_eq!(G::ScalarField::from(word.rotate_right(rot)), witness[1][1]);
    }

    (witness, cs)
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

#[should_panic]
#[test]
// Test that a bad rotation fails as expected
fn test_zero_rot() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let word = rng.gen_range(0..2u128.pow(64)) as u64;
    rot::create_witness::<PallasField>(word, 0, RotMode::Left);
}

#[should_panic]
#[test]
// Test that a bad rotation fails as expected
fn test_large_rot() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let word = rng.gen_range(0..2u128.pow(64)) as u64;
    rot::create_witness::<PallasField>(word, 64, RotMode::Left);
}

#[test]
// Test bad rotation
fn test_bad_constraints() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let rot = rng.gen_range(1..=63);
    let word = rng.gen_range(0..2u128.pow(64)) as u64;
    let (mut witness, cs) =
        setup_rot::<Vesta, VestaBaseSponge, VestaScalarSponge>(word, rot, RotMode::Left);

    // Check constraints C1..C8
    for i in 0..8 {
        // Modify crumb
        witness[i + 7][1] += PallasField::from(4u32);
        // Decomposition constraint fails
        assert_eq!(
            cs.gates[1].verify_witness::<Vesta>(1, &witness, &cs, &witness[0][0..cs.public]),
            Err(CircuitGateError::Constraint(GateType::Rot64, i + 1))
        );
        // undo
        witness[i + 7][1] -= PallasField::from(4u32);
    }

    // Check constraint C9
    // Modify input word
    witness[0][1] += PallasField::one();
    // Decomposition constraint fails
    assert_eq!(
        cs.gates[1].verify_witness::<Vesta>(1, &witness, &cs, &witness[0][0..cs.public]),
        Err(CircuitGateError::Constraint(GateType::Rot64, 9))
    );
    // undo
    witness[0][1] -= PallasField::one();

    // Check constraint C10
    // Modify rotated word
    witness[1][1] += PallasField::one();
    // Rotated word is wrong
    assert_eq!(
        cs.gates[1].verify_witness::<Vesta>(1, &witness, &cs, &witness[0][0..cs.public]),
        Err(CircuitGateError::Constraint(GateType::Rot64, 10))
    );
    // undo
    witness[1][1] -= PallasField::one();

    // Check constraint C11
    // Modify bound
    for i in 0..4 {
        // Modify limb
        witness[i + 3][1] += PallasField::one();
        // Bound constraint fails
        assert_eq!(
            cs.gates[1].verify_witness::<Vesta>(1, &witness, &cs, &witness[0][0..cs.public]),
            Err(CircuitGateError::Constraint(GateType::Rot64, 11))
        );
        // undo
        witness[i + 3][1] -= PallasField::one();
    }

    // modify excess
    witness[2][1] += PallasField::one();
    assert_eq!(
        cs.gates[1].verify_witness::<Vesta>(1, &witness, &cs, &witness[0][0..cs.public]),
        Err(CircuitGateError::Constraint(GateType::Rot64, 9))
    );
    witness[2][1] -= PallasField::one();

    // modify shifted
    witness[0][2] += PallasField::one();
    assert_eq!(
        cs.gates[1].verify_witness::<Vesta>(1, &witness, &cs, &witness[0][0..cs.public]),
        Err(CircuitGateError::Constraint(GateType::Rot64, 9))
    );
    assert_eq!(
        cs.gates[2].verify_witness::<Vesta>(2, &witness, &cs, &witness[0][0..cs.public]),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 9))
    );

    // modify value of shifted to be more than 64 bits
    witness[0][2] += PallasField::two_pow(64);
    assert_eq!(
        cs.gates[2].verify_witness::<Vesta>(2, &witness, &cs, &witness[0][0..cs.public]),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 9))
    );
    // Update decomposition
    witness[2][2] += PallasField::one();
    // Make sure the 64-bit check fails
    assert_eq!(
        cs.gates[2].verify_witness::<Vesta>(2, &witness, &cs, &witness[0][0..cs.public]),
        Err(CircuitGateError::CopyConstraint {
            typ: GateType::RangeCheck0,
            src: Wire { row: 2, col: 2 },
            dst: Wire { row: 0, col: 0 }
        })
    );
}
