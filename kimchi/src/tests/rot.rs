use std::{array, sync::Arc};

use super::framework::TestFramework;
use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, CircuitGateError, Connect, GateType},
        polynomial::COLUMNS,
        polynomials::{
            generic::GenericGateSpec,
            rot::{self, RotMode},
        },
        wires::Wire,
    },
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
    prover_index::ProverIndex,
};
use ark_ec::AffineCurve;
use ark_ff::{One, PrimeField, Zero};
use ark_poly::EvaluationDomain;
use mina_curves::pasta::{Fp, Fq, Pallas, PallasParameters, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use o1_utils::Two;
use poly_commitment::srs::{endos, SRS};
use rand::{rngs::StdRng, Rng, SeedableRng};

type PallasField = <Pallas as AffineCurve>::BaseField;
type SpongeParams = PlonkSpongeConstantsKimchi;
type VestaBaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type VestaScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
type PallasBaseSponge = DefaultFqSponge<PallasParameters, SpongeParams>;
type PallasScalarSponge = DefaultFrSponge<Fq, SpongeParams>;

type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

const RNG_SEED: [u8; 32] = [
    211, 31, 143, 75, 29, 255, 0, 126, 237, 193, 86, 160, 1, 90, 131, 221, 186, 168, 4, 95, 50, 48,
    89, 29, 13, 250, 215, 172, 130, 24, 164, 162,
];

fn create_rot_gadget<G: KimchiCurve>(rot: u32, side: RotMode) -> Vec<CircuitGate<G::ScalarField>>
where
    G::BaseField: PrimeField,
{
    // gate for the zero value
    let mut gates = vec![CircuitGate::<G::ScalarField>::create_generic_gadget(
        Wire::for_row(0),
        GenericGateSpec::Pub,
        None,
    )];
    CircuitGate::<G::ScalarField>::extend_rot(&mut gates, rot, side, 0);
    gates
}

fn create_rot_witness<G: KimchiCurve>(
    word: u64,
    rot: u32,
    side: RotMode,
) -> [Vec<G::ScalarField>; COLUMNS]
where
    G::BaseField: PrimeField,
{
    // Include the zero row
    let mut witness: [Vec<G::ScalarField>; COLUMNS] =
        array::from_fn(|_| vec![G::ScalarField::zero()]);
    rot::extend_rot(&mut witness, word, rot, side);
    witness
}

fn create_test_constraint_system<G: KimchiCurve, EFqSponge, EFrSponge>(
    rot: u32,
    side: RotMode,
) -> ConstraintSystem<G::ScalarField>
where
    G::BaseField: PrimeField,
{
    // gate for the zero value
    let mut gates = create_rot_gadget::<G>(rot, side);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(gates.len())));
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
    let mut gates = create_rot_gadget::<G>(rot, RotMode::Left);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(gates.len())));
    }

    // Create input
    let word = rng.gen_range(0..2u128.pow(64)) as u64;

    // Create witness
    let witness = create_rot_witness::<G>(word, rot, RotMode::Left);

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

    let witness = create_rot_witness::<G>(word, rot, side);

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
    create_rot_witness::<Vesta>(word, 0, RotMode::Left);
}

#[should_panic]
#[test]
// Test that a bad rotation fails as expected
fn test_large_rot() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let word = rng.gen_range(0..2u128.pow(64)) as u64;
    create_rot_witness::<Vesta>(word, 64, RotMode::Left);
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

#[test]
// Finalization test
fn test_rot_finalization() {
    // Includes the actual input of the rotation and a row with the zero value
    let num_public_inputs = 2;
    // 1 ROT of 32 to the left
    let rot = 32;
    let mode = RotMode::Left;

    // circuit
    let gates = {
        let mut gates = vec![];
        // public inputs
        for row in 0..num_public_inputs {
            gates.push(CircuitGate::<Fp>::create_generic_gadget(
                Wire::for_row(row),
                GenericGateSpec::Pub,
                None,
            ));
        }
        CircuitGate::<Fp>::extend_rot(&mut gates, rot, mode, 1);
        // connect first public input to the word of the ROT
        gates.connect_cell_pair((0, 0), (2, 0));

        // Temporary workaround for lookup-table/domain-size issue
        for _ in 0..(1 << 13) {
            gates.push(CircuitGate::zero(Wire::for_row(gates.len())));
        }

        gates
    };

    // witness
    let witness = {
        // create one row for the public word
        let mut cols: [_; COLUMNS] = array::from_fn(|_col| vec![Fp::zero(); 2]);

        // initialize the public input containing the word to be rotated
        let input = 0xDC811727DAF22EC1u64;
        cols[0][0] = input.into();
        rot::extend_rot::<Fp>(&mut cols, input, rot, mode);

        cols
    };

    let index = {
        let cs = ConstraintSystem::create(gates.clone())
            .public(num_public_inputs)
            .lookup(vec![rot::lookup_table()])
            .build()
            .unwrap();
        let mut srs = SRS::<Vesta>::create(cs.domain.d1.size());
        srs.add_lagrange_basis(cs.domain.d1);
        let srs = Arc::new(srs);

        let (endo_q, _endo_r) = endos::<Pallas>();
        ProverIndex::<Vesta>::create(cs, endo_q, srs)
    };

    for row in 0..witness[0].len() {
        assert_eq!(
            index.cs.gates[row].verify_witness::<Vesta>(
                row,
                &witness,
                &index.cs,
                &witness[0][0..index.cs.public]
            ),
            Ok(())
        );
    }

    assert!(TestFramework::<Vesta>::default()
        .gates(gates)
        .witness(witness.clone())
        .public_inputs(vec![witness[0][0], witness[0][1]])
        .setup()
        .prove_and_verify::<BaseSponge, ScalarSponge>()
        .is_ok());
}
