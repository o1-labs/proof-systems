use super::framework::TestFramework;
use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, CircuitGateError, Connect, GateType},
        polynomial::COLUMNS,
        polynomials::{
            generic::GenericGateSpec,
            keccak::{constants::DIM, OFF},
            rot::{self, RotMode},
        },
        wires::Wire,
    },
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
    prover_index::ProverIndex,
};
use ark_ec::AffineRepr;
use ark_ff::{One, PrimeField, Zero};
use ark_poly::EvaluationDomain;
use core::array;
use mina_curves::pasta::{Fp, Fq, Pallas, PallasParameters, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    poseidon::ArithmeticSpongeParams,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use o1_utils::Two;
use poly_commitment::{
    ipa::{endos, SRS},
    SRS as _,
};
use rand::Rng;
use std::sync::Arc;

type PallasField = <Pallas as AffineRepr>::BaseField;
type SpongeParams = PlonkSpongeConstantsKimchi;
type VestaBaseSponge = DefaultFqSponge<VestaParameters, SpongeParams, 55>;
type VestaScalarSponge = DefaultFrSponge<Fp, SpongeParams, 55>;
type PallasBaseSponge = DefaultFqSponge<PallasParameters, SpongeParams, 55>;
type PallasScalarSponge = DefaultFrSponge<Fq, SpongeParams, 55>;

type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams, 55>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams, 55>;

fn create_rot_gadget<const ROUNDS: usize, G: KimchiCurve<ROUNDS>>(
    rot: u32,
    side: RotMode,
) -> Vec<CircuitGate<G::ScalarField>>
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

fn create_rot_witness<const ROUNDS: usize, G: KimchiCurve<ROUNDS>>(
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

fn create_test_constraint_system<const ROUNDS: usize, G: KimchiCurve<ROUNDS>>(
    rot: u32,
    side: RotMode,
) -> ConstraintSystem<G::ScalarField>
where
    G::BaseField: PrimeField,
{
    // gate for the zero value
    let gates = create_rot_gadget::<ROUNDS, G>(rot, side);

    ConstraintSystem::create(gates).build().unwrap()
}

// Function to create a prover and verifier to test the ROT circuit
fn prove_and_verify<const ROUNDS: usize, G: KimchiCurve<ROUNDS>, EFqSponge, EFrSponge>()
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField, ROUNDS>,
    EFrSponge: FrSponge<G::ScalarField>,
    EFrSponge: From<&'static ArithmeticSpongeParams<G::ScalarField, ROUNDS>>,
{
    let rng = &mut o1_utils::tests::make_test_rng(None);
    let rot = rng.gen_range(1..64);
    // Create
    let gates = create_rot_gadget::<ROUNDS, G>(rot, RotMode::Left);

    // Create input
    let word = rng.gen_range(0..2u128.pow(64)) as u64;

    // Create witness
    let witness = create_rot_witness::<ROUNDS, G>(word, rot, RotMode::Left);

    TestFramework::<ROUNDS, G>::default()
        .gates(gates)
        .witness(witness)
        .setup()
        .prove_and_verify::<EFqSponge, EFrSponge>()
        .unwrap();
}

#[test]
// End-to-end test
fn test_prove_and_verify() {
    prove_and_verify::<55, Vesta, VestaBaseSponge, VestaScalarSponge>();
    prove_and_verify::<55, Pallas, PallasBaseSponge, PallasScalarSponge>();
}

fn test_rot<const ROUNDS: usize, G>(word: u64, rot: u32, side: RotMode)
where
    G: KimchiCurve<ROUNDS>,
    G::BaseField: PrimeField,
{
    let (witness, cs) = setup_rot::<ROUNDS, G>(word, rot, side);
    for row in 0..=2 {
        assert_eq!(
            cs.gates[row].verify_witness::<ROUNDS, G>(
                row,
                &witness,
                &cs,
                &witness[0][0..cs.public]
            ),
            Ok(())
        );
    }
}

// Creates constraint system and witness for rotation
fn setup_rot<const ROUNDS: usize, G: KimchiCurve<ROUNDS>>(
    word: u64,
    rot: u32,
    side: RotMode,
) -> (
    [Vec<G::ScalarField>; COLUMNS],
    ConstraintSystem<G::ScalarField>,
)
where
    G::BaseField: PrimeField,
{
    let cs = create_test_constraint_system::<ROUNDS, G>(rot, side);

    let witness = create_rot_witness::<ROUNDS, G>(word, rot, side);

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
    let rng = &mut o1_utils::tests::make_test_rng(None);
    let rot = rng.gen_range(1..=63);
    let word = rng.gen_range(0..2u128.pow(64)) as u64;
    test_rot::<55, Vesta>(word, rot, RotMode::Left);
    test_rot::<55, Vesta>(word, rot, RotMode::Right);
    test_rot::<55, Pallas>(word, rot, RotMode::Left);
    test_rot::<55, Pallas>(word, rot, RotMode::Right);
}

#[test]
// Test that a bad rotation fails as expected
fn test_zero_rot() {
    let rng = &mut o1_utils::tests::make_test_rng(None);
    let word = rng.gen_range(0..2u128.pow(64)) as u64;
    test_rot::<55, Pallas>(word, 0, RotMode::Left);
}

#[test]
// Test that a bad rotation fails as expected
fn test_large_rot() {
    let rng = &mut o1_utils::tests::make_test_rng(None);
    let word = rng.gen_range(0..2u128.pow(64)) as u64;
    test_rot::<55, Pallas>(word, 64, RotMode::Left);
}

#[test]
// Test bad rotation
fn test_bad_constraints() {
    let rng = &mut o1_utils::tests::make_test_rng(None);
    let rot = rng.gen_range(1..=63);
    let word = rng.gen_range(0..2u128.pow(64)) as u64;
    let (mut witness, cs) = setup_rot::<55, Vesta>(word, rot, RotMode::Left);

    // Check constraints C1..C8
    for i in 0..8 {
        // Modify crumb
        witness[i + 7][1] += PallasField::from(4u32);
        // Decomposition constraint fails
        assert_eq!(
            cs.gates[1].verify_witness::<55, Vesta>(1, &witness, &cs, &witness[0][0..cs.public]),
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
        cs.gates[1].verify_witness::<55, Vesta>(1, &witness, &cs, &witness[0][0..cs.public]),
        Err(CircuitGateError::Constraint(GateType::Rot64, 9))
    );
    // undo
    witness[0][1] -= PallasField::one();

    // Check constraint C10
    // Modify rotated word
    witness[1][1] += PallasField::one();
    // Rotated word is wrong
    assert_eq!(
        cs.gates[1].verify_witness::<55, Vesta>(1, &witness, &cs, &witness[0][0..cs.public]),
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
            cs.gates[1].verify_witness::<55, Vesta>(1, &witness, &cs, &witness[0][0..cs.public]),
            Err(CircuitGateError::Constraint(GateType::Rot64, 11))
        );
        // undo
        witness[i + 3][1] -= PallasField::one();
    }

    // modify excess
    witness[2][1] += PallasField::one();
    witness[0][3] += PallasField::one();
    assert_eq!(
        cs.gates[1].verify_witness::<55, Vesta>(1, &witness, &cs, &witness[0][0..cs.public]),
        Err(CircuitGateError::Constraint(GateType::Rot64, 9))
    );
    assert_eq!(
        cs.gates[3].verify_witness::<55, Vesta>(3, &witness, &cs, &witness[0][0..cs.public]),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 9))
    );
    witness[2][1] -= PallasField::one();
    witness[0][3] -= PallasField::one();

    // modify shifted
    witness[0][2] += PallasField::one();
    assert_eq!(
        cs.gates[1].verify_witness::<55, Vesta>(1, &witness, &cs, &witness[0][0..cs.public]),
        Err(CircuitGateError::Constraint(GateType::Rot64, 9))
    );
    assert_eq!(
        cs.gates[2].verify_witness::<55, Vesta>(2, &witness, &cs, &witness[0][0..cs.public]),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 9))
    );
    witness[0][2] -= PallasField::one();

    // modify value of shifted to be more than 64 bits
    witness[0][2] += PallasField::two_pow(64);
    assert_eq!(
        cs.gates[2].verify_witness::<55, Vesta>(2, &witness, &cs, &witness[0][0..cs.public]),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 9))
    );
    // Update decomposition
    witness[2][2] += PallasField::one();
    // Make sure the 64-bit check fails
    assert_eq!(
        cs.gates[2].verify_witness::<55, Vesta>(2, &witness, &cs, &witness[0][0..cs.public]),
        Err(CircuitGateError::CopyConstraint {
            typ: GateType::RangeCheck0,
            src: Wire { row: 2, col: 2 },
            dst: Wire { row: 0, col: 0 }
        })
    );
    witness[2][2] -= PallasField::one();
    witness[0][2] -= PallasField::two_pow(64);

    // modify value of excess to be more than 64 bits
    witness[0][3] += PallasField::two_pow(64);
    witness[2][1] += PallasField::two_pow(64);
    assert_eq!(
        cs.gates[3].verify_witness::<55, Vesta>(3, &witness, &cs, &witness[0][0..cs.public]),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 9))
    );
    // Update decomposition
    witness[2][3] += PallasField::one();
    // Make sure the 64-bit check fails
    assert_eq!(
        cs.gates[3].verify_witness::<55, Vesta>(3, &witness, &cs, &witness[0][0..cs.public]),
        Err(CircuitGateError::CopyConstraint {
            typ: GateType::RangeCheck0,
            src: Wire { row: 3, col: 2 },
            dst: Wire { row: 2, col: 2 }
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
            .build()
            .unwrap();
        let srs = SRS::<Vesta>::create(cs.domain.d1.size());
        srs.get_lagrange_basis(cs.domain.d1);
        let srs = Arc::new(srs);

        let (endo_q, _endo_r) = endos::<Pallas>();
        ProverIndex::create(cs, endo_q, srs, false)
    };

    for row in 0..witness[0].len() {
        assert_eq!(
            index.cs.gates[row].verify_witness::<55, Vesta>(
                row,
                &witness,
                &index.cs,
                &witness[0][0..index.cs.public]
            ),
            Ok(())
        );
    }

    TestFramework::<55, Vesta>::default()
        .gates(gates)
        .witness(witness.clone())
        .public_inputs(vec![witness[0][0], witness[0][1]])
        .setup()
        .prove_and_verify::<BaseSponge, ScalarSponge>()
        .unwrap();
}

#[test]
// Test that all of the offsets in the rotation table work fine
fn test_keccak_table() {
    let zero_row = 0;
    let mut gates = vec![CircuitGate::<PallasField>::create_generic_gadget(
        Wire::for_row(zero_row),
        GenericGateSpec::Pub,
        None,
    )];
    let mut rot_row = zero_row + 1;
    for col in OFF {
        for rot in col {
            // if rotation by 0 bits, no need to create a gate for it
            if rot == 0 {
                continue;
            }
            let mut rot64_gates = CircuitGate::create_rot64(rot_row, rot as u32);
            rot_row += rot64_gates.len();
            // Append them to the full gates vector
            gates.append(&mut rot64_gates);
            // Check that 2 most significant limbs of shifted are zero
            gates.connect_64bit(zero_row, rot_row - 1);
        }
    }
    let cs = ConstraintSystem::create(gates).build().unwrap();

    let state: [[u64; DIM]; DIM] = array::from_fn(|_| {
        array::from_fn(|_| rand::thread_rng().gen_range(0..2u128.pow(64)) as u64)
    });
    let mut witness: [Vec<PallasField>; COLUMNS] = array::from_fn(|_| vec![PallasField::zero()]);
    for (y, col) in OFF.iter().enumerate() {
        for (x, &rot) in col.iter().enumerate() {
            if rot == 0 {
                continue;
            }
            rot::extend_rot(&mut witness, state[x][y], rot as u32, RotMode::Left);
        }
    }

    for row in 0..=48 {
        assert_eq!(
            cs.gates[row].verify_witness::<55, Vesta>(
                row,
                &witness,
                &cs,
                &witness[0][0..cs.public]
            ),
            Ok(())
        );
    }
    let mut rot = 0;
    for (y, col) in OFF.iter().enumerate() {
        for (x, &bits) in col.iter().enumerate() {
            if bits == 0 {
                continue;
            }
            assert_eq!(
                PallasField::from(state[x][y].rotate_left(bits as u32)),
                witness[1][1 + 3 * rot],
            );
            rot += 1;
        }
    }
}
