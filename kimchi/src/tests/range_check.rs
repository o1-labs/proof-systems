use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, CircuitGateError, GateType},
        polynomial::COLUMNS,
        polynomials::{
            generic::GenericGateSpec,
            range_check::{self},
        },
        wires::Wire,
    },
    proof::ProverProof,
    prover_index::testing::new_index_for_test_with_lookups,
};

use ark_ec::AffineCurve;
use ark_ff::{Field, One, Zero};
use mina_curves::pasta::{Fp, Pallas, Vesta, VestaParameters};
use o1_utils::FieldHelpers;

use std::array;

use crate::{prover_index::ProverIndex, verifier::verify};
use commitment_dlog::commitment::CommitmentCurve;
use groupmap::GroupMap;
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};

type BaseSponge = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
type ScalarSponge = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;

type PallasField = <Pallas as AffineCurve>::BaseField;

fn create_test_constraint_system() -> ConstraintSystem<Fp> {
    let (mut next_row, mut gates) = CircuitGate::<Fp>::create_multi_range_check(0);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates).build().unwrap()
}

fn create_test_prover_index(public_size: usize) -> ProverIndex<Vesta> {
    let (mut next_row, mut gates) = CircuitGate::<Fp>::create_multi_range_check(0);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    new_index_for_test_with_lookups(
        gates,
        public_size,
        0,
        vec![range_check::gadget::lookup_table()],
        None,
        None,
    )
}

#[test]
fn verify_range_check0_zero_valid_witness() {
    let cs = create_test_constraint_system();
    let witness: [Vec<PallasField>; COLUMNS] = array::from_fn(|_| vec![PallasField::from(0); 4]);

    // gates[0] is RangeCheck0
    assert_eq!(
        cs.gates[0].verify_range_check::<Vesta>(0, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[0].verify_witness::<Vesta>(0, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );

    // gates[1] is RangeCheck0
    assert_eq!(
        cs.gates[1].verify_range_check::<Vesta>(1, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[1].verify_witness::<Vesta>(1, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );
}

#[test]
fn verify_range_check0_one_invalid_witness() {
    let cs = create_test_constraint_system();
    let witness: [Vec<PallasField>; COLUMNS] = array::from_fn(|_| vec![PallasField::from(1); 4]);

    // gates[0] is RangeCheck0
    assert_eq!(
        cs.gates[0].verify_range_check::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(GateType::RangeCheck0))
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[0].verify_witness::<Vesta>(0, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 8))
    );

    // gates[1] is RangeCheck0
    assert_eq!(
        cs.gates[1].verify_range_check::<Vesta>(1, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(GateType::RangeCheck0))
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[1].verify_witness::<Vesta>(1, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 8))
    );
}

#[test]
fn verify_range_check0_valid_witness() {
    let cs = create_test_constraint_system();

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from_hex("115655443433221211ffef000000000000000000000000000000000000000000")
            .unwrap(),
        PallasField::from_hex("eeddcdccbbabaa99898877000000000000000000000000000000000000000000")
            .unwrap(),
        PallasField::from_hex("7766565544343322121100000000000000000000000000000000000000000000")
            .unwrap(),
    );

    // gates[0] is RangeCheck0
    assert_eq!(
        cs.gates[0].verify_range_check::<Vesta>(0, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[0].verify_witness::<Vesta>(0, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );

    // gates[1] is RangeCheck0
    assert_eq!(
        cs.gates[1].verify_range_check::<Vesta>(1, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[1].verify_witness::<Vesta>(1, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from_hex("23d406ac800d1af73040dd000000000000000000000000000000000000000000")
            .unwrap(),
        PallasField::from_hex("a8fe8555371eb021469863000000000000000000000000000000000000000000")
            .unwrap(),
        PallasField::from_hex("3edff808d8f533be9af500000000000000000000000000000000000000000000")
            .unwrap(),
    );

    // gates[0] is RangeCheck0
    assert_eq!(
        cs.gates[0].verify_range_check::<Vesta>(0, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[0].verify_witness::<Vesta>(0, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );

    // gates[1] is RangeCheck0
    assert_eq!(
        cs.gates[1].verify_range_check::<Vesta>(1, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[1].verify_witness::<Vesta>(1, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );
}

#[test]
fn verify_range_check0_invalid_witness() {
    let cs = create_test_constraint_system();

    let mut witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from_hex("22f6b4e7ecb4488433ade7000000000000000000000000000000000000000000")
            .unwrap(),
        PallasField::from_hex("e20e9d80333f2fba463ffd000000000000000000000000000000000000000000")
            .unwrap(),
        PallasField::from_hex("25d28bfd6cdff91ca9bc00000000000000000000000000000000000000000000")
            .unwrap(),
    );

    // Invalidate witness copy constraint
    witness[1][0] += PallasField::one();

    // gates[0] is RangeCheck0
    assert_eq!(
        cs.gates[0].verify_range_check::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidCopyConstraint(
            GateType::RangeCheck0
        ))
    );

    // Invalidate witness copy constraint
    witness[2][1] += PallasField::one();

    // gates[1] is RangeCheck0
    assert_eq!(
        cs.gates[1].verify_range_check::<Vesta>(1, &witness, &cs),
        Err(CircuitGateError::InvalidCopyConstraint(
            GateType::RangeCheck0
        ))
    );

    let mut witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from_hex("22cab5e27101eeafd2cbe1000000000000000000000000000000000000000000")
            .unwrap(),
        PallasField::from_hex("1ab61d31f4e27fe41a318c000000000000000000000000000000000000000000")
            .unwrap(),
        PallasField::from_hex("449a45cd749f1e091a3000000000000000000000000000000000000000000000")
            .unwrap(),
    );

    // Invalidate witness
    witness[8][0] = witness[0][0] + PallasField::one();

    // gates[0] is RangeCheck0
    assert_eq!(
        cs.gates[0].verify_range_check::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(GateType::RangeCheck0))
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[0].verify_witness::<Vesta>(0, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 1))
    );

    // Invalidate witness
    witness[9][1] = witness[0][1] + PallasField::one();

    // gates[1] is RangeCheck0
    assert_eq!(
        cs.gates[1].verify_range_check::<Vesta>(1, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(GateType::RangeCheck0))
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[1].verify_witness::<Vesta>(1, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 2))
    );
}

#[test]
fn verify_range_check0_valid_v0_in_range() {
    let cs = create_test_constraint_system();

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from(PallasField::from(2u64).pow([88]) - PallasField::one()),
        PallasField::zero(),
        PallasField::zero(),
    );

    // gates[0] is RangeCheck0 and contains v0
    assert_eq!(
        cs.gates[0].verify_range_check::<Vesta>(0, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[0].verify_witness::<Vesta>(0, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from(PallasField::from(2u64).pow([64])),
        PallasField::zero(),
        PallasField::zero(),
    );

    // gates[0] is RangeCheck0 and contains v0
    assert_eq!(
        cs.gates[0].verify_range_check::<Vesta>(0, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[0].verify_witness::<Vesta>(0, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from(42u64),
        PallasField::zero(),
        PallasField::zero(),
    );

    // gates[0] is RangeCheck0 and contains v0
    assert_eq!(
        cs.gates[0].verify_range_check::<Vesta>(0, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[0].verify_witness::<Vesta>(0, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::one(),
        PallasField::zero(),
        PallasField::zero(),
    );

    // gates[0] is RangeCheck0 and contains v0
    assert_eq!(
        cs.gates[0].verify_range_check::<Vesta>(0, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[0].verify_witness::<Vesta>(0, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );
}

#[test]
fn verify_range_check0_valid_v1_in_range() {
    let cs = create_test_constraint_system();

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::from(PallasField::from(2u64).pow([88]) - PallasField::one()),
        PallasField::zero(),
    );

    // gates[1] is RangeCheck0 and contains v1
    assert_eq!(
        cs.gates[1].verify_range_check::<Vesta>(1, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[1].verify_witness::<Vesta>(1, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::from(PallasField::from(2u64).pow([63])),
        PallasField::zero(),
    );

    // gates[1] is RangeCheck0 and contains v1
    assert_eq!(
        cs.gates[1].verify_range_check::<Vesta>(1, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[1].verify_witness::<Vesta>(1, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::from(48u64),
        PallasField::zero(),
    );

    // gates[1] is RangeCheck0 and contains v1
    assert_eq!(
        cs.gates[1].verify_range_check::<Vesta>(1, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[1].verify_witness::<Vesta>(1, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::one() + PallasField::one(),
        PallasField::zero(),
    );

    // gates[1] is RangeCheck0 and contains v1
    assert_eq!(
        cs.gates[1].verify_range_check::<Vesta>(1, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[1].verify_witness::<Vesta>(1, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );
}

#[test]
fn verify_range_check0_invalid_v0_not_in_range() {
    let cs = create_test_constraint_system();

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from(2u64).pow([88]), // out of range
        PallasField::zero(),
        PallasField::zero(),
    );

    // gates[0] is RangeCheck0 and contains v0
    assert_eq!(
        cs.gates[0].verify_range_check::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(GateType::RangeCheck0))
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[0].verify_witness::<Vesta>(0, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 8))
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from(2u64).pow([96]), // out of range
        PallasField::zero(),
        PallasField::zero(),
    );

    // gates[0] is RangeCheck0 and contains v0
    assert_eq!(
        cs.gates[0].verify_range_check::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(GateType::RangeCheck0))
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[0].verify_witness::<Vesta>(0, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 8))
    );
}

#[test]
fn verify_range_check0_invalid_v1_not_in_range() {
    let cs = create_test_constraint_system();

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::from(2u64).pow([88]), // out of range
        PallasField::zero(),
    );

    // gates[1] is RangeCheck0 and contains v1
    assert_eq!(
        cs.gates[1].verify_range_check::<Vesta>(1, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(GateType::RangeCheck0))
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[1].verify_witness::<Vesta>(1, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 8))
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::from(2u64).pow([96]), // out of range
        PallasField::zero(),
    );

    // gates[1] is RangeCheck0 and contains v1
    assert_eq!(
        cs.gates[1].verify_range_check::<Vesta>(1, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(GateType::RangeCheck0))
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[1].verify_witness::<Vesta>(1, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 8))
    );
}

#[test]
fn verify_range_check0_test_copy_constraints() {
    let cs = create_test_constraint_system();

    for row in 0..=1 {
        for col in 1..=2 {
            // Copy constraints impact v0 and v1
            let mut witness = range_check::witness::create_multi::<PallasField>(
                PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
                PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
                PallasField::zero(),
            );

            // Positive test case (gates[row] is a RangeCheck0 circuit gate)
            assert_eq!(
                cs.gates[row].verify_range_check::<Vesta>(row, &witness, &cs),
                Ok(())
            );

            // Generic witness verification test
            assert_eq!(
                cs.gates[row].verify_witness::<Vesta>(
                    row,
                    &witness,
                    &cs,
                    &witness[0][0..cs.public].to_vec()
                ),
                Ok(())
            );

            // Negative test cases by breaking a copy constraint
            assert_ne!(witness[col][row], PallasField::zero());
            witness[col][row] = PallasField::zero();
            assert_eq!(
                cs.gates[row].verify_range_check::<Vesta>(row, &witness, &cs),
                Err(CircuitGateError::InvalidCopyConstraint(cs.gates[row].typ))
            );

            // Generic witness verification test
            assert_eq!(
                cs.gates[row].verify_witness::<Vesta>(
                    row,
                    &witness,
                    &cs,
                    &witness[0][0..cs.public].to_vec()
                ),
                Err(CircuitGateError::CopyConstraint {
                    typ: cs.gates[row].typ,
                    src: Wire { row, col },
                    dst: Wire {
                        row: 3,
                        col: 2 * row + col + 2,
                    }
                })
            );
        }
    }
}

#[test]
fn verify_range_check0_v0_test_lookups() {
    let cs = create_test_constraint_system();

    for i in 3..=6 {
        // Test ith lookup
        let mut witness = range_check::witness::create_multi::<PallasField>(
            PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
            PallasField::zero(),
            PallasField::zero(),
        );

        // Positive test
        // gates[0] is RangeCheck0 and constrains some of v0
        assert_eq!(
            cs.gates[0].verify_range_check::<Vesta>(0, &witness, &cs),
            Ok(())
        );

        // Negative test
        // make ith plookup limb out of range
        witness[i][0] = PallasField::from(2u64.pow(12));

        // gates[0] is RangeCheck0 and constrains some of v0
        assert_eq!(
            cs.gates[0].verify_range_check::<Vesta>(0, &witness, &cs),
            Err(CircuitGateError::InvalidLookupConstraintSorted(
                GateType::RangeCheck0
            ))
        );
    }
}

#[test]
fn verify_range_check0_v1_test_lookups() {
    let cs = create_test_constraint_system();

    for i in 3..=6 {
        // Test ith lookup
        let mut witness = range_check::witness::create_multi::<PallasField>(
            PallasField::zero(),
            PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
            PallasField::zero(),
        );

        // Positive test
        // gates[1] is RangeCheck0 and constrains some of v1
        assert_eq!(
            cs.gates[1].verify_range_check::<Vesta>(1, &witness, &cs),
            Ok(())
        );

        // Negative test
        // make ith plookup limb out of range
        witness[i][1] = PallasField::from(2u64.pow(12));

        // gates[1] is RangeCheck0 and constrains some of v1
        assert_eq!(
            cs.gates[1].verify_range_check::<Vesta>(1, &witness, &cs),
            Err(CircuitGateError::InvalidLookupConstraintSorted(
                GateType::RangeCheck0
            ))
        );
    }
}

#[test]
fn verify_range_check1_zero_valid_witness() {
    let cs = create_test_constraint_system();
    let witness: [Vec<PallasField>; COLUMNS] = array::from_fn(|_| vec![PallasField::from(0); 4]);

    // gates[2] is RangeCheck1
    assert_eq!(
        cs.gates[2].verify_range_check::<Vesta>(2, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[2].verify_witness::<Vesta>(2, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );
}

#[test]
fn verify_range_check1_one_invalid_witness() {
    let cs = create_test_constraint_system();
    let witness: [Vec<PallasField>; COLUMNS] = array::from_fn(|_| vec![PallasField::from(1); 4]);

    // gates[2] is RangeCheck1
    assert_eq!(
        cs.gates[2].verify_range_check::<Vesta>(2, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(GateType::RangeCheck1))
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[2].verify_witness::<Vesta>(2, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Err(CircuitGateError::Constraint(GateType::RangeCheck1, 20))
    );
}

#[test]
fn verify_range_check1_valid_witness() {
    let cs = create_test_constraint_system();

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from_hex("22cab5e27101eeafd2cbe1000000000000000000000000000000000000000000")
            .unwrap(),
        PallasField::from_hex("1ab61d31f4e27fe41a318c000000000000000000000000000000000000000000")
            .unwrap(),
        PallasField::from_hex("449a45cd749f1e091a3000000000000000000000000000000000000000000000")
            .unwrap(),
    );

    // gates[2] is RangeCheck1
    assert_eq!(
        cs.gates[2].verify_range_check::<Vesta>(2, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[2].verify_witness::<Vesta>(2, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from_hex("0d96f6fc210316c73bcc4d000000000000000000000000000000000000000000")
            .unwrap(),
        PallasField::from_hex("59c8e7b0ffb3cab6ce8d48000000000000000000000000000000000000000000")
            .unwrap(),
        PallasField::from_hex("686c10e73930b92f375800000000000000000000000000000000000000000000")
            .unwrap(),
    );

    // gates[2] is RangeCheck1
    assert_eq!(
        cs.gates[2].verify_range_check::<Vesta>(2, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[2].verify_witness::<Vesta>(2, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );
}

#[test]
fn verify_range_check1_invalid_witness() {
    let cs = create_test_constraint_system();

    let mut witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from_hex("2ce2d3ac942f98d59e7e11000000000000000000000000000000000000000000")
            .unwrap(),
        PallasField::from_hex("52dd43524b95399f5d458d000000000000000000000000000000000000000000")
            .unwrap(),
        PallasField::from_hex("60ca087b427918fa0e2600000000000000000000000000000000000000000000")
            .unwrap(),
    );

    // Corrupt witness
    witness[0][2] = witness[7][2];

    // gates[2] is RangeCheck1
    assert_eq!(
        cs.gates[2].verify_range_check::<Vesta>(2, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(GateType::RangeCheck1))
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[2].verify_witness::<Vesta>(2, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Err(CircuitGateError::Constraint(GateType::RangeCheck1, 20))
    );

    let mut witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from_hex("1bd50c94d2dc83d32f01c0000000000000000000000000000000000000000000")
            .unwrap(),
        PallasField::from_hex("e983d7cd9e28e440930f86000000000000000000000000000000000000000000")
            .unwrap(),
        PallasField::from_hex("ea226054772cd009d2af00000000000000000000000000000000000000000000")
            .unwrap(),
    );

    // Corrupt witness
    witness[13][2] = witness[3][2];

    // gates[2] is RangeCheck1
    assert_eq!(
        cs.gates[2].verify_range_check::<Vesta>(2, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(GateType::RangeCheck1))
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[2].verify_witness::<Vesta>(2, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Err(CircuitGateError::Constraint(GateType::RangeCheck1, 8))
    );
}

#[test]
fn verify_range_check1_valid_v2_in_range() {
    let cs = create_test_constraint_system();

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::zero(),
        PallasField::from(PallasField::from(2u64).pow([88]) - PallasField::one()),
    );

    // gates[2] is RangeCheck1 and constrains v2
    assert_eq!(
        cs.gates[2].verify_range_check::<Vesta>(2, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[2].verify_witness::<Vesta>(2, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::zero(),
        PallasField::from(PallasField::from(2u64).pow([64])),
    );

    // gates[2] is RangeCheck1 and constrains v2
    assert_eq!(
        cs.gates[2].verify_range_check::<Vesta>(2, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[2].verify_witness::<Vesta>(2, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::zero(),
        PallasField::from(42u64),
    );

    // gates[2] is RangeCheck1 and constrains v2
    assert_eq!(
        cs.gates[2].verify_range_check::<Vesta>(2, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[2].verify_witness::<Vesta>(2, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::zero(),
        PallasField::one(),
    );

    // gates[2] is RangeCheck1 and constrains v2
    assert_eq!(
        cs.gates[2].verify_range_check::<Vesta>(2, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[2].verify_witness::<Vesta>(2, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );
}

#[test]
fn verify_range_check1_invalid_v2_not_in_range() {
    let cs = create_test_constraint_system();

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::zero(),
        PallasField::from(2u64).pow([88]), // out of range
    );

    // gates[2] is RangeCheck1 and constrains v2
    assert_eq!(
        cs.gates[2].verify_range_check::<Vesta>(2, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(GateType::RangeCheck1))
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[2].verify_witness::<Vesta>(2, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Err(CircuitGateError::Constraint(GateType::RangeCheck1, 20))
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::zero(),
        PallasField::from(2u64).pow([96]), // out of range
    );

    // gates[2] is RangeCheck1 and constrains v2
    assert_eq!(
        cs.gates[2].verify_range_check::<Vesta>(2, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(GateType::RangeCheck1))
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[2].verify_witness::<Vesta>(2, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Err(CircuitGateError::Constraint(GateType::RangeCheck1, 20))
    );
}

#[test]
fn verify_range_check1_test_copy_constraints() {
    let cs = create_test_constraint_system();

    for row in 0..=1 {
        for col in 1..=2 {
            // Copy constraints impact v0 and v1
            let mut witness = range_check::witness::create_multi::<PallasField>(
                PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
                PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
                PallasField::zero(),
            );

            // Positive test case (gates[2] is a RangeCheck1 circuit gate)
            assert_eq!(
                cs.gates[2].verify_range_check::<Vesta>(2, &witness, &cs),
                Ok(())
            );

            // Negative test case by breaking a copy constraint
            assert_ne!(witness[col][row], PallasField::zero());
            witness[col][row] = PallasField::zero();
            assert_eq!(
                cs.gates[2].verify_range_check::<Vesta>(2, &witness, &cs),
                Err(CircuitGateError::InvalidCopyConstraint(
                    GateType::RangeCheck1
                ))
            );

            // Generic witness verification test
            // RangeCheck1's current row doesn't have any copy constraints
            assert_eq!(
                cs.gates[2].verify_witness::<Vesta>(
                    2,
                    &witness,
                    &cs,
                    &witness[0][0..cs.public].to_vec()
                ),
                Ok(())
            );

            // Generic witness verification test
            // RangeCheck1's next row has copy constraints, but it's a Zero gate
            assert_eq!(
                cs.gates[3].verify_witness::<Vesta>(
                    3,
                    &witness,
                    &cs,
                    &witness[0][0..cs.public].to_vec()
                ),
                Err(CircuitGateError::CopyConstraint {
                    typ: GateType::Zero,
                    src: Wire {
                        row: 3,
                        col: 2 * row + col + 2
                    },
                    dst: Wire { row, col }
                })
            );
        }
    }
}

#[test]
fn verify_range_check1_test_curr_row_lookups() {
    let cs = create_test_constraint_system();

    for i in 3..=6 {
        // Test ith lookup (impacts v2)
        let mut witness = range_check::witness::create_multi::<PallasField>(
            PallasField::zero(),
            PallasField::zero(),
            PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
        );

        // Positive test
        // gates[2] is RangeCheck1 and constrains v2
        assert_eq!(
            cs.gates[2].verify_range_check::<Vesta>(2, &witness, &cs),
            Ok(())
        );

        // Negative test
        // make ith plookup limb out of range
        witness[i][2] = PallasField::from(2u64.pow(12));

        // gates[2] is RangeCheck1 and constrains v2
        assert_eq!(
            cs.gates[2].verify_range_check::<Vesta>(2, &witness, &cs),
            Err(CircuitGateError::InvalidLookupConstraintSorted(
                GateType::RangeCheck1
            ))
        );
    }
}

#[test]
fn verify_range_check1_test_next_row_lookups() {
    // TODO
    let cs = create_test_constraint_system();

    for row in 0..=1 {
        for col in 1..=2 {
            let mut witness = range_check::witness::create_multi::<PallasField>(
                PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
                PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
                PallasField::zero(),
            );

            // Positive test case (gates[2] is RangeCheck1 and constrains
            // both v0's and v1's lookups that are deferred to 4th row)
            assert_eq!(
                cs.gates[2].verify_range_check::<Vesta>(2, &witness, &cs),
                Ok(())
            );

            // Negative test by making plookup limb out of range
            // and making sure copy constraint is valid
            witness[col][row] = PallasField::from(2u64.pow(12));
            witness[col - 1 + 2 * row + 3][3] = PallasField::from(2u64.pow(12));
            assert_eq!(
                cs.gates[2].verify_range_check::<Vesta>(2, &witness, &cs),
                Err(CircuitGateError::InvalidLookupConstraintSorted(
                    GateType::RangeCheck1
                ))
            );
        }
    }
}

#[test]
fn verify_64_bit_range_check() {
    // Test circuit layout
    //    Row Gate        Cells       Description
    //      0 GenericPub  0 <-,-, ... Used to get a cell with zero
    //      1 RangeCheck0 v0  0 0 ... Wire cells 1 and 2 to 1st cell 0 of GenericPub
    let mut gates = vec![];
    gates.push(CircuitGate::<Fp>::create_generic_gadget(
        Wire::new(0),
        GenericGateSpec::Pub,
        None,
    ));
    gates.append(&mut CircuitGate::<Fp>::create_range_check(1).1);
    gates[1].wires[1] = Wire { row: 1, col: 2 };
    gates[1].wires[2] = Wire { row: 0, col: 0 };
    gates[0].wires[0] = Wire { row: 1, col: 1 };

    // Temporary workaround for lookup-table/domain-size issue
    let mut next_row = 2;
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    // Create constraint system
    let cs =
        ConstraintSystem::<Fp>::create(gates /*, mina_poseidon::pasta::fp_kimchi::params()*/)
            .build()
            .unwrap();

    // Witness layout (positive test case)
    //   Row 0 1 2 3 ... 14  Gate
    //   0   0 0 0 0 ... 0   GenericPub
    //   1   0 0 X X ... X   RangeCheck0
    let mut witness: [Vec<PallasField>; COLUMNS] = array::from_fn(|_| vec![PallasField::zero()]);
    range_check::witness::create::<PallasField>(
        PallasField::from(2u64).pow([64]) - PallasField::one(), // in range
    )
    .iter_mut()
    .enumerate()
    .for_each(|(row, col)| witness[row].append(col));

    // Positive test case
    assert_eq!(
        cs.gates[1].verify_range_check::<Vesta>(1, &witness, &cs),
        Ok(())
    );

    // Generic witness verification test
    assert_eq!(
        cs.gates[1].verify_witness::<Vesta>(1, &witness, &cs, &witness[0][0..cs.public].to_vec()),
        Ok(())
    );

    // Witness layout (negative test case)
    //   Row 0 1 2 3 ... 14  Gate
    //   0   0 0 0 0 ... 0   GenericPub
    //   1   0 X X X ... X   RangeCheck0
    let mut witness: [Vec<PallasField>; COLUMNS] = array::from_fn(|_| vec![PallasField::zero()]);
    range_check::witness::create::<PallasField>(
        PallasField::from(2u64).pow([64]), // out of range
    )
    .iter_mut()
    .enumerate()
    .for_each(|(row, col)| witness[row].append(col));

    // Negative test case
    assert_eq!(
        cs.gates[1].verify_range_check::<Vesta>(1, &witness, &cs),
        Err(CircuitGateError::InvalidCopyConstraint(
            GateType::RangeCheck0
        ))
    );
}

#[test]
fn verify_range_check_valid_proof1() {
    // Create prover index
    let prover_index = create_test_prover_index(0);

    // Create witness
    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from_hex("2bc0afaa2f6f50b1d1424b000000000000000000000000000000000000000000")
            .unwrap(),
        PallasField::from_hex("8b30889f3a39e297ac851a000000000000000000000000000000000000000000")
            .unwrap(),
        PallasField::from_hex("c1c85ec47635e8edac5600000000000000000000000000000000000000000000")
            .unwrap(),
    );

    // Verify computed witness satisfies the circuit
    prover_index.cs.verify::<Vesta>(&witness, &[]).unwrap();

    // Generate proof
    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    let proof =
        ProverProof::create::<BaseSponge, ScalarSponge>(&group_map, witness, &[], &prover_index)
            .expect("failed to generate proof");

    // Get the verifier index
    let verifier_index = prover_index.verifier_index();

    // Verify proof
    let res = verify::<Vesta, BaseSponge, ScalarSponge>(&group_map, &verifier_index, &proof);

    assert!(!res.is_err());
}
