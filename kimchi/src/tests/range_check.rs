use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, CircuitGateError, GateType},
        polynomial::COLUMNS,
        polynomials::{
            foreign_field_common::{
                BigUintArrayFieldHelpers, BigUintForeignFieldHelpers, FieldArrayCompact,
                KimchiForeignElement,
            },
            generic::GenericGateSpec,
            range_check::{self},
        },
        wires::Wire,
    },
    proof::ProverProof,
    prover_index::{testing::new_index_for_test_with_lookups, ProverIndex},
    verifier::verify,
};
use ark_ec::AffineRepr;
use ark_ff::{Field, One, Zero};
use ark_poly::EvaluationDomain;
use core::array;
use groupmap::GroupMap;
use mina_curves::pasta::{Fp, Pallas, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use num_bigint::{BigUint, RandBigInt};
use o1_utils::{foreign_field::ForeignFieldHelpers, FieldHelpers};
use poly_commitment::{
    commitment::CommitmentCurve,
    ipa::{endos, OpeningProof, SRS},
    OpenProof, SRS as _,
};
use std::sync::Arc;

use super::framework::TestFramework;

type BaseSponge = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi, 55>;
type ScalarSponge = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi, 55>;

type PallasField = <Pallas as AffineRepr>::BaseField;

fn create_test_prover_index(
    public_size: usize,
    compact: bool,
) -> ProverIndex<55, Vesta, <OpeningProof<Vesta, 55> as OpenProof<Vesta, 55>>::SRS> {
    let (_next_row, gates) = if compact {
        CircuitGate::<Fp>::create_compact_multi_range_check(0)
    } else {
        CircuitGate::<Fp>::create_multi_range_check(0)
    };

    new_index_for_test_with_lookups(gates, public_size, 0, vec![], None, false, None, false)
}

#[test]
fn verify_range_check0_zero_valid_witness() {
    let index = create_test_prover_index(0, false);
    let witness: [Vec<PallasField>; COLUMNS] = array::from_fn(|_| vec![PallasField::from(0); 4]);

    // gates[0] is RangeCheck0
    assert_eq!(
        index.cs.gates[0].verify_witness::<55, Vesta>(
            0,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );

    // gates[1] is RangeCheck0
    assert_eq!(
        index.cs.gates[1].verify_witness::<55, Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );
}

#[test]
fn verify_range_check0_one_invalid_witness() {
    let index = create_test_prover_index(0, false);
    let witness: [Vec<PallasField>; COLUMNS] = array::from_fn(|_| vec![PallasField::from(1); 4]);

    // gates[0] is RangeCheck0
    assert_eq!(
        index.cs.gates[0].verify_witness::<55, Vesta>(
            0,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 9))
    );

    // gates[1] is RangeCheck0
    assert_eq!(
        index.cs.gates[1].verify_witness::<55, Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 9))
    );
}

#[test]
fn verify_range_check0_valid_witness() {
    let index = create_test_prover_index(0, false);

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
        index.cs.gates[0].verify_witness::<55, Vesta>(
            0,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );

    // gates[1] is RangeCheck0
    assert_eq!(
        index.cs.gates[1].verify_witness::<55, Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
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
        index.cs.gates[0].verify_witness::<55, Vesta>(
            0,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );

    // gates[1] is RangeCheck0
    assert_eq!(
        index.cs.gates[1].verify_witness::<55, Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );
}

#[test]
fn verify_range_check0_invalid_witness() {
    let index = create_test_prover_index(0, false);

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
        index.cs.gates[0].verify_witness::<55, Vesta>(
            0,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::CopyConstraint {
            typ: GateType::RangeCheck0,
            src: Wire { row: 0, col: 1 },
            dst: Wire { row: 3, col: 3 }
        })
    );

    // Invalidate witness copy constraint
    witness[2][1] += PallasField::one();

    // gates[1] is RangeCheck0
    assert_eq!(
        index.cs.gates[1].verify_witness::<55, Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::CopyConstraint {
            typ: GateType::RangeCheck0,
            src: Wire { row: 1, col: 2 },
            dst: Wire { row: 3, col: 6 }
        })
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
        index.cs.gates[0].verify_witness::<55, Vesta>(
            0,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 2))
    );

    // Invalidate witness
    witness[9][1] = witness[0][1] + PallasField::one();

    // gates[1] is RangeCheck0
    assert_eq!(
        index.cs.gates[1].verify_witness::<55, Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 3))
    );
}

#[test]
fn verify_range_check0_valid_v0_in_range() {
    let index = create_test_prover_index(0, false);

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from(2u64).pow([88]) - PallasField::one(),
        PallasField::zero(),
        PallasField::zero(),
    );

    // gates[0] is RangeCheck0 and contains v0
    assert_eq!(
        index.cs.gates[0].verify_witness::<55, Vesta>(
            0,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from(2u64).pow([64]),
        PallasField::zero(),
        PallasField::zero(),
    );

    // gates[0] is RangeCheck0 and contains v0
    assert_eq!(
        index.cs.gates[0].verify_witness::<55, Vesta>(
            0,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from(42u64),
        PallasField::zero(),
        PallasField::zero(),
    );

    // gates[0] is RangeCheck0 and contains v0
    assert_eq!(
        index.cs.gates[0].verify_witness::<55, Vesta>(
            0,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::one(),
        PallasField::zero(),
        PallasField::zero(),
    );

    // gates[0] is RangeCheck0 and contains v0
    assert_eq!(
        index.cs.gates[0].verify_witness::<55, Vesta>(
            0,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );
}

#[test]
fn verify_range_check0_valid_v1_in_range() {
    let index = create_test_prover_index(0, false);

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::from(2u64).pow([88]) - PallasField::one(),
        PallasField::zero(),
    );

    // gates[1] is RangeCheck0 and contains v1
    assert_eq!(
        index.cs.gates[1].verify_witness::<55, Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::from(2u64).pow([63]),
        PallasField::zero(),
    );

    // gates[1] is RangeCheck0 and contains v1
    assert_eq!(
        index.cs.gates[1].verify_witness::<55, Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::from(48u64),
        PallasField::zero(),
    );

    // gates[1] is RangeCheck0 and contains v1
    assert_eq!(
        index.cs.gates[1].verify_witness::<55, Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::one() + PallasField::one(),
        PallasField::zero(),
    );

    // gates[1] is RangeCheck0 and contains v1
    assert_eq!(
        index.cs.gates[1].verify_witness::<55, Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );
}

#[test]
fn verify_range_check0_invalid_v0_not_in_range() {
    let index = create_test_prover_index(0, false);

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from(2u64).pow([88]), // out of range
        PallasField::zero(),
        PallasField::zero(),
    );

    // gates[0] is RangeCheck0 and contains v0
    assert_eq!(
        index.cs.gates[0].verify_witness::<55, Vesta>(
            0,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 9))
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from(2u64).pow([96]), // out of range
        PallasField::zero(),
        PallasField::zero(),
    );

    // gates[0] is RangeCheck0 and contains v0
    assert_eq!(
        index.cs.gates[0].verify_witness::<55, Vesta>(
            0,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 9))
    );
}

#[test]
fn verify_range_check0_invalid_v1_not_in_range() {
    let index = create_test_prover_index(0, false);

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::from(2u64).pow([88]), // out of range
        PallasField::zero(),
    );

    // gates[1] is RangeCheck0 and contains v1
    assert_eq!(
        index.cs.gates[1].verify_witness::<55, Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 9))
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::from(2u64).pow([96]), // out of range
        PallasField::zero(),
    );

    // gates[1] is RangeCheck0 and contains v1
    assert_eq!(
        index.cs.gates[1].verify_witness::<55, Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::RangeCheck0, 9))
    );
}

#[test]
fn verify_range_check0_test_copy_constraints() {
    let index = create_test_prover_index(0, false);

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
                index.cs.gates[row].verify_witness::<55, Vesta>(
                    row,
                    &witness,
                    &index.cs,
                    &witness[0][0..index.cs.public]
                ),
                Ok(())
            );

            // Negative test cases by breaking a copy constraint
            assert_ne!(witness[col][row], PallasField::zero());
            witness[col][row] = PallasField::zero();
            assert_eq!(
                index.cs.gates[row].verify_witness::<55, Vesta>(
                    row,
                    &witness,
                    &index.cs,
                    &witness[0][0..index.cs.public]
                ),
                Err(CircuitGateError::CopyConstraint {
                    typ: index.cs.gates[row].typ,
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
    let index = create_test_prover_index(0, false);

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
        PallasField::zero(),
        PallasField::zero(),
    );

    let cs = match Arc::try_unwrap(index.cs) {
        Ok(cs) => cs,
        Err(_) => panic!("Multiple references of Arc"),
    };

    // Positive test
    // gates[0] is RangeCheck0 and constrains some of v0
    assert_eq!(
        cs.gates[0].verify_witness::<55, Vesta>(0, &witness, &cs, &witness[0][0..cs.public]),
        Ok(())
    );

    let test_runner = TestFramework::<55, Vesta>::default()
        .gates(Arc::try_unwrap(cs.gates).unwrap())
        .setup();

    for i in 3..=6 {
        // Test ith lookup
        let mut witness = witness.clone();

        // Negative test
        // Make ith plookup limb out of range while keeping the
        // rest of the witness consistent
        witness[i][0] += PallasField::from(2u64.pow(12));
        witness[i - 1][0] -= PallasField::one();
        if i == 3 {
            // Make sure copy constraint doesn't fail
            witness[4][3] -= PallasField::one();
        }

        // Perform test that will catch invalid plookup constraints
        assert_eq!(
            test_runner
                .clone()
                .witness(witness)
                .prove_and_verify::<BaseSponge, ScalarSponge>(),
            Err(String::from(
                "the lookup failed to find a match in the table: row=0"
            ))
        );
    }
}

#[test]
fn verify_range_check0_v1_test_lookups() {
    let index = create_test_prover_index(0, false);

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
        PallasField::zero(),
    );

    let cs = match Arc::try_unwrap(index.cs) {
        Ok(cs) => cs,
        Err(_) => panic!("Multiple references of Arc"),
    };

    // Positive test
    // gates[1] is RangeCheck0 and constrains some of v1
    assert_eq!(
        cs.gates[1].verify_witness::<55, Vesta>(1, &witness, &cs, &witness[0][0..cs.public]),
        Ok(())
    );

    let test_runner = TestFramework::<55, Vesta>::default()
        .gates(Arc::try_unwrap(cs.gates).unwrap())
        .setup();

    for i in 3..=6 {
        // Test ith lookup
        let mut witness = witness.clone();

        // Negative test
        // Make ith plookup limb out of range while keeping the
        // rest of the witness consistent
        witness[i][1] += PallasField::from(2u64.pow(12));
        witness[i - 1][1] -= PallasField::one();
        if i == 3 {
            // Make sure copy constraint doesn't fail
            witness[6][3] -= PallasField::one();
        }

        // Perform test that will catch invalid plookup constraints
        assert_eq!(
            test_runner
                .clone()
                .witness(witness)
                .prove_and_verify::<BaseSponge, ScalarSponge>(),
            Err(String::from(
                "the lookup failed to find a match in the table: row=1"
            ))
        );
    }
}

#[test]
fn verify_range_check1_zero_valid_witness() {
    let index = create_test_prover_index(0, false);
    let witness: [Vec<PallasField>; COLUMNS] = array::from_fn(|_| vec![PallasField::from(0); 4]);

    // gates[2] is RangeCheck1
    assert_eq!(
        index.cs.gates[2].verify_witness::<55, Vesta>(
            2,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );
}

#[test]
fn verify_range_check1_one_invalid_witness() {
    let index = create_test_prover_index(0, false);
    let witness: [Vec<PallasField>; COLUMNS] = array::from_fn(|_| vec![PallasField::from(1); 4]);

    // gates[2] is RangeCheck1
    assert_eq!(
        index.cs.gates[2].verify_witness::<55, Vesta>(
            2,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::RangeCheck1, 21))
    );
}

#[test]
fn verify_range_check1_valid_witness() {
    let index = create_test_prover_index(0, false);

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
        index.cs.gates[2].verify_witness::<55, Vesta>(
            2,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
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
        index.cs.gates[2].verify_witness::<55, Vesta>(
            2,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );
}

#[test]
fn verify_range_check1_invalid_witness() {
    let index = create_test_prover_index(0, false);

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
        index.cs.gates[2].verify_witness::<55, Vesta>(
            2,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::RangeCheck1, 21))
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
        index.cs.gates[2].verify_witness::<55, Vesta>(
            2,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::RangeCheck1, 8))
    );
}

#[test]
fn verify_range_check1_valid_v2_in_range() {
    let index = create_test_prover_index(0, false);

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::zero(),
        PallasField::from(2u64).pow([88]) - PallasField::one(),
    );

    // gates[2] is RangeCheck1 and constrains v2
    assert_eq!(
        index.cs.gates[2].verify_witness::<55, Vesta>(
            2,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::zero(),
        PallasField::from(2u64).pow([64]),
    );

    // gates[2] is RangeCheck1 and constrains v2
    assert_eq!(
        index.cs.gates[2].verify_witness::<55, Vesta>(
            2,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::zero(),
        PallasField::from(42u64),
    );

    // gates[2] is RangeCheck1 and constrains v2
    assert_eq!(
        index.cs.gates[2].verify_witness::<55, Vesta>(
            2,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::zero(),
        PallasField::one(),
    );

    // gates[2] is RangeCheck1 and constrains v2
    assert_eq!(
        index.cs.gates[2].verify_witness::<55, Vesta>(
            2,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );
}

#[test]
fn verify_range_check1_invalid_v2_not_in_range() {
    let index = create_test_prover_index(0, false);

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::zero(),
        PallasField::from(2u64).pow([88]), // out of range
    );

    // gates[2] is RangeCheck1 and constrains v2
    assert_eq!(
        index.cs.gates[2].verify_witness::<55, Vesta>(
            2,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::RangeCheck1, 21))
    );

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::zero(),
        PallasField::from(2u64).pow([96]), // out of range
    );

    // gates[2] is RangeCheck1 and constrains v2
    assert_eq!(
        index.cs.gates[2].verify_witness::<55, Vesta>(
            2,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::RangeCheck1, 21))
    );
}

#[test]
fn verify_range_check1_test_copy_constraints() {
    let index = create_test_prover_index(0, false);

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
                index.cs.gates[2].verify_witness::<55, Vesta>(
                    2,
                    &witness,
                    &index.cs,
                    &witness[0][0..index.cs.public]
                ),
                Ok(())
            );

            // Negative test case by breaking a copy constraint
            assert_ne!(witness[col][row], PallasField::zero());
            witness[col][row] = PallasField::zero();

            // RangeCheck1's current row doesn't have any copy constraints
            assert_eq!(
                index.cs.gates[2].verify_witness::<55, Vesta>(
                    2,
                    &witness,
                    &index.cs,
                    &witness[0][0..index.cs.public]
                ),
                Ok(())
            );

            // RangeCheck1's next row has copy constraints, but it's a Zero gate
            assert_eq!(
                index.cs.gates[3].verify_witness::<55, Vesta>(
                    3,
                    &witness,
                    &index.cs,
                    &witness[0][0..index.cs.public]
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
    let index = create_test_prover_index(0, false);
    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::zero(),
        PallasField::zero(),
        PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
    );

    // Positive test
    // gates[2] is RangeCheck1 and constrains v2
    assert_eq!(
        index.cs.gates[2].verify_witness::<55, Vesta>(
            2,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(())
    );

    let test_runner = TestFramework::<55, Vesta>::default()
        .gates(
            Arc::try_unwrap(
                Arc::try_unwrap(index.cs)
                    .expect("Multiple references of Arc")
                    .gates,
            )
            .unwrap(),
        )
        .setup();

    for i in 3..=6 {
        // Test ith lookup (impacts v2)
        let mut witness = witness.clone();

        // Negative test
        // Make ith plookup limb out of range while keeping the
        // rest of the witness consistent
        witness[i][2] += PallasField::from(2u64.pow(12));
        witness[i - 1][2] -= PallasField::one();

        // Perform test that will catch invalid plookup constraints
        assert_eq!(
            test_runner
                .clone()
                .witness(witness.clone())
                .prove_and_verify::<BaseSponge, ScalarSponge>(),
            Err(String::from(
                "the lookup failed to find a match in the table: row=2"
            ))
        );
    }
}

#[test]
fn verify_range_check1_test_next_row_lookups() {
    let index = create_test_prover_index(0, false);

    let witness = range_check::witness::create_multi::<PallasField>(
        PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
        PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
        PallasField::zero(),
    );

    let cs = match Arc::try_unwrap(index.cs) {
        Ok(cs) => cs,
        Err(_) => panic!("Multiple references of Arc"),
    };

    // Positive test case (gates[2] is RangeCheck1 and constrains
    // both v0's and v1's lookups that are deferred to 4th row)
    assert_eq!(
        cs.gates[2].verify_witness::<55, Vesta>(2, &witness, &cs, &witness[0][0..cs.public]),
        Ok(())
    );

    let test_runner = TestFramework::<55, Vesta>::default()
        .gates(Arc::try_unwrap(cs.gates).unwrap())
        .setup();

    for row in 0..=1 {
        for col in 1..=2 {
            let mut witness = witness.clone();

            // Negative test by making plookup limb out of range
            // while also assuring the rest of the witness is still valid
            witness[col][row] += PallasField::from(2u64.pow(12));
            if col > 1 {
                witness[col - 1][row] -= PallasField::one();
                witness[col - 1 + 2 * row + 2][3] -= PallasField::one();
            } else {
                witness[col - 1][row] += KimchiForeignElement::<PallasField>::two_to_limb();
            }
            witness[col - 1 + 2 * row + 3][3] += PallasField::from(2u64.pow(12));

            // Perform test that will catch invalid plookup constraints
            assert_eq!(
                test_runner
                    .clone()
                    .witness(witness.clone())
                    .prove_and_verify::<BaseSponge, ScalarSponge>(),
                Err(String::from(
                    "the lookup failed to find a match in the table: row=3"
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
        Wire::for_row(0),
        GenericGateSpec::Pub,
        None,
    ));
    gates.append(&mut CircuitGate::<Fp>::create_range_check(1).1);
    gates[1].wires[1] = Wire { row: 1, col: 2 };
    gates[1].wires[2] = Wire { row: 0, col: 0 };
    gates[0].wires[0] = Wire { row: 1, col: 1 };

    // Create constraint system
    let cs =
        ConstraintSystem::<Fp>::create(gates /*, mina_poseidon::pasta::fp_kimchi::params()*/)
            .build()
            .unwrap();

    let index = {
        let srs = SRS::<Vesta>::create(cs.domain.d1.size());
        srs.get_lagrange_basis(cs.domain.d1);
        let srs = Arc::new(srs);

        let (endo_q, _endo_r) = endos::<Pallas>();
        ProverIndex::create(cs, endo_q, srs, false)
    };

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
        index.cs.gates[1].verify_witness::<55, Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
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
        index.cs.gates[1].verify_witness::<55, Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::CopyConstraint {
            typ: GateType::RangeCheck0,
            src: Wire { row: 1, col: 1 },
            dst: Wire { row: 1, col: 2 }
        })
    );
}

#[test]
fn compact_multi_range_check() {
    let rng = &mut o1_utils::tests::make_test_rng(None);

    // Create prover index
    let index = create_test_prover_index(0, true);

    for _ in 0..3 {
        // Generate some random limbs in compact format
        let limbs: [PallasField; 3] =
            array::from_fn(|_| rng.gen_biguint_below(&BigUint::two_to_limb())).to_fields();
        let limbs = limbs.to_compact_limbs();

        // Create witness
        let mut witness = range_check::witness::create_multi_compact_limbs::<PallasField>(&limbs);

        // Positive test
        assert_eq!(
            index.cs.gates[1].verify_witness::<55, Vesta>(
                1,
                &witness,
                &index.cs,
                &witness[0][0..index.cs.public]
            ),
            Ok(())
        );

        // Invalidate witness
        witness[1][2] = PallasField::one();

        // Negative test
        assert_eq!(
            index.cs.gates[1].verify_witness::<55, Vesta>(
                1,
                &witness,
                &index.cs,
                &witness[0][0..index.cs.public]
            ),
            Err(CircuitGateError::Constraint(GateType::RangeCheck0, 10))
        );
    }
}

#[test]
fn verify_range_check_valid_proof1() {
    // Create prover index
    let prover_index = create_test_prover_index(0, false);

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
    prover_index.verify(&witness, &[]).unwrap();

    // Generate proof
    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    let public_input = witness[0][0..prover_index.cs.public].to_vec();
    let proof = ProverProof::create::<BaseSponge, ScalarSponge, _>(
        &group_map,
        witness,
        &[],
        &prover_index,
        &mut rand::rngs::OsRng,
    )
    .expect("failed to generate proof");

    // Get the verifier index
    let verifier_index = prover_index.verifier_index();

    // Verify proof
    let res = verify::<55, Vesta, BaseSponge, ScalarSponge, OpeningProof<Vesta, 55>>(
        &group_map,
        &verifier_index,
        &proof,
        &public_input,
    );

    res.unwrap();
}

#[test]
fn verify_compact_multi_range_check_proof() {
    let rng = &mut o1_utils::tests::make_test_rng(None);

    let limbs: [PallasField; 3] =
        array::from_fn(|_| rng.gen_biguint_below(&BigUint::two_to_limb())).to_fields();
    let limbs = limbs.to_compact_limbs();

    // Create witness
    let witness = range_check::witness::create_multi_compact_limbs::<PallasField>(&limbs);

    let (_next_row, gates) = CircuitGate::<Fp>::create_compact_multi_range_check(0);

    TestFramework::<55, Vesta>::default()
        .gates(gates)
        .witness(witness)
        .setup()
        .prove_and_verify::<BaseSponge, ScalarSponge>()
        .unwrap();
}
