use std::array;

use ark_ec::AffineCurve;
use ark_ff::{PrimeField, Zero};
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use num_bigint::{BigUint, RandBigInt};
use o1_utils::BigUintFieldHelpers;
use rand::{rngs::StdRng, SeedableRng};

use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, GateType},
        polynomial::COLUMNS,
        polynomials::boolean,
        wires::{Wire, PERMUTS},
    },
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
};

type BaseSponge = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
type ScalarSponge = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;
type ScalarField = <Vesta as AffineCurve>::ScalarField;

use super::framework::TestFramework;

const RNG_SEED: [u8; 32] = [0; 32];

fn run_test<G: KimchiCurve, EFqSponge, EFrSponge>(
    full: bool,
    values: &[G::ScalarField; PERMUTS],
    invalidations: Vec<((usize, usize), G::ScalarField)>,
) -> (Result<(), String>, [Vec<G::ScalarField>; COLUMNS])
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    let (next_row, mut gates) = CircuitGate::<G::ScalarField>::create_boolean(0);
    let mut witness = boolean::create(values);

    // Pad with a zero gate (kimchi requires at least two)
    gates.push(CircuitGate {
        typ: GateType::Zero,
        wires: Wire::for_row(next_row),
        coeffs: vec![],
    });
    for col in &mut witness {
        col.push(G::ScalarField::zero())
    }

    let runner = if full {
        // Create prover index with test framework
        Some(
            TestFramework::<G>::default()
                .gates(gates.clone())
                .witness(witness.clone())
                .setup(),
        )
    } else {
        None
    };

    let cs = if let Some(runner) = runner.as_ref() {
        runner.prover_index().cs.clone()
    } else {
        // If not full mode, just create constraint system (this is much faster)
        ConstraintSystem::create(gates.clone()).build().unwrap()
    };

    // Perform witness verification that everything is ok before invalidation (quick checks)
    for (row, gate) in gates.iter().enumerate().take(witness[0].len()) {
        let result = gate.verify_witness::<G>(row, &witness, &cs, &witness[0][0..cs.public]);
        if result.is_err() {
            return (result.map_err(|e| e.to_string()), witness);
        }
    }

    if let Some(runner) = runner {
        // Perform full test that everything is ok before invalidation
        assert_eq!(runner.prove_and_verify::<EFqSponge, EFrSponge>(), Ok(()));
    }

    if !invalidations.is_empty() {
        for ((row, col), value) in invalidations {
            // Invalidate witness
            assert_ne!(witness[col][row], value);
            witness[col][row] = value;
        }

        if full {
            return (
                TestFramework::<G>::default()
                    .gates(gates.clone())
                    .witness(witness.clone())
                    .setup()
                    .prove_and_verify::<EFqSponge, EFrSponge>(),
                witness,
            );
        }
    }

    (Ok(()), witness)
}

#[test]
fn test_boolean() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    for _ in 0..2 {
        // Deterministically generate 7 random boolean values
        let values: [ScalarField; PERMUTS] = array::from_fn(|_| {
            rng.gen_biguint_below(&BigUint::from(2u64))
                .to_field()
                .expect("failed to convert to field")
        });

        // Positive test
        let (result, witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(true, &values, vec![]);

        // Check witness was created correctly
        assert_eq!(witness[0][0], values[0]);
        assert_eq!(witness[1][0], values[1]);
        assert_eq!(witness[2][0], values[2]);
        assert_eq!(witness[3][0], values[3]);
        assert_eq!(witness[4][0], values[4]);
        assert_eq!(witness[5][0], values[5]);
        assert_eq!(witness[6][0], values[6]);

        // Check for valid witness and proof generation/verification
        assert_eq!(result, Ok(()));

        // Negative tests (check each constraint)
        for i in 0..PERMUTS {
            let (result, _) = run_test::<Vesta, BaseSponge, ScalarSponge>(
                true,
                &values,
                vec![((0, i), ScalarField::from(3u64))], // Invalidate bi
            );
            assert_eq!(
                result,
                Err(format!(
                    "Custom {{ row: 0, err: \"Invalid Boolean constraint: {}\" }}",
                    i + 1
                ))
            );
        }
    }
}
