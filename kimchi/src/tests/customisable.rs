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
use o1_utils::{foreign_field::BigUintForeignFieldHelpers, BigUintFieldHelpers, FieldHelpers};
use rand::{rngs::StdRng, SeedableRng};

use crate::{
    circuits::{
        constraints::ConstraintSystem,
        expr::PolishToken,
        gate::{CircuitGate, GateType},
        polynomial::COLUMNS,
        polynomials::foreign_field_add::{self, witness::FFOps},
    },
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
};

type BaseSponge = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
type ScalarSponge = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;
type ScalarField = <Vesta as AffineCurve>::ScalarField;

use super::framework::TestFramework;

const RNG_SEED: [u8; 32] = [1; 32];

fn custom_gate_definition() -> Option<Vec<PolishToken<ScalarField>>> {
    // Define conditional gate in RPN
    //     w(0) = w(1) * w(3) + (1 - w(3)) * w(2)
    use crate::circuits::expr::{PolishToken::*, *};
    use crate::circuits::gate::CurrOrNext::Curr;
    Some(vec![
        Cell(Variable {
            col: Column::Index(GateType::ForeignFieldAdd),
            row: Curr,
        }),
        Cell(Variable {
            col: Column::Witness(3),
            row: Curr,
        }),
        Dup,
        Mul,
        Cell(Variable {
            col: Column::Witness(3),
            row: Curr,
        }),
        Sub,
        Alpha,
        Pow(1),
        Cell(Variable {
            col: Column::Witness(0),
            row: Curr,
        }),
        Cell(Variable {
            col: Column::Witness(3),
            row: Curr,
        }),
        Cell(Variable {
            col: Column::Witness(1),
            row: Curr,
        }),
        Mul,
        Literal(ScalarField::from(1u32)),
        Cell(Variable {
            col: Column::Witness(3),
            row: Curr,
        }),
        Sub,
        Cell(Variable {
            col: Column::Witness(2),
            row: Curr,
        }),
        Mul,
        Add,
        Sub,
        Mul,
        Add,
        Mul,
    ])
}

fn run_test<G: KimchiCurve, EFqSponge, EFrSponge>(
    full: bool,
    custom_gate_type: Option<Vec<PolishToken<G::ScalarField>>>,
    x: BigUint,
    y: BigUint,
    b: bool,
    invalidations: Vec<((usize, usize), G::ScalarField)>,
) -> (Result<(), String>, [Vec<G::ScalarField>; COLUMNS])
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    let (gates, mut witness) = {
        match custom_gate_type.clone() {
            None => {
                // Foreign field add circuit and witness
                let fmod = BigUint::max_foreign_field_modulus::<G::ScalarField>();

                let (mut _row, gates) =
                    CircuitGate::<G::ScalarField>::create_single_ffadd(0, FFOps::Add, &fmod);

                let witness =
                    foreign_field_add::witness::create_chain(&vec![x, y], &[FFOps::Add], fmod);

                (gates, witness)
            }
            Some(_custom_gate_type) => {
                // Customised circuit and witness
                let fmod = BigUint::max_foreign_field_modulus::<G::ScalarField>();

                let (mut _row, gates) =
                    CircuitGate::<G::ScalarField>::create_single_ffadd(0, FFOps::Add, &fmod);

                let mut witness = array::from_fn(|_| vec![G::ScalarField::zero(); 2]);

                witness[1][0] = x.to_field().expect("to field");
                witness[2][0] = y.to_field().expect("to field");
                witness[3][0] = if b {
                    G::ScalarField::from(1u32)
                } else {
                    G::ScalarField::zero()
                };
                witness[0][0] = if b { witness[1][0] } else { witness[2][0] };

                (gates, witness)
            }
        }
    };

    let runner = if full {
        Some(
            TestFramework::<G>::default()
                .custom_gate_type(custom_gate_type)
                .gates(gates.clone())
                .setup(),
        )
    } else {
        None
    };

    let cs = if let Some(runner) = runner.as_ref() {
        runner.clone().prover_index().cs.clone()
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

    if let Some(runner) = runner.as_ref() {
        // Perform full test that everything is ok before invalidation
        assert_eq!(
            runner
                .clone()
                .witness(witness.clone())
                .prove_and_verify::<EFqSponge, EFrSponge>(),
            Ok(())
        );
    }

    if !invalidations.is_empty() {
        for ((row, col), value) in invalidations {
            // Invalidate witness
            assert_ne!(witness[col][row], value);
            witness[col][row] = value;
        }

        if let Some(runner) = runner.as_ref() {
            return (
                runner
                    .clone()
                    .witness(witness.clone())
                    .prove_and_verify::<EFqSponge, EFrSponge>(),
                witness,
            );
        }
    }

    (Ok(()), witness)
}

#[test]
fn test_ffadd() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    let x = rng.gen_biguint_below(&ScalarField::modulus_biguint());
    let y = rng.gen_biguint_below(&ScalarField::modulus_biguint());

    assert_ne!(x, y);

    // Positive test case
    let (result, _witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        true,
        None,
        x.clone(),
        y.clone(),
        false,
        vec![],
    );
    assert_eq!(result, Ok(()));

    // Negative test case
    let (result, _witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        true,
        None,
        x,
        y,
        false,
        vec![((0, 0), ScalarField::from(7820u32))],
    );

    assert_eq!(
        result,
        Err("Custom { row: 0, err: \"Invalid ForeignFieldAdd constraint: 3\" }".to_string())
    );
}

#[test]
fn test_overridden_gate_valid_witness() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    let x = rng.gen_biguint_below(&ScalarField::modulus_biguint());
    let y = rng.gen_biguint_below(&ScalarField::modulus_biguint());

    assert_ne!(x, y);

    // Override ffadd custom gate
    let custom_gate_type: Option<Vec<PolishToken<ScalarField>>> = custom_gate_definition();

    // Valid witness 1
    let (result, _witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        true,
        custom_gate_type.clone(),
        x.clone(),
        y.clone(),
        false,
        vec![],
    );
    assert_eq!(result, Ok(()));

    // Valid witness 2
    let (result, _witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        true,
        custom_gate_type.clone(),
        x.clone(),
        y.clone(),
        true,
        vec![],
    );
    assert_eq!(result, Ok(()));
}

#[test]
#[should_panic]
fn test_overridden_gate_invalid_witness() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    let x = rng.gen_biguint_below(&ScalarField::modulus_biguint());
    let y = rng.gen_biguint_below(&ScalarField::modulus_biguint());

    assert_ne!(x, y);

    // Invalid witness
    let _ = run_test::<Vesta, BaseSponge, ScalarSponge>(
        true,
        custom_gate_definition(),
        x,
        y.clone(),
        false,
        vec![((0, 0), ScalarField::zero())],
    );
}
