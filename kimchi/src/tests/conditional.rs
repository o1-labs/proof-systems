use std::{array, marker::PhantomData};

use ark_ec::AffineCurve;
use ark_ff::{PrimeField, SquareRootField, Zero};
use macros::GateImpl;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use num_bigint::RandBigInt;
use o1_utils::{BigUintFieldHelpers, FieldHelpers};
use rand::{rngs::StdRng, SeedableRng};

use crate::{
    circuits::{
        argument::ArgumentEnv,
        expr::{constraints::ExprOps, Cache},
        gate::Gate,
        witness::{self, ConstantCell, VariableCell, Variables, WitnessCell},
    },
    tests::conditional,
    variable_map,
};
use crate::{
    circuits::{
        constraints::ConstraintSystem, gate::CircuitGate, polynomial::COLUMNS,
        polynomials::zero::Zero as ZeroGate, wires::Wire,
    },
    curve::KimchiCurve,
    gates,
    plonk_sponge::FrSponge,
    prover::ProverContext,
};

/// Implements two conditional statements of the form `if(b, x, y) = b * x + (1 - b) * y`
#[derive(Default, Debug, Clone, GateImpl)]
pub struct Conditional<F>(PhantomData<F>);

impl<F: PrimeField, T: ExprOps<F>> Gate<F, T> for Conditional<F> {
    fn typ(&self) -> String {
        String::from("Conditional")
    }

    // fn domain(&self, eval_domains: EvaluationDomains<F>) -> Domain {
    //     lazy_static! {
    //         pub static ref DOMAIN = Gate<F>::domain(self, eval_domains);
    //     }
    //     DOMAIN
    // }

    fn constraint_checks(&self, env: &ArgumentEnv<F, T>, _cache: &mut Cache) -> Vec<T> {
        let mut constraints = vec![];

        // Outputs r1 and r2
        let output = [env.witness_curr(0), env.witness_curr(3)];

        // Operands x1 and x2
        let x = [env.witness_curr(1), env.witness_curr(4)];

        // Operands y1 and y2
        let y = [env.witness_curr(2), env.witness_curr(5)];

        // Condition values b, b1 and b2
        let b = env.witness_curr(6);
        let b1 = env.witness_curr(7);
        let b2 = env.witness_curr(8);

        // C1: Constrain b \in [0, 3]
        constraints.push(b.crumb());

        // C2: b = 2 * b1 + b2
        constraints.push(b - (T::from(2u64) * b1.clone() + b2.clone()));

        // C3: r1 = b1 * x1 + (1 - b1) * y1
        constraints
            .push(output[0].clone() - (b1.clone() * x[0].clone() + (T::one() - b1) * y[0].clone()));

        // C4: r2 = b2 * x2 + (1 - b2) * y2
        constraints
            .push(output[1].clone() - (b2.clone() * x[1].clone() + (T::one() - b2) * y[1].clone()));

        constraints
    }
}

impl<F: PrimeField + SquareRootField> CircuitGate<F> {
    /// Create if conditional gate
    ///     Inputs the starting row
    ///     Outputs tuple (next_row, circuit_gates) where
    ///       next_row      - next row after this gate
    ///       circuit_gates - vector of circuit gates comprising this gate
    pub fn create_conditional(start_row: usize) -> (usize, Vec<Self>) {
        let circuit_gates = vec![CircuitGate {
            typ: Conditional::<F>::typ(),
            wires: Wire::for_row(start_row),
            coeffs: vec![],
        }];

        (start_row + circuit_gates.len(), circuit_gates)
    }

    /// Create if conditional gate by extending the existing gates
    pub fn extend_conditional(gates: &mut Vec<Self>, curr_row: &mut usize) {
        let (next_row, circuit_gates) = Self::create_conditional(*curr_row);
        *curr_row = next_row;
        gates.extend_from_slice(&circuit_gates);
    }
}

fn layout<F: PrimeField>() -> [[Box<dyn WitnessCell<F>>; COLUMNS]; 1] {
    [[
        VariableCell::create("r1"),
        VariableCell::create("x1"),
        VariableCell::create("y1"),
        VariableCell::create("r2"),
        VariableCell::create("x2"),
        VariableCell::create("y2"),
        VariableCell::create("b"),
        VariableCell::create("b1"),
        VariableCell::create("b2"),
        ConstantCell::create(F::zero()),
        ConstantCell::create(F::zero()),
        ConstantCell::create(F::zero()),
        ConstantCell::create(F::zero()),
        ConstantCell::create(F::zero()),
        ConstantCell::create(F::zero()),
    ]]
}

/// Create an if conditional witness
pub fn create<F: PrimeField>(x: &[F; 2], y: &[F; 2], b: &[bool; 2]) -> [Vec<F>; COLUMNS] {
    let [b1, b2] = b.map(|x| if x { F::one() } else { F::zero() });
    let b = F::from(2u64) * b1 + b2;
    let r1 = b1 * x[0] + (F::one() - b1) * y[0];
    let r2 = b2 * x[1] + (F::one() - b2) * y[1];

    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 1]);
    witness::init(
        &mut witness,
        0,
        &layout(),
        &variable_map!("r1" => r1,
                                 "x1" => x[0],
                                 "y1" => y[0],
                                 "r2" => r2,
                                 "x2" => x[1],
                                 "y2" => y[1],
                                 "b" => b,
                                 "b1" => b1,
                                 "b2" => b2),
    );

    witness
}

type BaseSponge = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
type ScalarSponge = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;
type ScalarField = <Vesta as AffineCurve>::ScalarField;

use super::framework::TestFramework;

const RNG_SEED: [u8; 32] = [1; 32];

fn run_test<G: KimchiCurve, EFqSponge, EFrSponge>(
    prover_context: &ProverContext<G::ScalarField>,
    full: bool,
    x: &[G::ScalarField; 2],
    y: &[G::ScalarField; 2],
    b: &[bool; 2],
    invalidations: Vec<((usize, usize), G::ScalarField)>,
) -> (Result<(), String>, [Vec<G::ScalarField>; COLUMNS])
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    let (next_row, mut gates) = CircuitGate::<G::ScalarField>::create_conditional(0);
    let mut witness = conditional::create(x, y, b);

    // Pad with a zero gate (kimchi requires at least two)
    gates.push(CircuitGate {
        typ: ZeroGate::<G::ScalarField>::typ(),
        wires: Wire::for_row(next_row),
        coeffs: vec![],
    });
    for col in &mut witness {
        col.push(G::ScalarField::zero())
    }

    let runner = if full {
        // Create prover index with test framework
        Some(
            TestFramework::<G>::create(&prover_context)
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
        ConstraintSystem::create(&prover_context, gates.clone())
            .build()
            .unwrap()
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
fn test_conditional_default_once() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    let x: [ScalarField; 2] = array::from_fn(|_| {
        rng.gen_biguint_below(&ScalarField::modulus_biguint())
            .to_field()
            .expect("failed to convert to field")
    });
    let y: [ScalarField; 2] = array::from_fn(|_| {
        rng.gen_biguint_below(&ScalarField::modulus_biguint())
            .to_field()
            .expect("failed to convert to field")
    });

    // Assert all test values are unique
    assert_ne!(x[0], x[1]);
    assert_ne!(y[0], y[1]);
    for x_val in x {
        for y_val in y {
            assert_ne!(x_val, y_val);
        }
    }

    // Set up prover context with default set of gates
    let mut prover_context = ProverContext::<ScalarField>::default();

    // Register the Conditional gate
    prover_context.gates.register(gates![Conditional]);

    // Positive test case 1
    let (result, witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        &prover_context,
        true,
        &x,
        &y,
        &[true, false],
        vec![],
    );
    assert_eq!(witness[0][0], witness[1][0]);
    assert_eq!(witness[3][0], witness[5][0]);
    assert_eq!(result, Ok(()));
}

#[test]
fn test_conditional_once() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    let x: [ScalarField; 2] = array::from_fn(|_| {
        rng.gen_biguint_below(&ScalarField::modulus_biguint())
            .to_field()
            .expect("failed to convert to field")
    });
    let y: [ScalarField; 2] = array::from_fn(|_| {
        rng.gen_biguint_below(&ScalarField::modulus_biguint())
            .to_field()
            .expect("failed to convert to field")
    });

    // Assert all test values are unique
    assert_ne!(x[0], x[1]);
    assert_ne!(y[0], y[1]);
    for x_val in x {
        for y_val in y {
            assert_ne!(x_val, y_val);
        }
    }

    // Set up prover context with default set of gates
    let mut prover_context = ProverContext::<ScalarField>::new();

    // Register the Conditional gate
    prover_context.gates.register(gates![Conditional, ZeroGate]);

    // Positive test case 1
    let (result, witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        &prover_context,
        true,
        &x,
        &y,
        &[true, false],
        vec![],
    );
    assert_eq!(witness[0][0], witness[1][0]);
    assert_eq!(witness[3][0], witness[5][0]);
    assert_eq!(result, Ok(()));
}

#[test]
fn test_conditional() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    let x: [ScalarField; 2] = array::from_fn(|_| {
        rng.gen_biguint_below(&ScalarField::modulus_biguint())
            .to_field()
            .expect("failed to convert to field")
    });
    let y: [ScalarField; 2] = array::from_fn(|_| {
        rng.gen_biguint_below(&ScalarField::modulus_biguint())
            .to_field()
            .expect("failed to convert to field")
    });

    // Assert all test values are unique
    assert_ne!(x[0], x[1]);
    assert_ne!(y[0], y[1]);
    for x_val in x {
        for y_val in y {
            assert_ne!(x_val, y_val);
        }
    }

    // Set up prover context with default set of gates
    let mut prover_context = ProverContext::<ScalarField>::new();

    // Register the Conditional gate
    prover_context.gates.register(gates![Conditional, ZeroGate]);

    // Positive test case 1
    let (result, witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        &prover_context,
        true,
        &x,
        &y,
        &[true, false],
        vec![],
    );
    assert_eq!(witness[0][0], witness[1][0]);
    assert_eq!(witness[3][0], witness[5][0]);
    assert_eq!(result, Ok(()));

    // Positive test case 2
    let (result, witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        &prover_context,
        true,
        &x,
        &y,
        &[false, true],
        vec![],
    );
    assert_eq!(witness[0][0], witness[2][0]);
    assert_eq!(witness[3][0], witness[4][0]);
    assert_eq!(result, Ok(()));

    // Positive test case 3
    let (result, witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        &prover_context,
        true,
        &x,
        &y,
        &[true, true],
        vec![],
    );
    assert_eq!(witness[0][0], witness[1][0]);
    assert_eq!(witness[3][0], witness[4][0]);
    assert_eq!(result, Ok(()));

    // Positive test case 4
    let (result, witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        &prover_context,
        true,
        &x,
        &y,
        &[false, false],
        vec![],
    );
    assert_eq!(witness[0][0], witness[2][0]);
    assert_eq!(witness[3][0], witness[5][0]);
    assert_eq!(result, Ok(()));

    // Negative test case 1
    let (result, _) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        &prover_context,
        true,
        &x,
        &y,
        &[true, false],
        vec![((0, 6), ScalarField::from(4u64))], // Invalidate b
    );
    assert_eq!(
        result,
        Err(String::from(
            "Custom { row: 0, err: \"Invalid Conditional constraint: 1\" }"
        ))
    );

    // Negative test case 2 a
    let (result, _) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        &prover_context,
        true,
        &x,
        &y,
        &[true, false],
        vec![((0, 7), ScalarField::from(2u64))], // Invalidate b1
    );
    assert_eq!(
        result,
        Err(String::from(
            "Custom { row: 0, err: \"Invalid Conditional constraint: 2\" }"
        ))
    );

    // Negative test case 2 b
    let (result, _) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        &prover_context,
        true,
        &x,
        &y,
        &[true, false],
        vec![((0, 8), ScalarField::from(2u64))], // Invalidate b2
    );
    assert_eq!(
        result,
        Err(String::from(
            "Custom { row: 0, err: \"Invalid Conditional constraint: 2\" }"
        ))
    );

    // Negative test case 3
    let (result, witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        &prover_context,
        true,
        &x,
        &y,
        &[true, false],
        vec![((0, 0), y[0])], // Invalidate r1
    );
    assert_ne!(witness[0][0], witness[1][0]);
    assert_eq!(
        result,
        Err(String::from(
            "Custom { row: 0, err: \"Invalid Conditional constraint: 3\" }"
        ))
    );

    // Negative test case 4
    let (result, witness) = run_test::<Vesta, BaseSponge, ScalarSponge>(
        &prover_context,
        true,
        &x,
        &y,
        &[true, false],
        vec![((0, 3), x[1])], // Invalidate r2
    );
    assert_ne!(witness[3][0], witness[5][0]);
    assert_eq!(
        result,
        Err(String::from(
            "Custom { row: 0, err: \"Invalid Conditional constraint: 4\" }"
        ))
    );
}
