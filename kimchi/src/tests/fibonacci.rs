use crate::circuits::gate::CircuitGateError::Constraint;
use crate::circuits::gate::GateType;
use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, CircuitGateResult},
        polynomials::fibonacci::{create_fib_witness, FIB_COLS},
    },
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
    tests::framework::TestFramework,
};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{One, PrimeField};
use mina_curves::pasta::{Fq, Pallas, PallasParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};

type SpongeParams = PlonkSpongeConstantsKimchi;
type PallasBaseSponge = DefaultFqSponge<PallasParameters, SpongeParams>;
type PallasScalarSponge = DefaultFrSponge<Fq, SpongeParams>;

fn test_fib<G: KimchiCurve, EFqSponge, EFrSponge>(full: bool) -> CircuitGateResult<()>
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<FIB_COLS, G::ScalarField>,
{
    let (_, mut gates) = CircuitGate::<G::ScalarField>::create_fib_gadget(0);
    let (_, mut gate2) = CircuitGate::<G::ScalarField>::create_fib_gadget(1);

    gates.append(&mut gate2);

    let mut witness: [Vec<<<G as AffineCurve>::Projective as ProjectiveCurve>::ScalarField>;
        FIB_COLS] = create_fib_witness::<FIB_COLS, G::ScalarField>();

    println!("entering runner");
    let runner = if full {
        // Create prover index with test framework
        Some(
            TestFramework::<FIB_COLS, G>::default()
                .gates(gates.clone())
                .setup(),
        )
    } else {
        None
    };
    let cs = if let Some(runner) = runner.as_ref() {
        runner.clone().prover_index().cs.clone()
    } else {
        ConstraintSystem::create(gates.clone())
            .build::<FIB_COLS>()
            .unwrap()
    };

    witness[100][0] += &G::ScalarField::one();
    for (row, gate) in gates.iter().enumerate().take(witness[0].len()) {
        let result =
            gate.verify_witness::<FIB_COLS, G>(row, &witness, &cs, &witness[0][0..cs.public]);
        assert_eq!(result, Err(Constraint(GateType::Fibonacci, 99)));
    }
    witness[100][0] -= &G::ScalarField::one();
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

    Ok(())
}

#[test]
fn test_wide_gate() {
    let res: Result<(), crate::circuits::gate::CircuitGateError> =
        test_fib::<Pallas, PallasBaseSponge, PallasScalarSponge>(true);
    assert_eq!(res, Ok(()));
}
