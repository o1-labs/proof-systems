use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, CircuitGateResult},
        polynomials::fibonacci::create_fib_witness,
    },
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
    tests::framework::TestFramework,
};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
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
    EFrSponge: FrSponge<30, G::ScalarField>,
{
    let (_, mut gates) = CircuitGate::<G::ScalarField>::create_fib_gadget(0);
    let (_, mut gate2) = CircuitGate::<G::ScalarField>::create_fib_gadget(1);

    gates.append(&mut gate2);

    let witness: [Vec<<<G as AffineCurve>::Projective as ProjectiveCurve>::ScalarField>; 30] =
        create_fib_witness::<30, G::ScalarField>();

    println!("entering runner");
    let runner = if full {
        // Create prover index with test framework
        Some(
            TestFramework::<30, G>::default()
                .gates(gates.clone())
                .setup(),
        )
    } else {
        None
    };
    println!("entering constraint system");
    let cs = if let Some(runner) = runner.as_ref() {
        runner.clone().prover_index().cs.clone()
    } else {
        ConstraintSystem::create(gates.clone())
            .build::<30>()
            .unwrap()
    };
    println!("enter constraint system");
    // Perform witness verification that everything is ok before invalidation (quick checks)
    for (row, gate) in gates.iter().enumerate().take(witness[0].len()) {
        let result = gate.verify_witness::<30, G>(row, &witness, &cs, &witness[0][0..cs.public]);
        if result.is_err() {
            return result;
        }
    }
    println!("entering prover");
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
