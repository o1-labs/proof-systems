use crate::{
    loc,
    snarky::{api::SnarkyCircuit, boolean::Boolean},
    snarky::{checked_runner::RunState, cvar::FieldVar},
};
use ark_ff::One;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};

use super::prelude::*;

type BaseSponge = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
type ScalarSponge = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;

struct TestCircuit {
    x: Fp,
    y: Fp,
    z: Fp,
}

impl SnarkyCircuit for TestCircuit {
    type Curve = Vesta;

    type PublicInput = Boolean<Fp>;
    type PublicOutput = (Boolean<Fp>, FieldVar<Fp>);

    fn circuit(
        &self,
        sys: &mut RunState<Fp>,
        public: Self::PublicInput,
    ) -> SnarkyResult<Self::PublicOutput> {
        let x: FieldVar<Fp> = sys.compute(&loc!(), |_| self.x)?;
        let y: FieldVar<Fp> = sys.compute(&loc!(), |_| self.y)?;
        let z: FieldVar<Fp> = sys.compute(&loc!(), |_| self.z)?;

        sys.assert_r1cs(Some("x * y = z"), x, y, z)?;

        let other: Boolean<Fp> = sys.compute(&loc!(), |_| true)?;

        // res1 = public & other
        dbg!(&public);
        dbg!(&other);
        let res1 = public.and(&other, sys, &loc!());
        dbg!(&res1);

        // res2 = res1 + 3;
        let three = FieldVar::constant(Fp::from(3));
        let res2 = res1.to_field_var() + three;
        dbg!(&res2);

        Ok((res1, res2))
    }
}

#[test]
fn test_simple_circuit() {
    let test_circuit = TestCircuit {
        x: Fp::one(),
        y: Fp::from(2),
        z: Fp::from(2),
    };

    let (mut prover_index, verifier_index) = test_circuit.compile_to_indexes().unwrap();

    println!("{}", prover_index.asm());

    let public_input = true;
    let debug = true;
    let (proof, public_output) = prover_index
        .prove::<BaseSponge, ScalarSponge>(public_input, debug)
        .unwrap();

    let expected_public_output = (true, Fp::from(4));
    assert_eq!(public_output, expected_public_output);

    verifier_index.verify::<BaseSponge, ScalarSponge>(proof, public_input, public_output);
}
