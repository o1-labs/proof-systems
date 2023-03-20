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
    type PublicOutput = Boolean<Fp>;

    fn circuit(
        &self,
        sys: &mut RunState<Fp>,
        public: Self::PublicInput,
    ) -> SnarkyResult<Self::PublicOutput> {
        let x: FieldVar<Fp> = sys.compute(&loc!(), |_| self.x)?;
        let y: FieldVar<Fp> = sys.compute(&loc!(), |_| self.y)?;
        let z: FieldVar<Fp> = sys.compute(&loc!(), |_| self.z)?;

        sys.assert_r1cs(Some("x * y = z"), x, y, z);

        let other: Boolean<Fp> = sys.compute(&loc!(), |_| true)?;

        let res = public.and(&other, sys, &loc!());

        Ok(res)
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

    verifier_index.verify::<BaseSponge, ScalarSponge>(proof, public_input, public_output);
}
