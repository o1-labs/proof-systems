use ark_ff::One;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};

use crate::{
    loc,
    snarky::{checked_runner::RunState, cvar::CVar},
};

use super::{api::SnarkyCircuit, boolean::Boolean};

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

    fn circuit(&self, sys: &mut RunState<Fp>, public: Self::PublicInput) -> Self::PublicOutput {
        let x: CVar<Fp> = sys.compute(loc!(), |_| self.x);
        let y: CVar<Fp> = sys.compute(loc!(), |_| self.y);
        let z: CVar<Fp> = sys.compute(loc!(), |_| self.z);

        sys.assert_r1cs(Some("x * y = z"), x, y, z);

        let other: Boolean<Fp> = sys.compute(loc!(), |_| true);

        return public.and(&other, sys);
    }
}

#[test]
fn test_simple_circuit() {
    let test_circuit = TestCircuit {
        x: Fp::one(),
        y: Fp::from(2),
        z: Fp::from(2),
    };

    let (mut prover_index, verifier_index) = test_circuit.compile_to_indexes();

    println!("{}", prover_index.asm());

    let public_input = true;
    let debug = true;
    let (proof, public_output) =
        prover_index.prove::<BaseSponge, ScalarSponge>(public_input, debug);

    verifier_index.verify::<BaseSponge, ScalarSponge>(proof, public_input, public_output);
}
