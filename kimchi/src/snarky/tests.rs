use ark_ff::One;
use mina_curves::pasta::{Fp, Vesta};

use crate::{
    loc,
    snarky::{checked_runner::RunState, cvar::CVar},
};

fn main_circuit(runner: &mut RunState<Fp>) {
    let x: CVar<Fp> = runner.compute(TypeCreation::Checked, loc!(), |_| Fp::one());
    let y: CVar<Fp> = runner.compute(TypeCreation::Checked, loc!(), |_| Fp::one());
    let z: CVar<Fp> = runner.compute(TypeCreation::Checked, loc!(), |_| Fp::one());

    runner.assert_r1cs(Some("x * y = z"), x, y, z);
}

#[test]
fn test_simple_circuit() {
    // create snarky constraint system
    let mut runner = RunState::new::<Vesta>(0);

    // run it on the circuit
    main_circuit(&mut runner);

    // finalize and get gates
    let gates = runner.compile();
    println!("gates: {:#?}", gates);

    // witness
    runner.generate_witness(vec![Fp::one(), Fp::one()]);
    main_circuit(&mut runner);
    let witness = runner.generate_witness_end();

    println!("witness: {:#?}", witness);
}
