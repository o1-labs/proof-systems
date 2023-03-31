use ark_ff::PrimeField;
use kimchi::circuits::gate::{Circuit, CircuitGate};
use mina_curves::pasta::Fp;
use serde::de::DeserializeOwned;

#[derive(serde::Deserialize)]
pub struct DeserializableCircuit<F>
where
    F: PrimeField,
{
    pub public_input_size: usize,
    #[serde(bound = "CircuitGate<F>:  DeserializeOwned")]
    pub gates: Vec<CircuitGate<F>>,
}

impl<'a, F> From<&'a DeserializableCircuit<F>> for Circuit<'a, F>
where
    F: PrimeField,
{
    fn from(circuit: &'a DeserializableCircuit<F>) -> Self {
        Circuit::new(circuit.public_input_size, &circuit.gates)
    }
}

fn main() {
    // get what was piped to this binary
    let stdin = std::io::stdin();

    // deserialize it to JSON
    let circuit: DeserializableCircuit<Fp> =
        serde_json::from_reader(stdin).expect("couldn't deserialize the circuit");

    let circuit: Circuit<_> = (&circuit).into();

    println!("{}", circuit.generate_asm());
}
