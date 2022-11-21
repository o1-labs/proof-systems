use ark_ff::PrimeField;
use o1_utils::hasher::CryptoDigest;

use self::gate::CircuitGate;

#[macro_use]
pub mod macros;

pub mod argument;
pub mod constraints;
pub mod domain_constant_evaluation;
pub mod domains;
pub mod expr;
pub mod gate;
pub mod lookup;
pub mod polynomial;
pub mod polynomials;
pub mod scalars;
mod serialization_helper;
pub mod wires;
pub mod witness;

/// A circuit is specified as a public input size and a list of [`CircuitGate`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(bound = "CircuitGate<F>: serde::Serialize + serde::de::DeserializeOwned")]
pub struct Circuit<F: PrimeField> {
    /// Number of public input field elements in the circuit (includes public outputs).
    pub public_input_size: usize,

    /// Series of gates that describes the circuit.
    pub gates: Vec<gate::CircuitGate<F>>,
}

impl<F> Circuit<F>
where
    F: PrimeField,
{
    /// Constructs a new circuit from a number of public input field elements, and a list of [`CircuitGate`].
    pub fn new(public_input_size: usize, gates: Vec<CircuitGate<F>>) -> Self {
        Self {
            public_input_size,
            gates,
        }
    }
}

impl<F> CryptoDigest for Circuit<F>
where
    F: PrimeField,
{
    const PREFIX: &'static [u8; 15] = b"kimchi-circuit0";
}
