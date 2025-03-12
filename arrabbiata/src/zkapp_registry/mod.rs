use ark_ff::PrimeField;

use crate::interpreter::InterpreterEnv;

/// A ZkApp is simply a method taking a mutable interpreter environment and
/// returning nothing
pub trait ZkApp<E: InterpreterEnv> {
    /// Provide a dummy witness, used to generate a first non-folded instance.
    fn dummy_witness<F: PrimeField>(&self, srs_log2_size: usize) -> Vec<Vec<F>>;

    /// Execute the ZkApp
    fn run(&self, env: &mut E);

    fn setup(&mut self, env: &mut E);
}
