use ark_ff::PrimeField;

use crate::{interpreter::InterpreterEnv, NUMBER_OF_COLUMNS};

/// A ZkApp for Arrabbiata is a program that is built over a generic interpreter
/// environment `E`.
/// An interpreter environment is a structure that holds an execution trace over
/// a set of "registers" (called columns). The environment provides methods to
/// - access the registers,
/// - allocate new registers "on the fly" (with a maximum of
/// [NUMBER_OF_COLUMNS]).
/// - fetch value previously computed in the trace,
/// - store values in the trace.
/// - [...]
///
/// A ZkApp structure is responsible to provide a dummy witness, used to generate
/// a first non-folded instance. The dummy witness is a satisfying execution
/// trace for dummy inputs.
///
/// A ZkApp structure is also responsible to provide "up-front" a "setup" method
/// that describe the shape of the execution trace.
/// The shape is defined by a list of "selectors" that are used to select the
/// columns that are used in the computation, and how constrained they are.
/// The method "run" will be responsible to build the execution trace, using the
/// selectors the setup phase defined.
/// The method "run" will use the interpreter environment to build the execution
/// trace, based on previously computed values.
pub trait ZkApp<E: InterpreterEnv> {
    /// Provide a dummy witness, used to generate a first non-folded instance.
    fn dummy_witness<F: PrimeField>(&self, srs_size: usize) -> Vec<Vec<F>>;

    /// Execute the ZkApp
    fn run(&self, env: &mut E);

    fn setup(&mut self, env: &mut E);
}
