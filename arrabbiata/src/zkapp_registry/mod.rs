use ark_ec::CurveConfig;
use ark_ff::PrimeField;
use poly_commitment::commitment::CommitmentCurve;

use crate::{column::Gadget, curve::ArrabbiataCurve, interpreter::InterpreterEnv};

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
///
/// The method "run" will use the interpreter environment to build the execution
/// trace, based on previously computed values.
pub trait ZkApp<C: ArrabbiataCurve>
where
    C::BaseField: PrimeField,
    <<C as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    /// Provide a dummy witness, used to generate a first non-folded instance.
    fn dummy_witness(&self, srs_size: usize) -> Vec<Vec<C::ScalarField>>;

    /// Execute the ZkApp over the interpreter environment `E`.
    fn run<E: InterpreterEnv>(&self, env: &mut E);

    /// Create a setup for the ZkApp.
    /// The setup will define the shape of the execution trace.
    /// It is mostly consisting of the list of selectors that are used to select
    /// the columns that are used in the computation, and how constrained they are.
    ///
    /// For now, the concept of gadget and selectors are mixed together. We
    /// should separate them in the future to allow more flexibility.
    fn setup(&self, app_size: usize) -> Vec<Gadget>;
}

pub mod minroot;

/// An app implemening the verifier of Arrabbiata.
pub mod verifier;
