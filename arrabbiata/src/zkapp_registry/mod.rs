use ark_ec::CurveConfig;
use ark_ff::PrimeField;
use poly_commitment::commitment::CommitmentCurve;

use crate::{
    column::Gadget,
    curve::ArrabbiataCurve,
    interpreter::{Instruction, InterpreterEnv},
};

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
pub trait ZkApp<C: ArrabbiataCurve, Gadget, Instruction: Into<Gadget>>
where
    C::BaseField: PrimeField,
    <<C as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    /// The type of gadgets used in the ZkApp.
    ///
    /// A gadget is a collection of instructions defined by the type
    /// [Self::Instruction], all sharing the same set of constraints.
    /// A gadget has a specific selector assigned to it, which determines the
    /// set of polynomials that will constrain the row that is being processed.
    ///
    /// A gadget can be used on a consecutive set of rows.
    ///
    /// For instance, a gadget could be [EllipticCurveScaling], which could be
    /// formed by a set of instructions [EllipticCurveScaling(bit)] where `bit`
    /// defines the bit of the scalar that is being processed.
    ///
    /// All instructions in a gadget are expected to be of the same type, i.e.
    /// described by the same set of multivariate polynomials.
    type Gadget = Gadget;

    /// The type of the instructions used in the ZkApp.
    ///
    /// An instruction is a more granular part of a gadget. It is applied to a
    /// single row, and can be parametrized by a value that will be used to
    /// define some behaviors of the gadget.
    type Instruction = Instruction;

    /// Provide a dummy witness, used to generate a first non-folded instance.
    fn dummy_witness(&self, srs_size: usize) -> Vec<Vec<C::ScalarField>>;

    /// Describe the control-flow of the ZkApp.
    fn fetch_next_instruction(&self, current_instr: Self::Instruction) -> Self::Instruction;

    /// Execute the ZkApp over the interpreter environment `E`.
    fn run<E: InterpreterEnv>(&self, env: &mut E, instr: Self::Instruction);

    /// Create a setup for the ZkApp.
    ///
    /// The setup will define the shape of the execution trace.
    /// It is mostly consisting of the list of selectors that are used to select
    /// the columns that are used in the computation, and how constrained they are.
    ///
    /// For now, the concept of gadget and selectors are mixed together. We
    /// should separate them in the future to allow more flexibility.
    fn setup(&self, app_size: usize) -> Vec<Self::Gadget>;
}

pub mod minroot;

/// An app implemening the verifier of Arrabbiata.
pub mod verifier;
