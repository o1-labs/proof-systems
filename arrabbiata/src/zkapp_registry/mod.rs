use crate::{column::E, curve::ArrabbiataCurve, interpreter::InterpreterEnv};
use ark_ff::PrimeField;
use std::{collections::HashMap, hash::Hash};

/// A ZkApp is a program that can be executed and proven using a
/// (zero-knowledge) succinct non-interactive argument of knowledge or in short
/// a zkSNARK. In particular, the interface is designed to be used with the
/// Arrabbiata accumulation scheme and its corresponding decider.
///
/// A ZkApp is defined over a list of instructions (of type `Instruction`),
/// where each instruction is a step of the computation. The computation is
/// defined by the control-flow of the ZkApp, which is defined by the methods
/// [Self::fetch_next_instruction] and [Self::fetch_instruction].
/// An instruction is considered to be filling only one row of the execution
/// trace.
///
/// A list of instructions sharing the same constraints is called a gadget (of
/// type `Gadget`). Each instruction must be convertible to a gadget, therefore
/// the type restriction to `From<Instruction>`. It will be used in particular
/// by the method [setup] to build the list of selectors.
///
/// An instruction can also transport some data, which can be used to guide the
/// control-flow and to provide additional information to the interpreter while
/// executing [Self::run].
/// For instance, a gadget could be `EllipticCurveScaling`, which could be
/// formed by a set of instructions `EllipticCurveScaling(bit)` where `bit`
/// defines the bit of the scalar that is being processed.
///
/// A ZkApp structure is responsible to provide a dummy witness, used to
/// generate a first non-folded instance. The dummy witness is a satisfying
/// execution trace for dummy inputs.
pub trait ZkApp<C, Instruction, Gadget>
where
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
    Instruction: Copy,
    Gadget: From<Instruction> + Eq + Hash,
{
    /// Provide a dummy witness, used to generate a first non-folded instance.
    fn dummy_witness(&self, srs_size: usize) -> Vec<Vec<C::ScalarField>>;

    /// Fetch the first instruction to execute.
    fn fetch_instruction(&self) -> Instruction;

    /// Describe the control-flow of the ZkApp.
    /// This function should return the next instruction to execute after
    /// `current_instr`.
    ///
    /// If the current instruction is the last one, it should return `None`.
    ///
    /// The method is going to be called by the [execute] function and [setup]
    /// function.
    fn fetch_next_instruction(&self, current_instr: Instruction) -> Option<Instruction>;

    /// Execute the instruction `instr` over the interpreter environment `E`.
    ///
    /// The interpreter environment is responsible to keep track of the
    /// execution trace, and to provide the necessary values to the ZkApp.
    ///
    /// The method is going to be called by the [execute] function, which is
    /// responsible to build the whole execution trace, instruction by
    /// instruction. The stoppingcondition is when the
    /// [Self::fetch_next_instruction] returns `None`.
    fn run<E: InterpreterEnv>(&self, env: &mut E, instr: Instruction);
}

/// Execute the ZkApp `zkapp` over the interpreter environment `env`.
/// This is a generic function that can be used to execute any ZkApp.
pub fn execute<E, C, Instruction, Gadget, Z>(zkapp: &Z, env: &mut E)
where
    E: InterpreterEnv,
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
    Instruction: Copy,
    Gadget: From<Instruction> + Eq + Hash,
    Z: ZkApp<C, Instruction, Gadget>,
{
    let mut instr: Option<Instruction> = Some(zkapp.fetch_instruction());
    while let Some(i) = instr {
        zkapp.run(env, i);
        env.reset();
        instr = zkapp.fetch_next_instruction(i);
    }
}

/// Create a setup for the ZkApp.
///
/// The setup will define the shape of the execution trace.
/// It is mostly consisting of the list of selectors that are used to select the
/// columns that are used in the computation, and how constrained they are.
///
/// For now, the concept of gadget and selectors are mixed together. We
/// should separate them in the future to allow more flexibility.
pub fn setup<C, Instruction, Gadget, Z>(zkapp: &Z) -> Vec<Gadget>
where
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
    Instruction: Copy,
    Gadget: From<Instruction> + Eq + Hash,
    Z: ZkApp<C, Instruction, Gadget>,
{
    let mut circuit: Vec<Gadget> = vec![];
    let mut instr: Option<Instruction> = Some(zkapp.fetch_instruction());
    while let Some(i) = instr {
        circuit.push(Gadget::from(i));
        instr = zkapp.fetch_next_instruction(i);
    }
    circuit
}

/// Get the constraints per gadget for the ZkApp `zkapp`.
/// The constraints are the polynomials that are used to define the execution
/// trace.
///
/// The hypothesis is that each instruction of the ZkApp gives the same
/// constraints.
///
/// The output will contain all the constraints that would be used in a single
/// execution.
pub fn get_constraints_per_gadget<C, Instruction, Gadget, Z>(
    zkapp: &Z,
) -> HashMap<Gadget, Vec<E<C::ScalarField>>>
where
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
    Instruction: Copy,
    Gadget: From<Instruction> + Eq + Hash,
    Z: ZkApp<C, Instruction, Gadget>,
{
    let mut env = crate::constraint::Env::<C>::new();
    let mut constraints = HashMap::new();
    let mut instr: Option<Instruction> = Some(zkapp.fetch_instruction());
    while let Some(i) = instr {
        zkapp.run(&mut env, i);
        constraints.insert(Gadget::from(i), env.constraints.clone());
        env.reset();
        instr = zkapp.fetch_next_instruction(i);
    }
    constraints
}

pub mod verifier;
