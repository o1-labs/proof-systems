use crate::{
    column::E, curve::ArrabbiataCurve, interpreter::InterpreterEnv, MAX_DEGREE,
    MV_POLYNOMIAL_ARITY, NUMBER_OF_COLUMNS,
};
use ark_ff::PrimeField;
use mvpoly::{monomials::Sparse, MVPoly};
use std::{collections::HashMap, hash::Hash};

pub mod minroot;
pub mod verifiable_minroot;
pub mod verifier;

/// A ZkApp is a (stateless) program that can be executed and proven using a
/// (zero-knowledge) succinct non-interactive argument of knowledge or in short
/// a zkSNARK. In particular, the interface is designed to be used with the
/// Arrabbiata accumulation scheme and its corresponding decider.
///
/// A ZkApp is defined over a list of instructions (of type
/// [Self::Instruction]), where each instruction is a step of the computation.
/// The computation is defined by the control-flow of the ZkApp, which is
/// defined by the methods [Self::fetch_next_instruction] and
/// [Self::fetch_instruction].
/// An instruction is considered to be filling only one row of the execution
/// trace.
///
/// A list of instructions sharing the same constraints is called a gadget (of
/// type [Self::Gadget]). Each instruction must be convertible to a gadget,
/// therefore the type restriction to [From<Self::Instruction>]. It will be used
/// in particular by the method [setup] to build the list of selectors.
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
///
/// More specialised ZkApp's can be implemented with this interface.
/// For instance, a [VerifierApp] is a ZkApp that is designed to implement the
/// verifier part of the accumulation scheme.
/// Naturally, it has to implement the ZkApp trait.
///
/// Another kind of ZkApp is a [VerifiableZkApp], which is a ZkApp that is
/// designed to be verifiable with a [VerifierApp], i.e., it is designed to be
/// accompanied by a verifier.
pub trait ZkApp<C>
where
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
{
    type Instruction: Copy;

    type Gadget: From<Self::Instruction> + Eq + Hash;

    /// Provide a dummy witness, used to generate a first non-folded instance.
    fn dummy_witness(&self, srs_size: usize) -> Vec<Vec<C::ScalarField>>;

    /// Fetch the first instruction to execute.
    fn fetch_instruction(&self) -> Self::Instruction;

    /// Describe the control-flow of the ZkApp.
    /// This function should return the next instruction to execute after
    /// `current_instr`.
    ///
    /// If the current instruction is the last one, it should return `None`.
    ///
    /// The method is going to be called by the [execute] function and [setup]
    /// function.
    fn fetch_next_instruction(&self, current_instr: Self::Instruction)
        -> Option<Self::Instruction>;

    /// Execute the instruction `instr` over the interpreter environment `E`.
    ///
    /// The interpreter environment is responsible to keep track of the
    /// execution trace, and to provide the necessary values to the ZkApp.
    ///
    /// The method is going to be called by the [execute] function, which is
    /// responsible to build the whole execution trace, instruction by
    /// instruction. The stoppingcondition is when the
    /// [Self::fetch_next_instruction] returns `None`.
    fn run<E: InterpreterEnv>(&self, env: &mut E, instr: Self::Instruction);
}

/// A VerifierApp is a ZkApp that is designed to implement the verifier part of
/// the accumulation scheme.
///
/// The verifier is responsible to check the validity of a previously generated
/// proof.
///
/// Naturally, it has to implement the ZkApp trait, as it is a program that can
/// be accumulated.
pub trait VerifierApp<C>: ZkApp<C> + Copy + Clone + Hash + Eq + PartialEq
where
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
{
}

/// A VerifiableZkApp is a ZkApp that is designed to be verifiable with a
/// [VerifierApp], i.e., it is designed to be accompanied by a verifier.
///
/// An example of a [VerifiableZkApp] is the [verifiable_minroot::MinRoot] ZkApp
/// that uses the vanilla Arrabbiata verifier [verifier::Verifier].
pub trait VerifiableZkApp<C>: ZkApp<C>
where
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
{
    type Verifier: VerifierApp<C>;
}

/// Execute the ZkApp `zkapp` over the interpreter environment `env`.
/// This is a generic function that can be used to execute any ZkApp.
pub fn execute<E, C, Z>(zkapp: &Z, env: &mut E)
where
    E: InterpreterEnv,
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
    Z: ZkApp<C>,
{
    let mut instr: Option<Z::Instruction> = Some(zkapp.fetch_instruction());
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
pub fn setup<C, Z>(zkapp: &Z) -> Vec<Z::Gadget>
where
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
    Z: ZkApp<C>,
{
    let mut circuit: Vec<Z::Gadget> = vec![];
    let mut instr: Option<Z::Instruction> = Some(zkapp.fetch_instruction());
    while let Some(i) = instr {
        circuit.push(Z::Gadget::from(i));
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
pub fn get_constraints_per_gadget<C, Z>(zkapp: &Z) -> HashMap<Z::Gadget, Vec<E<C::ScalarField>>>
where
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
    Z: ZkApp<C>,
{
    let mut env = crate::constraint::Env::<C>::new();
    let mut constraints = HashMap::new();
    let mut instr: Option<Z::Instruction> = Some(zkapp.fetch_instruction());
    while let Some(i) = instr {
        zkapp.run(&mut env, i);
        constraints.insert(Z::Gadget::from(i), env.constraints.clone());
        env.reset();
        instr = zkapp.fetch_next_instruction(i);
    }
    constraints
}

pub fn get_mvpoly_per_gadget<C, Z>(
    zkapp: &Z,
) -> HashMap<Z::Gadget, Vec<Sparse<C::ScalarField, { MV_POLYNOMIAL_ARITY }, { MAX_DEGREE }>>>
where
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
    Z: ZkApp<C>,
{
    let mut env = crate::constraint::Env::<C>::new();
    let mut constraints = HashMap::new();
    let mut instr: Option<Z::Instruction> = Some(zkapp.fetch_instruction());
    while let Some(i) = instr {
        zkapp.run(&mut env, i);
        let polys: Vec<_> = env
            .constraints
            .iter()
            .map(|c| Sparse::from_expr(c.clone(), Some(NUMBER_OF_COLUMNS)))
            .collect::<Vec<_>>();
        constraints.insert(Z::Gadget::from(i), polys);
        env.reset();
        instr = zkapp.fetch_next_instruction(i);
    }
    constraints
}
