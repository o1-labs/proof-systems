pub mod minroot;
use crate::interpreter2::InterpreterEnv;
use std::hash::Hash;

pub trait ZkApp {
    type Input;

    type Output;

    type Instruction: Copy;

    type Gadget: From<Self::Instruction> + Eq + Hash;

    fn native_implementation(&self, input: Self::Input) -> Self::Output;

    fn fetch_instruction(&self) -> Self::Instruction;

    fn fetch_next_instruction(&self, current_instr: Self::Instruction)
        -> Option<Self::Instruction>;

    fn run<E: InterpreterEnv>(&self, env: &mut E, instr: Self::Instruction);
}
