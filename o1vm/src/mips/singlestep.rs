// Amalgamation of the different MIPS circuits into a "single" circuit.

use super::column;

pub trait SingleStepper {
    type S<I, P, V>;

    type Position;

    type Instruction;

    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::fmt::Debug
        + ark_ff::Zero
        + ark_ff::One;

    type State = S<Self::Instruction, Self::Position, Self::Variable>;

    /// Helpers

    fn alloc_scratch(state: Self::State) -> (Self::Position, Self::State);

    fn variable(state: &Self::State, column: Self::Position) -> Self::Variable;

    fn add_constraint(state: Self::State, assert_equals_zero: Self::Variable) -> Self::State;

    // ABORTS
    fn check_is_zero(assert_equals_zero: &Self::Variable);

    fn assert_is_zero(state: Self::State, assert_equals_zero: Self::Variable) -> Self::State {
        Self::check_is_zero(&assert_equals_zero);
        self.add_constraint(assert_equals_zero)
    }

    // ABORTS
    fn check_equal(x: &Self::Variable, y: &Self::Variable);

    fn assert_equal(state: Self::State, x: Self::Variable, y: Self::Variable) -> Self::State {
        Self::check_equal(&x, &y);
        self.add_constraint(x - y)
    }

    // ABORTS
    fn check_boolean(x: &Self::Variable);

    fn assert_boolean(state: Self::State, x: Self::Variable) {
        Self::check_boolean(&x);
        self.add_constraint(x.clone() * x.clone() - x); // polynomial with roots {0, 1}
    }

    fn add_lookup(state: Self::State, lookup: Lookup<Self::Variable>) -> Self::State;

    // compared to original, this is divided by 4.
    fn instruction_counter(state: &Self::State) -> Self::Variable;

    fn increase_instruction_counter(state: Self::State) -> Self::State;

    /// Actual stepper

    fn step(state: Self::State, instructions: &Vec<Self::Instruction>) -> Self::State;
}

/// A simple example

#[derive(
    Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, EnumCount, EnumIter
)]
pub enum ExampleRegister {
    A,
    B,
    C,
    D,
    Lo,
    Hi,
    Ip,
    NextIp,
}

pub type ExamplePosition = column::ColumnAlias;

pub type ExampleVariable = ark_bn254::Bn254;

const SCRATCH_SIZE: usize = 64;

pub struct ExampleRegisterBank<T> {
    a: T,
    b: T,
    c: T,
    d: T,
    lo: T,
    hi: T,
    ip: T,
    next_ip: T,
}

#[derive(
    Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd
)]
pub enum ExampleInstruction<F> {
    Div(ExampleRegister, ExampleRegister),
    ShiftLeftLogicalVariable(ExampleRegister, ExampleRegister),
    JumpRegister(ExampleRegister),
    Load8(ExampleRegister, ExampleRegister, u32),
    SyscallExitGroup,
}

pub struct ExampleS<I, P, V> {
    registers: ExampleRegisterBank<u32>,
    memory: Vec<(u32, Vec<u8>)>,
    halt: bool,
    scratch_state_idx: usize,
    scratch_state: [V; SCRATCH_SIZE],
}