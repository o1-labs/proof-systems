use super::{
    column::{Column, E},
    interpreter::{Instruction, InterpreterEnv},
    INSTRUCTION_SET_SIZE,
};
use crate::{
    interpreters::riscv32im::{constraints::ConstantTerm::Literal, SCRATCH_SIZE},
    lookups::Lookup,
};
use ark_ff::{Field, One};
use kimchi::circuits::{
    expr::{ConstantTerm, Expr, ExprInner, Operations, Variable},
    gate::CurrOrNext,
};

pub struct Env<F: Field> {
    pub scratch_state_idx: usize,
    pub scratch_state_idx_inverse: usize,
    pub lookups: Vec<Lookup<E<F>>>,
    pub constraints: Vec<E<F>>,
    pub selector: Option<E<F>>,
}

impl<Fp: Field> Default for Env<Fp> {
    fn default() -> Self {
        Self {
            scratch_state_idx: 0,
            scratch_state_idx_inverse: 0,
            constraints: Vec::new(),
            lookups: Vec::new(),
            selector: None,
        }
    }
}

impl<Fp: Field> InterpreterEnv for Env<Fp> {
    /// In the concrete implementation for the constraints, the interpreter will
    /// work over columns. The position in this case can be seen as a new
    /// variable/input of our circuit.
    type Position = Column;

    // Use one of the available columns. It won't create a new column every time
    // this function is called. The number of columns is defined upfront by
    // crate::mips::witness::SCRATCH_SIZE.
    fn alloc_scratch(&mut self) -> Self::Position {
        // All columns are implemented using a simple index, and a name is given
        // to the index. See crate::SCRATCH_SIZE for the maximum number of
        // columns the circuit can use.
        let scratch_idx = self.scratch_state_idx;
        self.scratch_state_idx += 1;
        Column::ScratchState(scratch_idx)
    }

    fn alloc_scratch_inverse(&mut self) -> Self::Position {
        let scratch_idx = self.scratch_state_idx_inverse;
        self.scratch_state_idx_inverse += 1;
        Column::ScratchStateInverse(scratch_idx)
    }

    type Variable = E<Fp>;

    fn variable(&self, column: Self::Position) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: column,
            row: CurrOrNext::Curr,
        }))
    }

    fn activate_selector(&mut self, selector: Instruction) {
        // Sanity check: we only want to activate once per instruction
        assert!(self.selector.is_none(), "A selector has been already activated. You might need to reset the environment if you want to start a new instruction.");
        let n = usize::from(selector) - SCRATCH_SIZE - 1;
        self.selector = Some(self.variable(Column::Selector(n)))
    }

    fn add_constraint(&mut self, assert_equals_zero: Self::Variable) {
        self.constraints.push(assert_equals_zero)
    }

    fn check_is_zero(_assert_equals_zero: &Self::Variable) {
        // No-op, witness only
    }

    fn check_equal(_x: &Self::Variable, _y: &Self::Variable) {
        // No-op, witness only
    }

    fn assert_boolean(&mut self, x: &Self::Variable) {
        self.add_constraint(x.clone() * x.clone() - x.clone());
    }

    fn add_lookup(&mut self, lookup: Lookup<Self::Variable>) {
        self.lookups.push(lookup);
    }

    fn instruction_counter(&self) -> Self::Variable {
        self.variable(Column::InstructionCounter)
    }

    fn increase_instruction_counter(&mut self) {
        // No-op, witness only
    }

    unsafe fn fetch_register(
        &mut self,
        _idx: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable {
        self.variable(output)
    }

    unsafe fn push_register_if(
        &mut self,
        _idx: &Self::Variable,
        _value: Self::Variable,
        _if_is_true: &Self::Variable,
    ) {
        // No-op, witness only
    }

    unsafe fn fetch_register_access(
        &mut self,
        _idx: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable {
        self.variable(output)
    }

    unsafe fn push_register_access_if(
        &mut self,
        _idx: &Self::Variable,
        _value: Self::Variable,
        _if_is_true: &Self::Variable,
    ) {
        // No-op, witness only
    }

    unsafe fn fetch_memory(
        &mut self,
        _addr: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable {
        self.variable(output)
    }

    unsafe fn push_memory(&mut self, _addr: &Self::Variable, _value: Self::Variable) {
        // No-op, witness only
    }

    unsafe fn fetch_memory_access(
        &mut self,
        _addr: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable {
        self.variable(output)
    }

    unsafe fn push_memory_access(&mut self, _addr: &Self::Variable, _value: Self::Variable) {
        // No-op, witness only
    }

    fn constant(x: u32) -> Self::Variable {
        Self::Variable::constant(Operations::from(Literal(Fp::from(x))))
    }

    unsafe fn bitmask(
        &mut self,
        _x: &Self::Variable,
        _highest_bit: u32,
        _lowest_bit: u32,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn shift_left(
        &mut self,
        _x: &Self::Variable,
        _by: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn shift_right(
        &mut self,
        _x: &Self::Variable,
        _by: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn shift_right_arithmetic(
        &mut self,
        _x: &Self::Variable,
        _by: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn test_zero(
        &mut self,
        _x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    fn is_zero(&mut self, x: &Self::Variable) -> Self::Variable {
        let res = {
            let pos = self.alloc_scratch();
            unsafe { self.test_zero(x, pos) }
        };
        let x_inv_or_zero = {
            let pos = self.alloc_scratch_inverse();
            self.variable(pos)
        };
        // If x = 0, then res = 1 and x_inv_or_zero = 0
        // If x <> 0, then res = 0 and x_inv_or_zero = x^(-1)
        self.add_constraint(x.clone() * x_inv_or_zero.clone() + res.clone() - Self::constant(1));
        self.add_constraint(x.clone() * res.clone());
        res
    }

    fn equal(&mut self, x: &Self::Variable, y: &Self::Variable) -> Self::Variable {
        self.is_zero(&(x.clone() - y.clone()))
    }

    unsafe fn test_less_than(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn test_less_than_signed(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn and_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn nor_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn or_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn xor_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn add_witness(
        &mut self,
        _y: &Self::Variable,
        _x: &Self::Variable,
        out_position: Self::Position,
        overflow_position: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        (
            self.variable(out_position),
            self.variable(overflow_position),
        )
    }

    unsafe fn sub_witness(
        &mut self,
        _y: &Self::Variable,
        _x: &Self::Variable,
        out_position: Self::Position,
        underflow_position: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        (
            self.variable(out_position),
            self.variable(underflow_position),
        )
    }

    unsafe fn mul_signed_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn mul_hi_signed(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn mul_lo_signed(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn mul_hi(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn mul_hi_signed_unsigned(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn div_signed(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn mod_signed(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn div(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn mod_unsigned(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn mul_lo(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn count_leading_zeros(
        &mut self,
        _x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn count_leading_ones(
        &mut self,
        _x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    fn copy(&mut self, x: &Self::Variable, position: Self::Position) -> Self::Variable {
        let res = self.variable(position);
        self.constraints.push(x.clone() - res.clone());
        res
    }

    fn set_halted(&mut self, _flag: Self::Variable) {
        // TODO
    }

    fn report_exit(&mut self, _exit_code: &Self::Variable) {}

    fn reset(&mut self) {
        self.scratch_state_idx = 0;
        self.constraints.clear();
        self.lookups.clear();
        self.selector = None;
    }
}

impl<Fp: Field> Env<Fp> {
    /// Return the constraints for the selector.
    /// Each selector must be a boolean.
    pub fn get_selector_constraints(&self) -> Vec<E<Fp>> {
        let one = <Self as InterpreterEnv>::Variable::one();
        let mut enforce_bool: Vec<E<Fp>> = (0..INSTRUCTION_SET_SIZE)
            .map(|i| {
                let var = self.variable(Column::Selector(i));
                (var.clone() - one.clone()) * var.clone()
            })
            .collect();
        let enforce_one_activation = (0..INSTRUCTION_SET_SIZE).fold(E::<Fp>::one(), |res, i| {
            let var = self.variable(Column::Selector(i));
            res - var.clone()
        });

        enforce_bool.push(enforce_one_activation);
        enforce_bool
    }

    pub fn get_selector(&self) -> E<Fp> {
        self.selector
            .clone()
            .unwrap_or_else(|| panic!("Selector is not set"))
    }

    /// Return the constraints for the current instruction, without the selector
    pub fn get_constraints(&self) -> Vec<E<Fp>> {
        self.constraints.clone()
    }

    pub fn get_lookups(&self) -> Vec<Lookup<E<Fp>>> {
        self.lookups.clone()
    }
}
