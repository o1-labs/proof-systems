use crate::mips::{
    column::Column as MIPSColumn,
    interpreter::{self, InterpreterEnv},
};
use ark_ff::Field;
use kimchi::circuits::{
    expr::{ConstantExpr, Expr, ExprInner, Variable},
    gate::CurrOrNext,
};

pub struct Env<Fp> {
    pub scratch_state_idx: usize,
    pub constraints: Vec<Expr<ConstantExpr<Fp>, MIPSColumn>>,
}

impl<Fp: Field> InterpreterEnv for Env<Fp> {
    type Position = MIPSColumn;

    fn alloc_scratch(&mut self) -> Self::Position {
        let scratch_idx = self.scratch_state_idx;
        self.scratch_state_idx += 1;
        MIPSColumn::ScratchState(scratch_idx)
    }

    type Variable = Expr<ConstantExpr<Fp>, MIPSColumn>;

    fn add_constraint(&mut self, assert_equals_zero: Self::Variable) {
        self.constraints.push(assert_equals_zero)
    }

    fn check_is_zero(_assert_equals_zero: &Self::Variable) {
        // No-op, witness only
    }

    fn check_equal(_x: &Self::Variable, _y: &Self::Variable) {
        // No-op, witness only
    }

    fn check_boolean(_x: &Self::Variable) {
        // No-op, witness only
    }

    fn add_lookup(&mut self, _lookup: interpreter::Lookup<Self::Variable>) {
        // FIXME: Track the lookup values in the environment.
    }

    fn instruction_counter(&self) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: MIPSColumn::InstructionCounter,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn fetch_register(
        &mut self,
        _idx: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: output,
            row: CurrOrNext::Curr,
        }))
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
        Expr::Atom(ExprInner::Cell(Variable {
            col: output,
            row: CurrOrNext::Curr,
        }))
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
        Expr::Atom(ExprInner::Cell(Variable {
            col: output,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn push_memory(&mut self, _addr: &Self::Variable, _value: Self::Variable) {
        // No-op, witness only
    }

    unsafe fn fetch_memory_access(
        &mut self,
        _addr: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: output,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn push_memory_access(&mut self, _addr: &Self::Variable, _value: Self::Variable) {
        // No-op, witness only
    }

    fn constant(x: u32) -> Self::Variable {
        Expr::from(x as u64)
    }

    unsafe fn bitmask(
        &mut self,
        _x: &Self::Variable,
        _highest_bit: u32,
        _lowest_bit: u32,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn shift_left(
        &mut self,
        _x: &Self::Variable,
        _by: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn shift_right(
        &mut self,
        _x: &Self::Variable,
        _by: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn shift_right_arithmetic(
        &mut self,
        _x: &Self::Variable,
        _by: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn test_zero(
        &mut self,
        _x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn inverse_or_zero(
        &mut self,
        _x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn test_less_than(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn test_less_than_signed(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn and_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn nor_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn or_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn xor_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn add_witness(
        &mut self,
        _y: &Self::Variable,
        _x: &Self::Variable,
        out_position: Self::Position,
        overflow_position: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        (
            Expr::Atom(ExprInner::Cell(Variable {
                col: out_position,
                row: CurrOrNext::Curr,
            })),
            Expr::Atom(ExprInner::Cell(Variable {
                col: overflow_position,
                row: CurrOrNext::Curr,
            })),
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
            Expr::Atom(ExprInner::Cell(Variable {
                col: out_position,
                row: CurrOrNext::Curr,
            })),
            Expr::Atom(ExprInner::Cell(Variable {
                col: underflow_position,
                row: CurrOrNext::Curr,
            })),
        )
    }

    unsafe fn mul_signed_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn mul_hi_lo_signed(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position_hi: Self::Position,
        position_lo: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        (
            Expr::Atom(ExprInner::Cell(Variable {
                col: position_hi,
                row: CurrOrNext::Curr,
            })),
            Expr::Atom(ExprInner::Cell(Variable {
                col: position_lo,
                row: CurrOrNext::Curr,
            })),
        )
    }

    unsafe fn mul_hi_lo(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position_hi: Self::Position,
        position_lo: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        (
            Expr::Atom(ExprInner::Cell(Variable {
                col: position_hi,
                row: CurrOrNext::Curr,
            })),
            Expr::Atom(ExprInner::Cell(Variable {
                col: position_lo,
                row: CurrOrNext::Curr,
            })),
        )
    }

    unsafe fn divmod_signed(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position_quotient: Self::Position,
        position_remainder: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        (
            Expr::Atom(ExprInner::Cell(Variable {
                col: position_quotient,
                row: CurrOrNext::Curr,
            })),
            Expr::Atom(ExprInner::Cell(Variable {
                col: position_remainder,
                row: CurrOrNext::Curr,
            })),
        )
    }

    unsafe fn divmod(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position_quotient: Self::Position,
        position_remainder: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        (
            Expr::Atom(ExprInner::Cell(Variable {
                col: position_quotient,
                row: CurrOrNext::Curr,
            })),
            Expr::Atom(ExprInner::Cell(Variable {
                col: position_remainder,
                row: CurrOrNext::Curr,
            })),
        )
    }

    unsafe fn count_leading_zeros(
        &mut self,
        _x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    fn copy(&mut self, x: &Self::Variable, position: Self::Position) -> Self::Variable {
        let res = Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }));
        self.constraints.push(x.clone() - res.clone());
        res
    }

    fn set_halted(&mut self, _flag: Self::Variable) {
        // TODO
    }

    fn report_exit(&mut self, _exit_code: &Self::Variable) {}

    fn request_preimage_write(
        &mut self,
        _addr: &Self::Variable,
        _len: &Self::Variable,
        pos: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: pos,
            row: CurrOrNext::Curr,
        }))
    }

    fn request_hint_write(&mut self, _addr: &Self::Variable, _len: &Self::Variable) {
        // No-op, witness only
    }
}
