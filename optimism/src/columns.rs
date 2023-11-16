use kimchi::circuits::{
    domains::EvaluationDomains,
    expr::{self, ColumnEnvironment, Constants, Domain, GenericColumn},
};
use ark_ff::FftField;
use ark_poly::{Evaluations, Radix2EvaluationDomain as D};
use core::ops::{Index, IndexMut};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use strum_macros::{EnumCount, EnumIter};
use crate::mips::interpreter::{RTypeInstruction, JTypeInstruction, ITypeInstruction};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Column {
    InstructionPart(InstructionPart),
    InstructionSelector(InstructionSelector),
    FixedColumn(FixedColumn),
    InitialMemory(usize),
    FinalMemory(usize),
    FinalMemoryWriteIndex(usize),
    InitialRegisters,
    FinalRegisters,
    FinalRegistersWriteIndex,
    LookupTerm(usize),
    LookupAggregation,
    InstructionPointer,
    ScratchState(usize),
    LookupCounter(LookupCounter),
    Halt,
}

impl GenericColumn for Column {
    fn domain(&self) -> Domain {
        // TODO: Optimize
        Domain::D8
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FixedColumn {
    Counter,       // 16-bit counter
    SparseCounter, // 16-bit counter, encoded as 4^i * b_i for each bit
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LookupCounter {
    Counter,       // 16-bit counter
    SparseCounter, // 16-bit counter, encoded as 4^i * b_i for each bit
}

#[derive(Clone)]
pub struct ColumnsEnv<'a, F: FftField> {
    pub domain: EvaluationDomains<F>,
    pub constants: Constants<F>,
    pub instruction_parts: InstructionParts<&'a Evaluations<F, D<F>>>,
    pub instruction_selectors: InstructionSelectors<&'a Evaluations<F, D<F>>>,
    pub initial_memory: &'a [Evaluations<F, D<F>>],
    pub final_memory: &'a [Evaluations<F, D<F>>],
    pub final_memory_write_index: &'a [Evaluations<F, D<F>>],
    pub initial_registers: &'a Evaluations<F, D<F>>,
    pub final_registers: &'a Evaluations<F, D<F>>,
    pub final_registers_write_index: &'a Evaluations<F, D<F>>,
    pub lookup_terms: &'a [Evaluations<F, D<F>>; NUM_LOOKUP_TERMS],
    pub lookup_aggregation: &'a Evaluations<F, D<F>>,
    pub fixed_columns: FixedColumns<&'a Evaluations<F, D<F>>>,
    pub instruction_pointer: &'a Evaluations<F, D<F>>,
    pub scratch_state: &'a [Evaluations<F, D<F>>; SCRATCH_SIZE],
    pub lookup_counters: LookupCounters<&'a Evaluations<F, D<F>>>,
    pub halt: &'a Evaluations<F, D<F>>,
    pub vanishes_on_last_row: &'a Evaluations<F, D<F>>,
    pub l0_1: F,
}

impl<'a, F: FftField> ColumnEnvironment<'a, F> for ColumnsEnv<'a, F> {
    type Column = Column;

    fn get_column(&self, col: &Self::Column) -> Option<&'a Evaluations<F, D<F>>> {
        match col {
            Column::InstructionSelector(selector) => Some(self.instruction_selectors[*selector]),
            Column::FixedColumn(col) => Some(self.fixed_columns[*col]),
            Column::InstructionPart(instr_part) => Some(self.instruction_parts[*instr_part]),
            Column::InitialMemory(idx) => Some(&self.initial_memory[*idx]),
            Column::FinalMemory(idx) => Some(&self.final_memory[*idx]),
            Column::FinalMemoryWriteIndex(idx) => Some(&self.final_memory_write_index[*idx]),
            Column::InitialRegisters => Some(self.initial_registers),
            Column::FinalRegisters => Some(self.final_registers),
            Column::FinalRegistersWriteIndex => Some(self.final_registers_write_index),
            Column::LookupTerm(i) => Some(&self.lookup_terms[*i]),
            Column::LookupAggregation => Some(self.lookup_aggregation),
            Column::InstructionPointer => Some(self.instruction_pointer),
            Column::ScratchState(i) => Some(&self.scratch_state[*i]),
            Column::LookupCounter(i) => Some(&self.lookup_counters[*i]),
            Column::Halt => Some(&self.halt),
        }
    }

    fn get_domain(&self, d: Domain) -> D<F> {
        match d {
            Domain::D1 => self.domain.d1,
            Domain::D2 => self.domain.d2,
            Domain::D4 => self.domain.d4,
            Domain::D8 => self.domain.d8,
        }
    }

    fn get_constants(&self) -> &Constants<F> {
        &self.constants
    }

    fn vanishes_on_last_4_rows(&self) -> &'a Evaluations<F, D<F>> {
        unimplemented!()
    }

    fn vanishes_on_last_row(&self) -> &'a Evaluations<F, D<F>> {
        &self.vanishes_on_last_row
    }

    fn l0_1(&self) -> F {
        self.l0_1
    }
}

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
pub struct FixedColumns<T> {
    pub counter: T,
    pub sparse_counter: T,
}

impl<A> Index<FixedColumn> for FixedColumns<A> {
    type Output = A;

    fn index(&self, index: FixedColumn) -> &Self::Output {
        match index {
            FixedColumn::Counter => &self.counter,
            FixedColumn::SparseCounter => &self.sparse_counter,
        }
    }
}

impl<A> IndexMut<FixedColumn> for FixedColumns<A> {
    fn index_mut(&mut self, index: FixedColumn) -> &mut Self::Output {
        match index {
            FixedColumn::Counter => &mut self.counter,
            FixedColumn::SparseCounter => &mut self.sparse_counter,
        }
    }
}

impl<A> FixedColumns<A> {
    pub fn as_ref(&self) -> FixedColumns<&A> {
        FixedColumns {
            counter: &self.counter,
            sparse_counter: &self.sparse_counter,
        }
    }

    pub fn as_mut(&mut self) -> FixedColumns<&mut A> {
        FixedColumns {
            counter: &mut self.counter,
            sparse_counter: &mut self.sparse_counter,
        }
    }

    pub fn map<B, F: FnMut(A) -> B>(self, mut f: F) -> FixedColumns<B> {
        let FixedColumns {
            counter,
            sparse_counter,
        } = self;
        FixedColumns {
            counter: f(counter),
            sparse_counter: f(sparse_counter),
        }
    }

    pub fn into_iter(self) -> impl Iterator<Item = A> {
        let FixedColumns {
            counter,
            sparse_counter,
        } = self;
        vec![counter, sparse_counter].into_iter()
    }
}

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
pub struct LookupCounters<T> {
    pub counter: T,
    pub sparse_counter: T,
}

impl<A> Index<LookupCounter> for LookupCounters<A> {
    type Output = A;

    fn index(&self, index: LookupCounter) -> &Self::Output {
        match index {
            LookupCounter::Counter => &self.counter,
            LookupCounter::SparseCounter => &self.sparse_counter,
        }
    }
}

impl<A> IndexMut<LookupCounter> for LookupCounters<A> {
    fn index_mut(&mut self, index: LookupCounter) -> &mut Self::Output {
        match index {
            LookupCounter::Counter => &mut self.counter,
            LookupCounter::SparseCounter => &mut self.sparse_counter,
        }
    }
}

impl<A> LookupCounters<A> {
    pub fn as_ref(&self) -> LookupCounters<&A> {
        LookupCounters {
            counter: &self.counter,
            sparse_counter: &self.sparse_counter,
        }
    }

    pub fn as_mut(&mut self) -> LookupCounters<&mut A> {
        LookupCounters {
            counter: &mut self.counter,
            sparse_counter: &mut self.sparse_counter,
        }
    }

    pub fn map<B, F: FnMut(A) -> B>(self, mut f: F) -> LookupCounters<B> {
        let LookupCounters {
            counter,
            sparse_counter,
        } = self;
        LookupCounters {
            counter: f(counter),
            sparse_counter: f(sparse_counter),
        }
    }

    pub fn into_iter(self) -> impl Iterator<Item = A> {
        let LookupCounters {
            counter,
            sparse_counter,
        } = self;
        vec![counter, sparse_counter].into_iter()
    }
}

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
pub struct InstructionSelectors<T> {
    pub r_type: RTypeInstructionSelectors<T>,
    pub j_type: JTypeInstructionSelectors<T>,
    pub i_type: ITypeInstructionSelectors<T>,
}

impl<A> Index<InstructionSelector> for InstructionSelectors<A> {
    type Output = A;

    fn index(&self, idx: InstructionSelector) -> &Self::Output {
        match idx {
            InstructionSelector::RType(instr) => &self.r_type[instr],
            InstructionSelector::JType(instr) => &self.j_type[instr],
            InstructionSelector::IType(instr) => &self.i_type[instr],
        }
    }
}

impl<A> IndexMut<InstructionSelector> for InstructionSelectors<A> {
    fn index_mut(&mut self, idx: InstructionSelector) -> &mut Self::Output {
        match idx {
            InstructionSelector::RType(instr) => &mut self.r_type[instr],
            InstructionSelector::JType(instr) => &mut self.j_type[instr],
            InstructionSelector::IType(instr) => &mut self.i_type[instr],
        }
    }
}

impl<A> InstructionSelectors<A> {
    pub fn as_ref(&self) -> InstructionSelectors<&A> {
        InstructionSelectors {
            r_type: self.r_type.as_ref(),
            j_type: self.j_type.as_ref(),
            i_type: self.i_type.as_ref(),
        }
    }

    pub fn as_mut(&mut self) -> InstructionSelectors<&mut A> {
        InstructionSelectors {
            r_type: self.r_type.as_mut(),
            j_type: self.j_type.as_mut(),
            i_type: self.i_type.as_mut(),
        }
    }

    pub fn map<B, F: FnMut(A) -> B>(self, mut f: F) -> InstructionSelectors<B> {
        let InstructionSelectors {
            r_type,
            j_type,
            i_type,
        } = self;
        InstructionSelectors {
            r_type: r_type.map(|x| f(x)),
            j_type: j_type.map(|x| f(x)),
            i_type: i_type.map(|x| f(x)),
        }
    }

    pub fn into_iter(self) -> impl Iterator<Item = A> {
        let InstructionSelectors {
            r_type,
            j_type,
            i_type,
        } = self;
        r_type
            .into_iter()
            .chain(j_type.into_iter())
            .chain(i_type.into_iter())
    }
}

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
pub struct RTypeInstructionSelectors<T> {
    pub shift_left_logical: T,
    pub shift_right_logical: T,
    pub shift_right_arithmetic: T,
    pub shift_left_logical_variable: T,
    pub shift_right_logical_variable: T,
    pub shift_right_arithmetic_variable: T,
    pub jump_register: T,
    pub jump_and_link_register: T,
    pub syscall: T,
    pub move_from_hi: T,
    pub move_to_hi: T,
    pub move_from_lo: T,
    pub move_to_lo: T,
    pub multiply: T,
    pub multiply_unsigned: T,
    pub div: T,
    pub div_unsigned: T,
    pub add: T,
    pub add_unsigned: T,
    pub sub: T,
    pub sub_unsigned: T,
    pub and: T,
    pub or: T,
    pub xor: T,
    pub nor: T,
    pub set_less_than: T,
    pub set_less_than_unsigned: T,
}

impl<A> Index<RTypeInstruction> for RTypeInstructionSelectors<A> {
    type Output = A;

    fn index(&self, index: RTypeInstruction) -> &Self::Output {
        match index {
            RTypeInstruction::ShiftLeftLogical => &self.shift_left_logical,
            RTypeInstruction::ShiftRightLogical => &self.shift_right_logical,
            RTypeInstruction::ShiftRightArithmetic => &self.shift_right_arithmetic,
            RTypeInstruction::ShiftLeftLogicalVariable => &self.shift_left_logical_variable,
            RTypeInstruction::ShiftRightLogicalVariable => &self.shift_right_logical_variable,
            RTypeInstruction::ShiftRightArithmeticVariable => &self.shift_right_arithmetic_variable,
            RTypeInstruction::JumpRegister => &self.jump_register,
            RTypeInstruction::JumpAndLinkRegister => &self.jump_and_link_register,
            RTypeInstruction::Syscall => &self.syscall,
            RTypeInstruction::MoveFromHi => &self.move_from_hi,
            RTypeInstruction::MoveToHi => &self.move_to_hi,
            RTypeInstruction::MoveFromLo => &self.move_from_lo,
            RTypeInstruction::MoveToLo => &self.move_to_lo,
            RTypeInstruction::Multiply => &self.multiply,
            RTypeInstruction::MultiplyUnsigned => &self.multiply_unsigned,
            RTypeInstruction::Div => &self.div,
            RTypeInstruction::DivUnsigned => &self.div_unsigned,
            RTypeInstruction::Add => &self.add,
            RTypeInstruction::AddUnsigned => &self.add_unsigned,
            RTypeInstruction::Sub => &self.sub,
            RTypeInstruction::SubUnsigned => &self.sub_unsigned,
            RTypeInstruction::And => &self.and,
            RTypeInstruction::Or => &self.or,
            RTypeInstruction::Xor => &self.xor,
            RTypeInstruction::Nor => &self.nor,
            RTypeInstruction::SetLessThan => &self.set_less_than,
            RTypeInstruction::SetLessThanUnsigned => &self.set_less_than_unsigned,
        }
    }
}

impl<A> IndexMut<RTypeInstruction> for RTypeInstructionSelectors<A> {
    fn index_mut(&mut self, index: RTypeInstruction) -> &mut Self::Output {
        match index {
            RTypeInstruction::ShiftLeftLogical => &mut self.shift_left_logical,
            RTypeInstruction::ShiftRightLogical => &mut self.shift_right_logical,
            RTypeInstruction::ShiftRightArithmetic => &mut self.shift_right_arithmetic,
            RTypeInstruction::ShiftLeftLogicalVariable => &mut self.shift_left_logical_variable,
            RTypeInstruction::ShiftRightLogicalVariable => &mut self.shift_right_logical_variable,
            RTypeInstruction::ShiftRightArithmeticVariable => {
                &mut self.shift_right_arithmetic_variable
            }
            RTypeInstruction::JumpRegister => &mut self.jump_register,
            RTypeInstruction::JumpAndLinkRegister => &mut self.jump_and_link_register,
            RTypeInstruction::SyscallMmap => &mut self.syscall,
            RTypeInstruction::MoveFromHi => &mut self.move_from_hi,
            RTypeInstruction::MoveToHi => &mut self.move_to_hi,
            RTypeInstruction::MoveFromLo => &mut self.move_from_lo,
            RTypeInstruction::MoveToLo => &mut self.move_to_lo,
            RTypeInstruction::Multiply => &mut self.multiply,
            RTypeInstruction::MultiplyUnsigned => &mut self.multiply_unsigned,
            RTypeInstruction::Div => &mut self.div,
            RTypeInstruction::DivUnsigned => &mut self.div_unsigned,
            RTypeInstruction::Add => &mut self.add,
            RTypeInstruction::AddUnsigned => &mut self.add_unsigned,
            RTypeInstruction::Sub => &mut self.sub,
            RTypeInstruction::SubUnsigned => &mut self.sub_unsigned,
            RTypeInstruction::And => &mut self.and,
            RTypeInstruction::Or => &mut self.or,
            RTypeInstruction::Xor => &mut self.xor,
            RTypeInstruction::Nor => &mut self.nor,
            RTypeInstruction::SetLessThan => &mut self.set_less_than,
            RTypeInstruction::SetLessThanUnsigned => &mut self.set_less_than_unsigned,
            _ => /* TODO */ assert!(false)
        }
    }
}

impl<A> RTypeInstructionSelectors<A> {
    pub fn as_ref(&self) -> RTypeInstructionSelectors<&A> {
        RTypeInstructionSelectors {
            shift_left_logical: &self.shift_left_logical,
            shift_right_logical: &self.shift_right_logical,
            shift_right_arithmetic: &self.shift_right_arithmetic,
            shift_left_logical_variable: &self.shift_left_logical_variable,
            shift_right_logical_variable: &self.shift_right_logical_variable,
            shift_right_arithmetic_variable: &self.shift_right_arithmetic_variable,
            jump_register: &self.jump_register,
            jump_and_link_register: &self.jump_and_link_register,
            syscall: &self.syscall,
            move_from_hi: &self.move_from_hi,
            move_to_hi: &self.move_to_hi,
            move_from_lo: &self.move_from_lo,
            move_to_lo: &self.move_to_lo,
            multiply: &self.multiply,
            multiply_unsigned: &self.multiply_unsigned,
            div: &self.div,
            div_unsigned: &self.div_unsigned,
            add: &self.add,
            add_unsigned: &self.add_unsigned,
            sub: &self.sub,
            sub_unsigned: &self.sub_unsigned,
            and: &self.and,
            or: &self.or,
            xor: &self.xor,
            nor: &self.nor,
            set_less_than: &self.set_less_than,
            set_less_than_unsigned: &self.set_less_than_unsigned,
        }
    }

    pub fn as_mut(&mut self) -> RTypeInstructionSelectors<&mut A> {
        RTypeInstructionSelectors {
            shift_left_logical: &mut self.shift_left_logical,
            shift_right_logical: &mut self.shift_right_logical,
            shift_right_arithmetic: &mut self.shift_right_arithmetic,
            shift_left_logical_variable: &mut self.shift_left_logical_variable,
            shift_right_logical_variable: &mut self.shift_right_logical_variable,
            shift_right_arithmetic_variable: &mut self.shift_right_arithmetic_variable,
            jump_register: &mut self.jump_register,
            jump_and_link_register: &mut self.jump_and_link_register,
            syscall: &mut self.syscall,
            move_from_hi: &mut self.move_from_hi,
            move_to_hi: &mut self.move_to_hi,
            move_from_lo: &mut self.move_from_lo,
            move_to_lo: &mut self.move_to_lo,
            multiply: &mut self.multiply,
            multiply_unsigned: &mut self.multiply_unsigned,
            div: &mut self.div,
            div_unsigned: &mut self.div_unsigned,
            add: &mut self.add,
            add_unsigned: &mut self.add_unsigned,
            sub: &mut self.sub,
            sub_unsigned: &mut self.sub_unsigned,
            and: &mut self.and,
            or: &mut self.or,
            xor: &mut self.xor,
            nor: &mut self.nor,
            set_less_than: &mut self.set_less_than,
            set_less_than_unsigned: &mut self.set_less_than_unsigned,
        }
    }

    pub fn map<B, F: FnMut(A) -> B>(self, mut f: F) -> RTypeInstructionSelectors<B> {
        let RTypeInstructionSelectors {
            shift_left_logical,
            shift_right_logical,
            shift_right_arithmetic,
            shift_left_logical_variable,
            shift_right_logical_variable,
            shift_right_arithmetic_variable,
            jump_register,
            jump_and_link_register,
            syscall,
            move_from_hi,
            move_to_hi,
            move_from_lo,
            move_to_lo,
            multiply,
            multiply_unsigned,
            div,
            div_unsigned,
            add,
            add_unsigned,
            sub,
            sub_unsigned,
            and,
            or,
            xor,
            nor,
            set_less_than,
            set_less_than_unsigned,
        } = self;
        RTypeInstructionSelectors {
            shift_left_logical: f(shift_left_logical),
            shift_right_logical: f(shift_right_logical),
            shift_right_arithmetic: f(shift_right_arithmetic),
            shift_left_logical_variable: f(shift_left_logical_variable),
            shift_right_logical_variable: f(shift_right_logical_variable),
            shift_right_arithmetic_variable: f(shift_right_arithmetic_variable),
            jump_register: f(jump_register),
            jump_and_link_register: f(jump_and_link_register),
            syscall: f(syscall),
            move_from_hi: f(move_from_hi),
            move_to_hi: f(move_to_hi),
            move_from_lo: f(move_from_lo),
            move_to_lo: f(move_to_lo),
            multiply: f(multiply),
            multiply_unsigned: f(multiply_unsigned),
            div: f(div),
            div_unsigned: f(div_unsigned),
            add: f(add),
            add_unsigned: f(add_unsigned),
            sub: f(sub),
            sub_unsigned: f(sub_unsigned),
            and: f(and),
            or: f(or),
            xor: f(xor),
            nor: f(nor),
            set_less_than: f(set_less_than),
            set_less_than_unsigned: f(set_less_than_unsigned),
        }
    }

    pub fn into_iter(self) -> impl Iterator<Item = A> {
        let RTypeInstructionSelectors {
            shift_left_logical,
            shift_right_logical,
            shift_right_arithmetic,
            shift_left_logical_variable,
            shift_right_logical_variable,
            shift_right_arithmetic_variable,
            jump_register,
            jump_and_link_register,
            syscall,
            move_from_hi,
            move_to_hi,
            move_from_lo,
            move_to_lo,
            multiply,
            multiply_unsigned,
            div,
            div_unsigned,
            add,
            add_unsigned,
            sub,
            sub_unsigned,
            and,
            or,
            xor,
            nor,
            set_less_than,
            set_less_than_unsigned,
        } = self;
        vec![
            shift_left_logical,
            shift_right_logical,
            shift_right_arithmetic,
            shift_left_logical_variable,
            shift_right_logical_variable,
            shift_right_arithmetic_variable,
            jump_register,
            jump_and_link_register,
            syscall,
            move_from_hi,
            move_to_hi,
            move_from_lo,
            move_to_lo,
            multiply,
            multiply_unsigned,
            div,
            div_unsigned,
            add,
            add_unsigned,
            sub,
            sub_unsigned,
            and,
            or,
            xor,
            nor,
            set_less_than,
            set_less_than_unsigned,
        ]
        .into_iter()
    }
}

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
pub struct JTypeInstructionSelectors<T> {
    pub jump: T,
    pub jump_and_link: T,
}

impl<A> Index<JTypeInstruction> for JTypeInstructionSelectors<A> {
    type Output = A;

    fn index(&self, index: JTypeInstruction) -> &Self::Output {
        match index {
            JTypeInstruction::Jump => &self.jump,
            JTypeInstruction::JumpAndLink => &self.jump_and_link,
        }
    }
}

impl<A> IndexMut<JTypeInstruction> for JTypeInstructionSelectors<A> {
    fn index_mut(&mut self, index: JTypeInstruction) -> &mut Self::Output {
        match index {
            JTypeInstruction::Jump => &mut self.jump,
            JTypeInstruction::JumpAndLink => &mut self.jump_and_link,
        }
    }
}

impl<A> JTypeInstructionSelectors<A> {
    pub fn as_ref(&self) -> JTypeInstructionSelectors<&A> {
        JTypeInstructionSelectors {
            jump: &self.jump,
            jump_and_link: &self.jump_and_link,
        }
    }

    pub fn as_mut(&mut self) -> JTypeInstructionSelectors<&mut A> {
        JTypeInstructionSelectors {
            jump: &mut self.jump,
            jump_and_link: &mut self.jump_and_link,
        }
    }

    pub fn map<B, F: FnMut(A) -> B>(self, mut f: F) -> JTypeInstructionSelectors<B> {
        let JTypeInstructionSelectors {
            jump,
            jump_and_link,
        } = self;
        JTypeInstructionSelectors {
            jump: f(jump),
            jump_and_link: f(jump_and_link),
        }
    }

    pub fn into_iter(self) -> impl Iterator<Item = A> {
        let JTypeInstructionSelectors {
            jump,
            jump_and_link,
        } = self;
        vec![jump, jump_and_link].into_iter()
    }
}

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
pub struct ITypeInstructionSelectors<T> {
    pub branch_eq: T,
    pub branch_neq: T,
    pub branch_leq_zero: T,
    pub branch_gt_zero: T,
    pub add_immediate: T,
    pub add_unsigned_immediate: T,
    pub set_less_than_immediate: T,
    pub set_less_than_unsigned_immediate: T,
    pub and_immediate: T,
    pub or_immediate: T,
    pub xor_immediate: T,
    pub load_immediate: T,
    pub load_8: T,
    pub load_16: T,
    pub load_32: T,
    pub load_8_unsigned: T,
    pub load_16_unsigned: T,
    pub store_8: T,
    pub store_16: T,
    pub store_32: T,
}

impl<A> Index<ITypeInstruction> for ITypeInstructionSelectors<A> {
    type Output = A;

    fn index(&self, index: ITypeInstruction) -> &Self::Output {
        match index {
            ITypeInstruction::BranchEq => &self.branch_eq,
            ITypeInstruction::BranchNeq => &self.branch_neq,
            ITypeInstruction::BranchLeqZero => &self.branch_leq_zero,
            ITypeInstruction::BranchGtZero => &self.branch_gt_zero,
            ITypeInstruction::AddImmediate => &self.add_immediate,
            ITypeInstruction::AddImmediateUnsigned => &self.add_unsigned_immediate,
            ITypeInstruction::SetLessThanImmediate => &self.set_less_than_immediate,
            ITypeInstruction::SetLessThanImmediateUnsigned => {
                &self.set_less_than_unsigned_immediate
            }
            ITypeInstruction::AndImmediate => &self.and_immediate,
            ITypeInstruction::OrImmediate => &self.or_immediate,
            ITypeInstruction::XorImmediate => &self.xor_immediate,
            ITypeInstruction::LoadImmediate => &self.load_immediate,
            ITypeInstruction::Load8 => &self.load_8,
            ITypeInstruction::Load16 => &self.load_16,
            ITypeInstruction::Load32 => &self.load_32,
            ITypeInstruction::Load8Unsigned => &self.load_8_unsigned,
            ITypeInstruction::Load16Unsigned => &self.load_16_unsigned,
            ITypeInstruction::Store8 => &self.store_8,
            ITypeInstruction::Store16 => &self.store_16,
            ITypeInstruction::Store32 => &self.store_32,
        }
    }
}

impl<A> IndexMut<ITypeInstruction> for ITypeInstructionSelectors<A> {
    fn index_mut(&mut self, index: ITypeInstruction) -> &mut Self::Output {
        match index {
            ITypeInstruction::BranchEq => &mut self.branch_eq,
            ITypeInstruction::BranchNeq => &mut self.branch_neq,
            ITypeInstruction::BranchLeqZero => &mut self.branch_leq_zero,
            ITypeInstruction::BranchGtZero => &mut self.branch_gt_zero,
            ITypeInstruction::AddImmediate => &mut self.add_immediate,
            ITypeInstruction::AddImmediateUnsigned => &mut self.add_unsigned_immediate,
            ITypeInstruction::SetLessThanImmediate => &mut self.set_less_than_immediate,
            ITypeInstruction::SetLessThanImmediateUnsigned => {
                &mut self.set_less_than_unsigned_immediate
            }
            ITypeInstruction::AndImmediate => &mut self.and_immediate,
            ITypeInstruction::OrImmediate => &mut self.or_immediate,
            ITypeInstruction::XorImmediate => &mut self.xor_immediate,
            ITypeInstruction::LoadImmediate => &mut self.load_immediate,
            ITypeInstruction::Load8 => &mut self.load_8,
            ITypeInstruction::Load16 => &mut self.load_16,
            ITypeInstruction::Load32 => &mut self.load_32,
            ITypeInstruction::Load8Unsigned => &mut self.load_8_unsigned,
            ITypeInstruction::Load16Unsigned => &mut self.load_16_unsigned,
            ITypeInstruction::Store8 => &mut self.store_8,
            ITypeInstruction::Store16 => &mut self.store_16,
            ITypeInstruction::Store32 => &mut self.store_32,
        }
    }
}

impl<A> ITypeInstructionSelectors<A> {
    pub fn as_ref(&self) -> ITypeInstructionSelectors<&A> {
        ITypeInstructionSelectors {
            branch_eq: &self.branch_eq,
            branch_neq: &self.branch_neq,
            branch_leq_zero: &self.branch_leq_zero,
            branch_gt_zero: &self.branch_gt_zero,
            add_immediate: &self.add_immediate,
            add_unsigned_immediate: &self.add_unsigned_immediate,
            set_less_than_immediate: &self.set_less_than_immediate,
            set_less_than_unsigned_immediate: &self.set_less_than_unsigned_immediate,
            and_immediate: &self.and_immediate,
            or_immediate: &self.or_immediate,
            xor_immediate: &self.xor_immediate,
            load_immediate: &self.load_immediate,
            load_8: &self.load_8,
            load_16: &self.load_16,
            load_32: &self.load_32,
            load_8_unsigned: &self.load_8_unsigned,
            load_16_unsigned: &self.load_16_unsigned,
            store_8: &self.store_8,
            store_16: &self.store_16,
            store_32: &self.store_32,
        }
    }

    pub fn as_mut(&mut self) -> ITypeInstructionSelectors<&mut A> {
        ITypeInstructionSelectors {
            branch_eq: &mut self.branch_eq,
            branch_neq: &mut self.branch_neq,
            branch_leq_zero: &mut self.branch_leq_zero,
            branch_gt_zero: &mut self.branch_gt_zero,
            add_immediate: &mut self.add_immediate,
            add_unsigned_immediate: &mut self.add_unsigned_immediate,
            set_less_than_immediate: &mut self.set_less_than_immediate,
            set_less_than_unsigned_immediate: &mut self.set_less_than_unsigned_immediate,
            and_immediate: &mut self.and_immediate,
            or_immediate: &mut self.or_immediate,
            xor_immediate: &mut self.xor_immediate,
            load_immediate: &mut self.load_immediate,
            load_8: &mut self.load_8,
            load_16: &mut self.load_16,
            load_32: &mut self.load_32,
            load_8_unsigned: &mut self.load_8_unsigned,
            load_16_unsigned: &mut self.load_16_unsigned,
            store_8: &mut self.store_8,
            store_16: &mut self.store_16,
            store_32: &mut self.store_32,
        }
    }

    pub fn map<B, F: FnMut(A) -> B>(self, mut f: F) -> ITypeInstructionSelectors<B> {
        let ITypeInstructionSelectors {
            branch_eq,
            branch_neq,
            branch_leq_zero,
            branch_gt_zero,
            add_immediate,
            add_unsigned_immediate,
            set_less_than_immediate,
            set_less_than_unsigned_immediate,
            and_immediate,
            or_immediate,
            xor_immediate,
            load_immediate,
            load_8,
            load_16,
            load_32,
            load_8_unsigned,
            load_16_unsigned,
            store_8,
            store_16,
            store_32,
        } = self;
        ITypeInstructionSelectors {
            branch_eq: f(branch_eq),
            branch_neq: f(branch_neq),
            branch_leq_zero: f(branch_leq_zero),
            branch_gt_zero: f(branch_gt_zero),
            add_immediate: f(add_immediate),
            add_unsigned_immediate: f(add_unsigned_immediate),
            set_less_than_immediate: f(set_less_than_immediate),
            set_less_than_unsigned_immediate: f(set_less_than_unsigned_immediate),
            and_immediate: f(and_immediate),
            or_immediate: f(or_immediate),
            xor_immediate: f(xor_immediate),
            load_immediate: f(load_immediate),
            load_8: f(load_8),
            load_16: f(load_16),
            load_32: f(load_32),
            load_8_unsigned: f(load_8_unsigned),
            load_16_unsigned: f(load_16_unsigned),
            store_8: f(store_8),
            store_16: f(store_16),
            store_32: f(store_32),
        }
    }

    pub fn into_iter(self) -> impl Iterator<Item = A> {
        let ITypeInstructionSelectors {
            branch_eq,
            branch_neq,
            branch_leq_zero,
            branch_gt_zero,
            add_immediate,
            add_unsigned_immediate,
            set_less_than_immediate,
            set_less_than_unsigned_immediate,
            and_immediate,
            or_immediate,
            xor_immediate,
            load_immediate,
            load_8,
            load_16,
            load_32,
            load_8_unsigned,
            load_16_unsigned,
            store_8,
            store_16,
            store_32,
        } = self;
        vec![
            branch_eq,
            branch_neq,
            branch_leq_zero,
            branch_gt_zero,
            add_immediate,
            add_unsigned_immediate,
            set_less_than_immediate,
            set_less_than_unsigned_immediate,
            and_immediate,
            or_immediate,
            xor_immediate,
            load_immediate,
            load_8,
            load_16,
            load_32,
            load_8_unsigned,
            load_16_unsigned,
            store_8,
            store_16,
            store_32,
        ]
        .into_iter()
    }
}

impl IntoEnumIterator for InstructionSelector {
    // The underlying type is inexpressible, due to the function types :|
    type Iterator = Box<dyn Iterator<Item = Self>>;
    fn iter() -> Self::Iterator {
        Box::new(
            RTypeInstruction::iter()
                .map(&InstructionSelector::RType)
                .chain(JTypeInstruction::iter().map(&InstructionSelector::JType))
                .chain(ITypeInstruction::iter().map(&InstructionSelector::IType)),
        )
    }
}

pub fn all_instruction_selectors() -> impl Iterator<Item = Column> {
    InstructionSelector::iter().map(Column::InstructionSelector)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter)]
pub enum InstructionPart {
    OpCode,
    RS,
    RT,
    RD,
    Shamt,
    Funct,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct InstructionParts<T> {
    pub op_code: T,
    pub rs: T,
    pub rt: T,
    pub rd: T,
    pub shamt: T,
    pub funct: T,
}

impl<A> Index<InstructionPart> for InstructionParts<A> {
    type Output = A;

    fn index(&self, index: InstructionPart) -> &Self::Output {
        match index {
            InstructionPart::OpCode => &self.op_code,
            InstructionPart::RS => &self.rs,
            InstructionPart::RT => &self.rt,
            InstructionPart::RD => &self.rd,
            InstructionPart::Shamt => &self.shamt,
            InstructionPart::Funct => &self.funct,
        }
    }
}

impl<A> IndexMut<InstructionPart> for InstructionParts<A> {
    fn index_mut(&mut self, index: InstructionPart) -> &mut Self::Output {
        match index {
            InstructionPart::OpCode => &mut self.op_code,
            InstructionPart::RS => &mut self.rs,
            InstructionPart::RT => &mut self.rt,
            InstructionPart::RD => &mut self.rd,
            InstructionPart::Shamt => &mut self.shamt,
            InstructionPart::Funct => &mut self.funct,
        }
    }
}

impl<A> InstructionParts<A> {
    pub fn as_ref(&self) -> InstructionParts<&A> {
        InstructionParts {
            op_code: &self.op_code,
            rs: &self.rs,
            rt: &self.rt,
            rd: &self.rd,
            shamt: &self.shamt,
            funct: &self.funct,
        }
    }

    pub fn as_mut(&mut self) -> InstructionParts<&mut A> {
        InstructionParts {
            op_code: &mut self.op_code,
            rs: &mut self.rs,
            rt: &mut self.rt,
            rd: &mut self.rd,
            shamt: &mut self.shamt,
            funct: &mut self.funct,
        }
    }

    pub fn map<B, F: FnMut(A) -> B>(self, mut f: F) -> InstructionParts<B> {
        let InstructionParts {
            op_code,
            rs,
            rt,
            rd,
            shamt,
            funct,
        } = self;
        InstructionParts {
            op_code: f(op_code),
            rs: f(rs),
            rt: f(rt),
            rd: f(rd),
            shamt: f(shamt),
            funct: f(funct),
        }
    }

    pub fn into_iter(self) -> impl Iterator<Item = A> {
        let InstructionParts {
            op_code,
            rs,
            rt,
            rd,
            shamt,
            funct,
        } = self;
        vec![op_code, rs, rt, rd, shamt, funct].into_iter()
    }
}

impl expr::PrintableColumn for Column {
    fn latex(&self) -> String {
        format!("{:?}", self)
    }

    fn text(&self) -> String {
        format!("{:?}", self)
    }
}
