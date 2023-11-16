use crate::mips::interpreter::{
    Instruction, InstructionPart, InstructionParts, InstructionSelectors,
};
use ark_ff::FftField;
use ark_poly::{Evaluations, Radix2EvaluationDomain as D};
use core::ops::{Index, IndexMut};
use kimchi::circuits::{
    domains::EvaluationDomains,
    expr::{ColumnEnvironment, Constants, Domain, GenericColumn},
};
use serde::{Deserialize, Serialize};

use super::{NUM_LOOKUP_TERMS, SCRATCH_SIZE};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Column {
    InstructionPart(InstructionPart),
    InstructionSelector(Instruction),
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
            Column::LookupCounter(i) => Some(self.lookup_counters[*i]),
            Column::Halt => Some(self.halt),
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

    fn vanishes_on_zero_knowledge_and_previous_rows(&self) -> &'a Evaluations<F, D<F>> {
        unimplemented!()
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
}

impl<A> IntoIterator for FixedColumns<A> {
    type Item = A;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
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
}

impl<A> IntoIterator for LookupCounters<A> {
    type Item = A;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let LookupCounters {
            counter,
            sparse_counter,
        } = self;
        vec![counter, sparse_counter].into_iter()
    }
}
