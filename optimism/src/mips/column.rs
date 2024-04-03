use std::ops::{Index, IndexMut};

use super::{
    interpreter::{ITypeInstruction, JTypeInstruction, RTypeInstruction},
    witness::SCRATCH_SIZE,
};
use kimchi_msm::witness::Witness;
use strum::EnumCount;

pub(crate) const MIPS_HASH_COUNTER_OFFSET: usize = 80;
pub(crate) const MIPS_IS_SYSCALL_OFFSET: usize = 81;
pub(crate) const MIPS_READING_PREIMAGE_OFFSET: usize = 82;
pub(crate) const MIPS_BYTES_READ_OFFSET: usize = 83;
pub(crate) const MIPS_PREIMAGE_LEFT_OFFSET: usize = 84;
pub(crate) const MIPS_PREIMAGE_BYTES_OFFSET: usize = 85;
pub(crate) const MIPS_HAS_N_BYTES_OFFSET: usize = 89;
pub(crate) const MIPS_CHUNK_BYTES_LENGTH: usize = 4;

pub(crate) const MIPS_SELECTORS_SIZE: usize = 71;

/// Abstract columns (or variables of our multi-variate polynomials) that will be used to
/// describe our constraints.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Column {
    // Can be seen as the abstract indexed variable X_{i}
    ScratchState(usize),
    // There are 71 MIPS instructions
    Selector(Instruction),
    InstructionCounter,
}

/// All the 71 MIPS instructions that can be executed by the virtual machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Instruction {
    /// 42 register-register instructions:
    /// sll, srl, sra, sllv, srlv, srav,
    /// jr, jalr, syscall (Mmap), syscall (ExitGroup),
    /// syscall (Read 3), syscall (Read 5), syscall (Read ?),
    /// syscall (Write 4), syscall (Write 6), syscall (Write ?),
    /// syscall (Fcntl), syscall (Brk, Clone, ?),
    /// movz, movn, sync, mfhi, mthi, mflo mtlo,
    /// mult, multu, div, divu, add, addu, sub, subbu,
    /// and, or, xor, not, slt, sltu mul, clo, clz
    RType(RTypeInstruction),
    /// 27 immediate instructions:
    /// beq, bne, blez, bgtz, bltz, bgez,
    /// addi, addiu, slti, sltiu, andi, ori,
    /// xori, lui, lb, lh, lw, lbu, lhu, lwl,
    /// lwr, sb, sh, sw, sc, swl, swr
    IType(ITypeInstruction),
    /// 2 jump instructions:
    /// j, jal
    JType(JTypeInstruction),
}

/// Represents one line of the execution trace of the virtual machine
/// It does contain [SCRATCH_SIZE] columns + 2 additional columns to keep track
/// of the instruction index and one for the system error code.
/// The column are, in order,
/// - the 32 general purpose registers
/// - the low and hi registers used by some arithmetic instructions
/// - the current instruction pointer
/// - the next instruction pointer
/// - the heap pointer
/// - the preimage key, splitted in 8 consecutive columns representing 4 bytes
/// of the 32 bytes long preimage key
/// - the preimage offset, i.e. the number of bytes that have been read for the
/// currently processing preimage
/// - `[SCRATCH_SIZE] - 46` intermediate columns that can be used by the
/// instruction set
/// - the hash counter
/// - the flag to indicate if the current instruction is a preimage syscall
/// - the flag to indicate if the current instruction is reading a preimage
/// - the number of bytes read so far for the current preimage
/// - how many bytes are left to be read for the current preimage
/// - the (at most) 4 bytes of the preimage key that are currently being processed
/// - 4 helpers to check if at least n bytes were read in the current row
pub type MIPSWitness<T> = Witness<MIPS_COLUMNS, T>;

pub const MIPS_COLUMNS: usize = SCRATCH_SIZE + 2 + MIPS_SELECTORS_SIZE;

pub trait MIPSWitnessTrait<T> {
    fn scratch(&self) -> &[T];
    fn selector(&self) -> &[T];
    fn selector_mut(&mut self) -> &mut [T];
    fn instruction_counter(&self) -> &T;
    fn error(&mut self) -> &T;
}

impl<T: Clone> MIPSWitnessTrait<T> for MIPSWitness<T> {
    fn scratch(&self) -> &[T] {
        &self.cols[..SCRATCH_SIZE]
    }

    fn selector(&self) -> &[T] {
        &self.cols[SCRATCH_SIZE..SCRATCH_SIZE + MIPS_SELECTORS_SIZE]
    }
    fn selector_mut(&mut self) -> &mut [T] {
        &mut self.cols[SCRATCH_SIZE..SCRATCH_SIZE + MIPS_SELECTORS_SIZE]
    }

    fn instruction_counter(&self) -> &T {
        &self.cols[SCRATCH_SIZE + MIPS_SELECTORS_SIZE]
    }

    fn error(&mut self) -> &T {
        &self.cols[SCRATCH_SIZE + MIPS_SELECTORS_SIZE + 1]
    }
}

impl<T: Clone> Index<Column> for MIPSWitness<T> {
    type Output = T;

    /// Map the column alias to the actual column index.
    /// Note that the column index depends on the step kind (Sponge or Round).
    /// For instance, the column 800 represents PadLength in the Sponge step, while it
    /// is used by intermediary values when executing the Round step.
    fn index(&self, index: Column) -> &Self::Output {
        match index {
            Column::ScratchState(i) => &self.scratch()[i],
            Column::Selector(i) => match i {
                Instruction::RType(r) => &self.selector()[r as usize],
                Instruction::IType(i) => &self.selector()[i as usize + RTypeInstruction::COUNT],
                Instruction::JType(j) => {
                    &self.selector()[j as usize + RTypeInstruction::COUNT + ITypeInstruction::COUNT]
                }
            },
            Column::InstructionCounter => self.instruction_counter(),
        }
    }
}

impl<T: Clone> IndexMut<Column> for MIPSWitness<T> {
    fn index_mut(&mut self, index: Column) -> &mut Self::Output {
        match index {
            Column::ScratchState(i) => &mut self.cols[i],
            Column::Selector(i) => match i {
                Instruction::RType(r) => &mut self.selector_mut()[r as usize],
                Instruction::IType(i) => {
                    &mut self.selector_mut()[i as usize + RTypeInstruction::COUNT]
                }
                Instruction::JType(j) => &mut self.selector_mut()
                    [j as usize + RTypeInstruction::COUNT + ITypeInstruction::COUNT],
            },
            Column::InstructionCounter => &mut self.cols[SCRATCH_SIZE],
        }
    }
}
