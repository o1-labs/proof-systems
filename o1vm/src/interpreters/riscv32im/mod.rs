/// The minimal number of columns required for the VM
pub const SCRATCH_SIZE: usize = 39;
pub const SCRATCH_SIZE_INVERSE: usize = 1;

/// Number of instructions in the ISA
pub const INSTRUCTION_SET_SIZE: usize = 48;

pub const PAGE_ADDRESS_SIZE: u32 = 12;
pub const PAGE_SIZE: u32 = 1 << PAGE_ADDRESS_SIZE;
pub const PAGE_ADDRESS_MASK: u32 = PAGE_SIZE - 1;

/// List all columns used by the interpreter
pub mod column;

pub mod constraints;

pub mod interpreter;

/// All the registers used by the ISA
pub mod registers;

pub mod witness;

#[cfg(test)]
mod tests;
