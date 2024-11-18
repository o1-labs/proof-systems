/// The minimal number of columns required for the VM
// FIXME: the value will be updated when the interpreter is fully
// implemented. Using a small value for now.
pub const SCRATCH_SIZE: usize = 80;

/// Number of instructions in the ISA
// FIXME: the value might not be correct. It will be updated when the
// interpreter is fully implemented.
pub const INSTRUCTION_SET_SIZE: usize = 40;
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
