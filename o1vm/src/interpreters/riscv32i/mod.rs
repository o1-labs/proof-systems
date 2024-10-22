pub mod column;
pub mod constraints;
pub mod interpreter;
pub mod registers;
pub mod witness;

/// The minimal number of columns required for the VM
// FIXME: this is not correct
pub const SCRATCH_SIZE: usize = 80;

// FIXME: I don't know yet how many instructions do exist in the RiscV32i ISA
pub const INSTRUCTION_SET_SIZE: usize = 90;

pub const PAGE_ADDRESS_SIZE: u32 = 12;
pub const PAGE_SIZE: u32 = 1 << PAGE_ADDRESS_SIZE;
pub const PAGE_ADDRESS_MASK: u32 = PAGE_SIZE - 1;
