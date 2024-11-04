/// The minimal number of columns required for the VM
// FIXME: the value will be updated when the interpreter is fully
// implemented. Using a small value for now.
pub const SCRATCH_SIZE: usize = 20;

/// List all columns used by the interpreter
pub mod column;

/// All the registers used by the ISA
pub mod registers;
