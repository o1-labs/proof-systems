pub mod column;
pub mod interpreter;
pub mod registers;

/// The minimal number of columns required for the VM
// FIXME: this is not correct
pub const SCRATCH_SIZE: usize = 80;
