use serde::{Deserialize, Serialize};

/// This represents the internal state of the virtual machine.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Registers<T> {
    /// There are 32 general purpose registers.
    /// - x0: hard-wired zero
    /// - x1: return address
    /// - x2: stack pointer
    /// - x3: global pointer
    /// - x4: thread pointer
    /// - x5: temporary/alternate register
    /// - x6-x7: temporaries
    /// - x8: saved register/frame pointer
    /// - x9: saved register
    /// - x10-x11: function arguments/results
    /// - x12-x17: function arguments
    /// - x18-x27: saved registers
    /// - x28-x31: temporaries
    pub general_purpose: [T; 32],
    pub current_instruction_pointer: T,
    pub next_instruction_pointer: T,
    pub heap_pointer: T,
}
