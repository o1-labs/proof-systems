use std::ops::{Index, IndexMut};

use serde::{Deserialize, Serialize};

pub const N_GP_REGISTERS: usize = 32;
pub const REGISTER_CURRENT_IP: usize = N_GP_REGISTERS + 1;
pub const REGISTER_NEXT_IP: usize = N_GP_REGISTERS + 2;
pub const REGISTER_HEAP_POINTER: usize = N_GP_REGISTERS + 3;

/// This represents the internal state of the virtual machine.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Registers<T> {
    /// There are 32 general purpose registers.
    /// - x0: hard-wired zero (zero)
    /// - x1: return address (ra)
    /// - x2: stack pointer (sp)
    /// - x3: global pointer (gp)
    /// - x4: thread pointer (tp)
    /// - x5: temporary/alternate register (t0)
    /// - x6-x7: temporaries (t1 - t2)
    /// - x8: saved register/frame pointer (s0 / fp)
    /// - x9: saved register (s1)
    /// - x10-x11: function arguments/results (a0 - a1)
    /// - x12-x17: function arguments (a2 - a7)
    /// - x18-x27: saved registers (s2 - s11)
    /// - x28-x31: temporaries (t3 - t6)
    pub general_purpose: [T; N_GP_REGISTERS],
    pub current_instruction_pointer: T,
    pub next_instruction_pointer: T,
    pub heap_pointer: T,
}

impl<T: Clone> Index<usize> for Registers<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        if index < N_GP_REGISTERS {
            &self.general_purpose[index]
        } else if index == REGISTER_CURRENT_IP {
            &self.current_instruction_pointer
        } else if index == REGISTER_NEXT_IP {
            &self.next_instruction_pointer
        } else if index == REGISTER_HEAP_POINTER {
            &self.heap_pointer
        } else {
            panic!("Index out of bounds");
        }
    }
}

impl<T: Clone> IndexMut<usize> for Registers<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        if index < N_GP_REGISTERS {
            &mut self.general_purpose[index]
        } else if index == REGISTER_CURRENT_IP {
            &mut self.current_instruction_pointer
        } else if index == REGISTER_NEXT_IP {
            &mut self.next_instruction_pointer
        } else if index == REGISTER_HEAP_POINTER {
            &mut self.heap_pointer
        } else {
            panic!("Index out of bounds");
        }
    }
}
