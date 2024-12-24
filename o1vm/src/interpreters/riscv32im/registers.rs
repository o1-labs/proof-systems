use std::ops::{Index, IndexMut};

use serde::{Deserialize, Serialize};

pub const N_GP_REGISTERS: usize = 32;
// FIXME:
pub const REGISTER_CURRENT_IP: usize = N_GP_REGISTERS + 1;
pub const REGISTER_NEXT_IP: usize = N_GP_REGISTERS + 2;
pub const REGISTER_HEAP_POINTER: usize = N_GP_REGISTERS + 3;

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

/// This enum provides aliases for the registers.
/// This is useful for debugging and for providing a more readable interface.
/// It can be used to index the registers in the witness.
pub enum RegisterAlias {
    Zero,
    /// Return address
    Ra,
    /// Stack pointer
    Sp,
    /// Global pointer
    Gp,
    /// Thread pointer
    Tp,
    /// Temporary/alternate register
    T0,
    /// Temporaries
    T1,
    T2,
    /// Frame pointer/saved register. This is the same register.
    Fp,
    S0,
    /// Saved registers
    S1,
    /// Function arguments/results
    A0,
    A1,
    A2,
    A3,
    A4,
    A5,
    A6,
    A7,
    S2,
    S3,
    S4,
    S5,
    S6,
    S7,
    S8,
    S9,
    S10,
    S11,
    T3,
    T4,
    T5,
    T6,
    /// Current instruction pointer
    Ip,
    /// Next instruction pointer
    NextIp,
    HeapPointer,
}

impl<T: Clone> Index<RegisterAlias> for Registers<T> {
    type Output = T;

    fn index(&self, index: RegisterAlias) -> &Self::Output {
        match index {
            RegisterAlias::Zero => &self.general_purpose[0],
            RegisterAlias::Ra => &self.general_purpose[1],
            RegisterAlias::Sp => &self.general_purpose[2],
            RegisterAlias::Gp => &self.general_purpose[3],
            RegisterAlias::Tp => &self.general_purpose[4],
            RegisterAlias::T0 => &self.general_purpose[5],
            RegisterAlias::T1 => &self.general_purpose[6],
            RegisterAlias::T2 => &self.general_purpose[7],
            // Frame pointer and first saved register are the same register.
            RegisterAlias::Fp => &self.general_purpose[8],
            RegisterAlias::S0 => &self.general_purpose[8],
            RegisterAlias::S1 => &self.general_purpose[9],
            RegisterAlias::A0 => &self.general_purpose[10],
            RegisterAlias::A1 => &self.general_purpose[11],
            RegisterAlias::A2 => &self.general_purpose[12],
            RegisterAlias::A3 => &self.general_purpose[13],
            RegisterAlias::A4 => &self.general_purpose[14],
            RegisterAlias::A5 => &self.general_purpose[15],
            RegisterAlias::A6 => &self.general_purpose[16],
            RegisterAlias::A7 => &self.general_purpose[17],
            RegisterAlias::S2 => &self.general_purpose[18],
            RegisterAlias::S3 => &self.general_purpose[19],
            RegisterAlias::S4 => &self.general_purpose[20],
            RegisterAlias::S5 => &self.general_purpose[21],
            RegisterAlias::S6 => &self.general_purpose[22],
            RegisterAlias::S7 => &self.general_purpose[23],
            RegisterAlias::S8 => &self.general_purpose[24],
            RegisterAlias::S9 => &self.general_purpose[25],
            RegisterAlias::S10 => &self.general_purpose[26],
            RegisterAlias::S11 => &self.general_purpose[27],
            RegisterAlias::T3 => &self.general_purpose[28],
            RegisterAlias::T4 => &self.general_purpose[29],
            RegisterAlias::T5 => &self.general_purpose[30],
            RegisterAlias::T6 => &self.general_purpose[31],
            RegisterAlias::Ip => &self.current_instruction_pointer,
            RegisterAlias::NextIp => &self.next_instruction_pointer,
            RegisterAlias::HeapPointer => &self.heap_pointer,
        }
    }
}
