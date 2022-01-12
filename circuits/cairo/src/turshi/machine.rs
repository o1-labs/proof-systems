/*
use cairo::instruction;
use cairo::memory;
use cairo::state;

use ark_ff::{BigInteger, FftField, Field, PrimeField};

/// A Cairo public input for the proof system
pub struct CairoMachine<F: FftField> {
    /// number of steps of computation
    pub steps: usize,
    /// public memory with compiled Cairo program
    pub memory: CairoMemory<F>,
    /// claimed registers
    pub regs: CairoRegisters<F>,
}

/// A set of claimed values for Cairo registers
pub struct CairoRegisters<F: FftField> {
    /// claimed initial program counter
    pub pc_ini: F,
    /// claimed final program counter
    pub pc_fin: F,
    /// claimed initial allocation pointer
    pub ap_ini: F,
    /// claimed final allocation pointer
    pub ap_fin: F,
}
impl CairoMachine {
    /// Creates a Cairo machine from the public input
    pub fn new_machine(
        steps: usize,
        memory: CairoMemory<F>,
        regs: CairoRegisters<F>,
    ) -> CairoMachine {
        CairoMachine {
            steps,
            memory,
            regs,
        }
    }

    /// Obtain claimed values for program counter
    pub fn get_claimed_pc(&self) -> (F, F) {
        (self.regs.pc_ini, self.regs.pc_fin)
    }

    /// Obtain claimed values for allocation pointer
    pub fn get_claimed_ap(&self) -> (F, F) {
        (self.regs.ap_ini, self.regs.ap_fin)
    }
}

*/
