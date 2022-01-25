use crate::turshi::memory::CairoMemory;

use ark_ff::FftField;

/// A set of claimed values for Cairo registers
pub struct CairoClaim<F: FftField> {
    /// claimed initial program counter
    pub pc_ini: F,
    /// claimed final program counter
    pub pc_fin: F,
    /// claimed initial allocation pointer
    pub ap_ini: F,
    /// claimed final allocation pointer
    pub ap_fin: F,
}

/// A Cairo public input for the proof system
pub struct CairoMachine<'a, F: FftField> {
    /// number of steps of computation
    pub steps: usize,
    /// public memory with compiled Cairo program
    pub stack: &'a CairoMemory<F>,
    /// claimed registers
    pub regs: CairoClaim<F>,
}

impl<'a, F: FftField> CairoMachine<'a, F> {
    /// Creates a Cairo machine from the public input
    pub fn new(steps: usize, stack: &CairoMemory<F>, regs: CairoClaim<F>) -> CairoMachine<F> {
        CairoMachine { steps, stack, regs }
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
