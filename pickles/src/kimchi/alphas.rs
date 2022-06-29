use ark_ff::{FftField, PrimeField};

use circuit_construction::{Var, Cs};

use kimchi::circuits::argument::{ArgumentType, Argument};
use kimchi::circuits::polynomials::permutation;
use kimchi::circuits::polynomials::varbasemul::VarbaseMul;

pub struct Alphas<F: FftField + PrimeField> {
    alphas: Vec<Var<F>>,
}

fn total_alphas<F: FftField + PrimeField>() -> usize {    
    let t = VarbaseMul::<F>::CONSTRAINTS as usize; // TODO: this is error prone, we should compute max automatically!
    let t = t + permutation::CONSTRAINTS as usize;
    t
}

impl <F: FftField + PrimeField> Alphas<F> {
    pub fn new<C: Cs<F>>(cs: &mut C, alpha: Var<F>) -> Self {
        unimplemented!()
    }

    pub fn gate(&self) -> &[Var<F>] {
        let offset = 0;
        &self.alphas[offset..VarbaseMul::<F>::CONSTRAINTS as usize]
    }

    pub fn permutation(&self) -> &[Var<F>] {
        let offset = VarbaseMul::<F>::CONSTRAINTS as usize;
        &self.alphas[offset..offset + permutation::CONSTRAINTS as usize]
    }

    pub fn pow(&self, i: usize) -> Var<F> {
        self.alphas[i]
    }

    pub fn get(&self, ty: ArgumentType) -> &[Var<F>] {
        match ty {
            ArgumentType::Gate(_) => self.gate(),
            ArgumentType::Permutation => self.permutation(),
            ArgumentType::Lookup => {
                unimplemented!()
            }
        }
    }
}