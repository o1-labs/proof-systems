//! This module implements a zero-knowledge virtual machine (zkVM) for the MIPS
//! architecture.
//! A zkVM is used by a prover to convince a verifier that the execution trace
//! (also called the `witness`) of a program execution is correct. In the case
//! of this zkVM, we will represent the execution trace by using a set of
//! columns whose values will represent the evaluations of polynomials over a
//! certain pre-defined domain. The correct execution will be proven using a
//! polynomial commitment protocol. The polynomials are described in the
//! structure [crate::mips::column::ColumnAlias]. These polynomials will be
//! committed and evaluated at certain points following the polynomial protocol,
//! and it will form the proof of the correct execution that the prover will
//! build and send to the verifier. The corresponding structure is
//! Proof. The prover will start by computing the
//! execution trace using the interpreter implemented in the module
//! [crate::mips::interpreter], and the evaluations will be kept in the
//! structure ProofInputs.

use std::collections::HashMap;

use ark_ff::Field;
use kimchi_msm::witness::Witness;
use strum::{EnumCount, IntoEnumIterator};

use crate::{
    mips::{
        column::MIPS_COLUMNS,
        constraints::Env,
        interpreter::Instruction::{self, *},
    },
    Circuit, CircuitTrait,
};

use self::interpreter::{
    interpret_instruction,
    ITypeInstruction::{self, *},
    JTypeInstruction::{self, *},
    RTypeInstruction::{self, *},
};

pub mod column;
pub mod constraints;
pub mod folding;
pub mod interpreter;
pub mod registers;
pub mod witness;

#[allow(dead_code)]
/// The Keccak circuit
pub type MIPSCircuit<F> = Circuit<MIPS_COLUMNS, Instruction, F>;

impl<F: Field> CircuitTrait<MIPS_COLUMNS, Instruction, F, Env<F>> for MIPSCircuit<F> {
    fn new(domain_size: usize, env: &mut Env<F>) -> Self {
        let mut circuit = Self {
            domain_size,
            witness: HashMap::new(),
            constraints: Default::default(),
            lookups: Default::default(),
        };

        for instr in Instruction::iter() {
            circuit.witness.insert(
                instr,
                Witness {
                    cols: Box::new(std::array::from_fn(|_| Vec::with_capacity(domain_size))),
                },
            );
            interpret_instruction(env, instr);
            circuit.constraints.insert(instr, env.constraints.clone());
            circuit.lookups.insert(instr, env.lookups.clone());
            env.constraints = vec![]; // Clear the constraints for the next instruction
            env.lookups = vec![]; // Clear the lookups for the next instruction
        }
        circuit
    }

    fn push_row(&mut self, instr: Instruction, row: &[F; MIPS_COLUMNS]) {
        self.witness.entry(instr).and_modify(|wit| {
            for (i, value) in row.iter().enumerate() {
                if wit.cols[i].len() < wit.cols[i].capacity() {
                    wit.cols[i].push(*value);
                }
            }
        });
    }

    fn pad(&mut self, instr: Instruction) -> bool {
        let rows_left = self.domain_size - self.witness[&instr].cols[0].len();
        if rows_left == 0 {
            return false;
        }
        self.witness.entry(instr).and_modify(|wit| {
            for col in wit.cols.iter_mut() {
                col.extend((0..rows_left).map(|_| F::zero()));
            }
        });
        true
    }

    fn pad_witnesses(&mut self) {
        for instr in Instruction::iter() {
            self.pad(instr);
        }
    }

    fn reset(&mut self, instr: Instruction) {
        self.witness.insert(
            instr,
            Witness {
                cols: Box::new(std::array::from_fn(|_| {
                    Vec::with_capacity(self.domain_size)
                })),
            },
        );
    }
}
