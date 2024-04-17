use std::collections::HashMap;

use ark_ff::Field;
use kimchi_msm::witness::Witness;
use strum::IntoEnumIterator;

use crate::{
    circuit::{Circuit, CircuitTrait},
    keccak::column::{
        Steps::{self, *},
        ZKVM_KECCAK_COLS,
    },
};

use super::environment::KeccakEnv;

/// The Keccak circuit
pub type KeccakCircuit<F> = Circuit<ZKVM_KECCAK_COLS, Steps, F>;

impl<F: Field> CircuitTrait<ZKVM_KECCAK_COLS, Steps, F, KeccakEnv<F>> for KeccakCircuit<F> {
    fn new(domain_size: usize, _env: &mut KeccakEnv<F>) -> Self {
        let mut circuit = Self {
            domain_size,
            witness: HashMap::new(),
            constraints: Default::default(),
            lookups: Default::default(),
        };

        for step in Steps::iter().flat_map(|step| step.into_iter()) {
            circuit.witness.insert(
                step,
                Witness {
                    cols: Box::new(std::array::from_fn(|_| Vec::with_capacity(domain_size))),
                },
            );
            circuit
                .constraints
                .insert(step, KeccakEnv::constraints_of(step));
            circuit.lookups.insert(step, KeccakEnv::lookups_of(step));
        }
        circuit
    }

    fn push_row(&mut self, step: Steps, row: &[F; ZKVM_KECCAK_COLS]) {
        // Make sure we are using the same round number to refer to round steps
        let mut step = step;
        if let Round(_) = step {
            step = Round(0);
        }
        self.witness.entry(step).and_modify(|wit| {
            for (i, value) in row.iter().enumerate() {
                if wit.cols[i].len() < wit.cols[i].capacity() {
                    wit.cols[i].push(*value);
                }
            }
        });
    }

    fn pad(&mut self, step: Steps) -> bool {
        let rows_left = self.domain_size - self.witness[&step].cols[0].len();
        if rows_left == 0 {
            return false;
        }
        self.witness.entry(step).and_modify(|wit| {
            for col in wit.cols.iter_mut() {
                col.extend((0..rows_left).map(|_| F::zero()));
            }
        });
        true
    }

    fn pad_witnesses(&mut self) {
        for step in Steps::iter().flat_map(|step| step.into_iter()) {
            self.pad(step);
        }
    }

    fn reset(&mut self, step: Steps) {
        self.witness.insert(
            step,
            Witness {
                cols: Box::new(std::array::from_fn(|_| {
                    Vec::with_capacity(self.domain_size)
                })),
            },
        );
    }
}
