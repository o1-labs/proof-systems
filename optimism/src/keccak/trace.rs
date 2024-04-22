use std::{array, collections::HashMap};

use ark_ff::Field;
use kimchi_msm::witness::Witness;
use strum::IntoEnumIterator;

use crate::{
    keccak::column::{
        Steps::{self, *},
        ZKVM_KECCAK_COLS,
    },
    trace::{Trace, Tracer},
};

use super::environment::KeccakEnv;

/// The Keccak circuit trace
pub type KeccakTrace<F> = Trace<ZKVM_KECCAK_COLS, Steps, F>;

fn standardize(step: Steps) -> Steps {
    // Note that steps of execution are obtained from the constraints environment.
    // There, the round steps can be anything between 0 and 23 (for the 24 permutations).
    // Nonetheless, all of them contain the same set of constraints and lookups.
    // Therefore, we want to treat them as the same step when it comes to splitting the
    // circuit into multiple instances with shared behaviour. By default, we use `Round(0)`.
    if let Round(_) = step {
        Round(0)
    } else {
        step
    }
}

impl<F: Field> Tracer<ZKVM_KECCAK_COLS, Steps, F, KeccakEnv<F>> for KeccakTrace<F> {
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

    fn pad_with_row(&mut self, step: Steps, row: &[F; ZKVM_KECCAK_COLS]) -> usize {
        let step = standardize(step);
        // No need to check if it is negative, because they are usize.
        let rows_to_add = self.domain_size - self.witness[&step].cols[0].len();
        // When we reach the domain size, we don't need to pad anymore.
        for _ in 0..rows_to_add {
            self.push_row(step, row);
        }
        rows_to_add
    }

    fn pad_with_zeros(&mut self, step: Steps) -> usize {
        let step = standardize(step);
        // No need to check if it is negative, because they are usize.
        let rows_to_add = self.domain_size - self.witness[&step].cols[0].len();
        // When we reach the domain size, we don't need to pad anymore.
        self.witness.entry(step).and_modify(|wit| {
            for col in wit.cols.iter_mut() {
                col.extend((0..rows_to_add).map(|_| F::zero()));
            }
        });
        rows_to_add
    }

    fn pad_dummy(&mut self, step: Steps) -> usize {
        // We only want to pad non-empty witnesses.
        if !self.in_circuit(step) {
            0
        } else {
            let step = standardize(step);
            // We keep track of the first row of the non-empty witness, which is a real step witness.
            let row = array::from_fn(|i| self.witness[&step].cols[i][0]);
            self.pad_with_row(step, &row)
        }
    }

    fn pad_witnesses(&mut self) {
        for step in Steps::iter().flat_map(|step| step.into_iter()) {
            self.pad_dummy(step);
        }
    }
}
