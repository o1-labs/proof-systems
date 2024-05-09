use std::{array, collections::BTreeMap};

use ark_ff::Zero;
use kimchi_msm::witness::Witness;
use strum::IntoEnumIterator;

use crate::{
    folding::ScalarField,
    keccak::{
        column::{Steps, N_ZKVM_KECCAK_COLS, N_ZKVM_KECCAK_REL_COLS, N_ZKVM_KECCAK_SEL_COLS},
        environment::KeccakEnv,
        standardize,
    },
    trace::{DecomposableTrace, DecomposableTracer},
};

use super::folding::KeccakConfig;

/// The Keccak circuit trace
pub type KeccakTrace = DecomposableTrace<
    N_ZKVM_KECCAK_COLS,
    N_ZKVM_KECCAK_REL_COLS,
    N_ZKVM_KECCAK_SEL_COLS,
    KeccakConfig,
>;

impl
    DecomposableTracer<
        N_ZKVM_KECCAK_COLS,
        N_ZKVM_KECCAK_REL_COLS,
        N_ZKVM_KECCAK_SEL_COLS,
        KeccakConfig,
        KeccakEnv<ScalarField<KeccakConfig>>,
    > for KeccakTrace
{
    fn new(domain_size: usize, _env: &mut KeccakEnv<ScalarField<KeccakConfig>>) -> Self {
        let mut circuit = Self {
            domain_size,
            witness: BTreeMap::new(),
            constraints: Default::default(),
            lookups: Default::default(),
        };

        for opcode in Steps::iter().flat_map(|step| step.into_iter()) {
            circuit.witness.insert(
                opcode,
                Witness {
                    cols: Box::new(std::array::from_fn(|_| Vec::with_capacity(domain_size))),
                },
            );
            circuit
                .constraints
                .insert(opcode, KeccakEnv::constraints_of(opcode));
            circuit
                .lookups
                .insert(opcode, KeccakEnv::lookups_of(opcode));
        }
        circuit
    }

    fn push_row(
        &mut self,
        opcode: Steps,
        row: &[ScalarField<KeccakConfig>; N_ZKVM_KECCAK_REL_COLS],
    ) {
        // Make sure we are using the same round number to refer to round steps
        let opcode = standardize(opcode);
        self.witness.entry(opcode).and_modify(|wit| {
            for (i, value) in row.iter().enumerate() {
                if wit.cols[i].len() < wit.cols[i].capacity() {
                    wit.cols[i].push(*value);
                }
            }
        });
    }

    fn pad_with_row(
        &mut self,
        opcode: Steps,
        row: &[ScalarField<KeccakConfig>; N_ZKVM_KECCAK_REL_COLS],
    ) -> usize {
        let opcode = standardize(opcode);
        let len = self.witness[&opcode].cols[0].len();
        assert!(len <= self.domain_size);
        let rows_to_add = self.domain_size - len;
        // When we reach the domain size, we don't need to pad anymore.
        for _ in 0..rows_to_add {
            self.push_row(opcode, row);
        }
        rows_to_add
    }

    fn pad_with_zeros(&mut self, opcode: Steps) -> usize {
        let opcode = standardize(opcode);
        let len = self.witness[&opcode].cols[0].len();
        assert!(len <= self.domain_size);
        let rows_to_add = self.domain_size - len;
        // When we reach the domain size, we don't need to pad anymore.
        self.witness.entry(opcode).and_modify(|wit| {
            for col in wit.cols.iter_mut() {
                col.extend((0..rows_to_add).map(|_| ScalarField::<KeccakConfig>::zero()));
            }
        });
        rows_to_add
    }

    fn pad_dummy(&mut self, opcode: Steps) -> usize {
        // We only want to pad non-empty witnesses.
        if !self.in_circuit(opcode) {
            0
        } else {
            let opcode = standardize(opcode);
            // We keep track of the first row of the non-empty witness, which is a real step witness.
            let row = array::from_fn(|i| self.witness[&opcode].cols[i][0]);
            self.pad_with_row(opcode, &row)
        }
    }

    fn pad_witnesses(&mut self) {
        for opcode in Steps::iter().flat_map(|opcode| opcode.into_iter()) {
            self.pad_dummy(opcode);
        }
    }
}
