use std::{array, collections::BTreeMap};

use ark_ff::Zero;
use kimchi_msm::witness::Witness;
use strum::IntoEnumIterator;

use crate::{
    folding::ScalarField,
    keccak::{
        column::{Steps, N_ZKVM_KECCAK_COLS, N_ZKVM_KECCAK_REL_COLS},
        environment::KeccakEnv,
        standardize,
    },
    trace::{DecomposableTracer, DecomposedTrace, Trace, Tracer},
};

use super::folding::KeccakConfig;

/// A Keccak instruction trace
pub type KeccakTrace = Trace<N_ZKVM_KECCAK_COLS, KeccakConfig>;
/// The Keccak circuit trace
pub type DecomposedKeccakTrace = DecomposedTrace<N_ZKVM_KECCAK_COLS, KeccakConfig>;

impl DecomposableTracer<KeccakEnv<ScalarField<KeccakConfig>>> for DecomposedKeccakTrace {
    fn new(domain_size: usize, env: &mut KeccakEnv<ScalarField<KeccakConfig>>) -> Self {
        let mut circuit = Self {
            domain_size,
            trace: BTreeMap::new(),
        };
        for step in Steps::iter().flat_map(|step| step.into_iter()) {
            circuit
                .trace
                .insert(step, KeccakTrace::init(domain_size, step, env));
        }
        circuit
    }

    fn pad_witnesses(&mut self) {
        for opcode in Steps::iter().flat_map(|opcode| opcode.into_iter()) {
            if self.in_circuit(opcode) {
                self.trace.get_mut(&opcode).unwrap().pad_dummy(());
            }
        }
    }
}

impl Tracer<N_ZKVM_KECCAK_REL_COLS, KeccakConfig, KeccakEnv<ScalarField<KeccakConfig>>>
    for KeccakTrace
{
    type Selector = ();

    fn init(
        domain_size: usize,
        selector: Steps,
        _env: &mut KeccakEnv<ScalarField<KeccakConfig>>,
    ) -> Self {
        // Make sure we are using the same round number to refer to round steps
        let step = standardize(selector);
        let mut trace = Self {
            domain_size,
            witness: Witness {
                cols: Box::new(std::array::from_fn(|_| Vec::with_capacity(domain_size))),
            },
            constraints: KeccakEnv::constraints_of(step),
            lookups: KeccakEnv::lookups_of(step),
            delayed_columns: BTreeMap::new(),
        };
        trace.set_delayed_columns();
        trace
    }

    fn push_row(
        &mut self,
        _selector: Self::Selector,
        row: &[ScalarField<KeccakConfig>; N_ZKVM_KECCAK_REL_COLS],
    ) {
        for (i, value) in row.iter().enumerate() {
            if self.witness.cols[i].len() < self.witness.cols[i].capacity() {
                self.witness.cols[i].push(*value);
            }
        }
    }

    fn pad_with_row(
        &mut self,
        _selector: Self::Selector,
        row: &[ScalarField<KeccakConfig>; N_ZKVM_KECCAK_REL_COLS],
    ) -> usize {
        let len = self.witness.cols[0].len();
        assert!(len <= self.domain_size);
        let rows_to_add = self.domain_size - len;
        // When we reach the domain size, we don't need to pad anymore.
        for _ in 0..rows_to_add {
            self.push_row((), row);
        }
        rows_to_add
    }

    fn pad_with_zeros(&mut self, _selector: Self::Selector) -> usize {
        let len = self.witness.cols[0].len();
        assert!(len <= self.domain_size);
        let rows_to_add = self.domain_size - len;
        // When we reach the domain size, we don't need to pad anymore.
        for col in self.witness.cols.iter_mut() {
            col.extend((0..rows_to_add).map(|_| ScalarField::<KeccakConfig>::zero()));
        }
        rows_to_add
    }

    fn pad_dummy(&mut self, _selector: Self::Selector) -> usize {
        // We keep track of the first row of the non-empty witness, which is a real step witness.
        let row = array::from_fn(|i| self.witness.cols[i][0]);
        self.pad_with_row(_selector, &row)
    }
}
