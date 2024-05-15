use crate::{
    folding::ScalarField,
    mips::{
        column::{N_MIPS_COLS, N_MIPS_REL_COLS},
        constraints::Env,
        folding::DecomposableMIPSFoldingConfig,
        interpreter::{interpret_instruction, Instruction},
    },
    trace::{DecomposableTracer, DecomposedTrace, Trace, Tracer},
};
use ark_ff::Zero;
use kimchi_msm::witness::Witness;
use std::{array, collections::BTreeMap};
use strum::IntoEnumIterator;

/// The MIPS instruction trace
pub type MIPSTrace = Trace<N_MIPS_COLS, DecomposableMIPSFoldingConfig>;
/// The MIPS circuit trace
pub type DecomposedMIPSTrace = DecomposedTrace<N_MIPS_COLS, DecomposableMIPSFoldingConfig>;

impl DecomposableTracer<Env<ScalarField<DecomposableMIPSFoldingConfig>>> for DecomposedMIPSTrace {
    fn new(domain_size: usize, env: &mut Env<ScalarField<DecomposableMIPSFoldingConfig>>) -> Self {
        let mut circuit = Self {
            domain_size,
            trace: BTreeMap::new(),
        };
        for instr in Instruction::iter().flat_map(|step| step.into_iter()) {
            circuit
                .trace
                .insert(instr, <MIPSTrace>::init(domain_size, instr, env));
        }
        circuit
    }

    fn pad_witnesses(&mut self) {
        for opcode in Instruction::iter().flat_map(|opcode| opcode.into_iter()) {
            self.trace.get_mut(&opcode).unwrap().pad_dummy(());
        }
    }
}

impl
    Tracer<
        N_MIPS_REL_COLS,
        DecomposableMIPSFoldingConfig,
        Env<ScalarField<DecomposableMIPSFoldingConfig>>,
    > for MIPSTrace
{
    type Selector = ();

    fn init(
        domain_size: usize,
        instr: Instruction,
        env: &mut Env<ScalarField<DecomposableMIPSFoldingConfig>>,
    ) -> Self {
        interpret_instruction(env, instr);

        let trace = Self {
            domain_size,
            witness: Witness {
                cols: Box::new(std::array::from_fn(|_| Vec::with_capacity(domain_size))),
            },
            constraints: env.constraints.clone(),
            lookups: env.lookups.clone(),
        };
        env.scratch_state_idx = 0; // Reset the scratch state index for the next instruction
        env.constraints = vec![]; // Clear the constraints for the next instruction
        env.lookups = vec![]; // Clear the lookups for the next instruction

        trace
    }

    fn push_row(
        &mut self,
        _selector: Self::Selector,
        row: &[ScalarField<DecomposableMIPSFoldingConfig>; N_MIPS_REL_COLS],
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
        row: &[ScalarField<DecomposableMIPSFoldingConfig>; N_MIPS_REL_COLS],
    ) -> usize {
        let len = self.witness.cols[0].len();
        assert!(len <= self.domain_size);
        let rows_to_add = self.domain_size - len;
        // When we reach the domain size, we don't need to pad anymore.
        for _ in 0..rows_to_add {
            self.push_row(_selector, row);
        }
        rows_to_add
    }

    fn pad_with_zeros(&mut self, _selector: Self::Selector) -> usize {
        let len = self.witness.cols[0].len();
        assert!(len <= self.domain_size);
        let rows_to_add = self.domain_size - len;
        // When we reach the domain size, we don't need to pad anymore.
        for col in self.witness.cols.iter_mut() {
            col.extend(
                (0..rows_to_add).map(|_| ScalarField::<DecomposableMIPSFoldingConfig>::zero()),
            );
        }
        rows_to_add
    }

    fn pad_dummy(&mut self, _selector: Self::Selector) -> usize {
        // We keep track of the first row of the non-empty witness, which is a real step witness.
        let row = array::from_fn(|i| self.witness.cols[i][0]);
        self.pad_with_row(_selector, &row)
    }
}
