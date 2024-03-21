use ark_ff::PrimeField;
use ark_ff::Zero;

use crate::{
    columns::{Column, ColumnIndexer},
    lookups::LookupTableIDs,
    proof::ProofInputs,
    test::{
        columns::{TestColumnIndexer, TEST_N_COLUMNS},
        interpreter::TestInterpreterEnv,
    },
    witness::Witness,
    {BN254G1Affine, Fp},
};

#[allow(dead_code)]
/// Builder environment for a native group `G`.
pub struct WitnessBuilderEnv<F: PrimeField> {
    /// Aggregated witness, in raw form. For accessing [`Witness`], see the
    /// `get_witness` method.
    witness: Vec<Witness<TEST_N_COLUMNS, F>>,
}

impl<F: PrimeField> TestInterpreterEnv<F> for WitnessBuilderEnv<F> {
    type Position = Column;

    type Variable = F;

    fn empty() -> Self {
        WitnessBuilderEnv {
            witness: vec![Witness {
                cols: [Zero::zero(); TEST_N_COLUMNS],
            }],
        }
    }

    fn assert_zero(&mut self, cst: Self::Variable) {
        assert_eq!(cst, F::zero());
    }

    fn constant(value: F) -> Self::Variable {
        value
    }

    fn copy(&mut self, value: &Self::Variable, position: Self::Position) -> Self::Variable {
        let Column::X(i) = position else { todo!() };
        self.witness.last_mut().unwrap().cols[i] = *value;
        *value
    }

    // TODO deduplicate, remove this
    fn column_pos(ix: TestColumnIndexer) -> Self::Position {
        ix.ix_to_column()
    }

    fn read_column(&self, ix: TestColumnIndexer) -> Self::Variable {
        let Column::X(i) = Self::column_pos(ix) else {
            todo!()
        };
        self.witness.last().unwrap().cols[i]
    }
}

impl WitnessBuilderEnv<Fp> {
    /// Each WitnessColumn stands for both one row and multirow. This
    /// function converts from a vector of one-row instantiation to a
    /// single multi-row form (which is a `Witness`).
    pub fn get_witness(
        &self,
        domain_size: usize,
    ) -> ProofInputs<TEST_N_COLUMNS, BN254G1Affine, LookupTableIDs> {
        let mut cols: [Vec<Fp>; TEST_N_COLUMNS] = std::array::from_fn(|_| vec![]);

        if self.witness.len() > domain_size {
            panic!("Too many witness rows added");
        }

        // Filling actually used rows
        for w in &self.witness {
            let Witness { cols: witness_row } = w;
            for i in 0..TEST_N_COLUMNS {
                cols[i].push(witness_row[i]);
            }
        }

        // Filling ther rows up to the domain size
        for _ in self.witness.len()..domain_size {
            for col in cols.iter_mut() {
                col.push(Zero::zero());
            }
        }

        ProofInputs {
            evaluations: Witness { cols },
            mvlookups: vec![],
            // FIXME
            fixed_lookup_tables: vec![],
        }
    }

    pub fn next_row(&mut self) {
        self.witness.push(Witness {
            cols: [Zero::zero(); TEST_N_COLUMNS],
        });
    }
}
