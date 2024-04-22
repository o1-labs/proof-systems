use std::{collections::HashSet, marker::PhantomData};

use ark_ff::{FpParameters, PrimeField, Zero};
use num_bigint::BigUint;
use o1_utils::field_helpers::FieldHelpers;

use crate::{
    columns::Column,
    fec::{columns::FEC_N_COLUMNS, interpreter::FECInterpreterEnv, lookups::LookupTable},
    lookups::LookupTableIDs,
    proof::ProofInputs,
    witness::Witness,
    BN254G1Affine, Fp, LIMB_BITSIZE, N_LIMBS,
};

#[allow(dead_code)]
/// Builder environment for a native group `G`.
pub struct WitnessBuilderEnv<F: PrimeField, Ff: PrimeField> {
    /// Aggregated witness, in raw form. For accessing [`Witness`], see the
    /// `get_witness` method.
    witness: Vec<Witness<FEC_N_COLUMNS, F>>,
    double_write_checker: HashSet<usize>,
    phantom: PhantomData<Ff>,
}

impl<F: PrimeField, Ff: PrimeField> FECInterpreterEnv<F, LookupTable<Ff>>
    for WitnessBuilderEnv<F, Ff>
{
    type Variable = F;

    fn empty() -> Self {
        WitnessBuilderEnv {
            witness: vec![Witness {
                cols: Box::new([Zero::zero(); FEC_N_COLUMNS]),
            }],
            double_write_checker: HashSet::new(),
            phantom: PhantomData,
        }
    }

    fn assert_zero(&mut self, cst: Self::Variable) {
        assert_eq!(cst, F::zero(), "The given value was nonzero");
    }

    fn constant(value: F) -> Self::Variable {
        value
    }

    fn copy(&mut self, value: &Self::Variable, position: Column) -> Self::Variable {
        let Column::X(i) = position else { todo!() };
        self.witness.last_mut().unwrap().cols[i] = *value;
        if self.double_write_checker.contains(&i) {
            panic!("Warning: double writing into column number {i:?}");
        }
        self.double_write_checker.insert(i);
        *value
    }

    fn read_column(&self, ix: Column) -> Self::Variable {
        let Column::X(i) = ix else { todo!() };
        self.witness.last().unwrap().cols[i]
    }

    fn range_check_abs1(&mut self, value: &Self::Variable) {
        assert!(*value == F::one() || *value == F::zero() - F::one());
    }

    fn range_check_ff_highest(&mut self, value: &Self::Variable) {
        let f_bui: BigUint = TryFrom::try_from(Ff::Params::MODULUS).unwrap();
        // N_LIMBS * LIMB_BITSIZE = 17*15 = 255
        // (N_LIMBS-1) * LIMB_BITSIZE = 16*15 = 240
        // So we only want to check that the highest 15 bits of our number is
        // less than the highest bits of f after dropping 240 of the lowest ones.
        let top_modulus: BigUint = f_bui >> ((N_LIMBS - 1) * LIMB_BITSIZE);
        let top_modulus_f: F = F::from_biguint(&top_modulus).unwrap();
        assert!(*value < top_modulus_f);
    }

    fn range_check_15bit(&mut self, value: &Self::Variable) {
        assert!(*value < F::from(1u64 << 15));
    }

    fn range_check_abs15bit(&mut self, value: &Self::Variable) {
        assert!(*value < F::from(1u64 << 15) || *value >= F::zero() - F::from(1u64 << 15));
    }

    fn range_check_abs4bit(&mut self, value: &Self::Variable) {
        assert!(*value < F::from(1u64 << 4) || *value >= F::zero() - F::from(1u64 << 4));
    }
}

impl<Ff: PrimeField> WitnessBuilderEnv<Fp, Ff> {
    /// Each WitnessColumn stands for both one row and multirow. This
    /// function converts from a vector of one-row instantiation to a
    /// single multi-row form (which is a `Witness`).
    pub fn get_witness(
        &self,
        domain_size: usize,
    ) -> ProofInputs<FEC_N_COLUMNS, BN254G1Affine, LookupTableIDs> {
        let mut cols: Box<[Vec<Fp>; FEC_N_COLUMNS]> = Box::new(std::array::from_fn(|_| vec![]));

        if self.witness.len() > domain_size {
            panic!("Too many witness rows added");
        }

        // Filling actually used rows
        for w in &self.witness {
            let Witness { cols: witness_row } = w;
            for i in 0..FEC_N_COLUMNS {
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
            logups: vec![],
        }
    }

    pub fn next_row(&mut self) {
        self.witness.push(Witness {
            cols: Box::new([Zero::zero(); FEC_N_COLUMNS]),
        });
        self.double_write_checker = HashSet::new();
    }
}
