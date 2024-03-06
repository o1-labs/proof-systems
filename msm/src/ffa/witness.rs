use ark_ff::PrimeField;
use ark_ff::Zero;
use num_bigint::BigUint;

use crate::{
    columns::{Column, ColumnIndexer},
    ffa::{
        columns::{FFAColumnIndexer, FFA_N_COLUMNS},
        interpreter::FFAInterpreterEnv,
    },
    lookups::LookupTableIDs,
    proof::ProofInputs,
    witness::Witness,
    {BN254G1Affine, Ff1, Fp, N_LIMBS},
};
use o1_utils::{field_helpers::FieldHelpers, foreign_field::ForeignElement};

// TODO use more foreign_field.rs with from/to bigint conversion
fn limb_decompose(input: &Ff1) -> [Fp; N_LIMBS] {
    let input_bi: BigUint = FieldHelpers::to_biguint(input);
    let ff_el: ForeignElement<Fp, N_LIMBS> = ForeignElement::from_biguint(input_bi);
    ff_el.limbs
}

#[allow(dead_code)]
/// Builder environment for a native group `G`.
pub struct WitnessBuilder<F: PrimeField> {
    /// Aggregated witness, in raw form. For accessing [`Witness`], see the
    /// `get_witness` method.
    witness_raw: Vec<Witness<FFA_N_COLUMNS, F>>,
}

impl<F: PrimeField> FFAInterpreterEnv<F> for WitnessBuilder<F> {
    type Position = Column;

    type Variable = F;

    fn add_constraint(&mut self, cst: Self::Variable) {
        assert_eq!(cst, F::zero());
    }

    fn constant(value: F) -> Self::Variable {
        value
    }

    fn copy(&mut self, x: &Self::Variable, position: Self::Position) -> Self::Variable {
        self.write_column(position, *x);
        *x
    }

    fn get_column(ix: FFAColumnIndexer) -> Self::Position {
        ix.ix_to_column()
    }
}

impl<F: PrimeField> WitnessBuilder<F> {
    pub fn write_column(&mut self, column: Column, _value: F) {
        match FFAColumnIndexer::column_to_ix(column) {
            FFAColumnIndexer::A(_i) => unimplemented!(),
            FFAColumnIndexer::B(_i) => unimplemented!(),
            FFAColumnIndexer::C(_i) => unimplemented!(),
            FFAColumnIndexer::D(_i) => unimplemented!(),
        }
    }

    pub fn empty() -> Self {
        WitnessBuilder {
            witness_raw: vec![],
        }
    }
}

impl WitnessBuilder<Fp> {
    /// Each WitnessColumn stands for both one row and multirow. This
    /// function converts from a vector of one-row instantiation to a
    /// single multi-row form (which is a `Witness`).
    pub fn get_witness(&self) -> ProofInputs<FFA_N_COLUMNS, BN254G1Affine, LookupTableIDs> {
        let mut cols: [Vec<Fp>; FFA_N_COLUMNS] = std::array::from_fn(|_| vec![]);

        for w in &self.witness_raw {
            let Witness { cols: witness_row } = w;
            for i in 0..4 * N_LIMBS {
                cols[i].push(witness_row[i]);
            }
        }

        ProofInputs {
            evaluations: Witness { cols },
            mvlookups: vec![],
        }
    }

    pub fn add_test_addition(&mut self, a: Ff1, b: Ff1) {
        let a_limbs: [Fp; N_LIMBS] = limb_decompose(&a);
        let b_limbs: [Fp; N_LIMBS] = limb_decompose(&b);
        let c_limbs_vec: Vec<Fp> = a_limbs
            .iter()
            .zip(b_limbs.iter())
            .map(|(ai, bi)| *ai + *bi)
            .collect();
        let c_limbs: [Fp; N_LIMBS] = c_limbs_vec
            .try_into()
            .unwrap_or_else(|_| panic!("Length mismatch"));
        let d_limbs: [Fp; N_LIMBS] = [Zero::zero(); N_LIMBS];

        let witness_row: [Fp; 4 * N_LIMBS] = [a_limbs, b_limbs, c_limbs, d_limbs]
            .concat()
            .try_into()
            .unwrap();

        self.witness_raw.push(Witness { cols: witness_row });
    }

    pub fn add_test_multiplication(&mut self, a: Ff1, b: Ff1) {
        let a_limbs: [Fp; N_LIMBS] = limb_decompose(&a);
        let b_limbs: [Fp; N_LIMBS] = limb_decompose(&b);
        let d_limbs_vec: Vec<Fp> = a_limbs
            .iter()
            .zip(b_limbs.iter())
            .map(|(ai, bi)| *ai * *bi)
            .collect();
        let d_limbs: [Fp; N_LIMBS] = d_limbs_vec
            .try_into()
            .unwrap_or_else(|_| panic!("Length mismatch"));

        let c_limbs: [Fp; N_LIMBS] = [Zero::zero(); N_LIMBS];

        let witness_row: [Fp; 4 * N_LIMBS] = [a_limbs, b_limbs, c_limbs, d_limbs]
            .concat()
            .try_into()
            .unwrap();

        self.witness_raw.push(Witness { cols: witness_row });
    }
}
