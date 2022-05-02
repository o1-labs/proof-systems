use crate::circuits::{
    gate::CurrOrNext,
    lookup::{
        lookups::{JointLookup, JointLookupSpec, LocalPosition, SingleLookup},
        tables::XOR_TABLE_ID,
    },
};
use ark_ff::Field;

use super::lookups::LookupTableID;

/// Helper
fn curr_row(column: usize) -> LocalPosition {
    LocalPosition {
        row: CurrOrNext::Curr,
        column,
    }
}

/// Represents a list of queries to different lookup tables
pub struct Queries<F>
where
    F: Field,
{
    pub queries: Vec<JointLookupSpec<F>>,
}

impl<F> Queries<F>
where
    F: Field,
{
    /// 4 XOR queries
    pub fn xor_queries() -> Self {
        let queries = (0..4)
            .map(|i| {
                // each row represents an XOR operation
                // where l XOR r = o
                //
                // 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14
                // - - - l - - - r - - -  o  -  -  -
                // - - - - l - - - r - -  -  o  -  -
                // - - - - - l - - - r -  -  -  o  -
                // - - - - - - l - - - r  -  -  -  o
                let left = curr_row(3 + i);
                let right = curr_row(7 + i);
                let output = curr_row(11 + i);
                let l = |loc: LocalPosition| SingleLookup {
                    value: vec![(F::one(), loc)],
                };
                JointLookupSpec {
                    table_id: LookupTableID::Constant(XOR_TABLE_ID),
                    entry: vec![l(left), l(right), l(output)],
                }
            })
            .collect();

        Self { queries }
    }

    /// 4 specific XOR queries useful in ChaCha-Final
    pub fn chacha_final_queries() -> Self {
        let one_half = F::from(2u64).inverse().unwrap();
        let neg_one_half = -one_half;

        let queries = (0..4)
            .map(|i| {
                let nybble = curr_row(1 + i);
                let low_bit = curr_row(5 + i);
                // Check
                // XOR((nybble - low_bit)/2, (nybble - low_bit)/2) = 0.
                let x = SingleLookup {
                    value: vec![(one_half, nybble), (neg_one_half, low_bit)],
                };
                JointLookup {
                    table_id: LookupTableID::Constant(XOR_TABLE_ID),
                    entry: vec![x.clone(), x, SingleLookup { value: vec![] }],
                }
            })
            .collect();

        Self { queries }
    }
}
