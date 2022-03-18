use super::tables::{
    combine_table_entry, get_table, GateLookupTable, GatesLookupMaps, GatesLookupSpec, LookupTable,
};
use crate::circuits::domains::EvaluationDomains;
use crate::circuits::gate::{CircuitGate, CurrOrNext, GateType};
use ark_ff::{FftField, Field, One, Zero};
use ark_poly::{Evaluations as E, Radix2EvaluationDomain as D};
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::ops::Mul;

type Evaluations<Field> = E<Field, D<Field>>;

impl GateType {
    /// Which lookup-patterns should be applied on which rows.
    /// Currently there is only the lookup pattern used in the ChaCha rows, and it
    /// is applied to each ChaCha row and its successor.
    ///
    /// See circuits/kimchi/src/polynomials/chacha.rs for an explanation of
    /// how these work.
    pub fn lookup_kinds<F: Field>() -> (Vec<Vec<JointLookupSpec<F>>>, Vec<GatesLookupSpec>) {
        let curr_row = |column| LocalPosition {
            row: CurrOrNext::Curr,
            column,
        };
        let chacha_pattern = (0..4)
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
                JointLookup {
                    table_id: 0,
                    entry: vec![l(left), l(right), l(output)],
                }
            })
            .collect();

        let mut chacha_where = HashSet::new();
        use CurrOrNext::{Curr, Next};
        use GateType::*;

        for g in &[ChaCha0, ChaCha1, ChaCha2] {
            for r in &[Curr, Next] {
                chacha_where.insert((*g, *r));
            }
        }

        let one_half = F::from(2u64).inverse().unwrap();
        let neg_one_half = -one_half;
        let chacha_final_pattern = (0..4)
            .map(|i| {
                let nybble = curr_row(1 + i);
                let low_bit = curr_row(5 + i);
                // Check
                // XOR((nybble - low_bit)/2, (nybble - low_bit)/2) = 0.
                let x = SingleLookup {
                    value: vec![(one_half, nybble), (neg_one_half, low_bit)],
                };
                JointLookup {
                    table_id: 0,
                    entry: vec![x.clone(), x, SingleLookup { value: vec![] }],
                }
            })
            .collect();

        let mut chacha_final_where = HashSet::new();
        for r in &[Curr, Next] {
            chacha_final_where.insert((ChaChaFinal, *r));
        }

        let lookups = [
            (chacha_pattern, chacha_where, Some(GateLookupTable::Xor)),
            (
                chacha_final_pattern,
                chacha_final_where,
                Some(GateLookupTable::Xor),
            ),
        ];

        // Convert from an array of tuples to a tuple of vectors
        {
            let mut patterns = Vec::with_capacity(lookups.len());
            let mut locations_with_tables = Vec::with_capacity(lookups.len());
            for (pattern, locations, table) in lookups {
                patterns.push(pattern);
                locations_with_tables.push(GatesLookupSpec {
                    gate_positions: locations,
                    gate_lookup_table: table,
                });
            }
            (patterns, locations_with_tables)
        }
    }

    pub fn lookup_kinds_map<F: Field>(
        locations_with_tables: Vec<GatesLookupSpec>,
    ) -> GatesLookupMaps {
        let mut index_map = HashMap::with_capacity(locations_with_tables.len());
        let mut table_map = HashMap::with_capacity(locations_with_tables.len());
        for (
            i,
            GatesLookupSpec {
                gate_positions: locs,
                gate_lookup_table: table_kind,
            },
        ) in locations_with_tables.into_iter().enumerate()
        {
            for location in locs {
                if let Entry::Vacant(e) = index_map.entry(location) {
                    e.insert(i);
                } else {
                    panic!("Multiple lookup patterns asserted on same row.")
                }
                if let Some(table_kind) = table_kind {
                    if let Entry::Vacant(e) = table_map.entry(location) {
                        e.insert(table_kind);
                    }
                }
            }
        }
        GatesLookupMaps {
            gate_selector_map: index_map,
            gate_table_map: table_map,
        }
    }
}
