use std::collections::HashSet;

use crate::circuits::{
    constraints::ZK_ROWS,
    domains::EvaluationDomains,
    gate::CircuitGate,
    lookup::{
        constraints::LookupConfiguration,
        lookups::{JointLookup, LookupInfo},
        tables::{get_table, GateLookupTable, LookupTable},
    },
};
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::{
    univariate::DensePolynomial as DP, EvaluationDomain, Evaluations as E,
    Radix2EvaluationDomain as D,
};
use itertools::repeat_n;
use o1_utils::field_helpers::i32_to_field;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

/// Represents an error found when computing the lookup constraint system
#[derive(Debug, Error)]
pub enum LookupError {
    #[error("One of the lookup tables has columns of different lengths")]
    InconsistentTableLength,
    #[error("The combined lookup table is larger than allowed by the domain size. Obsered: {length}, expected: {maximum_allowed}")]
    LookupTableTooLong {
        length: usize,
        maximum_allowed: usize,
    },
    #[error("Multiple tables shared the same table IDs")]
    DuplicateTableID,
    #[error("The table with id 0 must have an entry of all zeros")]
    TableIDZeroMustHaveZeroEntry,
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct LookupConstraintSystem<F: FftField> {
    /// Lookup tables
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub lookup_table: Vec<DP<F>>,
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub lookup_table8: Vec<E<F, D<F>>>,

    /// Table IDs for the lookup values.
    /// This may be `None` if all lookups originate from table 0.
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub table_ids: Option<DP<F>>,
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub table_ids8: Option<E<F, D<F>>>,

    /// Lookup selectors:
    /// For each kind of lookup-pattern, we have a selector that's
    /// 1 at the rows where that pattern should be enforced, and 0 at
    /// all other rows.
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub lookup_selectors: Vec<E<F, D<F>>>,

    /// Configuration for the lookup constraint.
    #[serde(bound = "LookupConfiguration<F>: Serialize + DeserializeOwned")]
    pub configuration: LookupConfiguration<F>,
}

impl<F: FftField + SquareRootField> LookupConstraintSystem<F> {
    pub fn create(
        gates: &[CircuitGate<F>],
        lookup_tables: Vec<LookupTable<F>>,
        domain: &EvaluationDomains<F>,
    ) -> Result<Option<Self>, LookupError> {
        let lookup_info = LookupInfo::<F>::create();
        println!("{:#?}", lookup_info);

        //~ 1. If no lookup is used in the circuit, do not create a lookup index
        match lookup_info.lookup_used(gates) {
            None => Ok(None),
            Some(lookup_used) => {
                let d1_size = domain.d1.size();

                // The maximum number of entries that can be provided across all tables.
                // Since we do not assert the lookup constraint on the final `ZK_ROWS` rows, and
                // because the row before is used to assert that the lookup argument's final
                // product is 1, we cannot use those rows to store any values.
                let max_num_entries = d1_size - (ZK_ROWS as usize) - 1;

                //~ 2. Get the lookup selectors and lookup tables (TODO: how?)
                let (lookup_selectors, gate_lookup_tables) =
                    lookup_info.selector_polynomials_and_tables(domain, gates);

                //~ 3. Concatenate runtime lookup tables with the ones used by gates
                let lookup_tables: Vec<_> = gate_lookup_tables
                    .into_iter()
                    .chain(lookup_tables.into_iter())
                    .collect();

                //~ 4. Get the highest number of columns `max_table_width`
                //~    that a lookup table can have.
                let max_table_width = lookup_tables
                    .iter()
                    .map(|table| table.data.len())
                    .max()
                    .unwrap_or(0);

                //~ 5. Add the table ID stuff
                let mut lookup_table = vec![Vec::with_capacity(d1_size); max_table_width];
                let mut table_ids: Vec<F> = Vec::with_capacity(d1_size);
                let mut table_ids_so_far = HashSet::new();

                //~ 6. For each table:
                for table in lookup_tables.iter() {
                    let table_len = table.data[0].len();

                    //~ a. Make sure tables don't share the same id.
                    if !table_ids_so_far.insert(table.id) {
                        return Err(LookupError::DuplicateTableID);
                    }

                    //~ b. Make sure that if table with id 0 is used, then it's the XOR table.
                    //~    We do this because we use a table with id 0 and
                    //~
                    if table.id == 0 {
                        if !table.has_zero_entry() {
                            return Err(LookupError::TableIDZeroMustHaveZeroEntry);
                        }
                    }

                    //~ c. Update table IDs
                    let table_id: F = i32_to_field(table.id);
                    table_ids.extend(repeat_n(table_id, table_len));

                    //~ d. Update lookup_table values
                    for (i, col) in table.data.iter().enumerate() {
                        if col.len() != table_len {
                            return Err(LookupError::InconsistentTableLength);
                        }
                        lookup_table[i].extend(col);
                    }

                    //~ e. Fill in any unused columns with 0 to match the dummy value
                    for lookup_table in lookup_table.iter_mut().skip(table.data.len()) {
                        lookup_table.extend(repeat_n(F::zero(), table_len))
                    }
                }

                // Note: we use `>=` here to leave space for the dummy value.
                if lookup_table[0].len() >= max_num_entries {
                    return Err(LookupError::LookupTableTooLong {
                        length: lookup_table[0].len(),
                        maximum_allowed: max_num_entries - 1,
                    });
                }

                // For computational efficiency, we choose the dummy lookup value to be all 0s in
                // table 0.
                let dummy_lookup_value: Vec<F> = vec![];
                let dummy_lookup_table_id = 0;

                // Pad up to the end of the table with the dummy value.
                lookup_table
                    .iter_mut()
                    .for_each(|col| col.extend(repeat_n(F::zero(), max_num_entries - col.len())));
                table_ids.extend(repeat_n(F::zero(), max_num_entries - table_ids.len()));

                // pre-compute polynomial and evaluation form for the look up tables
                let mut lookup_table_polys: Vec<DP<F>> = vec![];
                let mut lookup_table8: Vec<E<F, D<F>>> = vec![];
                for col in lookup_table.into_iter() {
                    let poly = E::<F, D<F>>::from_vec_and_domain(col, domain.d1).interpolate();
                    let eval = poly.evaluate_over_domain_by_ref(domain.d8);
                    lookup_table_polys.push(poly);
                    lookup_table8.push(eval);
                }

                // pre-compute polynomial and evaluation form for the table IDs, if needed

                let table_ids: DP<F> =
                    E::<F, D<F>>::from_vec_and_domain(table_ids, domain.d1).interpolate();

                let (table_ids, table_ids8) = if table_ids.is_zero() {
                    (None, None)
                } else {
                    let table_ids8: E<F, D<F>> = table_ids.evaluate_over_domain_by_ref(domain.d8);
                    (Some(table_ids), Some(table_ids8))
                };

                // calculate
                let max_lookups_per_row = lookup_selectors.len();
                let max_joint_size = u32::try_from(max_table_width).expect("unexpected table size");

                // generate the look up selector polynomials
                Ok(Some(Self {
                    lookup_selectors,
                    lookup_table8,
                    lookup_table: lookup_table_polys,
                    table_ids,
                    table_ids8,
                    configuration: LookupConfiguration {
                        lookup_used,
                        max_lookups_per_row,
                        max_joint_size,
                        dummy_lookup_value,
                        dummy_lookup_table_id,
                    },
                }))
            }
        }
    }
}
