use std::iter;

use crate::circuits::{domains::EvaluationDomains, gate::CircuitGate};
use crate::circuits::{
    lookup::{
        constraints::LookupConfiguration,
        lookups::{JointLookup, LookupInfo},
        tables::LookupTable,
    },
    polynomials::permutation::ZK_ROWS,
};
use ark_ff::{FftField, SquareRootField};
use ark_poly::{
    univariate::DensePolynomial as DP, EvaluationDomain, Evaluations as E,
    Radix2EvaluationDomain as D,
};
use itertools::repeat_n;
use o1_utils::field_helpers::i32_to_field;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

use super::runtime_tables::{RuntimeTableCfg, RuntimeTableSpec};

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

    /// An optional runtime table selector. It is 0 everywhere,
    /// except at the rows where the runtime tables apply.
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub runtime_selector: Option<E<F, D<F>>>,

    /// Configuration for the lookup constraint.
    #[serde(bound = "LookupConfiguration<F>: Serialize + DeserializeOwned")]
    pub configuration: LookupConfiguration<F>,
}

impl<F: FftField + SquareRootField> LookupConstraintSystem<F> {
    pub fn create(
        gates: &[CircuitGate<F>],
        lookup_tables: Vec<LookupTable<F>>,
        runtime_tables: Option<Vec<RuntimeTableCfg<F>>>,
        domain: &EvaluationDomains<F>,
    ) -> Result<Option<Self>, LookupError> {
        let lookup_info = LookupInfo::<F>::create();

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
                let mut lookup_tables: Vec<_> = gate_lookup_tables
                    .into_iter()
                    .chain(lookup_tables.into_iter())
                    .collect();

                let mut has_table_id_0 = false;

                // if we are using runtime tables
                let (runtime_table_offset, runtime_selector) =
                    if let Some(runtime_tables) = &runtime_tables {
                        // save the offset of the end of the table
                        let mut runtime_table_offset = 0;
                        for table in &lookup_tables {
                            runtime_table_offset += table.len();
                        }

                        // compute the length of the runtime table
                        let mut runtime_len = 0;
                        for t in runtime_tables {
                            runtime_len += t.len();
                        }

                        // compute the runtime selector
                        let runtime_selector = {
                            let mut evals = Vec::with_capacity(d1_size);

                            // it's 1 everywhere, except at the entries where
                            // the runtime table applies
                            evals.extend(iter::repeat(F::one()).take(runtime_table_offset));
                            evals.extend(iter::repeat(F::zero()).take(runtime_len));
                            evals.extend(
                                iter::repeat(F::one())
                                    .take(d1_size - runtime_table_offset - runtime_len),
                            );

                            // although the last ZK_ROWS are fine
                            for e in evals.iter_mut().rev().take(ZK_ROWS as usize) {
                                *e = F::zero();
                            }

                            E::<F, D<F>>::from_vec_and_domain(evals, domain.d1)
                                .interpolate()
                                .evaluate_over_domain(domain.d8)
                        };

                        // create fixed tables for indexing the runtime tables
                        for runtime_table in runtime_tables {
                            use RuntimeTableCfg::*;
                            let (id, first_column) = match runtime_table {
                                &Indexed(RuntimeTableSpec { id, len }) => {
                                    let indexes = (0..(len as u32)).map(F::from).collect();
                                    (id, indexes)
                                }
                                Custom { id, first_column } => (*id, first_column.clone()),
                            };

                            // record if table ID 0 is used in one of the runtime tables
                            // note: the check later will still force you to have a fixed table with ID 0
                            if id == 0 {
                                has_table_id_0 = true;
                            }

                            // important: we still need a placeholder column to make sure that
                            // if all other tables have a single column
                            // we don't use the second table as table ID column.
                            let placeholders = vec![F::zero(); first_column.len()];
                            let data = vec![first_column, placeholders];
                            let table = LookupTable { id, data };
                            lookup_tables.push(table);
                        }

                        (Some(runtime_table_offset), Some(runtime_selector))
                    } else {
                        (None, None)
                    };

                //~ 4. Get the highest number of columns `max_table_width`
                //~    that a lookup table can have.
                let max_table_width = lookup_tables
                    .iter()
                    .map(|table| table.data.len())
                    .max()
                    .unwrap_or(0);

                //~ 5. Create the concatenated table of all the fixed lookup tables.
                //~    It will be of height the size of the domain,
                //~    and of width the maximum width of any of the lookup tables.
                //~    In addition, create an additional column to store all the tables' table IDs.
                //~
                //~    For example, if you have a table with ID 0
                //~
                //~    |       |       |       |
                //~    | :---: | :---: | :---: |
                //~    |   1   |   2   |   3   |
                //~    |   5   |   6   |   7   |
                //~    |   0   |   0   |   0   |
                //~
                //~    and another table with ID 1
                //~
                //~    |       |       |
                //~    | :---: | :---: |
                //~    |   8   |   9   |
                //~
                //~    the concatenated table in a domain of size 5 looks like this:
                //~
                //~    |       |       |       |
                //~    | :---: | :---: | :---: |
                //~    |   1   |   2   |   3   |
                //~    |   5   |   6   |   7   |
                //~    |   0   |   0   |   0   |
                //~    |   8   |   9   |   0   |
                //~    |   0   |   0   |   0   |
                //~
                //~    with the table id vector:
                //~
                //~    | table id |
                //~    | :------: |
                //~    |    0     |
                //~    |    0     |
                //~    |    0     |
                //~    |    1     |
                //~    |    0     |
                //~
                //~    To do this, for each table:
                //~
                let mut lookup_table = vec![Vec::with_capacity(d1_size); max_table_width];
                let mut table_ids: Vec<F> = Vec::with_capacity(d1_size);

                let mut non_zero_table_id = false;
                let mut has_table_id_0_with_zero_entry = false;

                for table in lookup_tables.iter() {
                    let table_len = table.data[0].len();

                    if table.id != 0 {
                        non_zero_table_id = true;
                    } else {
                        has_table_id_0 = true;
                        if table.has_zero_entry() {
                            has_table_id_0_with_zero_entry = true;
                        }
                    }

                    //~~ - Update the corresponding entries in a table id vector (of size the domain as well)
                    //~    with the table ID of the table.
                    let table_id: F = i32_to_field(table.id);
                    table_ids.extend(repeat_n(table_id, table_len));

                    //~~ - Copy the entries from the table to new rows in the corresponding columns of the concatenated table.
                    for (i, col) in table.data.iter().enumerate() {
                        if col.len() != table_len {
                            return Err(LookupError::InconsistentTableLength);
                        }
                        lookup_table[i].extend(col);
                    }

                    //~~ - Fill in any unused columns with 0 (to match the dummy value)
                    for lookup_table in lookup_table.iter_mut().skip(table.data.len()) {
                        lookup_table.extend(repeat_n(F::zero(), table_len))
                    }
                }

                // If a table has ID 0, then it must have a zero entry.
                // This is for the dummy lookups to work.
                if has_table_id_0 && !has_table_id_0_with_zero_entry {
                    return Err(LookupError::TableIDZeroMustHaveZeroEntry);
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
                let dummy_lookup = JointLookup {
                    entry: vec![],
                    table_id: F::zero(),
                };

                //~ 6. Pad the end of the concatened table with the dummy value.
                lookup_table
                    .iter_mut()
                    .for_each(|col| col.extend(repeat_n(F::zero(), max_num_entries - col.len())));

                //~ 7. Pad the end of the table id vector with 0s.
                table_ids.extend(repeat_n(F::zero(), max_num_entries - table_ids.len()));

                //~ 8. pre-compute polynomial and evaluation form for the look up tables
                let mut lookup_table_polys: Vec<DP<F>> = vec![];
                let mut lookup_table8: Vec<E<F, D<F>>> = vec![];
                for col in lookup_table.into_iter() {
                    let poly = E::<F, D<F>>::from_vec_and_domain(col, domain.d1).interpolate();
                    let eval = poly.evaluate_over_domain_by_ref(domain.d8);
                    lookup_table_polys.push(poly);
                    lookup_table8.push(eval);
                }

                //~ 9. pre-compute polynomial and evaluation form for the table IDs,
                //~    only if a table with an ID different from zero was used.
                let (table_ids, table_ids8) = if non_zero_table_id {
                    let table_ids: DP<F> =
                        E::<F, D<F>>::from_vec_and_domain(table_ids, domain.d1).interpolate();
                    let table_ids8: E<F, D<F>> = table_ids.evaluate_over_domain_by_ref(domain.d8);
                    (Some(table_ids), Some(table_ids8))
                } else {
                    (None, None)
                };

                // store only the length of custom runtime tables in the index
                let runtime_tables =
                    runtime_tables.map(|rt| rt.into_iter().map(Into::into).collect());

                Ok(Some(Self {
                    lookup_selectors,
                    lookup_table8,
                    lookup_table: lookup_table_polys,
                    table_ids,
                    table_ids8,
                    runtime_selector,
                    configuration: LookupConfiguration {
                        lookup_used,
                        max_lookups_per_row: lookup_info.max_per_row as usize,
                        max_joint_size: lookup_info.max_joint_size,
                        runtime_tables,
                        runtime_table_offset,
                        dummy_lookup,
                    },
                }))
            }
        }
    }
}
