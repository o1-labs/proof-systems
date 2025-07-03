use super::runtime_tables::{RuntimeTableCfg, RuntimeTableSpec};
use crate::circuits::{
    domains::EvaluationDomains,
    gate::CircuitGate,
    lookup::{
        constraints::LookupConfiguration,
        lookups::{LookupInfo, LookupPattern},
        tables::LookupTable,
    },
};
use ark_ff::{FftField, PrimeField};
use ark_poly::{
    univariate::DensePolynomial as DP, EvaluationDomain, Evaluations as E,
    Radix2EvaluationDomain as D,
};
use core::iter;
use itertools::repeat_n;
use o1_utils::field_helpers::i32_to_field;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

/// Represents an error found when computing the lookup constraint system
#[derive(Debug, Error, Clone)]
pub enum LookupError {
    #[error("One of the lookup tables has columns of different lengths")]
    InconsistentTableLength,
    #[error("The combined lookup table is larger than allowed by the domain size. Observed: {length}, expected: {maximum_allowed}")]
    LookupTableTooLong {
        length: usize,
        maximum_allowed: usize,
    },
    #[error("The table with id 0 must have an entry of all zeros")]
    TableIDZeroMustHaveZeroEntry,
    #[error("Cannot create a combined table since ids for sub-tables are colliding. The collision type is: {collision_type}")]
    LookupTableIdCollision { collision_type: String },
}

/// Lookup selectors
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct LookupSelectors<T> {
    /// XOR pattern lookup selector
    pub xor: Option<T>,
    /// Lookup pattern lookup selector
    pub lookup: Option<T>,
    /// Range check pattern lookup selector
    pub range_check: Option<T>,
    /// Foreign field multiplication pattern lookup selector
    pub ffmul: Option<T>,
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
struct LookupSelectorsSerdeAs<F: FftField> {
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub xor: Option<E<F, D<F>>>,
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub lookup: Option<E<F, D<F>>>,
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub range_check: Option<E<F, D<F>>>,
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub ffmul: Option<E<F, D<F>>>,
}

impl<F: FftField> serde_with::SerializeAs<LookupSelectors<E<F, D<F>>>>
    for LookupSelectorsSerdeAs<F>
{
    fn serialize_as<S>(val: &LookupSelectors<E<F, D<F>>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let repr = LookupSelectorsSerdeAs {
            xor: val.xor.clone(),
            lookup: val.lookup.clone(),
            range_check: val.range_check.clone(),
            ffmul: val.ffmul.clone(),
        };
        repr.serialize(serializer)
    }
}

impl<'de, F: FftField> serde_with::DeserializeAs<'de, LookupSelectors<E<F, D<F>>>>
    for LookupSelectorsSerdeAs<F>
{
    fn deserialize_as<Dz>(deserializer: Dz) -> Result<LookupSelectors<E<F, D<F>>>, Dz::Error>
    where
        Dz: serde::Deserializer<'de>,
    {
        let LookupSelectorsSerdeAs {
            xor,
            lookup,
            range_check,
            ffmul,
        } = LookupSelectorsSerdeAs::deserialize(deserializer)?;
        Ok(LookupSelectors {
            xor,
            lookup,
            range_check,
            ffmul,
        })
    }
}

impl<T> core::ops::Index<LookupPattern> for LookupSelectors<T> {
    type Output = Option<T>;

    fn index(&self, index: LookupPattern) -> &Self::Output {
        match index {
            LookupPattern::Xor => &self.xor,
            LookupPattern::Lookup => &self.lookup,
            LookupPattern::RangeCheck => &self.range_check,
            LookupPattern::ForeignFieldMul => &self.ffmul,
        }
    }
}

impl<T> core::ops::IndexMut<LookupPattern> for LookupSelectors<T> {
    fn index_mut(&mut self, index: LookupPattern) -> &mut Self::Output {
        match index {
            LookupPattern::Xor => &mut self.xor,
            LookupPattern::Lookup => &mut self.lookup,
            LookupPattern::RangeCheck => &mut self.range_check,
            LookupPattern::ForeignFieldMul => &mut self.ffmul,
        }
    }
}

impl<T> LookupSelectors<T> {
    pub fn map<U, F: Fn(T) -> U>(self, f: F) -> LookupSelectors<U> {
        let LookupSelectors {
            xor,
            lookup,
            range_check,
            ffmul,
        } = self;
        // This closure isn't really redundant -- it shields the parameter from a copy -- but
        // clippy isn't smart enough to figure that out..
        #[allow(clippy::redundant_closure)]
        let f = |x| f(x);
        LookupSelectors {
            xor: xor.map(f),
            lookup: lookup.map(f),
            range_check: range_check.map(f),
            ffmul: ffmul.map(f),
        }
    }

    pub fn as_ref(&self) -> LookupSelectors<&T> {
        LookupSelectors {
            xor: self.xor.as_ref(),
            lookup: self.lookup.as_ref(),
            range_check: self.range_check.as_ref(),
            ffmul: self.ffmul.as_ref(),
        }
    }
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
    #[serde_as(as = "LookupSelectorsSerdeAs<F>")]
    pub lookup_selectors: LookupSelectors<E<F, D<F>>>,

    /// An optional runtime table selector. It is 0 everywhere,
    /// except at the rows where the runtime tables apply.
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub runtime_selector: Option<E<F, D<F>>>,

    /// Optional runtime tables, listed as tuples `(length, id)`.
    pub runtime_tables: Option<Vec<RuntimeTableSpec>>,

    /// The offset of the runtime table within the concatenated table
    pub runtime_table_offset: Option<usize>,

    /// Configuration for the lookup constraint.
    #[serde(bound = "LookupConfiguration<F>: Serialize + DeserializeOwned")]
    pub configuration: LookupConfiguration<F>,
}

impl<F: PrimeField> LookupConstraintSystem<F> {
    /// Create the `LookupConstraintSystem`.
    ///
    /// # Errors
    ///
    /// Will give error if inputs validation do not match.
    pub fn create(
        gates: &[CircuitGate<F>],
        fixed_lookup_tables: Vec<LookupTable<F>>,
        runtime_tables: Option<Vec<RuntimeTableCfg<F>>>,
        domain: &EvaluationDomains<F>,
        zk_rows: usize,
    ) -> Result<Option<Self>, LookupError> {
        //~ 1. If no lookup is used in the circuit, do not create a lookup index
        match LookupInfo::create_from_gates(gates, runtime_tables.is_some()) {
            None => Ok(None),
            Some(lookup_info) => {
                let d1_size = domain.d1.size();

                // The maximum number of entries that can be provided across all tables.
                // Since we do not assert the lookup constraint on the final `zk_rows` rows, and
                // because the row before is used to assert that the lookup argument's final
                // product is 1, we cannot use those rows to store any values.
                let max_num_entries = d1_size - zk_rows - 1;

                //~ 2. Get the lookup selectors and lookup tables that are specified implicitly
                // by the lookup gates.
                let (lookup_selectors, gate_lookup_tables) =
                    lookup_info.selector_polynomials_and_tables(domain, gates);

                // Checks whether an iterator contains any duplicates, and if yes, raises
                // a corresponding LookupTableIdCollision error.
                fn check_id_duplicates<'a, I: Iterator<Item = &'a i32>>(
                    iter: I,
                    msg: &str,
                ) -> Result<(), LookupError> {
                    use itertools::Itertools;
                    match iter.duplicates().collect::<Vec<_>>() {
                        dups if !dups.is_empty() => Err(LookupError::LookupTableIdCollision {
                            collision_type: format!("{}: {:?}", msg, dups).to_string(),
                        }),
                        _ => Ok(()),
                    }
                }

                // If there is a gate using a lookup table, this table must not be added
                // explicitly to the constraint system.
                let fixed_gate_joint_ids: Vec<i32> = fixed_lookup_tables
                    .iter()
                    .map(|lt| lt.id)
                    .chain(gate_lookup_tables.iter().map(|lt| lt.id))
                    .collect();
                check_id_duplicates(
                    fixed_gate_joint_ids.iter(),
                    "duplicates between fixed given and fixed from-gate tables",
                )?;

                //~ 3. Concatenate explicit runtime lookup tables with the ones (implicitly) used by gates.
                let mut lookup_tables: Vec<_> = fixed_lookup_tables
                    .into_iter()
                    .chain(gate_lookup_tables)
                    .collect();

                let mut has_table_id_0 = false;

                // if we are using runtime tables
                let (runtime_table_offset, runtime_selector) =
                    if let Some(runtime_tables) = &runtime_tables {
                        // Check duplicates in runtime table ids
                        let runtime_tables_ids: Vec<i32> =
                            runtime_tables.iter().map(|rt| rt.id).collect();
                        check_id_duplicates(runtime_tables_ids.iter(), "runtime table duplicates")?;
                        // Runtime table IDs /may/ collide with lookup
                        // table IDs, so we intentionally do not perform another potential check.

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

                            // although the last zk_rows are fine
                            for e in evals.iter_mut().rev().take(zk_rows) {
                                *e = F::zero();
                            }

                            E::<F, D<F>>::from_vec_and_domain(evals, domain.d1)
                                .interpolate()
                                .evaluate_over_domain(domain.d8)
                        };

                        // create fixed tables for indexing the runtime tables
                        for runtime_table in runtime_tables {
                            let (id, first_column) =
                                (runtime_table.id, runtime_table.first_column.clone());

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
                    .map(|table| table.width())
                    .max()
                    .unwrap_or(0);

                let max_table_width = core::cmp::max(
                    max_table_width,
                    lookup_info.max_joint_size.try_into().unwrap(),
                );

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

                for table in &lookup_tables {
                    let table_len = table.len();

                    if table.id == 0 {
                        has_table_id_0 = true;
                        if table.has_zero_entry() {
                            has_table_id_0_with_zero_entry = true;
                        }
                    } else {
                        non_zero_table_id = true;
                    }

                    //~~ * Update the corresponding entries in a table id vector (of size the domain as well)
                    //~    with the table ID of the table.
                    let table_id: F = i32_to_field(table.id);
                    table_ids.extend(repeat_n(table_id, table_len));

                    //~~ * Copy the entries from the table to new rows in the corresponding columns of the concatenated table.
                    for (i, col) in table.data.iter().enumerate() {
                        // See GH issue: https://github.com/MinaProtocol/mina/issues/14097
                        if col.len() != table_len {
                            return Err(LookupError::InconsistentTableLength);
                        }
                        lookup_table[i].extend(col);
                    }

                    //~~ * Fill in any unused columns with 0 (to match the dummy value)
                    for lookup_table in lookup_table.iter_mut().skip(table.width()) {
                        lookup_table.extend(repeat_n(F::zero(), table_len));
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

                //~ 6. Pad the end of the concatened table with the dummy value.
                //     By padding with 0, we constraint the table with ID 0 to
                //     have a zero entry.
                //     This is for the rows which do not have a lookup selector,
                //     see ../../../../book/src/kimchi/lookup.md.
                //     The zero entry row is contained in the built-in XOR table.
                //     An error is raised when creating the CS if a user-defined
                //     table is defined with ID 0 without a row contain zeroes.
                //     If no such table is used, we artificially add a dummy
                //     table with ID 0 and a row containing only zeroes.
                lookup_table
                    .iter_mut()
                    .for_each(|col| col.extend(repeat_n(F::zero(), max_num_entries - col.len())));

                //~ 7. Pad the end of the table id vector with 0s.
                table_ids.extend(repeat_n(F::zero(), max_num_entries - table_ids.len()));

                //~ 8. pre-compute polynomial and evaluation form for the look up tables
                let mut lookup_table_polys: Vec<DP<F>> = vec![];
                let mut lookup_table8: Vec<E<F, D<F>>> = vec![];
                for col in lookup_table {
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

                let configuration = LookupConfiguration::new(lookup_info);

                Ok(Some(Self {
                    lookup_selectors,
                    lookup_table8,
                    lookup_table: lookup_table_polys,
                    table_ids,
                    table_ids8,
                    runtime_selector,
                    runtime_tables,
                    runtime_table_offset,
                    configuration,
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{LookupError, LookupTable, RuntimeTableCfg};
    use crate::{
        circuits::{
            constraints::ConstraintSystem, gate::CircuitGate, lookup::tables::xor,
            polynomials::range_check,
        },
        error::SetupError,
    };
    use mina_curves::pasta::Fp;

    #[test]
    fn test_colliding_table_ids() {
        let (_, gates) = CircuitGate::<Fp>::create_multi_range_check(0);
        let collision_id: i32 = 5;

        let cs = ConstraintSystem::<Fp>::create(gates.clone())
            .lookup(vec![range_check::gadget::lookup_table()])
            .build();

        assert!(
            matches!(
                cs,
                Err(SetupError::LookupCreation(
                    LookupError::LookupTableIdCollision { .. }
                ))
            ),
            "LookupConstraintSystem::create(...) must fail due to range table passed twice"
        );

        let cs = ConstraintSystem::<Fp>::create(gates.clone())
            .lookup(vec![xor::xor_table()])
            .build();

        assert!(
            cs.is_ok(),
            "LookupConstraintSystem::create(...) must succeed, no duplicates exist"
        );

        let cs = ConstraintSystem::<Fp>::create(gates.clone())
            .lookup(vec![
                LookupTable {
                    id: collision_id,
                    data: vec![vec![From::from(0); 16]],
                },
                LookupTable {
                    id: collision_id,
                    data: vec![vec![From::from(1); 16]],
                },
            ])
            .build();

        assert!(
            matches!(
                cs,
                Err(SetupError::LookupCreation(
                    LookupError::LookupTableIdCollision { .. }
                ))
            ),
            "LookupConstraintSystem::create(...) must fail, collision in fixed ids"
        );

        let cs = ConstraintSystem::<Fp>::create(gates.clone())
            .runtime(Some(vec![
                RuntimeTableCfg {
                    id: collision_id,
                    first_column: vec![From::from(0); 16],
                },
                RuntimeTableCfg {
                    id: collision_id,
                    first_column: vec![From::from(1); 16],
                },
            ]))
            .build();

        assert!(
            matches!(
                cs,
                Err(SetupError::LookupCreation(
                    LookupError::LookupTableIdCollision { .. }
                ))
            ),
            "LookupConstraintSystem::create(...) must fail, collision in runtime ids"
        );

        let cs = ConstraintSystem::<Fp>::create(gates.clone())
            .lookup(vec![LookupTable {
                id: collision_id,
                data: vec![vec![From::from(0); 16]],
            }])
            .runtime(Some(vec![RuntimeTableCfg {
                id: collision_id,
                first_column: vec![From::from(1); 16],
            }]))
            .build();

        assert!(
            cs.is_ok(),
            "LookupConstraintSystem::create(...) must not fail when there is a collision between runtime and lookup ids"
        );
    }
}
