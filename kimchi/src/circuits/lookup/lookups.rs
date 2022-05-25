use crate::circuits::{
    domains::EvaluationDomains,
    gate::{CircuitGate, CurrOrNext, GateType},
    lookup::tables::{
        combine_table_entry, get_table, GateLookupTable, GatesLookupMaps, GatesLookupSpec,
        LookupTable, XOR_TABLE_ID,
    },
};
use ark_ff::{FftField, Field, One, Zero};
use ark_poly::{EvaluationDomain, Evaluations as E, Radix2EvaluationDomain as D};
use o1_utils::field_helpers::i32_to_field;
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::ops::{Mul, Neg};

type Evaluations<Field> = E<Field, D<Field>>;

fn max_lookups_per_row<F>(kinds: &[Vec<JointLookupSpec<F>>]) -> usize {
    kinds.iter().fold(0, |acc, x| std::cmp::max(x.len(), acc))
}

/// Specifies whether a constraint system uses joint lookups. Used to make sure we
/// squeeze the challenge `joint_combiner` when needed, and not when not needed.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum LookupsUsed {
    Single,
    Joint,
}

/// Describes the desired lookup configuration.
#[derive(Clone, Serialize, Deserialize)]
pub struct LookupInfo<F> {
    /// A single lookup constraint is a vector of lookup constraints to be applied at a row.
    /// This is a vector of all the kinds of lookup constraints in this configuration.
    pub kinds: Vec<Vec<JointLookupSpec<F>>>,
    /// A map from the kind of gate (and whether it is the current row or next row) to the lookup
    /// constraint (given as an index into `kinds`) that should be applied there, if any.
    pub kinds_map: HashMap<(GateType, CurrOrNext), usize>,
    /// A map from the kind of gate (and whether it is the current row or next row) to the lookup
    /// table that is used by the gate, if any.
    pub kinds_tables: HashMap<(GateType, CurrOrNext), GateLookupTable>,
    /// The maximum length of an element of `kinds`. This can be computed from `kinds`.
    pub max_per_row: usize,
    /// The maximum joint size of any joint lookup in a constraint in `kinds`. This can be computed from `kinds`.
    pub max_joint_size: u32,
    /// An empty vector.
    empty: Vec<JointLookupSpec<F>>,
}

impl<F: FftField> LookupInfo<F> {
    /// Create the default lookup configuration.
    pub fn create() -> Self {
        let (kinds, locations_with_tables): (Vec<_>, Vec<_>) = GateType::lookup_kinds::<F>();

        let GatesLookupMaps {
            gate_selector_map: kinds_map,
            gate_table_map: kinds_tables,
        } = GateType::lookup_kinds_map::<F>(locations_with_tables);

        let max_per_row = max_lookups_per_row(&kinds);

        LookupInfo {
            max_joint_size: kinds.iter().fold(0, |acc0, v| {
                v.iter()
                    .fold(acc0, |acc, j| std::cmp::max(acc, j.entry.len() as u32))
            }),

            kinds_map,
            kinds_tables,
            kinds,
            max_per_row,
            empty: vec![],
        }
    }

    /// Check what kind of lookups, if any, are used by this circuit.
    pub fn lookup_used(&self, gates: &[CircuitGate<F>]) -> Option<LookupsUsed> {
        let mut lookups_used = None;
        for g in gates.iter() {
            let typ = g.typ;

            for r in &[CurrOrNext::Curr, CurrOrNext::Next] {
                if let Some(v) = self.kinds_map.get(&(typ, *r)) {
                    if !self.kinds[*v].is_empty() {
                        return Some(LookupsUsed::Joint);
                    } else {
                        lookups_used = Some(LookupsUsed::Single);
                    }
                }
            }
        }
        lookups_used
    }

    /// Each entry in `kinds` has a corresponding selector polynomial that controls whether that
    /// lookup kind should be enforced at a given row. This computes those selector polynomials.
    pub fn selector_polynomials_and_tables(
        &self,
        domain: &EvaluationDomains<F>,
        gates: &[CircuitGate<F>],
    ) -> (Vec<Evaluations<F>>, Vec<LookupTable<F>>) {
        let n = domain.d1.size();
        let mut selector_values: Vec<_> = self.kinds.iter().map(|_| vec![F::zero(); n]).collect();
        let mut gate_tables = HashSet::new();

        // TODO: is take(n) useful here? I don't see why we need this
        for (i, gate) in gates.iter().enumerate().take(n) {
            let typ = gate.typ;

            if let Some(selector_index) = self.kinds_map.get(&(typ, CurrOrNext::Curr)) {
                selector_values[*selector_index][i] = F::one();
            }
            if let Some(selector_index) = self.kinds_map.get(&(typ, CurrOrNext::Next)) {
                selector_values[*selector_index][i + 1] = F::one();
            }

            if let Some(table_kind) = self.kinds_tables.get(&(typ, CurrOrNext::Curr)) {
                gate_tables.insert(*table_kind);
            }
            if let Some(table_kind) = self.kinds_tables.get(&(typ, CurrOrNext::Next)) {
                gate_tables.insert(*table_kind);
            }
        }

        // Actually, don't need to evaluate over domain 8 here.
        // TODO: so why do it :D?
        let selector_values8: Vec<_> = selector_values
            .into_iter()
            .map(|v| {
                E::<F, D<F>>::from_vec_and_domain(v, domain.d1)
                    .interpolate()
                    .evaluate_over_domain(domain.d8)
            })
            .collect();
        let res_tables: Vec<_> = gate_tables.into_iter().map(get_table).collect();
        (selector_values8, res_tables)
    }

    /// For each row in the circuit, which lookup-constraints should be enforced at that row.
    pub fn by_row<'a>(&'a self, gates: &[CircuitGate<F>]) -> Vec<&'a Vec<JointLookupSpec<F>>> {
        let mut kinds = vec![&self.empty; gates.len() + 1];
        for i in 0..gates.len() {
            let typ = gates[i].typ;

            if let Some(v) = self.kinds_map.get(&(typ, CurrOrNext::Curr)) {
                kinds[i] = &self.kinds[*v];
            }
            if let Some(v) = self.kinds_map.get(&(typ, CurrOrNext::Next)) {
                kinds[i + 1] = &self.kinds[*v];
            }
        }
        kinds
    }
}

/// A position in the circuit relative to a given row.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct LocalPosition {
    pub row: CurrOrNext,
    pub column: usize,
}

/// Look up a single value in a lookup table. The value may be computed as a linear
/// combination of locally-accessible cells.
#[derive(Clone, Serialize, Deserialize)]
pub struct SingleLookup<F> {
    /// Linear combination of local-positions
    pub value: Vec<(F, LocalPosition)>,
}

impl<F: Copy> SingleLookup<F> {
    /// Evaluate the linear combination specifying the lookup value to a field element.
    pub fn evaluate<K, G: Fn(LocalPosition) -> K>(&self, eval: G) -> K
    where
        K: Zero,
        K: Mul<F, Output = K>,
    {
        self.value
            .iter()
            .fold(K::zero(), |acc, (c, p)| acc + eval(*p) * *c)
    }
}

/// The table ID associated with a particular lookup
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum LookupTableID {
    /// Look up the value from the given fixed table ID
    Constant(i32),
    /// Look up the value in the table with ID given by the value in the witness column
    WitnessColumn(usize),
}

/// A spec for checking that the given vector belongs to a vector-valued lookup table.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct JointLookup<SingleLookup, LookupTableID> {
    /// The ID for the table associated with this lookup.
    /// Positive IDs are intended to be used for the fixed tables associated with individual gates,
    /// with negative IDs reserved for gates defined by the particular constraint system to avoid
    /// accidental collisions.
    pub table_id: LookupTableID,
    pub entry: Vec<SingleLookup>,
}

/// A spec for checking that the given vector belongs to a vector-valued lookup table, where the
/// components of the vector are computed from a linear combination of locally-accessible cells.
pub type JointLookupSpec<F> = JointLookup<SingleLookup<F>, LookupTableID>;

/// A concrete value or representation of a lookup.
pub type JointLookupValue<F> = JointLookup<F, F>;

impl<F: Zero + One + Clone + Neg<Output = F> + From<u64>> JointLookupValue<F> {
    // TODO: Support multiple tables
    /// Evaluate the combined value of a joint-lookup.
    pub fn evaluate(&self, joint_combiner: &F, table_id_combiner: &F) -> F {
        combine_table_entry(
            joint_combiner,
            table_id_combiner,
            self.entry.iter(),
            &self.table_id,
        )
    }
}

impl<F: Copy> JointLookup<SingleLookup<F>, LookupTableID> {
    /// Reduce linear combinations in the lookup entries to a single value, resolving local
    /// positions using the given function.
    pub fn reduce<K, G: Fn(LocalPosition) -> K>(&self, eval: &G) -> JointLookupValue<K>
    where
        K: Zero,
        K: Mul<F, Output = K>,
        K: Neg<Output = K>,
        K: From<u64>,
    {
        let table_id = match self.table_id {
            LookupTableID::Constant(table_id) => i32_to_field(table_id),
            LookupTableID::WitnessColumn(column) => eval(LocalPosition {
                row: CurrOrNext::Curr,
                column,
            }),
        };
        JointLookup {
            table_id,
            entry: self.entry.iter().map(|s| s.evaluate(eval)).collect(),
        }
    }

    /// Evaluate the combined value of a joint-lookup, resolving local positions using the given
    /// function.
    pub fn evaluate<K, G: Fn(LocalPosition) -> K>(
        &self,
        joint_combiner: &K,
        table_id_combiner: &K,
        eval: &G,
    ) -> K
    where
        K: Zero + One + Clone,
        K: Mul<F, Output = K>,
        K: Neg<Output = K>,
        K: From<u64>,
    {
        self.reduce(eval)
            .evaluate(joint_combiner, table_id_combiner)
    }
}

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
                    table_id: LookupTableID::Constant(XOR_TABLE_ID),
                    entry: vec![l(left), l(right), l(output)],
                }
            })
            .collect();

        let mut chacha_where = HashSet::new();
        use CurrOrNext::*;
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
                    table_id: LookupTableID::Constant(XOR_TABLE_ID),
                    entry: vec![x.clone(), x, SingleLookup { value: vec![] }],
                }
            })
            .collect();

        let mut chacha_final_where = HashSet::new();
        for r in &[Curr, Next] {
            chacha_final_where.insert((ChaChaFinal, *r));
        }

        let lookup_gate_pattern = (0..3)
            .map(|i| {
                // 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14
                // - i v - - - - - - - -  -  -  -  -
                // - - - i v - - - - - -  -  -  -  -
                // - - - - - i v - - - -  -  -  -  -
                let index = curr_row(2 * i + 1);
                let value = curr_row(2 * i + 2);
                let l = |loc: LocalPosition| SingleLookup {
                    value: vec![(F::one(), loc)],
                };
                JointLookup {
                    table_id: LookupTableID::WitnessColumn(0),
                    entry: vec![l(index), l(value)],
                }
            })
            .collect();
        let lookup_gate_where = HashSet::from([(Lookup, Curr)]);

        let lookups = [
            (chacha_pattern, chacha_where, Some(GateLookupTable::Xor)),
            (
                chacha_final_pattern,
                chacha_final_where,
                Some(GateLookupTable::Xor),
            ),
            (lookup_gate_pattern, lookup_gate_where, None),
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
