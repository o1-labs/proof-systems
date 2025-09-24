use crate::circuits::{
    domains::EvaluationDomains,
    gate::{CircuitGate, CurrOrNext, GateType},
    lookup::{
        index::LookupSelectors,
        tables::{
            combine_table_entry, get_table, GateLookupTable, LookupTable, RANGE_CHECK_TABLE_ID,
            XOR_TABLE_ID,
        },
    },
};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{EvaluationDomain, Evaluations as E, Radix2EvaluationDomain as D};
use o1_utils::field_helpers::i32_to_field;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    ops::{Mul, Neg},
};
use strum_macros::EnumIter;

type Evaluations<Field> = E<Field, D<Field>>;

//~ Lookups patterns are extremely flexible and can be configured in a number of ways.
//~ Every type of lookup is a JointLookup -- to create a single lookup your create a
//~ JointLookup that contains one SingleLookup.
//~
//~ Generally, the patterns of lookups possible are
//~   * Multiple lookups per row
//~    `JointLookup { }, ...,  JointLookup { }`
//~   * Multiple values in each lookup (via joining, think of it like a tuple)
//~    `JoinLookup { SingleLookup { }, ..., SingleLookup { } }`
//~   * Multiple columns combined in linear combination to create each value
//~    `JointLookup { SingleLookup { value: vec![(scale1, col1), ..., (scale2, col2)] } }`
//~   * Any combination of these

fn max_lookups_per_row(kinds: LookupPatterns) -> usize {
    kinds
        .into_iter()
        .fold(0, |acc, x| core::cmp::max(x.max_lookups_per_row(), acc))
}

/// Flags for each of the hard-coded lookup patterns.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)
)]
#[cfg_attr(feature = "wasm_types", wasm_bindgen::prelude::wasm_bindgen)]
#[cfg_attr(feature = "napi_types", napi_derive::napi)]
pub struct LookupPatterns {
    pub xor: bool,
    pub lookup: bool,
    pub range_check: bool,
    pub foreign_field_mul: bool,
}

impl IntoIterator for LookupPatterns {
    type Item = LookupPattern;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        // Destructor pattern to make sure we add new lookup patterns.
        let LookupPatterns {
            xor,
            lookup,
            range_check,
            foreign_field_mul,
        } = self;

        let mut patterns = Vec::with_capacity(5);

        if xor {
            patterns.push(LookupPattern::Xor)
        }
        if lookup {
            patterns.push(LookupPattern::Lookup)
        }
        if range_check {
            patterns.push(LookupPattern::RangeCheck)
        }
        if foreign_field_mul {
            patterns.push(LookupPattern::ForeignFieldMul)
        }
        patterns.into_iter()
    }
}

impl core::ops::Index<LookupPattern> for LookupPatterns {
    type Output = bool;

    fn index(&self, index: LookupPattern) -> &Self::Output {
        match index {
            LookupPattern::Xor => &self.xor,
            LookupPattern::Lookup => &self.lookup,
            LookupPattern::RangeCheck => &self.range_check,
            LookupPattern::ForeignFieldMul => &self.foreign_field_mul,
        }
    }
}

impl core::ops::IndexMut<LookupPattern> for LookupPatterns {
    fn index_mut(&mut self, index: LookupPattern) -> &mut Self::Output {
        match index {
            LookupPattern::Xor => &mut self.xor,
            LookupPattern::Lookup => &mut self.lookup,
            LookupPattern::RangeCheck => &mut self.range_check,
            LookupPattern::ForeignFieldMul => &mut self.foreign_field_mul,
        }
    }
}

impl LookupPatterns {
    pub fn from_gates<F: PrimeField>(gates: &[CircuitGate<F>]) -> LookupPatterns {
        let mut kinds = LookupPatterns::default();
        for g in gates.iter() {
            for r in &[CurrOrNext::Curr, CurrOrNext::Next] {
                if let Some(lookup_pattern) = LookupPattern::from_gate(g.typ, *r) {
                    kinds[lookup_pattern] = true;
                }
            }
        }
        kinds
    }

    /// Check what kind of lookups, if any, are used by this circuit.
    pub fn joint_lookups_used(&self) -> bool {
        for lookup_pattern in *self {
            if lookup_pattern.max_joint_size() > 1 {
                return true;
            }
        }
        false
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)
)]
#[cfg_attr(feature = "wasm_types", wasm_bindgen::prelude::wasm_bindgen)]
#[cfg_attr(feature = "napi_types", napi_derive::napi)]
pub struct LookupFeatures {
    /// A single lookup constraint is a vector of lookup constraints to be applied at a row.
    pub patterns: LookupPatterns,
    /// Whether joint lookups are used
    pub joint_lookup_used: bool,
    /// True if runtime lookup tables are used.
    pub uses_runtime_tables: bool,
}

impl LookupFeatures {
    pub fn from_gates<F: PrimeField>(gates: &[CircuitGate<F>], uses_runtime_tables: bool) -> Self {
        let patterns = LookupPatterns::from_gates(gates);

        let joint_lookup_used = patterns.joint_lookups_used();

        LookupFeatures {
            patterns,
            uses_runtime_tables,
            joint_lookup_used,
        }
    }
}

/// Describes the desired lookup configuration.
#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "wasm_types", wasm_bindgen::prelude::wasm_bindgen)]
#[cfg_attr(feature = "napi_types", napi_derive::napi)]
pub struct LookupInfo {
    /// The maximum length of an element of `kinds`. This can be computed from `kinds`.
    pub max_per_row: usize,
    /// The maximum joint size of any joint lookup in a constraint in `kinds`. This can be computed from `kinds`.
    pub max_joint_size: u32,
    /// The features enabled for this lookup configuration
    pub features: LookupFeatures,
}

impl LookupInfo {
    /// Create the default lookup configuration.
    pub fn create(features: LookupFeatures) -> Self {
        let max_per_row = max_lookups_per_row(features.patterns);

        LookupInfo {
            max_joint_size: features
                .patterns
                .into_iter()
                .fold(0, |acc, v| core::cmp::max(acc, v.max_joint_size())),
            max_per_row,
            features,
        }
    }

    pub fn create_from_gates<F: PrimeField>(
        gates: &[CircuitGate<F>],
        uses_runtime_tables: bool,
    ) -> Option<Self> {
        let features = LookupFeatures::from_gates(gates, uses_runtime_tables);

        if features.patterns == LookupPatterns::default() {
            None
        } else {
            Some(Self::create(features))
        }
    }

    /// Each entry in `kinds` has a corresponding selector polynomial that controls whether that
    /// lookup kind should be enforced at a given row. This computes those selector polynomials.
    pub fn selector_polynomials_and_tables<F: PrimeField>(
        &self,
        domain: &EvaluationDomains<F>,
        gates: &[CircuitGate<F>],
    ) -> (LookupSelectors<Evaluations<F>>, Vec<LookupTable<F>>) {
        let n = domain.d1.size();

        let mut selector_values = LookupSelectors::default();
        for kind in self.features.patterns {
            selector_values[kind] = Some(vec![F::zero(); n]);
        }

        let mut gate_tables = HashSet::new();

        let mut update_selector = |lookup_pattern, i| {
            let selector = selector_values[lookup_pattern]
                .as_mut()
                .unwrap_or_else(|| panic!("has selector for {lookup_pattern:?}"));
            selector[i] = F::one();
        };

        // TODO: is take(n) useful here? I don't see why we need this
        for (i, gate) in gates.iter().enumerate().take(n) {
            let typ = gate.typ;

            if let Some(lookup_pattern) = LookupPattern::from_gate(typ, CurrOrNext::Curr) {
                update_selector(lookup_pattern, i);
                if let Some(table_kind) = lookup_pattern.table() {
                    gate_tables.insert(table_kind);
                }
            }
            if let Some(lookup_pattern) = LookupPattern::from_gate(typ, CurrOrNext::Next) {
                update_selector(lookup_pattern, i + 1);
                if let Some(table_kind) = lookup_pattern.table() {
                    gate_tables.insert(table_kind);
                }
            }
        }

        // Actually, don't need to evaluate over domain 8 here.
        // TODO: so why do it :D?
        let selector_values8: LookupSelectors<_> = selector_values.map(|v| {
            E::<F, D<F>>::from_vec_and_domain(v, domain.d1)
                .interpolate()
                .evaluate_over_domain(domain.d8)
        });
        let res_tables: Vec<_> = gate_tables.into_iter().map(get_table).collect();
        (selector_values8, res_tables)
    }

    /// For each row in the circuit, which lookup-constraints should be enforced at that row.
    pub fn by_row<F: PrimeField>(&self, gates: &[CircuitGate<F>]) -> Vec<Vec<JointLookupSpec<F>>> {
        let mut kinds = vec![vec![]; gates.len() + 1];
        for i in 0..gates.len() {
            let typ = gates[i].typ;

            if let Some(lookup_pattern) = LookupPattern::from_gate(typ, CurrOrNext::Curr) {
                kinds[i] = lookup_pattern.lookups();
            }
            if let Some(lookup_pattern) = LookupPattern::from_gate(typ, CurrOrNext::Next) {
                kinds[i + 1] = lookup_pattern.lookups();
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

#[derive(
    Copy, Clone, Serialize, Deserialize, Debug, EnumIter, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Enum)
)]
pub enum LookupPattern {
    Xor,
    Lookup,
    RangeCheck,
    ForeignFieldMul,
}

impl LookupPattern {
    /// Returns the maximum number of lookups per row that are used by the pattern.
    pub fn max_lookups_per_row(&self) -> usize {
        match self {
            LookupPattern::Xor | LookupPattern::RangeCheck | LookupPattern::ForeignFieldMul => 4,
            LookupPattern::Lookup => 3,
        }
    }

    /// Returns the maximum number of values that are used in any vector lookup in this pattern.
    pub fn max_joint_size(&self) -> u32 {
        match self {
            LookupPattern::Xor => 3,
            LookupPattern::Lookup => 2,
            LookupPattern::ForeignFieldMul | LookupPattern::RangeCheck => 1,
        }
    }

    /// Returns the layout of the lookups used by this pattern.
    ///
    /// # Panics
    ///
    /// Will panic if `multiplicative inverse` operation fails.
    pub fn lookups<F: Field>(&self) -> Vec<JointLookupSpec<F>> {
        let curr_row = |column| LocalPosition {
            row: CurrOrNext::Curr,
            column,
        };
        match self {
            LookupPattern::Xor => {
                (0..4)
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
                    .collect()
            }
            LookupPattern::Lookup => {
                (0..3)
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
                    .collect()
            }
            LookupPattern::RangeCheck => {
                (3..=6)
                    .map(|column| {
                        //   0 1 2 3 4 5 6 7 8 9 10 11 12 13 14
                        //   - - - L L L L - - - -  -  -  -  -
                        JointLookup {
                            table_id: LookupTableID::Constant(RANGE_CHECK_TABLE_ID),
                            entry: vec![SingleLookup {
                                value: vec![(F::one(), curr_row(column))],
                            }],
                        }
                    })
                    .collect()
            }
            LookupPattern::ForeignFieldMul => {
                (7..=10)
                    .map(|col| {
                        // curr and next (in next carry0 is in w(7))
                        //   0 1 2 3 4 5 6 7 8 9 10 11 12 13 14
                        //   - - - - - - - L L L L  -  -  -  -
                        //    * Constrain w(7), w(8), w(9), w(10) to 12-bits
                        JointLookup {
                            table_id: LookupTableID::Constant(RANGE_CHECK_TABLE_ID),
                            entry: vec![SingleLookup {
                                value: vec![(F::one(), curr_row(col))],
                            }],
                        }
                    })
                    .collect()
            }
        }
    }

    /// Returns the lookup table used by the pattern, or `None` if no specific table is rqeuired.
    pub fn table(&self) -> Option<GateLookupTable> {
        match self {
            LookupPattern::Xor => Some(GateLookupTable::Xor),
            LookupPattern::Lookup => None,
            LookupPattern::RangeCheck => Some(GateLookupTable::RangeCheck),
            LookupPattern::ForeignFieldMul => Some(GateLookupTable::RangeCheck),
        }
    }

    /// Returns the lookup pattern used by a [`GateType`] on a given row (current or next).
    pub fn from_gate(gate_type: GateType, curr_or_next: CurrOrNext) -> Option<Self> {
        use CurrOrNext::{Curr, Next};
        use GateType::*;
        match (gate_type, curr_or_next) {
            (Lookup, Curr) => Some(LookupPattern::Lookup),
            (RangeCheck0, Curr) | (RangeCheck1, Curr | Next) | (Rot64, Curr) => {
                Some(LookupPattern::RangeCheck)
            }
            (ForeignFieldMul, Curr | Next) => Some(LookupPattern::ForeignFieldMul),
            (Xor16, Curr) => Some(LookupPattern::Xor),
            _ => None,
        }
    }
}

impl GateType {
    /// Which lookup-patterns should be applied on which rows.
    pub fn lookup_kinds() -> Vec<LookupPattern> {
        vec![
            LookupPattern::Xor,
            LookupPattern::Lookup,
            LookupPattern::RangeCheck,
            LookupPattern::ForeignFieldMul,
        ]
    }
}

#[test]
fn lookup_pattern_constants_correct() {
    use strum::IntoEnumIterator;

    for pat in LookupPattern::iter() {
        let lookups = pat.lookups::<mina_curves::pasta::Fp>();
        let max_joint_size = lookups
            .iter()
            .map(|lookup| lookup.entry.len())
            .max()
            .unwrap_or(0);
        // NB: We include pat in the assertions so that the test will print out which pattern failed
        assert_eq!((pat, pat.max_lookups_per_row()), (pat, lookups.len()));
        assert_eq!((pat, pat.max_joint_size()), (pat, max_joint_size as u32));
    }
}

#[cfg(feature = "wasm_types")]
pub mod wasm {
    use super::*;

    #[wasm_bindgen::prelude::wasm_bindgen]
    impl LookupPatterns {
        #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
        pub fn new(
            xor: bool,
            lookup: bool,
            range_check: bool,
            foreign_field_mul: bool,
        ) -> LookupPatterns {
            LookupPatterns {
                xor,
                lookup,
                range_check,
                foreign_field_mul,
            }
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen]
    impl LookupFeatures {
        #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
        pub fn new(
            patterns: LookupPatterns,
            joint_lookup_used: bool,
            uses_runtime_tables: bool,
        ) -> LookupFeatures {
            LookupFeatures {
                patterns,
                joint_lookup_used,
                uses_runtime_tables,
            }
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen]
    impl LookupInfo {
        #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
        pub fn new(
            max_per_row: usize,
            max_joint_size: u32,
            features: LookupFeatures,
        ) -> LookupInfo {
            LookupInfo {
                max_per_row,
                max_joint_size,
                features,
            }
        }
    }
}

#[cfg(feature = "napi_types")]
pub mod native {
    use super::*;

    impl LookupPatterns {
        #[napi_derive::napi]
        pub fn new(
            xor: bool,
            lookup: bool,
            range_check: bool,
            foreign_field_mul: bool,
        ) -> LookupPatterns {
            LookupPatterns {
                xor,
                lookup,
                range_check,
                foreign_field_mul,
            }
        }
    }

    impl LookupFeatures {
        #[napi_derive::napi]
        pub fn new(
            patterns: LookupPatterns,
            joint_lookup_used: bool,
            uses_runtime_tables: bool,
        ) -> LookupFeatures {
            LookupFeatures {
                patterns,
                joint_lookup_used,
                uses_runtime_tables,
            }
        }
    }

    impl LookupInfo {
        #[napi_derive::napi]
        pub fn new(
            max_per_row: usize,
            max_joint_size: u32,
            features: LookupFeatures,
        ) -> LookupInfo {
            LookupInfo {
                max_per_row,
                max_joint_size,
                features,
            }
        }
    }
}
