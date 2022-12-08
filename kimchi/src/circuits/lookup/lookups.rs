use crate::circuits::{
    domains::EvaluationDomains,
    gate::{CircuitGate, CurrOrNext, GateType},
    lookup::index::LookupSelectors,
    lookup::tables::{
        combine_table_entry, get_table, GateLookupTable, LookupTable, RANGE_CHECK_TABLE_ID,
        XOR_TABLE_ID,
    },
};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{EvaluationDomain, Evaluations as E, Radix2EvaluationDomain as D};
use o1_utils::field_helpers::i32_to_field;
use o1_utils::Two;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ops::{Mul, Neg};
use strum_macros::EnumIter;

type Evaluations<Field> = E<Field, D<Field>>;

fn max_lookups_per_row(kinds: &[LookupPattern]) -> usize {
    kinds
        .iter()
        .fold(0, |acc, x| std::cmp::max(x.max_lookups_per_row(), acc))
}

/// Specifies whether a constraint system uses joint lookups. Used to make sure we
/// squeeze the challenge `joint_combiner` when needed, and not when not needed.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum LookupsUsed {
    Single,
    Joint,
}

/// Describes the desired lookup configuration.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct LookupInfo {
    /// A single lookup constraint is a vector of lookup constraints to be applied at a row.
    /// This is a vector of all the kinds of lookup constraints in this configuration.
    pub kinds: Vec<LookupPattern>,
    /// The maximum length of an element of `kinds`. This can be computed from `kinds`.
    pub max_per_row: usize,
    /// The maximum joint size of any joint lookup in a constraint in `kinds`. This can be computed from `kinds`.
    pub max_joint_size: u32,
    /// True if runtime lookup tables are used.
    pub uses_runtime_tables: bool,
}

impl LookupInfo {
    /// Create the default lookup configuration.
    pub fn create(patterns: HashSet<LookupPattern>, uses_runtime_tables: bool) -> Self {
        let mut kinds: Vec<LookupPattern> = patterns.into_iter().collect();
        kinds.sort();

        let max_per_row = max_lookups_per_row(&kinds);

        LookupInfo {
            max_joint_size: kinds
                .iter()
                .fold(0, |acc, v| std::cmp::max(acc, v.max_joint_size())),

            kinds,
            max_per_row,
            uses_runtime_tables,
        }
    }

    pub fn create_from_gates<F: PrimeField>(
        gates: &[CircuitGate<F>],
        uses_runtime_tables: bool,
    ) -> Option<Self> {
        let mut kinds = HashSet::new();
        for g in gates.iter() {
            for r in &[CurrOrNext::Curr, CurrOrNext::Next] {
                if let Some(lookup_pattern) = LookupPattern::from_gate(g.typ, *r) {
                    kinds.insert(lookup_pattern);
                }
            }
        }
        if kinds.is_empty() {
            None
        } else {
            Some(Self::create(kinds, uses_runtime_tables))
        }
    }

    /// Check what kind of lookups, if any, are used by this circuit.
    pub fn lookup_used(&self) -> Option<LookupsUsed> {
        let mut lookups_used = None;
        for lookup_pattern in &self.kinds {
            if lookup_pattern.max_joint_size() > 1 {
                return Some(LookupsUsed::Joint);
            } else {
                lookups_used = Some(LookupsUsed::Single);
            }
        }
        lookups_used
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
        for kind in &self.kinds {
            selector_values[*kind] = Some(vec![F::zero(); n]);
        }

        let mut gate_tables = HashSet::new();

        let mut update_selector = |lookup_pattern, i| {
            let selector = selector_values[lookup_pattern]
                .as_mut()
                .expect(&*format!("has selector for {:?}", lookup_pattern));
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

#[derive(
    Copy, Clone, Serialize, Deserialize, Debug, EnumIter, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Enum)
)]
pub enum LookupPattern {
    Xor,
    ChaChaFinal,
    Lookup,
    RangeCheck,
    ForeignFieldMul,
}

impl LookupPattern {
    /// Returns the maximum number of lookups per row that are used by the pattern.
    pub fn max_lookups_per_row(&self) -> usize {
        match self {
            LookupPattern::Xor | LookupPattern::ChaChaFinal | LookupPattern::RangeCheck => 4,
            LookupPattern::Lookup => 3,
            LookupPattern::ForeignFieldMul => 2,
        }
    }

    /// Returns the maximum number of values that are used in any vector lookup in this pattern.
    pub fn max_joint_size(&self) -> u32 {
        match self {
            LookupPattern::Xor | LookupPattern::ChaChaFinal => 3,
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
            LookupPattern::ChaChaFinal => {
                let one_half = F::two().inverse().unwrap();
                let neg_one_half = -one_half;
                (0..4)
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
                (7..=8)
                    .map(|column| {
                        //   0 1 2 3 4 5 6 7 8 9 10 11 12 13 14
                        //   - - - - - - - L L - -  -  -  -  -
                        JointLookup {
                            table_id: LookupTableID::Constant(RANGE_CHECK_TABLE_ID),
                            entry: vec![SingleLookup {
                                value: vec![(F::one(), curr_row(column))],
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
            LookupPattern::Xor | LookupPattern::ChaChaFinal => Some(GateLookupTable::Xor),
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
            (ChaCha0 | ChaCha1 | ChaCha2, Curr | Next) => Some(LookupPattern::Xor),
            (ChaChaFinal, Curr | Next) => Some(LookupPattern::ChaChaFinal),
            (Lookup, Curr) => Some(LookupPattern::Lookup),
            (RangeCheck0, Curr) | (RangeCheck1, Curr | Next) | (Rot64, Curr) => {
                Some(LookupPattern::RangeCheck)
            }
            (ForeignFieldMul, Curr) => Some(LookupPattern::ForeignFieldMul),
            (Xor16, Curr) => Some(LookupPattern::Xor),
            _ => None,
        }
    }
}

impl GateType {
    /// Which lookup-patterns should be applied on which rows.
    /// Currently there is only the lookup pattern used in the `ChaCha` rows, and it
    /// is applied to each `ChaCha` row and its successor.
    ///
    /// See circuits/kimchi/src/polynomials/chacha.rs for an explanation of
    /// how these work.
    pub fn lookup_kinds() -> Vec<LookupPattern> {
        vec![
            LookupPattern::Xor,
            LookupPattern::ChaChaFinal,
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
