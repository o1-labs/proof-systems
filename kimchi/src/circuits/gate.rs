//! This module implements Plonk constraint gate primitive.

use crate::circuits::{constraints::ConstraintSystem, domains::EvaluationDomains, wires::*};
use ark_ff::bytes::ToBytes;
use ark_ff::{FftField, Field};
use ark_poly::{Evaluations as E, Radix2EvaluationDomain as D};
use num_traits::cast::ToPrimitive;
use o1_utils::hasher::CryptoDigest;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::io::{Result as IoResult, Write};

type Evaluations<Field> = E<Field, D<Field>>;

/// A row accessible from a given row, corresponds to the fact that we open all polynomials
/// at `zeta` **and** `omega * zeta`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Enum)
)]
#[cfg_attr(feature = "wasm_types", wasm_bindgen::prelude::wasm_bindgen)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum CurrOrNext {
    Curr,
    Next,
}

impl CurrOrNext {
    /// Compute the offset corresponding to the `CurrOrNext` value.
    /// - `Curr.shift() == 0`
    /// - `Next.shift() == 1`
    pub fn shift(&self) -> usize {
        match self {
            CurrOrNext::Curr => 0,
            CurrOrNext::Next => 1,
        }
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

/// Let's say we want to do a lookup in a "vector-valued" table `T: Vec<[F; n]>` (here I
/// am using `[F; n]` to model a vector of length `n`).
///
/// For `i < n`, define `T_i := T.map(|t| t[i]).collect()`. In other words, the table
/// obtained by taking the `ith` entry of each element of `T`.
///
/// In the lookup argument, we perform lookups in `T` by sampling a random challenge
/// `joint_combiner`, and computing a "combined" lookup table `sum_{i < n} joint_combiner^i T_i`.
///
/// To check a vector's membership in this lookup table, we combine the values in that vector
/// analogously using `joint_combiner`.
///
/// This function computes that combined value.
pub fn combine_table_entry<'a, F: Field, I: DoubleEndedIterator<Item = &'a F>>(
    joint_combiner: F,
    v: I,
) -> F {
    v.rev().fold(F::zero(), |acc, x| joint_combiner * acc + x)
}

impl<F: Field> SingleLookup<F> {
    /// Evaluate the linear combination specifying the lookup value to a field element.
    pub fn evaluate<G: Fn(LocalPosition) -> F>(&self, eval: G) -> F {
        self.value
            .iter()
            .fold(F::zero(), |acc, (c, p)| acc + *c * eval(*p))
    }
}

/// A spec for checking that the given vector belongs to a vector-valued lookup table.
#[derive(Clone, Serialize, Deserialize)]
pub struct JointLookup<F> {
    pub table_id: usize,
    pub entry: Vec<SingleLookup<F>>,
}

impl<F: Field> JointLookup<F> {
    // TODO: Support multiple tables
    /// Evaluate the combined value of a joint-lookup.
    pub fn evaluate<G: Fn(LocalPosition) -> F>(&self, joint_combiner: F, eval: &G) -> F {
        let mut res = F::zero();
        let mut c = F::one();
        for s in self.entry.iter() {
            res += c * s.evaluate(eval);
            c *= joint_combiner;
        }
        res
    }
}

/// The different types of gates the system supports.
/// Note that all the gates are mutually exclusive:
/// they cannot be used at the same time on single row.
/// If we were ever to support this feature, we would have to make sure
/// not to re-use powers of alpha across constraints.
#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    FromPrimitive,
    ToPrimitive,
    Serialize,
    Deserialize,
    Eq,
    Hash,
    PartialOrd,
    Ord,
)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Enum)
)]
#[cfg_attr(feature = "wasm_types", wasm_bindgen::prelude::wasm_bindgen)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum GateType {
    /// Zero gate
    Zero = 0,
    /// Generic arithmetic gate
    Generic = 1,
    /// Poseidon permutation gate
    Poseidon = 2,
    /// Complete EC addition in Affine form
    CompleteAdd = 3,
    /// EC variable base scalar multiplication
    VarBaseMul = 4,
    /// EC variable base scalar multiplication with group endomorphim optimization
    EndoMul = 5,
    /// Gate for computing the scalar corresponding to an endoscaling
    EndoMulScalar = 6,
    /// ChaCha
    ChaCha0 = 7,
    ChaCha1 = 8,
    ChaCha2 = 9,
    ChaChaFinal = 10,
    /// Gates for Cairo
    CairoInitial = 11,
    CairoMemory = 12,
    CairoInstruction = 13,
    CairoFlags = 14,
    CairoTransition = 15,
    CairoAuxiliary = 16,
    CairoClaim = 17,
}

/// Describes the desired lookup configuration.
#[derive(Clone, Serialize, Deserialize)]
pub struct LookupInfo<F> {
    /// A single lookup constraint is a vector of lookup constraints to be applied at a row.
    /// This is a vector of all the kinds of lookup constraints in this configuration.
    pub kinds: Vec<Vec<JointLookup<F>>>,
    /// A map from the kind of gate (and whether it is the current row or next row) to the lookup
    /// constraint (given as an index into `kinds`) that should be applied there, if any.
    pub kinds_map: HashMap<(GateType, CurrOrNext), usize>,
    /// A map from the kind of gate (and whether it is the current row or next row) to the lookup
    /// table that is used by the gate, if any.
    pub kinds_tables: HashMap<(GateType, CurrOrNext), GateLookupTable>,
    /// The maximum length of an element of `kinds`. This can be computed from `kinds`.
    pub max_per_row: usize,
    /// The maximum joint size of any joint lookup in a constraint in `kinds`. This can be computed from `kinds`.
    pub max_joint_size: usize,
    /// An empty vector.
    empty: Vec<JointLookup<F>>,
}

fn max_lookups_per_row<F>(kinds: &[Vec<JointLookup<F>>]) -> usize {
    kinds.iter().fold(0, |acc, x| std::cmp::max(x.len(), acc))
}

/// Specifies whether a constraint system uses joint lookups. Used to make sure we
/// squeeze the challenge `joint_combiner` when needed, and not when not needed.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum LookupsUsed {
    Single,
    Joint,
}

/// Enumerates the different 'fixed' lookup tables used by individual gates
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GateLookupTable {
    Xor,
}

pub type LookupTable<F> = Vec<Vec<F>>;

pub fn get_table<F: FftField>(table_name: GateLookupTable) -> LookupTable<F> {
    match table_name {
        GateLookupTable::Xor => crate::circuits::polynomials::chacha::xor_table(),
    }
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
                    .fold(acc0, |acc, j| std::cmp::max(acc, j.entry.len()))
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
        let n = domain.d1.size as usize;
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
    pub fn by_row<'a>(&'a self, gates: &[CircuitGate<F>]) -> Vec<&'a Vec<JointLookup<F>>> {
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

/// Specifies the relative position of gates and the fixed lookup table (if applicable) that a
/// given lookup configuration should apply to.
pub struct GatesLookupSpec {
    /// The set of positions relative to an active gate where a lookup configuration applies.
    pub gate_positions: HashSet<(GateType, CurrOrNext)>,
    /// The fixed lookup table that should be used for these lookups, if applicable.
    pub gate_lookup_table: Option<GateLookupTable>,
}

/// Specifies mapping from positions defined relative to gates into lookup data.
pub struct GatesLookupMaps {
    /// Enumerates the selector that should be active for a particular gate-relative position.
    pub gate_selector_map: HashMap<(GateType, CurrOrNext), usize>,
    /// Enumerates the fixed tables that should be used for lookups in a particular gate-relative
    /// position.
    pub gate_table_map: HashMap<(GateType, CurrOrNext), GateLookupTable>,
}

impl GateType {
    /// Which lookup-patterns should be applied on which rows.
    /// Currently there is only the lookup pattern used in the ChaCha rows, and it
    /// is applied to each ChaCha row and its successor.
    ///
    /// See circuits/kimchi/src/polynomials/chacha.rs for an explanation of
    /// how these work.
    pub fn lookup_kinds<F: Field>() -> (Vec<Vec<JointLookup<F>>>, Vec<GatesLookupSpec>) {
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

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
/// A single gate in a circuit.
pub struct CircuitGate<F: FftField> {
    /// type of the gate
    pub typ: GateType,
    /// gate wiring (for each cell, what cell it is wired to)
    pub wires: GateWires,
    /// public selector polynomials that can used as handy coefficients in gates
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub coeffs: Vec<F>,
}

impl<F: FftField> ToBytes for CircuitGate<F> {
    #[inline]
    fn write<W: Write>(&self, mut w: W) -> IoResult<()> {
        let typ: u8 = ToPrimitive::to_u8(&self.typ).unwrap();
        typ.write(&mut w)?;
        for i in 0..COLUMNS {
            self.wires[i].write(&mut w)?
        }

        (self.coeffs.len() as u8).write(&mut w)?;
        for x in self.coeffs.iter() {
            x.write(&mut w)?;
        }
        Ok(())
    }
}

impl<F: FftField> CircuitGate<F> {
    /// this function creates "empty" circuit gate
    pub fn zero(wires: GateWires) -> Self {
        CircuitGate {
            typ: GateType::Zero,
            wires,
            coeffs: Vec::new(),
        }
    }

    /// This function verifies the consistency of the wire
    /// assignments (witness) against the constraints
    pub fn verify(
        &self,
        row: usize,
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
        public: &[F],
    ) -> Result<(), String> {
        use GateType::*;
        match self.typ {
            Zero => Ok(()),
            Generic => self.verify_generic(row, witness, public),
            Poseidon => self.verify_poseidon(row, witness, cs),
            CompleteAdd => self.verify_complete_add(row, witness),
            VarBaseMul => self.verify_vbmul(row, witness),
            EndoMul => self.verify_endomul(row, witness, cs),
            EndoMulScalar => self.verify_endomul_scalar(row, witness, cs),
            // TODO: implement the verification for chacha
            ChaCha0 | ChaCha1 | ChaCha2 | ChaChaFinal => Ok(()),
            CairoInitial | CairoMemory | CairoInstruction | CairoFlags | CairoTransition
            | CairoAuxiliary | CairoClaim => self.verify_cairo_gate(row, witness, cs),
        }
    }
}

/// A circuit is specified as a series of [CircuitGate].
#[derive(Serialize)]
pub struct Circuit<'a, F: FftField>(
    #[serde(bound = "CircuitGate<F>: Serialize")] pub &'a [CircuitGate<F>],
);

impl<'a, F: FftField> CryptoDigest for Circuit<'a, F> {
    const PREFIX: &'static [u8; 15] = b"kimchi-circuit0";
}

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use crate::circuits::wires::caml::CamlWire;
    use itertools::Itertools;

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlCircuitGate<F> {
        pub typ: GateType,
        pub wires: (
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
        ),
        pub coeffs: Vec<F>,
    }

    impl<F, CamlF> From<CircuitGate<F>> for CamlCircuitGate<CamlF>
    where
        CamlF: From<F>,
        F: FftField,
    {
        fn from(cg: CircuitGate<F>) -> Self {
            Self {
                typ: cg.typ,
                wires: array_to_tuple(cg.wires),
                coeffs: cg.coeffs.into_iter().map(Into::into).collect(),
            }
        }
    }

    impl<F, CamlF> From<&CircuitGate<F>> for CamlCircuitGate<CamlF>
    where
        CamlF: From<F>,
        F: FftField,
    {
        fn from(cg: &CircuitGate<F>) -> Self {
            Self {
                typ: cg.typ,
                wires: array_to_tuple(cg.wires),
                coeffs: cg.coeffs.clone().into_iter().map(Into::into).collect(),
            }
        }
    }

    impl<F, CamlF> From<CamlCircuitGate<CamlF>> for CircuitGate<F>
    where
        F: From<CamlF>,
        F: FftField,
    {
        fn from(ccg: CamlCircuitGate<CamlF>) -> Self {
            Self {
                typ: ccg.typ,
                wires: tuple_to_array(ccg.wires),
                coeffs: ccg.coeffs.into_iter().map(Into::into).collect(),
            }
        }
    }

    /// helper to convert array to tuple (OCaml doesn't have fixed-size arrays)
    fn array_to_tuple<T1, T2>(a: [T1; PERMUTS]) -> (T2, T2, T2, T2, T2, T2, T2)
    where
        T1: Clone,
        T2: From<T1>,
    {
        a.into_iter()
            .map(Into::into)
            .next_tuple()
            .expect("bug in array_to_tuple")
    }

    /// helper to convert tuple to array (OCaml doesn't have fixed-size arrays)
    fn tuple_to_array<T1, T2>(a: (T1, T1, T1, T1, T1, T1, T1)) -> [T2; PERMUTS]
    where
        T2: From<T1>,
    {
        [
            a.0.into(),
            a.1.into(),
            a.2.into(),
            a.3.into(),
            a.4.into(),
            a.5.into(),
            a.6.into(),
        ]
    }
}

//
// Tests
//

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand as _;
    use mina_curves::pasta::Fp;
    use proptest::prelude::*;
    use rand::SeedableRng as _;

    // TODO: move to mina-curves
    prop_compose! {
        pub fn arb_fp()(seed: [u8; 32]) -> Fp {
            let rng = &mut rand::rngs::StdRng::from_seed(seed);
            Fp::rand(rng)
        }
    }

    prop_compose! {
        fn arb_fp_vec(max: usize)(seed: [u8; 32], num in 0..max) -> Vec<Fp> {
            let rng = &mut rand::rngs::StdRng::from_seed(seed);
            let mut v = vec![];
            for _ in 0..num {
                v.push(Fp::rand(rng))
            }
            v
        }
    }

    prop_compose! {
        fn arb_circuit_gate()(typ: GateType, wires: GateWires, coeffs in arb_fp_vec(25)) -> CircuitGate<Fp> {
            CircuitGate {
                typ,
                wires,
                coeffs,
            }
        }
    }

    proptest! {
        #[test]
        fn test_gate_serialization(cg in arb_circuit_gate()) {
            let encoded = rmp_serde::to_vec(&cg).unwrap();
            let decoded: CircuitGate<Fp> = rmp_serde::from_read_ref(&encoded).unwrap();
            prop_assert_eq!(cg.typ, decoded.typ);
            for i in 0..PERMUTS {
                prop_assert_eq!(cg.wires[i], decoded.wires[i]);
            }
            prop_assert_eq!(cg.coeffs, decoded.coeffs);
        }
    }
}
