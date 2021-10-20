/*****************************************************************************************************************

This source file implements Plonk constraint gate primitive.

*****************************************************************************************************************/

use crate::domains::EvaluationDomains;
use crate::{nolookup::constraints::ConstraintSystem, wires::*};
use ark_ff::bytes::ToBytes;
use ark_ff::{FftField, Field};
use ark_poly::{Evaluations as E, Radix2EvaluationDomain as D};
use num_traits::cast::ToPrimitive;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::{HashMap, HashSet};
use std::io::{Result as IoResult, Write};

/// A row accessible from a given row, corresponds to the fact that we open all polynomials
/// at `zeta` **and** `omega * zeta`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
    table_id: usize,
    // Linear combination of local-positions
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
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::OcamlEnum)
)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum GateType {
    /// zero gate
    Zero = 0,
    /// generic arithmetic gate
    Generic,
    /// Poseidon permutation gate
    Poseidon,
    /// Complete EC addition in Affine form
    CompleteAdd,
    /// EC variable base scalar multiplication
    Vbmul,
    /// EC variable base scalar multiplication with group endomorphim optimization
    Endomul,
    /// ChaCha
    ChaCha0,
    ChaCha1,
    ChaCha2,
    ChaChaFinal,
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
    /// The maximum length of an element of `kinds`. This can be computed from `kinds`.
    pub max_per_row: usize,
    /// The maximum joint size of any joint lookup in a constraint in `kinds`. This can be computed from `kinds`.
    pub max_joint_size: usize,
    /// An empty vector.
    empty: Vec<JointLookup<F>>,
}

fn lookup_kinds<F: Field>() -> Vec<Vec<JointLookup<F>>> {
    GateType::lookup_kinds()
        .into_iter()
        .map(|(x, _)| x)
        .collect()
}

fn max_lookups_per_row<F>(kinds: &Vec<Vec<JointLookup<F>>>) -> usize {
    kinds.iter().fold(0, |acc, x| std::cmp::max(x.len(), acc))
}

/// Specifies whether a constraint system uses joint lookups. Used to make sure we
/// squeeze the challenge `joint_combiner` when needed, and not when not needed.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum LookupsUsed {
    Single,
    Joint,
}

impl<F: FftField> LookupInfo<F> {
    /// Create the default lookup configuration.
    pub fn create() -> Self {
        let kinds = lookup_kinds::<F>();
        let max_per_row = max_lookups_per_row(&kinds);
        LookupInfo {
            max_joint_size: kinds.iter().fold(0, |acc0, v| {
                v.iter()
                    .fold(acc0, |acc, j| std::cmp::max(acc, j.entry.len()))
            }),

            kinds_map: GateType::lookup_kinds_map::<F>(),
            kinds,
            max_per_row,
            empty: vec![],
        }
    }

    /// Check what kind of lookups, if any, are used by this circuit.
    pub fn lookup_used(&self, gates: &Vec<CircuitGate<F>>) -> Option<LookupsUsed> {
        let mut lookups_used = None;
        for g in gates.iter() {
            let typ = g.typ;

            for r in &[CurrOrNext::Curr, CurrOrNext::Next] {
                if let Some(v) = self.kinds_map.get(&(typ, *r)) {
                    if self.kinds[*v].len() > 0 {
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
    pub fn selector_polynomials<'a>(
        &'a self,
        domain: EvaluationDomains<F>,
        gates: &Vec<CircuitGate<F>>,
    ) -> Vec<E<F, D<F>>> {
        let n = domain.d1.size as usize;
        let mut res: Vec<_> = self.kinds.iter().map(|_| vec![F::zero(); n]).collect();

        for i in 0..n {
            let typ = gates[i].typ;

            if let Some(v) = self.kinds_map.get(&(typ, CurrOrNext::Curr)) {
                res[*v][i] = F::one();
            }
            if let Some(v) = self.kinds_map.get(&(typ, CurrOrNext::Next)) {
                res[*v][i + 1] = F::one();
            }
        }

        // Actually, don't need to evaluate over domain 8 here.
        res.into_iter()
            .map(|v| {
                E::<F, D<F>>::from_vec_and_domain(v, domain.d1)
                    .interpolate()
                    .evaluate_over_domain(domain.d8)
            })
            .collect()
    }

    /// For each row in the circuit, which lookup-constraints should be enforced at that row.
    pub fn by_row<'a>(&'a self, gates: &Vec<CircuitGate<F>>) -> Vec<&'a Vec<JointLookup<F>>> {
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

impl GateType {
    /// Which lookup-patterns should be applied on which rows.
    /// Currently there is only the lookup pattern used in the ChaCha rows, and it
    /// is applied to each ChaCha row and its successor.
    ///
    /// See circuits/plonk-15-wires/src/polynomials/chacha.rs for an explanation of
    /// how these work.
    pub fn lookup_kinds<F: Field>() -> Vec<(Vec<JointLookup<F>>, HashSet<(GateType, CurrOrNext)>)> {
        let curr_row = |column| LocalPosition {
            row: CurrOrNext::Curr,
            column,
        };
        let chacha_pattern = (0..4)
            .map(|i| {
                let op1 = curr_row(3 + i);
                let op2 = curr_row(7 + i);
                let res = curr_row(11 + i);
                let l = |loc: LocalPosition| SingleLookup {
                    table_id: 0,
                    value: vec![(F::one(), loc)],
                };
                JointLookup {
                    entry: vec![l(op1), l(op2), l(res)],
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
                    table_id: 0,
                    value: vec![(one_half, nybble), (neg_one_half, low_bit)],
                };
                JointLookup {
                    entry: vec![
                        x.clone(),
                        x,
                        SingleLookup {
                            table_id: 0,
                            value: vec![],
                        },
                    ],
                }
            })
            .collect();

        let mut chacha_final_where = HashSet::new();
        for r in &[Curr, Next] {
            chacha_final_where.insert((ChaChaFinal, *r));
        }

        vec![
            (chacha_pattern, chacha_where),
            (chacha_final_pattern, chacha_final_where),
        ]
    }

    pub fn lookup_kinds_map<F: Field>() -> HashMap<(GateType, CurrOrNext), usize> {
        let mut res = HashMap::new();
        let lookup_kinds = Self::lookup_kinds::<F>();
        for (i, (_, locs)) in lookup_kinds.into_iter().enumerate() {
            for (g, r) in locs {
                if res.contains_key(&(g, r)) {
                    panic!("Multiple lookup patterns asserted on same row.")
                } else {
                    res.insert((g, r), i);
                }
            }
        }
        res
    }
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitGate<F: FftField> {
    /// row position in the circuit
    // TODO(mimoo): shouldn't this be u32 since we serialize it as a u32?
    pub row: usize,
    /// type of the gate
    pub typ: GateType,
    /// gate wires
    pub wires: GateWires,
    /// constraints vector
    // TODO: rename
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub c: Vec<F>,
}

impl<F: FftField> ToBytes for CircuitGate<F> {
    #[inline]
    fn write<W: Write>(&self, mut w: W) -> IoResult<()> {
        (self.row as u32).write(&mut w)?;
        let typ: u8 = ToPrimitive::to_u8(&self.typ).unwrap();
        typ.write(&mut w)?;
        for i in 0..COLUMNS {
            self.wires[i].write(&mut w)?
        }

        (self.c.len() as u8).write(&mut w)?;
        for x in self.c.iter() {
            x.write(&mut w)?;
        }
        Ok(())
    }
}

impl<F: FftField> FromBytes for CircuitGate<F> {
    #[inline]
    fn read<R: Read>(mut r: R) -> IoResult<Self> {
        let row = u32::read(&mut r)? as usize;
        let code = u8::read(&mut r)?;
        let typ = match FromPrimitive::from_u8(code) {
            Some(x) => Ok(x),
            None => Err(Error::new(ErrorKind::Other, "Invalid gate type")),
        }?;

        let wires = [
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
        ];

        let c_len = u8::read(&mut r)?;
        let mut c = vec![];
        for _ in 0..c_len {
            c.push(F::read(&mut r)?);
        }

        Ok(CircuitGate { row, typ, wires, c })
    }
}

impl<F: FftField> CircuitGate<F> {
    /// this function creates "empty" circuit gate
    pub fn zero(row: usize, wires: GateWires) -> Self {
        CircuitGate {
            row,
            typ: GateType::Zero,
            c: Vec::new(),
            wires,
        }
    }

    /// This function verifies the consistency of the wire
    /// assignements (witness) against the constraints
    pub fn verify(
        &self,
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
    ) -> Result<(), String> {
        use GateType::*;
        match self.typ {
            Zero => Ok(()),
            Generic => self.verify_generic(witness),
            Poseidon => self.verify_poseidon(witness, cs),
            CompleteAdd => self.verify_complete_add(witness),
            Vbmul => self.verify_vbmul(witness),
            Endomul => self.verify_endomul(witness, cs),
            ChaCha0 | ChaCha1 | ChaCha2 | ChaChaFinal => panic!("todo"),
        }
    }
}

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use crate::wires::caml::CamlWire;
    use itertools::Itertools;
    use ocaml_gen::OcamlGen;
    use std::convert::TryInto;

    #[derive(ocaml::IntoValue, ocaml::FromValue, OcamlGen)]
    pub struct CamlCircuitGate<F> {
        pub row: ocaml::Int,
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
        pub c: Vec<F>,
    }

    impl<F, CamlF> From<CircuitGate<F>> for CamlCircuitGate<CamlF>
    where
        CamlF: From<F>,
        F: FftField,
    {
        fn from(cg: CircuitGate<F>) -> Self {
            Self {
                row: cg.row.try_into().expect("usize -> isize"),
                typ: cg.typ,
                wires: array_to_tuple(cg.wires),
                c: cg.c.into_iter().map(Into::into).collect(),
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
                row: cg.row.try_into().expect("usize -> isize"),
                typ: cg.typ,
                wires: array_to_tuple(cg.wires),
                c: cg.c.clone().into_iter().map(Into::into).collect(),
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
                row: ccg.row.try_into().expect("isize -> usize"),
                typ: ccg.typ,
                wires: tuple_to_array(ccg.wires),
                c: ccg.c.into_iter().map(Into::into).collect(),
            }
        }
    }

    /// helper to convert array to tuple (OCaml doesn't have fixed-size arrays)
    fn array_to_tuple<T1, T2>(a: [T1; PERMUTS]) -> (T2, T2, T2, T2, T2, T2, T2)
    where
        T1: Clone,
        T2: From<T1>,
    {
        std::array::IntoIter::new(a)
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

#[cfg(any(test, feature = "testing"))]
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
        fn arb_circuit_gate()(row in any::<usize>(), typ: GateType, wires: GateWires, c in arb_fp_vec(25)) -> CircuitGate<Fp> {
            CircuitGate {
                row,
                typ,
                wires,
                c,
            }
        }
    }

    proptest! {
        #[test]
        fn test_gate_serialization(cg in arb_circuit_gate()) {
            let encoded = bincode::serialize(&cg).unwrap();
            println!("gate: {:?}", cg);
            println!("encoded gate: {:?}", encoded);
            let decoded: CircuitGate<Fp> = bincode::deserialize(&encoded).unwrap();
            println!("decoded gate: {:?}", decoded);
            prop_assert_eq!(cg.row, decoded.row);
            prop_assert_eq!(cg.typ, decoded.typ);
            for i in 0..COLUMNS {
                prop_assert_eq!(cg.wires[i], decoded.wires[i]);
            }
            prop_assert_eq!(cg.c, decoded.c);
        }
    }
}
