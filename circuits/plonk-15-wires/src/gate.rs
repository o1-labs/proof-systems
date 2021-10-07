/*****************************************************************************************************************

This source file implements Plonk constraint gate primitive.

*****************************************************************************************************************/

use crate::{nolookup::constraints::ConstraintSystem, wires::*};
use ark_ff::bytes::{FromBytes, ToBytes};
use ark_ff::{Field, FftField};
use num_traits::cast::{FromPrimitive, ToPrimitive};
use std::io::{Error, ErrorKind, Read, Result as IoResult, Write};
use std::collections::{HashMap, HashSet};
use ark_poly::{Radix2EvaluationDomain as D, Evaluations as E};
use crate::domains::EvaluationDomains;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CurrOrNext {
    Curr,
    Next,
}

impl CurrOrNext {
    pub fn shift(&self) -> usize {
        match self {
            CurrOrNext::Curr => 0,
            CurrOrNext::Next => 1,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LocalPosition {
    pub row: CurrOrNext,
    pub column: usize
}

#[derive(Clone)]
pub struct SingleLookup<F> {
    table_id: usize,
    // Linear combination of local-positions
    pub value: Vec<(F, LocalPosition)>
}

pub fn combine_table_entry<'a, F: Field, I: DoubleEndedIterator<Item=&'a F>>(joint_combiner: F, v: I) ->F {
    v.rev().fold(F::zero(), |acc, x| joint_combiner * acc + x)
}

impl<F: Field> SingleLookup<F> {
    pub fn evaluate<G: Fn(LocalPosition) -> F>(&self, eval: G) -> F {
        self.value.iter().fold(F::zero(), |acc, (c, p)| {
            acc + *c * eval(*p)
        })
    }
}

#[derive(Clone)]
pub struct JointLookup<F> {
    pub entry: Vec<SingleLookup<F>>
}

impl<F: Field> JointLookup<F> {
    // TODO: Support multiple tables
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
#[derive(Clone, Eq, Hash, Copy, Debug, PartialEq, FromPrimitive, ToPrimitive, PartialOrd, Ord)]
pub enum GateType {
    /// zero gate
    Zero=0,
    /// generic arithmetic gate
    Generic,
    /// Poseidon permutation gate
    Poseidon,
    /// EC addition in Affine form
    Add,
    /// EC point doubling in Affine form
    Double,
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

pub struct LookupInfo<F> {
    pub max_per_row: usize,
    pub max_joint_size: usize,
    pub kinds: Vec<Vec<JointLookup<F>>>,
    pub kinds_map: HashMap<(GateType, CurrOrNext), usize>,
    pub empty: Vec<JointLookup<F>>,
}

fn lookup_kinds<F: Field>() -> Vec<Vec<JointLookup<F>>> {
    GateType::lookup_kinds().into_iter().map(|(x, _)| x).collect()
}

fn max_lookups_per_row<F>(kinds: &Vec<Vec<JointLookup<F>>>) -> usize {
    kinds.iter().fold(0, |acc, x| std::cmp::max(x.len(), acc))
}

#[derive(Copy, Clone, Debug)]
pub enum LookupsUsed {
    Single,
    Joint,
}

impl<F: FftField> LookupInfo<F> {
    pub fn create() -> Self {
        let kinds = lookup_kinds::<F>();
        let max_per_row = max_lookups_per_row(&kinds);
        LookupInfo {
            max_joint_size:
                kinds.iter().fold(0, |acc0, v| {
                    v.iter().fold(acc0, |acc, j| {
                        std::cmp::max(acc, j.entry.len())
                    })
                }),

            kinds_map: GateType::lookup_kinds_map::<F>(),
            kinds,
            max_per_row,
            empty: vec![]
        }
    }

    pub fn lookup_used(&self, gates: &Vec<CircuitGate<F>>) -> Option<LookupsUsed> {
        let mut lookups_used = None;
        for g in gates.iter() {
            let typ = g.typ;

            for r in &[ CurrOrNext::Curr, CurrOrNext::Next ] {
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

    pub fn selector_polynomials<'a>(&'a self, domain: EvaluationDomains<F>, gates: &Vec<CircuitGate<F>>) -> Vec<E<F, D<F>>> {
        let n = domain.d1.size as usize;
        let mut res : Vec<_> = self.kinds.iter().map(|_| vec![F::zero(); n]).collect();

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
        let curr_row = |column| LocalPosition { row: CurrOrNext::Curr, column };
        let chacha_pattern =
            (0..4).map(|i| {
                let op1 = curr_row(3 + i);
                let op2 = curr_row(7 + i);
                let res = curr_row(11 + i);
                let l = |loc: LocalPosition|
                    SingleLookup { table_id:0, value: vec![(F::one(), loc)] };
                JointLookup { entry: vec![l(op1), l(op2), l(res)] }
            }).collect();

        let mut chacha_where = HashSet::new();
        use GateType::*;
        use CurrOrNext::*;

        for g in &[ ChaCha0, ChaCha1, ChaCha2 ] {
            for r in &[ Curr, Next ] {
                chacha_where.insert((*g, *r));
            }
        }

        let one_half = F::from(2u64).inverse().unwrap();
        let neg_one_half = -one_half;
        let chacha_final_pattern =
            (0..4).map(|i| {
                let nybble = curr_row(1 + i);
                let low_bit = curr_row(5 + i);
                // Check
                // XOR((nybble - low_bit)/2, (nybble - low_bit)/2) = 0.
                let x =
                    SingleLookup {
                        table_id:0,
                        value: vec![(one_half, nybble), (neg_one_half, low_bit)]
                    };
                JointLookup { entry: vec![x.clone(), x, SingleLookup { table_id:0, value: vec![] } ] }
            }).collect();

        let mut chacha_final_where = HashSet::new();
        for r in &[ Curr, Next ] {
            chacha_final_where.insert((ChaChaFinal, *r));
        }

        vec![(chacha_pattern, chacha_where), (chacha_final_pattern, chacha_final_where)]
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

#[derive(Clone, Debug)]
pub struct CircuitGate<F: FftField> {
    /// row position in the circuit
    // TODO(mimoo): shouldn't this be u32 since we serialize it as a u32?
    pub row: usize,
    /// type of the gate
    pub typ: GateType,
    /// gate wires
    pub wires: GateWires,
    /// constraints vector
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
            Add => self.verify_add(witness),
            Double => self.verify_double(witness),
            Vbmul => self.verify_vbmul(witness),
            Endomul => self.verify_endomul(witness, cs),
            ChaCha0 | ChaCha1 | ChaCha2 | ChaChaFinal => panic!("todo")
        }
    }
}
