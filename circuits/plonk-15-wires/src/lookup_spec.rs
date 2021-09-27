use ark_ff::{Field, FftField};
use std::collections::{HashMap, HashSet};
use ark_poly::{Radix2EvaluationDomain as D, Evaluations as E};
use crate::domains::EvaluationDomains;
use crate::gate::{GateType, CurrOrNext, CircuitGate};

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

pub struct LookupInfo<F> {
    pub max_per_row: usize,
    pub max_joint_size: usize,
    pub kinds: Vec<Vec<JointLookup<F>>>,
    pub kinds_map: HashMap<(GateType, CurrOrNext), usize>,
    pub empty: Vec<JointLookup<F>>,
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
        let kinds = lookup_kinds().into_iter().map(|(x, _)| x).collect();
        let max_per_row = max_lookups_per_row(&kinds);
        LookupInfo {
            max_joint_size:
                kinds.iter().fold(0, |acc0, v| {
                    v.iter().fold(acc0, |acc, j| {
                        std::cmp::max(acc, j.entry.len())
                    })
                }),

            kinds_map: lookup_kinds_map::<F>(),
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
    let lookup_kinds = lookup_kinds::<F>();
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
