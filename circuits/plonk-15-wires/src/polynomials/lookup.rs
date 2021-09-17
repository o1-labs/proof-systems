/*****************************************************************************************************************

This source file implements the arithmetization of plookup constraints 

Because of our ZK-rows, we can't do the trick in the plookup paper of
wrapping around to enforce consistency between the sorted lookup columns.

Instead, we arrange the LookupSorted table into columns in a snake-shape.

Like so,
   _   _
| | | | |
| | | | |
|_| |_| |

or, imagining the full sorted array is [ s0, ..., s8 ], like

s0 s4 s4 s8
s1 s3 s5 s7
s2 s2 s6 s6

So the direction ("increasing" or "decreasing" (relative to LookupTable)
is 
if i % 2 = 0 { Increasing } else { Decreasing }

Then, for each i < max_lookups_per_row, if i % 2 = 0, we enforce that the
last element of LookupSorted(i) = last element of LookupSorted(i + 1),
and if i % 2 = 1, we enforce that the
first element of LookupSorted(i) = first element of LookupSorted(i + 1)

*****************************************************************************************************************/

use ark_ff::{Field, FftField, Zero, One};
use rand::Rng;
use CurrOrNext::*;
use std::collections::{HashMap};
use ark_poly::{
    Evaluations, Radix2EvaluationDomain as D,
};
use crate::{
    wires::{COLUMNS},
    gate::{CircuitGate, LookupInfo, LocalPosition, CurrOrNext, SingleLookup, JointLookup},
};
use oracle::rndoracle::ProofError;
use crate::expr::{E, Variable, Column, ConstantExpr as C};

// TODO: Update for multiple tables
fn single_lookup<F: FftField>(s : &SingleLookup<F>) -> E<F> {
    // Combine the linear combination.
    s.value.iter().map(|(c, pos)| {
        E::literal(*c) * E::Cell(Variable { col: Column::Witness(pos.column), row: pos.row })
    }).fold(E::zero(), |acc, e| acc + e)
}

fn joint_lookup<F: FftField>(j : &JointLookup<F>) -> E<F> {
    j.entry.iter().enumerate()
        .map(|(i, s)| E::constant(C::JointCombiner.pow(i)) * single_lookup(s))
        .fold(E::zero(), |acc, x| acc + x)
}

struct AdjacentPairs<A, I: Iterator<Item=A>> {
    prev_second_component: Option<A>,
    i: I
}

impl<A: Copy, I: Iterator<Item=A>> Iterator for AdjacentPairs<A, I> {
    type Item = (A, A);

    fn next(&mut self) -> Option<(A, A)> {
        match self.prev_second_component {
            Some(x) => {
                match self.i.next() {
                    None => None,
                    Some(y) => {
                        self.prev_second_component = Some(y);
                        Some((x, y))
                    }
                }
            },
            None => {
                let x = self.i.next();
                let y = self.i.next();
                match (x, y) {
                    (None, _) | (_ , None) => None,
                    (Some(x), Some(y)) => {
                        self.prev_second_component = Some(y);
                        Some((x, y))
                    }
                }
            }
        }
    }
}

fn adjacent_pairs<A: Copy, I: Iterator<Item=A>>(i : I) -> AdjacentPairs<A, I> {
    AdjacentPairs { i, prev_second_component: None }
}

pub struct LookupWitness<F: FftField> {
    // The lookups, sorted
    pub sorted: Vec<Evaluations<F, D<F>>>,
    // The lookups, in-order and with the product taken in each row
    pub f_chunks: Vec<F>,
}

pub const ZK_ROWS: usize = 2;

// Pad with zeroes and then add 2 random elements in the last two
// rows for zero knowledge.
pub fn zk_patch<R: Rng + ?Sized, F: FftField>(mut e : Vec<F>, d: D<F>, rng: &mut R) -> Evaluations<F, D<F>> {
    let n = d.size as usize;
    let k = e.len();
    assert!(k <= n - ZK_ROWS);
    e.extend((0..((n - ZK_ROWS) - k)).map(|_| F::zero()));
    e.extend((0..ZK_ROWS).map(|_| F::rand(rng)));
    Evaluations::<F, D<F>>::from_vec_and_domain(e, d)
}

pub fn verify<F: FftField, I: Iterator<Item= F>, G: Fn() -> I>(
    dummy_lookup_value: F,
    lookup_table: G,
    lookup_table_entries: usize,
    d1: D<F>,
    gates: &Vec<CircuitGate<F>>,
    witness: &[Vec<F>; COLUMNS],
    joint_combiner: F,
    sorted: &Vec<Evaluations<F, D<F>>>,
    ) -> () {
    sorted.iter().for_each(|s| assert_eq!(d1.size, s.domain().size));
    let n = d1.size as usize;
    let lookup_rows = n - ZK_ROWS - 1;

    // Check that the (desnakified) sorted table is
    // 1. Sorted
    // 2. Adjacent pairs agree on the final overlap point
    // 3. Multiset-equal to the set lookups||table

    // Check agreement on overlaps
    for i in 0..sorted.len() - 1 {
        let pos = if i % 2 == 0 { lookup_rows } else { 0 };
        assert_eq!(sorted[i][pos], sorted[i + 1][pos]);
    }

    // Check sorting
    let mut sorted_joined : Vec<F> = vec![];
    for (i, s) in sorted.iter().enumerate() {
        let es = s.evals.iter().take(lookup_rows+1);
        if i % 2 == 0 {
            sorted_joined.extend(es)
        } else {
            sorted_joined.extend(es.rev())
        }
    }

    let mut s_index = 0;
    for t in lookup_table().take(lookup_table_entries) {
        while s_index < sorted_joined.len() && sorted_joined[s_index] == t {
            s_index += 1;
        }
    }
    assert_eq!(s_index, sorted_joined.len());

    let lookup_info = LookupInfo::<F>::create();
    let by_row = lookup_info.by_row(gates);

    // Compute lookups||table and check multiset equality
    let sorted_counts : HashMap<F, usize> = {
        let mut counts = HashMap::new();
        for (i, s) in sorted.iter().enumerate() {
            if i % 2 == 0 {
                for x in s.evals.iter().take(lookup_rows) {
                    *counts.entry(*x).or_insert(0) += 1
                }
            } else {
                for x in s.evals.iter().skip(1).take(lookup_rows) {
                    *counts.entry(*x).or_insert(0) += 1
                }
            }
        }
        counts
    };

    let mut all_lookups : HashMap<F, usize> = HashMap::new();
    lookup_table().take(lookup_rows).for_each(|t| {
        *all_lookups.entry(t).or_insert(0) += 1
    });
    for (i, spec) in by_row.iter().take(lookup_rows).enumerate() {
        let eval = |pos : LocalPosition| -> F {
            let row = match pos.row { Curr => i, Next => i + 1 };
            witness[pos.column][row]
        };
        for joint_lookup in spec.iter() {
            let table_entry = joint_lookup.evaluate(joint_combiner, &eval);
            *all_lookups.entry(table_entry).or_insert(0) += 1
        }

        *all_lookups.entry(dummy_lookup_value).or_insert(0) += lookup_info.max_per_row - spec.len()
    }

    assert_eq!(
        all_lookups.iter().fold(0, |acc, (_, v)| acc + v),
        sorted_counts.iter().fold(0, |acc, (_, v)| acc + v));

    for (k, v) in all_lookups.iter() {
        let s = sorted_counts.get(k).unwrap_or(&0);
        if v != s {
            panic!("For {}:\nall_lookups    = {}\nsorted_lookups = {}", k, v, s);
        }
    }
    for (k, s) in sorted_counts.iter() {
        let v = all_lookups.get(k).unwrap_or(&0);
        if v != s {
            panic!("For {}:\nall_lookups    = {}\nsorted_lookups = {}", k, v, s);
        }
    }
}

pub trait Entry {
    type Field: Field;
    type Params;

    fn evaluate(p: & Self::Params, j: &JointLookup<Self::Field>, witness: &[Vec<Self::Field>; COLUMNS], row: usize) -> Self;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CombinedEntry<F>(pub F);
impl<F: Field> Entry for CombinedEntry<F> {
    type Field = F;
    type Params = F;

    fn evaluate(joint_combiner: &F, j: &JointLookup<F>, witness: &[Vec<F>; COLUMNS], row: usize) -> CombinedEntry<F> {
        let eval = |pos : LocalPosition| -> F {
            let row = match pos.row { Curr => row, Next => row + 1 };
            witness[pos.column][row]
        };

        CombinedEntry(j.evaluate(*joint_combiner, &eval))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UncombinedEntry<F>(pub Vec<F>);

impl<F: Field> Entry for UncombinedEntry<F> {
    type Field = F;
    type Params = ();

    fn evaluate(_: &(), j: &JointLookup<F>, witness: &[Vec<F>; COLUMNS], row: usize) -> UncombinedEntry<F> {
        let eval = |pos : LocalPosition| -> F {
            let row = match pos.row { Curr => row, Next => row + 1 };
            witness[pos.column][row]
        };

        UncombinedEntry(j.entry.iter().map(|s| s.evaluate(&eval)).collect())
    }
}

/*
   Aggregration polyomial is the product of terms

    (1 + beta) \prod_j (gamma + f_{i,j}) (gamma(1 + beta) + t_i + beta t_{i+1})
    ---------------------------------------------------------------------------
    \prod_j (gamma(1 + beta) + s_{i,j} + beta s_{i+1,j})
*/
pub fn sorted
    <'a
    , F: FftField
    , E: Entry<Field=F> + Eq + std::hash::Hash + Clone
    , I: Iterator<Item= E>
    , G: Fn() -> I >
    (
    // TODO: Multiple tables
    dummy_lookup_value: E,
    lookup_table: G,
    lookup_table_entries: usize,
    d1: D<F>,
    gates: &Vec<CircuitGate<F>>,
    witness: &[Vec<F>; COLUMNS],
    params: E::Params,
    )
    -> Result<Vec<Vec<E>>, ProofError>
{
    // We pad the lookups so that it is as if we lookup exactly
    // `max_lookups_per_row` in every row.

    let n = d1.size as usize;
    let mut counts : HashMap<E, usize> = HashMap::new();

    let lookup_rows = n - ZK_ROWS - 1;
    let lookup_info = LookupInfo::<F>::create();
    let by_row = lookup_info.by_row(gates);
    let max_lookups_per_row = lookup_info.max_per_row;

    for i in 0..lookup_rows {
        let spec = by_row[i];
        let padding = max_lookups_per_row - spec.len();
        for joint_lookup in spec.iter() {
            let table_entry = E::evaluate(&params, joint_lookup, &witness, i);
            let count = counts.entry(table_entry).or_insert(0);
            *count += 1;
        }
        *counts.entry(dummy_lookup_value.clone()).or_insert(0) += padding;
    }

    for t in lookup_table().take(lookup_rows) {
        let count = counts.entry(t).or_insert(0);
        *count += 1;
    }

    let sorted = {
        let mut sorted : Vec<Vec<E>> = vec![];
        for _ in 0..max_lookups_per_row + 1 {
            sorted.push(vec![])
        }

        let mut i = 0;
        for t in lookup_table().take(lookup_table_entries) {
            let t_count = 
                match counts.get(&t) {
                    None => return Err(ProofError::ValueNotInTable),
                    Some(x) => *x
                };
            for j in 0..t_count {
                let idx = i + j;
                let col = idx / lookup_rows;
                sorted[col].push(t.clone());
            }
            i += t_count;
        }

        for i in 0..max_lookups_per_row {
            let end_val = sorted[i + 1][0].clone();
            sorted[i].push(end_val);
        }

        // snake-ify (see top comment)
        for i in 0..sorted.len() {
            if i % 2 != 0 {
                sorted[i].reverse();
            }
        }
        sorted
    };

    Ok(sorted)
}

pub fn aggregation<'a, R: Rng + ?Sized, F: FftField, I: Iterator<Item=F>>(
    dummy_lookup_value: F,
    lookup_table: I,
    d1: D<F>,
    gates: &Vec<CircuitGate<F>>,
    witness: &[Vec<F>; COLUMNS],
    joint_combiner: F,
    beta: F,
    gamma: F,
    sorted: &Vec<Evaluations<F, D<F>>>,
    rng: &mut R,
    ) -> Result<Evaluations<F, D<F>>, ProofError>  
{
    let n = d1.size as usize;
    let lookup_rows = n - ZK_ROWS - 1;
    let beta1 = F::one() + beta;
    let gammabeta1 = gamma * beta1;
    let mut lookup_aggreg = vec![F::one()];

    lookup_aggreg.extend((0..lookup_rows).map(|row| {
        sorted.iter().enumerate().map(|(i, s)| {
            let (i1, i2) =
                if i % 2 == 0 {
                    (row, row + 1)
                } else {
                    (row + 1, row)
                };
            gammabeta1 + s[i1] + beta * s[i2]
        }).fold(F::one(), |acc, x| acc * x)
    }));
    ark_ff::fields::batch_inversion::<F>(&mut lookup_aggreg[1..]);

    let lookup_info = LookupInfo::<F>::create();
    let max_lookups_per_row = lookup_info.max_per_row;

    let complements_with_beta_term = {
        let mut v = vec![F::one()];
        let x = gamma + dummy_lookup_value;
        for i in 1..(max_lookups_per_row+1) {
            v.push(v[i - 1] * x)
        }

        let beta1_per_row = beta1.pow(&[ max_lookups_per_row as u64]);
        v.iter_mut().for_each(|x| *x *= beta1_per_row);

        v
    };

    adjacent_pairs(lookup_table).take(lookup_rows)
        .zip(lookup_info.by_row(gates)).enumerate().for_each(| (i, ((t0, t1), spec) ) | {
        let f_chunk = {
            let eval = |pos : LocalPosition| -> F {
                let row = match pos.row { Curr => i, Next => i + 1 };
                witness[pos.column][row]
            };

            let padding = complements_with_beta_term[max_lookups_per_row - spec.len()];

            // This recomputes `joint_lookup.evaluate` on all the rows, which
            // is also computed in `sorted`. It should pretty cheap relative to
            // the whole cost of the prover, and saves us 
            // `max_lookups_per_row (=4) * n` field elements of
            // memory.
            spec.iter()
            .fold(padding, |acc, j| {
                acc * (gamma + j.evaluate(joint_combiner, &eval))
            })
        };

        // At this point, lookup_aggreg[i + 1] contains 1/s_chunk
        // f_chunk / s_chunk
        lookup_aggreg[i + 1] *= f_chunk;
        // f_chunk * t_chunk / s_chunk
        lookup_aggreg[i + 1] *= gammabeta1 + t0 + beta * t1;
        let prev = lookup_aggreg[i];
        // prev * f_chunk * t_chunk / s_chunk
        lookup_aggreg[i + 1] *= prev;
    });

    Ok(zk_patch(lookup_aggreg, d1, rng))
}

pub fn constraints<F: FftField>(dummy_lookup: F, d1: D<F>) -> Vec<E<F>> {
    // Something important to keep in mind is that the last 2 rows of
    // all columns will have random values in them to maintain zero-knowledge.
    //
    // Another important thing to note is that there are no lookups permitted
    // in the 3rd to last row.
    //
    // This is because computing the lookup-product requires 
    // num_lookup_rows + 1
    // rows, so we need to have 
    // num_lookup_rows + 1 = n - 2 (the last 2 being reserved for the zero-knowledge random
    // values) and thus
    //
    // num_lookup_rows = n - 3
    let lookup_info = LookupInfo::<F>::create();

    let column = |col: Column| E::cell(col, Curr);

    let lookup_indicator =
        lookup_info.kinds.iter().enumerate().map(|(i, _)| {
            column(Column::LookupKindIndex(i))
        }).fold(E::zero(), |acc: E<F>, x| acc + x);

    let one : E<F> = E::one();
    let non_lookup_indcator = one.clone() - lookup_indicator;

    let complements_with_beta_term: Vec<C<F>> = {
        let mut v = vec![C::one()];
        let x = C::Gamma + C::Literal(dummy_lookup);
        for i in 1..(lookup_info.max_per_row+1) {
            v.push(v[i - 1].clone() * x.clone())
        }

        let beta1_per_row: C<F> = (C::one() + C::Beta).pow(lookup_info.max_per_row);
        v.iter().map(|x| x.clone() * beta1_per_row.clone()).collect()
    };

    // This is set up so that on rows that have lookups, chunk will be equal
    // to the product over all lookups `f` in that row of `gamma + f`
    // and
    // on non-lookup rows, will be equal to 1.
    let f_term = |spec: &Vec<_>| {
        assert!(spec.len() <= lookup_info.max_per_row);
        let padding = complements_with_beta_term[lookup_info.max_per_row - spec.len()].clone();

        spec
        .iter()
        .map(|j| E::Constant(C::Gamma) + joint_lookup(j))
        .fold(E::Constant(padding), |acc: E<F>, x| acc * x)
    };
    let f_chunk =
        lookup_info.kinds.iter().enumerate()
        .map(|(i, spec)| {
            column(Column::LookupKindIndex(i)) * f_term(spec)
        }).fold(non_lookup_indcator * f_term(&vec![]), |acc, x| acc + x);
    let gammabeta1 = || E::<F>::Constant(C::Gamma * (C::Beta + C::one()));
    let ft_chunk = 
        f_chunk
        * (gammabeta1()
             + E::cell(Column::LookupTable, Curr)
             + E::beta() * E::cell(Column::LookupTable, Next));

    let num_rows = d1.size as usize;

    // Because of our ZK-rows, we can't do the trick in the plookup paper of
    // wrapping around to enforce consistency between the sorted lookup columns.
    //
    // Instead, we arrange the LookupSorted table into columns in a snake-shape.
    //
    // Like so,
    //    _   _
    // | | | | |
    // | | | | |
    // |_| |_| |
    //
    // or, imagining the full sorted array is [ s0, ..., s8 ], like
    //
    // s0 s4 s4 s8
    // s1 s3 s5 s7
    // s2 s2 s6 s6
    //
    // So the direction ("increasing" or "decreasing" (relative to LookupTable)
    // is 
    // if i % 2 = 0 { Increasing } else { Decreasing }
    //
    // Then, for each i < max_lookups_per_row, if i % 2 = 0, we enforce that the
    // last element of LookupSorted(i) = last element of LookupSorted(i + 1),
    // and if i % 2 = 1, we enforce that the
    // first element of LookupSorted(i) = first element of LookupSorted(i + 1)

    let s_chunk =
        (0..(lookup_info.max_per_row + 1))
        .map(|i| {
                let (s1, s2) =
                if i % 2 == 0 {
                    (Curr, Next)
                } else {
                    (Next, Curr)
                };

                gammabeta1()
                + E::cell(Column::LookupSorted(i), s1)
                + E::beta() * E::cell(Column::LookupSorted(i), s2)
        })
        .fold(E::one(), |acc: E<F>, x| acc * x);

    let last_lookup_row_index = num_rows - 4;

    let compatibility_checks : Vec<_> = (0..lookup_info.max_per_row).map(|i| {
        let first_or_last =
            if i % 2 == 0 {
                // Check compatibility of the last elements
                last_lookup_row_index
            } else {
                // Check compatibility of the first elements
                0
            };
        E::UnnormalizedLagrangeBasis(first_or_last) *
            (column(Column::LookupSorted(i)) - 
                column(Column::LookupSorted(i + 1)))
    }).collect();

    let aggreg_equation =
        E::cell(Column::LookupAggreg, Next) * s_chunk
        - E::cell(Column::LookupAggreg, Curr) * ft_chunk;

    /*
        aggreg.next = 
        aggreg.curr
        * f_chunk
        * (gammabeta1 + index.lookup_tables[0][i] + beta * index.lookup_tables[0][i+1];)
        / (\prod_i (gammabeta1 + lookup_sorted_i.curr + beta * lookup_sorted_i.next))

        rearranging,

        aggreg.next
        * (\prod_i (gammabeta1 + lookup_sorted_i.curr + beta * lookup_sorted_i.next))
        =
        aggreg.curr
        * f_chunk
        * (gammabeta1 + index.lookup_tables[0][i] + beta * index.lookup_tables[0][i+1];)

    */

    let mut res = vec![
        E::ZkPolynomial * aggreg_equation,
        E::UnnormalizedLagrangeBasis(0) *
            (E::cell(Column::LookupAggreg, Curr) - E::one()),
        // Check that the 3rd to last row (index = num_rows - 3), which
        // contains the full product, equals 1
        E::UnnormalizedLagrangeBasis(last_lookup_row_index + 1) *
            (E::cell(Column::LookupAggreg, Curr) - E::one()),
    ];
    res.extend(compatibility_checks);
    res
}
