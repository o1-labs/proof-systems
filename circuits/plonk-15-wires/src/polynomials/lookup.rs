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

use ark_ff::{FftField};
use rand::Rng;
use CurrOrNext::*;
use std::collections::HashMap;
use ark_poly::{
    Evaluations, Radix2EvaluationDomain as D,
};
use crate::{
    wires::{COLUMNS},
    gate::{CircuitGate, LookupInfo, LocalPosition, CurrOrNext, SingleLookup, JointLookup},
};
use oracle::rndoracle::ProofError;

use crate::expr::{Expr, Variable, Column};

// TODO: Update for multiple tables
fn single_lookup<F: FftField>(s : &SingleLookup<F>) -> Expr<F> {
    s.value.iter().map(|(c, pos)| {
        Expr::Constant(*c) * Expr::Cell(Variable { col: Column::Witness(pos.column), row: pos.row })
    }).fold(1.into(), |acc, e| acc * e)
}

fn joint_lookup<F: FftField>(j : &JointLookup<F>) -> Expr<F> {
    j.entry.iter().enumerate()
        .map(|(i, s)| Expr::JointCombiner{power:i} * single_lookup(s))
        .fold(0.into(), |acc, x| acc + x)
}

pub struct LookupWitness<F: FftField> {
    // The lookups, sorted
    pub sorted: Vec<Evaluations<F, D<F>>>,
    // The lookups, in-order and with the product taken in each row
    pub f_chunks: Vec<F>,
}

const ZK_ROWS: usize = 2;

// Pad with zeroes and then add 2 random elements in the last two
// rows for zero knowledge.
fn zk_patch<R: Rng + ?Sized, F: FftField>(mut e : Vec<F>, d: D<F>, rng: &mut R) -> Evaluations<F, D<F>> {
    let n = d.size as usize;
    let k = e.len();
    assert!(k <= n - ZK_ROWS);
    e.extend((0..((n - ZK_ROWS) - k)).map(|_| F::zero()));
    e.extend((0..ZK_ROWS).map(|_| F::rand(rng)));
    Evaluations::<F, D<F>>::from_vec_and_domain(e, d)
}

/*
   Aggregration polyomial is the product of terms

    (1 + beta) \prod_j (gamma + f_{i,j}) (gamma(1 + beta) + t_i + beta t_{i+1})
    ---------------------------------------------------------------------------
    \prod_j (gamma(1 + beta) + s_{i,j} + beta s_{i+1,j})
*/
pub fn sorted<'a, R: Rng + ?Sized, F: FftField, I: Iterator<Item=&'a F>, G: Fn() -> I>(
    // TODO: Multiple/joint tables
    dummy_lookup_value: F,
    lookup_table: G,
    lookup_table_entries: usize,
    d1: D<F>,
    gates: &Vec<CircuitGate<F>>,
    witness: &[Vec<F>; COLUMNS],
    joint_combiner: F,
    rng: &mut R,
    ) -> Result<Vec<Evaluations<F, D<F>>>, ProofError>  
{
    // We pad the lookups so that it is as if we lookup exactly
    // `max_lookups_per_row` in every row.

    let n = d1.size as usize;
    let mut counts : HashMap<F, usize> = HashMap::new();
    /*
    let lookup_specs = lookup_specs::<F>();
    let max_lookups_per_row = GateType::max_lookups_per_row::<F>();
    */

    // let mut f_chunks = vec![];

    let lookup_rows = n - ZK_ROWS - 1;
    let lookup_info = LookupInfo::<F>::create();
    let by_row = lookup_info.by_row(gates);
    let max_lookups_per_row = lookup_info.max_per_row;

    for i in 0..lookup_rows {
        let eval = |pos : LocalPosition| -> F {
            let row = match pos.row { Curr => i, Next => i + 1 };
            witness[pos.column][row]
        };

        let spec = by_row[i];
        let padding = max_lookups_per_row - spec.len();
        // let mut f_chunk = complements[padding];
        for joint_lookup in spec.iter() {
            let table_entry = joint_lookup.evaluate(joint_combiner, &eval);
            // f_chunk *= table_entry;
            let count = counts.entry(table_entry).or_insert(0);
            *count += 1;
        }
        // f_chunks.push(f_chunk);
        *counts.entry(dummy_lookup_value).or_insert(0) += padding;
    }

    // TODO: Multiple/joint tables
    for t in lookup_table() {
        let count = counts.entry(*t).or_insert(0);
        *count += 1;
    }

    let sorted = {
        let mut sorted : Vec<Vec<F>> = vec![vec![]; max_lookups_per_row + 1];

        let mut i = 0;
        // TODO: Multiple/joint tables
        for t in lookup_table().take(lookup_table_entries) {
            let t_count = 
                match counts.get(t) {
                    None => return Err(ProofError::ValueNotInTable),
                    Some(x) => *x
                };
            for j in 0..t_count {
                let idx = i + j;
                let col = idx / lookup_rows;
                sorted[col].push(*t);
            }
            i += t_count;
        }
        assert_eq!(i, max_lookups_per_row * lookup_rows);
        for i in 0..max_lookups_per_row {
            let end_val = sorted[i + 1][0];
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

    Ok (
        sorted.into_iter()
        .map(|v| zk_patch(v, d1, rng))
        .collect())
}

pub fn aggregation<'a, R: Rng + ?Sized, F: FftField, I: Iterator<Item=&'a F>, G: Fn() -> I>(
    dummy_lookup_value: F,
    lookup_table: G,
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
    let gammabeta1 = gamma * (F::one() + beta);
    let mut lookup_aggreg = vec![F::one()];
    lookup_aggreg.extend((0..lookup_rows).map(|i| {
        sorted.iter().map(|v| gammabeta1 + v[i] + beta * v[i + 1])
            .fold(F::one(), |acc, x| acc * x)
    }));
    ark_ff::fields::batch_inversion::<F>(&mut lookup_aggreg[1..]);

    let lookup_info = LookupInfo::<F>::create();
    let max_lookups_per_row = lookup_info.max_per_row;

    let complements = {
        let mut v = vec![F::one()];
        let x = gamma + dummy_lookup_value;
        for i in 1..max_lookups_per_row {
            v.push(v[i - 1] * x)
        }
        v
    };

    // TODO: I somehow feel the number of t-differences is wrong. Check this.
    // TODO: Count the number of f chunks + t chunks, and the number of s chunks
    lookup_table().zip(lookup_table().skip(1)).take(lookup_rows)
        .zip(lookup_info.by_row(gates)).enumerate()
        .for_each(|(i, ((t0, t1), spec))| {
        let f_chunk = {
            let eval = |pos : LocalPosition| -> F {
                let row = match pos.row { Curr => i, Next => i + 1 };
                witness[pos.column][row]
            };

            let padding = complements[max_lookups_per_row - spec.len()];

            // This recomputes `joint_lookup.evaluate` on all the rows, which
            // is also computed in `sorted`. It should pretty cheap relative to
            // the whole cost of the prover, and saves us 
            // `max_lookups_per_row (=4) * n` field elements of
            // memory.
            spec.iter()
            .fold(padding, |acc, j| acc * j.evaluate(joint_combiner, &eval))
        };
        // At this point, lookup_aggreg[i + 1] contains 1/s_chunk

        // f_chunk / s_chunk
        lookup_aggreg[i + 1] *= f_chunk;
        // f_chunk * t_chunk / s_chunk
        lookup_aggreg[i + 1] *= gammabeta1 + t0 + t1;
        let prev = lookup_aggreg[i];
        // prev * f_chunk * t_chunk / s_chunk
        lookup_aggreg[i + 1] *= prev;
    });

    Ok(zk_patch(lookup_aggreg, d1, rng))
}

pub fn constraints<F: FftField>(dummy_lookup: F, d1: D<F>) -> Vec<Expr<F>> {
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

    let cell = |col:Column, row: CurrOrNext| Expr::<F>::Cell(Variable { col, row });
    let column = |col: Column| cell(col, Curr);

    let lookup_indicator =
        lookup_info.kinds.iter().enumerate().map(|(i, _)| {
            column(Column::LookupKindIndex(i))
        }).fold(0.into(), |acc: Expr<F>, x| acc + x);

    let one : Expr<F> = 1.into();
    let non_lookup_indcator = one - lookup_indicator;

    // This is set up so that on rows that have lookups, chunk will be equal
    // to the product over all lookups `f` in that row of `gamma + f`
    // and
    // on non-lookup rows, will be equal to 1.
    let f_term = |spec: &Vec<_>| {
        assert!(spec.len() <= lookup_info.max_per_row);
        let complement = vec![Expr::Constant(dummy_lookup); lookup_info.max_per_row - spec.len()];
        spec
        .iter()
        .map(|j| joint_lookup(j))
        .chain(complement)
        .map(|x| Expr::Gamma + x)
        .fold(1.into(), |acc: Expr<F>, x| acc * x)
    };
    let f_chunk =
        lookup_info.kinds.iter().enumerate()
        .map(|(i, spec)| {
            column(Column::LookupKindIndex(i)) * f_term(spec)
        }).fold(non_lookup_indcator * f_term(&vec![]), |acc, x| acc + x);
    let gammabeta1 = || Expr::<F>::Gamma * (Expr::Beta + 1.into());
    let ft_chunk = 
        f_chunk 
        * (gammabeta1() + cell(Column::LookupTable, Curr) + Expr::Beta * cell(Column::LookupTable, Next));

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
                + cell(Column::LookupSorted(i), s1)
                + Expr::Beta * cell(Column::LookupSorted(i), s2)
        })
        .fold(1.into(), |acc: Expr<F>, x| acc * x);

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
        Expr::UnnormalizedLagrangeBasis(first_or_last) * 
            (column(Column::LookupSorted(i)) - 
                column(Column::LookupSorted(i + 1)))
    }).collect();

    let aggreg_equation =
        cell(Column::LookupAggreg, Next) * s_chunk
        - cell(Column::LookupAggreg, Curr) * ft_chunk;

    // need to assert when creating constraint system that final 2 rows must be zero rows
    // also, should only do aggreg update on all but the last *3* rows

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
        Expr::ZkPolynomial * aggreg_equation,
        Expr::UnnormalizedLagrangeBasis(0) *
            (cell(Column::LookupAggreg, Curr) - 1.into()),
        // Check that the 3rd to last row (index = num_rows - 3), which
        // contains the full product, equals 1
        Expr::UnnormalizedLagrangeBasis(last_lookup_row_index + 1) *
            (cell(Column::LookupAggreg, Curr) - 1.into()),
    ];
    res.extend(compatibility_checks);
    res
}
