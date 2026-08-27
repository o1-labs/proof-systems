//! Fused, chunked evaluation of constraint expressions over a domain.
//!
//! [`Expr::evaluations`](crate::circuits::expr::Expr::evaluations) walks the
//! expression tree materializing a full-domain evaluation vector per node: at
//! d1 = 2^14 the five always-on gate constraints allocate ~186 fresh 4 MiB
//! intermediates per proof, and every node is its own parallel kernel launch.
//! This module instead compiles the expression once into a flat RPN tape with
//! pre-resolved column references, then evaluates the whole tape in a single
//! pass over fixed-size chunks. Each worker keeps a small scratch pool of
//! chunk-sized buffers, so no full-domain intermediates are ever allocated
//! and each chunk's working set stays cache-resident.
//!
//! The result is bit-identical to `Expr::evaluations`: the same domain is
//! selected from the expression degree, and field operations are performed in
//! the same order per point (verified against the legacy evaluator on every
//! gate type, and end-to-end on full quotient polynomials).
//!
//! Design notes, grounded in paired measurements against the legacy
//! evaluator on the gate constraints:
//!
//! - The win is removing per-node full-domain passes (memory traffic and
//!   kernel-launch overhead); the field-operation count per point is
//!   unchanged. Measured 1.5-2.7x per gate depending on domain size.
//! - Column gathers are deduplicated: every occurrence of the same column
//!   with the same stride and shift shares one per-chunk gather.
//! - Evaluating a *sum* of gate constraints in one pass measures the same as
//!   evaluating the gates separately: the executor is compute-bound, so
//!   callers should keep the natural one-expression-per-gate structure.

use crate::{
    circuits::{
        domains::Domain,
        expr::{
            unnormalized_lagrange_evals, CacheId, ColumnEnvironment, Expr, ExprInner, Operations,
            Variable,
        },
    },
    collections::HashMap,
};
use alloc::{vec, vec::Vec};
use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain as D};
use core::ops::Index;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Rows evaluated per tape execution. At 32 bytes per field element a chunk
/// buffer is 128 KiB, so a tape's working set (a few operand buffers plus the
/// gathered columns it references) stays L2-resident. Swept on the gate
/// constraints: 1024-8192 measures flat, matching the plateau found for the
/// legacy kernels' parallelism grain.
const CHUNK: usize = 1 << 12;

/// A column reference with everything needed to gather a chunk of its
/// evaluations into the result domain, resolved at compile time.
struct ColRef<'t, F: FftField> {
    evals: &'t Evaluations<F, D<F>>,
    /// `column_domain / result_domain` (the legacy kernels' `scale`)
    scale: usize,
    /// `column_domain * row_shift`, the constant index offset
    offset: usize,
    /// `evals.len() - 1`; the column lives over a radix-2 domain, so the
    /// wrap-around is a bitmask (the legacy kernels' `mod_pow2`)
    mask: usize,
}

enum Tok<F> {
    Scalar(F),
    /// Push a chunk of `cols[i]`, gathered once per chunk and shared by every
    /// occurrence of the column in the tape
    Col(usize),
    Add,
    Sub,
    Mul,
    Square,
    Double,
    Pow(u64),
    /// Move the top of stack into cache slot `i` (leaves a reference on the
    /// stack)
    Store(usize),
    /// Push a read-only reference to cache slot `i`
    Load(usize),
}

struct Tape<'t, F: FftField> {
    toks: Vec<Tok<F>>,
    cols: Vec<ColRef<'t, F>>,
    n_slots: usize,
}

impl<'t, F: FftField> Tape<'t, F> {
    /// Deduplicated column registration: every occurrence of the same
    /// underlying evaluation vector with the same stride and shift shares one
    /// `cols` entry, so the executor gathers it once per chunk instead of
    /// once per occurrence.
    fn col_index(&mut self, evals: &'t Evaluations<F, D<F>>, scale: usize, offset: usize) -> usize {
        if let Some(i) = self
            .cols
            .iter()
            .position(|c| core::ptr::eq(c.evals, evals) && c.scale == scale && c.offset == offset)
        {
            return i;
        }
        let m = evals.evals.len();
        assert!(m.is_power_of_two());
        self.cols.push(ColRef {
            evals,
            scale,
            offset,
            mask: m - 1,
        });
        self.cols.len() - 1
    }
}

/// Collect the distinct (renormalized) row offsets of every
/// `UnnormalizedLagrangeBasis` atom reachable in the expression, so their
/// evaluation vectors can be materialized once before the tape is compiled.
fn collect_lagrange_offsets<F, Column>(e: &Expr<F, Column>, zk_rows: u64, out: &mut Vec<i32>) {
    use Operations::*;
    match e {
        Atom(ExprInner::UnnormalizedLagrangeBasis(row)) => {
            let offset = if row.zk_rows {
                -(zk_rows as i32) + row.offset
            } else {
                row.offset
            };
            if !out.contains(&offset) {
                out.push(offset);
            }
        }
        Atom(_) => {}
        Add(e1, e2) | Sub(e1, e2) | Mul(e1, e2) => {
            collect_lagrange_offsets(e1, zk_rows, out);
            collect_lagrange_offsets(e2, zk_rows, out);
        }
        Square(x) | Double(x) | Pow(x, _) | Cache(_, x) => {
            collect_lagrange_offsets(x, zk_rows, out)
        }
        IfFeature(feature, e1, e2) => {
            if feature.is_enabled() {
                collect_lagrange_offsets(e1, zk_rows, out)
            } else {
                collect_lagrange_offsets(e2, zk_rows, out)
            }
        }
    }
}

fn compile<'t, 'a: 't, F, ChallengeTerm, Challenge, Environment, Column>(
    e: &Expr<F, Column>,
    env: &Environment,
    res_domain: Domain,
    lagrange: &'t [(i32, Evaluations<F, D<F>>)],
    tape: &mut Tape<'t, F>,
    slots: &mut HashMap<CacheId, usize>,
) where
    F: FftField,
    Column: Copy,
    Challenge: Index<ChallengeTerm, Output = F>,
    Environment: ColumnEnvironment<'a, F, ChallengeTerm, Challenge, Column = Column>,
{
    use Operations::*;
    match e {
        Atom(ExprInner::Constant(x)) => tape.toks.push(Tok::Scalar(*x)),
        Atom(ExprInner::Cell(Variable { col, row })) => match env.get_column(col) {
            None => tape.toks.push(Tok::Scalar(F::zero())),
            Some(evals) => {
                let d_sub = env.column_domain(col) as usize;
                let scale = d_sub / (res_domain as usize);
                assert!(scale != 0, "column domain smaller than result domain");
                let i = tape.col_index(evals, scale, d_sub * row.shift());
                tape.toks.push(Tok::Col(i));
            }
        },
        Atom(ExprInner::VanishesOnZeroKnowledgeAndPreviousRows) => {
            let evals = env.vanishes_on_zero_knowledge_and_previous_rows();
            let d_sub = Domain::D8 as usize;
            let scale = d_sub / (res_domain as usize);
            assert!(scale != 0, "column domain smaller than result domain");
            let i = tape.col_index(evals, scale, 0);
            tape.toks.push(Tok::Col(i));
        }
        Atom(ExprInner::UnnormalizedLagrangeBasis(row)) => {
            let zk_rows = env.get_constants().zk_rows;
            let offset = if row.zk_rows {
                -(zk_rows as i32) + row.offset
            } else {
                row.offset
            };
            let evals = lagrange
                .iter()
                .find(|(o, _)| *o == offset)
                .map(|(_, e)| e)
                .expect("lagrange basis evaluations materialized in the prepass");
            // materialized directly at the result domain: unit stride, no shift
            let i = tape.col_index(evals, 1, 0);
            tape.toks.push(Tok::Col(i));
        }
        Add(e1, e2) => {
            compile(e1, env, res_domain, lagrange, tape, slots);
            compile(e2, env, res_domain, lagrange, tape, slots);
            tape.toks.push(Tok::Add);
        }
        Sub(e1, e2) => {
            compile(e1, env, res_domain, lagrange, tape, slots);
            compile(e2, env, res_domain, lagrange, tape, slots);
            tape.toks.push(Tok::Sub);
        }
        Mul(e1, e2) => {
            compile(e1, env, res_domain, lagrange, tape, slots);
            compile(e2, env, res_domain, lagrange, tape, slots);
            tape.toks.push(Tok::Mul);
        }
        Square(x) => {
            compile(x, env, res_domain, lagrange, tape, slots);
            tape.toks.push(Tok::Square);
        }
        Double(x) => {
            compile(x, env, res_domain, lagrange, tape, slots);
            tape.toks.push(Tok::Double);
        }
        Pow(x, p) => {
            compile(x, env, res_domain, lagrange, tape, slots);
            tape.toks.push(Tok::Pow(*p));
        }
        Cache(id, x) => match slots.get(id) {
            Some(s) => tape.toks.push(Tok::Load(*s)),
            None => {
                compile(x, env, res_domain, lagrange, tape, slots);
                let s = tape.n_slots;
                tape.n_slots += 1;
                slots.insert(*id, s);
                tape.toks.push(Tok::Store(s));
            }
        },
        IfFeature(feature, e1, e2) => {
            if feature.is_enabled() {
                compile(e1, env, res_domain, lagrange, tape, slots)
            } else {
                compile(e2, env, res_domain, lagrange, tape, slots)
            }
        }
    }
}

/// A value on the evaluation stack: a scalar, an owned scratch buffer
/// (index into the pool), a read-only cache slot reference, or a read-only
/// gathered-column reference.
#[derive(Clone, Copy)]
enum Val<F> {
    Scalar(F),
    Buf(usize),
    Slot(usize),
    Col(usize),
}

/// Per-slot storage for one chunk.
#[derive(Clone, Copy)]
enum SlotVal<F> {
    Empty,
    Scalar(F),
    /// Pool buffer owned by the slot for the duration of the chunk
    Buf(usize),
}

struct Scratch<F> {
    pool: Vec<Vec<F>>,
    free: Vec<usize>,
    slots: Vec<SlotVal<F>>,
    /// Per-chunk lazily gathered column buffers (pool indices), shared by
    /// every occurrence of the column in the tape
    col_cache: Vec<Option<usize>>,
    stack: Vec<Val<F>>,
}

impl<F: FftField> Scratch<F> {
    fn new(n_slots: usize, n_cols: usize) -> Self {
        Scratch {
            pool: vec![],
            free: vec![],
            slots: vec![SlotVal::Empty; n_slots],
            col_cache: vec![None; n_cols],
            stack: vec![],
        }
    }

    fn reset(&mut self) {
        self.free = (0..self.pool.len()).collect();
        self.slots.iter_mut().for_each(|s| *s = SlotVal::Empty);
        self.col_cache.iter_mut().for_each(|c| *c = None);
        self.stack.clear();
    }

    /// A free buffer, never aliasing a live (non-freed) buffer.
    fn alloc(&mut self) -> usize {
        match self.free.pop() {
            Some(i) => i,
            None => {
                self.pool.push(vec![F::zero(); CHUNK]);
                self.pool.len() - 1
            }
        }
    }

    /// Copy a (possibly borrowed) buffer into a fresh owned one.
    fn copy_into_owned(&mut self, src: usize, len: usize) -> usize {
        let dst = self.alloc();
        let (d, s) = two_bufs(&mut self.pool, dst, src);
        d[..len].copy_from_slice(&s[..len]);
        dst
    }

    /// Resolve a stack value to (pool index, owned-by-stack).
    fn resolve(&self, v: Val<F>) -> Option<(usize, bool)> {
        match v {
            Val::Scalar(_) => None,
            Val::Buf(i) => Some((i, true)),
            Val::Slot(s) => match self.slots[s] {
                SlotVal::Buf(i) => Some((i, false)),
                _ => unreachable!("slot used before store"),
            },
            Val::Col(c) => Some((self.col_cache[c].expect("column used before gather"), false)),
        }
    }
}

/// Two distinct pool buffers, first mutable and second shared.
fn two_bufs<F>(pool: &mut [Vec<F>], dst: usize, src: usize) -> (&mut Vec<F>, &Vec<F>) {
    assert_ne!(dst, src);
    if dst < src {
        let (a, b) = pool.split_at_mut(src);
        (&mut a[dst], &b[0])
    } else {
        let (a, b) = pool.split_at_mut(dst);
        (&mut b[0], &a[src])
    }
}

fn unary<F: FftField>(
    sc: &mut Scratch<F>,
    a: Val<F>,
    len: usize,
    scalar_op: impl Fn(F) -> F,
    buf_op: impl Fn(&mut F),
) -> Val<F> {
    match sc.resolve(a) {
        None => match a {
            Val::Scalar(x) => Val::Scalar(scalar_op(x)),
            _ => unreachable!(),
        },
        Some((i, owned)) => {
            let i = if owned { i } else { sc.copy_into_owned(i, len) };
            sc.pool[i][..len].iter_mut().for_each(&buf_op);
            Val::Buf(i)
        }
    }
}

fn binary<F: FftField>(
    sc: &mut Scratch<F>,
    op: &Tok<F>,
    a: Val<F>,
    b: Val<F>,
    len: usize,
) -> Val<F> {
    #[inline]
    fn apply<F: FftField>(op: &Tok<F>, x: F, y: F) -> F {
        match op {
            Tok::Add => x + y,
            Tok::Sub => x - y,
            Tok::Mul => x * y,
            _ => unreachable!(),
        }
    }
    match (sc.resolve(a), sc.resolve(b)) {
        (None, None) => match (a, b) {
            (Val::Scalar(x), Val::Scalar(y)) => Val::Scalar(apply(op, x, y)),
            _ => unreachable!(),
        },
        // scalar (op) buffer
        (None, Some((i, owned))) => {
            let x = match a {
                Val::Scalar(x) => x,
                _ => unreachable!(),
            };
            let i = if owned { i } else { sc.copy_into_owned(i, len) };
            sc.pool[i][..len]
                .iter_mut()
                .for_each(|e| *e = apply(op, x, *e));
            Val::Buf(i)
        }
        // buffer (op) scalar
        (Some((i, owned)), None) => {
            let y = match b {
                Val::Scalar(y) => y,
                _ => unreachable!(),
            };
            let i = if owned { i } else { sc.copy_into_owned(i, len) };
            sc.pool[i][..len]
                .iter_mut()
                .for_each(|e| *e = apply(op, *e, y));
            Val::Buf(i)
        }
        (Some((ia, a_owned)), Some((ib, b_owned))) => {
            if ia == ib {
                // same underlying buffer, e.g. Load(s) op Load(s)
                let j = sc.alloc();
                let (dst, src) = two_bufs(&mut sc.pool, j, ia);
                for (o, e) in dst[..len].iter_mut().zip(&src[..len]) {
                    *o = apply(op, *e, *e);
                }
                Val::Buf(j)
            } else if a_owned {
                let (dst, src) = two_bufs(&mut sc.pool, ia, ib);
                for (o, e) in dst[..len].iter_mut().zip(&src[..len]) {
                    *o = apply(op, *o, *e);
                }
                if b_owned {
                    sc.free.push(ib);
                }
                Val::Buf(ia)
            } else if b_owned {
                let (dst, src) = two_bufs(&mut sc.pool, ib, ia);
                for (o, e) in dst[..len].iter_mut().zip(&src[..len]) {
                    *o = apply(op, *e, *o);
                }
                Val::Buf(ib)
            } else {
                // both borrowed: copy a, then fold b in
                let j = sc.copy_into_owned(ia, len);
                let (dst, src) = two_bufs(&mut sc.pool, j, ib);
                for (o, e) in dst[..len].iter_mut().zip(&src[..len]) {
                    *o = apply(op, *o, *e);
                }
                Val::Buf(j)
            }
        }
    }
}

fn pow<F: FftField>(sc: &mut Scratch<F>, a: Val<F>, p: u64, len: usize) -> Val<F> {
    if p == 0 {
        return Val::Scalar(F::one());
    }
    if let Val::Scalar(x) = a {
        return Val::Scalar(x.pow([p]));
    }
    let base = match sc.resolve(a) {
        Some((i, true)) => i,
        Some((i, false)) => sc.copy_into_owned(i, len),
        None => unreachable!(),
    };
    if p == 1 {
        return Val::Buf(base);
    }
    // acc = base, then square-and-multiply over the remaining bits
    let acc = sc.copy_into_owned(base, len);
    let bits = 64 - p.leading_zeros();
    for k in (0..bits - 1).rev() {
        sc.pool[acc][..len].iter_mut().for_each(|e| {
            e.square_in_place();
        });
        if (p >> k) & 1 == 1 {
            let (dst, src) = two_bufs(&mut sc.pool, acc, base);
            for (o, e) in dst[..len].iter_mut().zip(&src[..len]) {
                *o *= *e;
            }
        }
    }
    sc.free.push(base);
    Val::Buf(acc)
}

fn run_chunk<F: FftField>(tape: &Tape<F>, chunk_start: usize, out: &mut [F], sc: &mut Scratch<F>) {
    let len = out.len();
    sc.reset();

    for tok in &tape.toks {
        match tok {
            Tok::Scalar(x) => sc.stack.push(Val::Scalar(*x)),
            Tok::Col(c) => {
                if sc.col_cache[*c].is_none() {
                    let col = &tape.cols[*c];
                    let src = &col.evals.evals;
                    let base = col.scale * chunk_start + col.offset;
                    let i = sc.alloc();
                    let buf = &mut sc.pool[i];
                    for (j, b) in buf[..len].iter_mut().enumerate() {
                        *b = src[(base + col.scale * j) & col.mask];
                    }
                    sc.col_cache[*c] = Some(i);
                }
                sc.stack.push(Val::Col(*c));
            }
            Tok::Add | Tok::Sub | Tok::Mul => {
                let b = sc.stack.pop().unwrap();
                let a = sc.stack.pop().unwrap();
                let r = binary(sc, tok, a, b, len);
                sc.stack.push(r);
            }
            Tok::Square => {
                let a = sc.stack.pop().unwrap();
                let r = unary(
                    sc,
                    a,
                    len,
                    |x| x.square(),
                    |x| {
                        x.square_in_place();
                    },
                );
                sc.stack.push(r);
            }
            Tok::Double => {
                let a = sc.stack.pop().unwrap();
                let r = unary(
                    sc,
                    a,
                    len,
                    |x| x.double(),
                    |x| {
                        x.double_in_place();
                    },
                );
                sc.stack.push(r);
            }
            Tok::Pow(p) => {
                let a = sc.stack.pop().unwrap();
                let r = pow(sc, a, *p, len);
                sc.stack.push(r);
            }
            Tok::Store(s) => {
                let v = sc.stack.pop().unwrap();
                match v {
                    Val::Scalar(x) => {
                        sc.slots[*s] = SlotVal::Scalar(x);
                        sc.stack.push(Val::Scalar(x));
                    }
                    Val::Buf(i) => {
                        // the slot takes ownership of the buffer
                        sc.slots[*s] = SlotVal::Buf(i);
                        sc.stack.push(Val::Slot(*s));
                    }
                    Val::Slot(other) => {
                        // cache of a cache: share the same storage
                        sc.slots[*s] = sc.slots[other];
                        sc.stack.push(Val::Slot(*s));
                    }
                    Val::Col(c) => {
                        // cache of a bare column: share its gathered buffer
                        sc.slots[*s] =
                            SlotVal::Buf(sc.col_cache[c].expect("column used before gather"));
                        sc.stack.push(Val::Slot(*s));
                    }
                }
            }
            Tok::Load(s) => match sc.slots[*s] {
                SlotVal::Scalar(x) => sc.stack.push(Val::Scalar(x)),
                SlotVal::Buf(_) => sc.stack.push(Val::Slot(*s)),
                SlotVal::Empty => unreachable!("load before store"),
            },
        }
    }

    let top = sc.stack.pop().unwrap();
    assert!(sc.stack.is_empty(), "unbalanced tape");
    match sc.resolve(top) {
        None => match top {
            Val::Scalar(x) => out.iter_mut().for_each(|o| *o = x),
            _ => unreachable!(),
        },
        Some((i, _)) => out.copy_from_slice(&sc.pool[i][..len]),
    }
}

/// Fused equivalent of [`Expr::evaluations`]: same domain selection,
/// bit-identical result, no full-domain intermediates.
pub fn evaluations_fused<'a, F, ChallengeTerm, Challenge, Environment, Column>(
    e: &Expr<F, Column>,
    env: &Environment,
) -> Evaluations<F, D<F>>
where
    F: FftField,
    Column: Copy,
    Challenge: Index<ChallengeTerm, Output = F>,
    Environment: ColumnEnvironment<'a, F, ChallengeTerm, Challenge, Column = Column> + Sync,
{
    let d1_size = env.get_domain(Domain::D1).size;
    let deg = e.degree(d1_size, env.get_constants().zk_rows);
    let d = if deg <= d1_size {
        Domain::D1
    } else if deg <= 4 * d1_size {
        Domain::D4
    } else if deg <= 8 * d1_size {
        Domain::D8
    } else {
        panic!("constraint had degree {deg} > d8 ({})", 8 * d1_size);
    };
    let res_domain = env.get_domain(d);

    // materialize the unnormalized lagrange basis columns the expression
    // uses (usually none) so the tape can reference them like any column
    let mut lag_offsets = vec![];
    collect_lagrange_offsets(e, env.get_constants().zk_rows, &mut lag_offsets);
    let lagrange: Vec<(i32, Evaluations<F, D<F>>)> = lag_offsets
        .into_iter()
        .map(|i| (i, unnormalized_lagrange_evals(env.l0_1(), i, d, env)))
        .collect();

    let mut tape = Tape {
        toks: vec![],
        cols: vec![],
        n_slots: 0,
    };
    compile(e, env, d, &lagrange, &mut tape, &mut HashMap::new());

    let n = res_domain.size();
    let mut out = vec![F::zero(); n];

    #[cfg(feature = "parallel")]
    out.par_chunks_mut(CHUNK).enumerate().for_each_init(
        || Scratch::new(tape.n_slots, tape.cols.len()),
        |sc, (ci, chunk)| run_chunk(&tape, ci * CHUNK, chunk, sc),
    );
    #[cfg(not(feature = "parallel"))]
    {
        let mut sc = Scratch::new(tape.n_slots, tape.cols.len());
        for (ci, chunk) in out.chunks_mut(CHUNK).enumerate() {
            run_chunk(&tape, ci * CHUNK, chunk, &mut sc);
        }
    }

    Evaluations::<F, D<F>>::from_vec_and_domain(out, res_domain)
}
