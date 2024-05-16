//! This module defines structures and traits to build and manipulate traces.
//! A trace is a collection of data points that represent the execution of a
//! program.
//! Some trace can be seen as "decomposable" in the sense that they can be
//! divided into sub-traces that share the same columns, and sub-traces can be
//! selected using "selectors".

use crate::{
    folding::{BaseField, FoldingInstance, FoldingWitness, ScalarField},
    lookups::Lookup,
    E,
};
use ark_ff::{One, Zero};
use ark_poly::{Evaluations, Radix2EvaluationDomain as D};
use folding::{expressions::FoldingCompatibleExpr, Alphas, FoldingConfig};
use itertools::Itertools;
use kimchi::circuits::expr::ChallengeTerm;
use kimchi_msm::{columns::Column, witness::Witness};
use mina_poseidon::sponge::FqSponge;
use poly_commitment::{commitment::absorb_commitment, PolyComm, SRS as _};
use rayon::{iter::ParallelIterator, prelude::IntoParallelIterator};
use std::{collections::BTreeMap, ops::Index};

/// Returns the index of the witness column in the trace.
pub trait Indexer {
    fn ix(&self) -> usize;
}

/// Represents an provable trace.
/// A trace is provable if it can be used to prove the correctness of the
/// computation it embeds.
/// For now, the only requirement is to be able to return the length of
/// the computation, which is commonly named the domain size.
pub trait ProvableTrace {
    fn domain_size(&self) -> usize;
}

/// Implement a trace for a single instruction.
// TODO: we should use the generic traits defined in [kimchi_msm].
// For now, we want to have this to be able to test the folding library for a
// single instruction.
// It is not recommended to use this in production and it should not be
// maintained in the long term.
#[derive(Clone)]
pub struct Trace<const N: usize, C: FoldingConfig> {
    pub domain_size: usize,
    pub witness: Witness<N, Vec<ScalarField<C>>>,
    pub constraints: Vec<E<ScalarField<C>>>,
    pub lookups: Vec<Lookup<E<ScalarField<C>>>>,
}

// Any single instruction trace is provable.
impl<const N: usize, C: FoldingConfig> ProvableTrace for Trace<N, C> {
    fn domain_size(&self) -> usize {
        self.domain_size
    }
}

/// Struct representing a circuit execution trace which is decomposable in
/// individual sub-circuits sharing the same columns.
/// It is parameterized by
/// - `N`: the total number of columns (constant), it must equal `N_REL + N_DSEL`
/// - `N_REL`: the number of relation columns (constant),
/// - `N_DSEL`: the number of dynamic selector columns (constant),
/// - `Selector`: an enum representing the different gate behaviours,
/// - `F`: the type of the witness data.
#[derive(Clone)]
pub struct DecomposedTrace<const N: usize, C: FoldingConfig> {
    /// The domain size of the circuit (should coincide with that of the traces)
    pub domain_size: usize,
    /// The traces are indexed by the selector
    /// Inside the witness of the trace for a given selector,
    /// - the last N_SEL columns represent the selector columns
    ///   and only the one for `Selector` should be all ones (the rest of selector columns should be all zeros)
    pub trace: BTreeMap<C::Selector, Trace<N, C>>,
}

// Implementation of [Index] using `C::Selector`` as the index for [DecomposedTrace] to access the trace directly.
impl<const N: usize, C: FoldingConfig> Index<C::Selector> for DecomposedTrace<N, C> {
    type Output = Trace<N, C>;

    fn index(&self, index: C::Selector) -> &Self::Output {
        &self.trace[&index]
    }
}

// Any decomposable trace is provable.
impl<const N: usize, C: FoldingConfig> ProvableTrace for DecomposedTrace<N, C> {
    fn domain_size(&self) -> usize {
        self.domain_size
    }
}

impl<const N: usize, C: FoldingConfig> DecomposedTrace<N, C>
where
    C::Selector: Indexer,
{
    /// Returns the number of rows that have been instantiated for the given
    /// selector.
    /// It is important that the column used is a relation column because
    /// selector columns are only instantiated at the very end, so their length
    /// could be zero most times.
    /// That is the reason that relation columns are located first.
    pub fn number_of_rows(&self, opcode: C::Selector) -> usize {
        self[opcode].witness.cols[0].len()
    }

    /// Returns a boolean indicating whether the witness for the given selector
    /// was ever found in the cirucit or not.
    pub fn in_circuit(&self, opcode: C::Selector) -> bool {
        self.number_of_rows(opcode) != 0
    }

    /// Returns whether the witness for the given selector has achieved a number
    /// of rows that is equal to the domain size.
    pub fn is_full(&self, opcode: C::Selector) -> bool {
        self.domain_size == self.number_of_rows(opcode)
    }

    /// Resets the witness after folding
    pub fn reset(&mut self, opcode: C::Selector) {
        (self.trace.get_mut(&opcode).unwrap().witness.cols.as_mut())
            .iter_mut()
            .for_each(Vec::clear);
    }

    /// Sets the selector column to all ones, and the rest to all zeros
    pub fn set_selector_column<const N_REL: usize>(
        &mut self,
        selector: C::Selector,
        number_of_rows: usize,
    ) {
        (N_REL..N).for_each(|i| {
            if i == selector.ix() {
                self.trace.get_mut(&selector).unwrap().witness.cols[i]
                    .extend((0..number_of_rows).map(|_| ScalarField::<C>::one()))
            } else {
                self.trace.get_mut(&selector).unwrap().witness.cols[i]
                    .extend((0..number_of_rows).map(|_| ScalarField::<C>::zero()))
            }
        });
    }
}

/// The trait [Foldable] describes structures that can be folded.
/// For that, it requires to be able to implement a way to return a folding
/// instance and a folding witness.
/// It is specialized for the [DecomposedTrace] struct for now and is expected
/// to fold individual instructions, selected with a specific `C::Selector`.
pub trait Foldable<const N: usize, C: FoldingConfig, Sponge> {
    /// Returns the witness for the given selector as a folding witness and
    /// folding instance pair.
    /// Note that this function will also absorb all commitments to the columns
    /// to coin challenges appropriately.
    fn to_folding_pair(
        &self,
        selector: C::Selector,
        fq_sponge: &mut Sponge,
        domain: D<ScalarField<C>>,
        srs: &poly_commitment::srs::SRS<C::Curve>,
    ) -> (
        FoldingInstance<N, C::Curve>,
        FoldingWitness<N, ScalarField<C>>,
    );

    /// Returns a map of constraints that are compatible with folding for each selector
    fn folding_constraints(&self) -> BTreeMap<C::Selector, Vec<FoldingCompatibleExpr<C>>>;
}

/// Implement the trait Foldable for the structure [DecomposedTrace]
impl<const N: usize, C: FoldingConfig<Column = Column>, Sponge> Foldable<N, C, Sponge>
    for DecomposedTrace<N, C>
where
    C::Selector: Indexer,
    Sponge: FqSponge<BaseField<C>, C::Curve, ScalarField<C>>,
    <C as FoldingConfig>::Challenge: From<ChallengeTerm>,
{
    fn to_folding_pair(
        &self,
        selector: C::Selector,
        fq_sponge: &mut Sponge,
        domain: D<ScalarField<C>>,
        srs: &poly_commitment::srs::SRS<C::Curve>,
    ) -> (
        FoldingInstance<N, C::Curve>,
        FoldingWitness<N, ScalarField<C>>,
    ) {
        let folding_witness = FoldingWitness {
            witness: (&self[selector].witness)
                .into_par_iter()
                .map(|w| Evaluations::from_vec_and_domain(w.to_vec(), domain))
                .collect(),
        };

        let commitments: Witness<N, PolyComm<C::Curve>> = (&folding_witness.witness)
            .into_par_iter()
            .map(|w| srs.commit_evaluations_non_hiding(domain, w))
            .collect();

        // Absorbing commitments
        (&commitments)
            .into_iter()
            .for_each(|c| absorb_commitment(fq_sponge, c));

        let commitments: [C::Curve; N] = commitments
            .into_iter()
            .map(|c| c.elems[0])
            .collect_vec()
            .try_into()
            .unwrap();

        let beta = fq_sponge.challenge();
        let gamma = fq_sponge.challenge();
        let joint_combiner = fq_sponge.challenge();
        let alpha = fq_sponge.challenge();
        let challenges = [beta, gamma, joint_combiner];
        let alphas = Alphas::new(alpha);
        let instance = FoldingInstance {
            commitments,
            challenges,
            alphas,
        };

        (instance, folding_witness)
    }

    fn folding_constraints(&self) -> BTreeMap<C::Selector, Vec<FoldingCompatibleExpr<C>>> {
        self.trace
            .iter()
            .map(|(k, instr)| {
                (
                    *k,
                    instr
                        .constraints
                        .iter()
                        .map(|x| FoldingCompatibleExpr::from(x.clone()))
                        .collect(),
                )
            })
            .collect()
    }
}

/// Tracer builds traces for some program executions.
/// The constant type `N_REL` is defined as the maximum number of relation
/// columns the trace can use per row.
/// The type `C` encodes the folding configuration, from which the selector,
/// which encodes the information of the kind of information the trace encodes,
/// and scalar field are derived. Examples of selectors are:
/// - For Keccak, `Step` encodes the row being performed at a time: round,
/// squeeze, padding, etc...
/// - For MIPS, `Instruction` encodes the CPU instruction being executed: add,
/// sub, load, store, etc...
pub trait Tracer<const N_REL: usize, C: FoldingConfig, Env> {
    type Selector;

    /// Initialize a new trace with the given domain size, selector, and environment.
    fn init(domain_size: usize, selector: C::Selector, env: &mut Env) -> Self;

    /// Add a witness row to the circuit (only for relation columns)
    fn push_row(&mut self, selector: Self::Selector, row: &[ScalarField<C>; N_REL]);

    /// Pad the rows of one opcode with the given row until
    /// reaching the domain size if needed.
    /// Returns the number of rows that were added.
    /// It does not add selector columns.
    fn pad_with_row(&mut self, selector: Self::Selector, row: &[ScalarField<C>; N_REL]) -> usize;

    /// Pads the rows of one opcode with zero rows until
    /// reaching the domain size if needed.
    /// Returns the number of rows that were added.
    /// It does not add selector columns.
    fn pad_with_zeros(&mut self, selector: Self::Selector) -> usize;

    /// Pad the rows of one opcode with the first row until
    /// reaching the domain size if needed.
    /// It only tries to pad witnesses which are non empty.
    /// Returns the number of rows that were added.
    /// It does not add selector columns.
    /// - Use `None` for single traces
    /// - Use `Some(selector)` for multi traces
    fn pad_dummy(&mut self, selector: Self::Selector) -> usize;
}

/// DecomposableTracer builds traces for some program executions.
/// The constant type `N_REL` is defined as the maximum number of relation
/// columns the trace can use per row.
/// The type `C` encodes the folding configuration, from which the selector,
/// and scalar field are derived. Examples of selectors are:
/// - For Keccak, `Step` encodes the row being performed at a time: round,
/// squeeze, padding, etc...
/// - For MIPS, `Instruction` encodes the CPU instruction being executed: add,
/// sub, load, store, etc...
pub trait DecomposableTracer<Env> {
    /// Create a new decomposable trace with the given domain size, and environment.
    fn new(domain_size: usize, env: &mut Env) -> Self;

    /// Pads the rows of the witnesses until reaching the domain size using the first
    /// row repeatedly. It does not add selector columns.
    fn pad_witnesses(&mut self);
}

/// Generic implementation of the [Tracer] trait for the [DecomposedTrace] struct.
/// It requires the [DecomposedTrace] to implement the [DecomposableTracer] trait,
/// and the [Trace] struct to implement the [Tracer] trait with Selector set to (),
/// and the `C::Selector` to implement the [Indexer] trait.
impl<const N: usize, const N_REL: usize, C: FoldingConfig, Env> Tracer<N_REL, C, Env>
    for DecomposedTrace<N, C>
where
    DecomposedTrace<N, C>: DecomposableTracer<Env>,
    Trace<N, C>: Tracer<N_REL, C, Env, Selector = ()>,
    <C as FoldingConfig>::Selector: Indexer,
{
    type Selector = C::Selector;

    fn init(domain_size: usize, _selector: C::Selector, env: &mut Env) -> Self {
        <Self as DecomposableTracer<Env>>::new(domain_size, env)
    }

    fn push_row(&mut self, selector: Self::Selector, row: &[ScalarField<C>; N_REL]) {
        self.trace.get_mut(&selector).unwrap().push_row((), row);
    }

    fn pad_with_row(&mut self, selector: Self::Selector, row: &[ScalarField<C>; N_REL]) -> usize {
        // We only want to pad non-empty witnesses.
        if !self.in_circuit(selector) {
            0
        } else {
            self.trace.get_mut(&selector).unwrap().pad_with_row((), row)
        }
    }

    fn pad_with_zeros(&mut self, selector: Self::Selector) -> usize {
        // We only want to pad non-empty witnesses.
        if !self.in_circuit(selector) {
            0
        } else {
            self.trace.get_mut(&selector).unwrap().pad_with_zeros(())
        }
    }

    fn pad_dummy(&mut self, selector: Self::Selector) -> usize {
        // We only want to pad non-empty witnesses.
        if !self.in_circuit(selector) {
            0
        } else {
            self.trace.get_mut(&selector).unwrap().pad_dummy(())
        }
    }
}
