#![allow(clippy::type_complexity)]

//! Implement a variant of the logarithmic derivative lookups based on the
//! equations described in the paper ["Multivariate lookups based on logarithmic
//! derivatives"](https://eprint.iacr.org/2022/1530.pdf).
//!
//! The variant is mostly based on the observation that the polynomial
//! identities can be verified using the "Idealised low-degree protocols"
//! described in the section 4 of the
//! ["PlonK"](https://eprint.iacr.org/2019/953.pdf) paper and "the quotient
//! polynomial" described in the round 3 of the PlonK protocol, instead of using
//! the sumcheck protocol.
//!
//! The protocol is based on the following observations:
//!
//! The sequence (a_i) is included in (b_i) if and only if the following
//! equation holds:
//! ```text
//!   k       1        l      m_i
//!   ∑    -------  =  ∑    -------                          (1)
//!  i=1   β + a_i    i=1   β + b_i
//! ```
//! where m_i is the number of times a_i appears in the sequence b_i.
//!
//! The sequence (b_i) will refer to the table values and the sequence (a_i) the
//! values the prover looks up.
//!
//! For readability, the table values are represented as the evaluations over a
//! subgroup H of the field F of a
//! polynomial t(X), and the looked-up values by the evaluations of a polynomial
//! f(X). If we suppose the subgroup H is defined as {1, ω, ω^2, ..., ω^{n-1}},
//! the equation (1) becomes:
//!
//! ```text
//!   n        1          n      m(ω^i)
//!   ∑    ----------  =  ∑    ----------                    (2)
//!  i=1   β + f(ω^i)    i=1   β + t(ω^i)
//! ```
//!
//! In the codebase, the multiplicities m_i are called the "lookup counters".
//!
//! The protocol can be generalized to multiple "looked-up" polynomials f_1,
//! ..., f_k (embedded in the structure `LogupWitness` in the codebase) and the
//! equation (2) becomes:
//!
//! ```text
//!   n    k           1          n       m(ω^i)
//!   ∑    ∑     ------------  =  ∑    -----------           (3)
//!  i=1  j=1    β + f_j(ω^i)    i=1    β + t(ω^i)
//! ```
//!
//! which can be rewritten as:
//! ```text
//!   n  (  k         1             m(ω^i)    )
//!   ∑  (  ∑   ------------   - -----------  )  = 0         (4)
//!  i=1 ( j=1  β + f_j(ω^i)      β + t(ω^i)  )
//!      \                                   /
//!       -----------------------------------
//!                "inner sums", h(ω^i)
//! ```
//!
//! The equation says that if we sum/accumulate the "inner sums" (called the
//! "lookup terms" in the codebase) over the
//! subgroup H, we will get a zero value. Note the analogy with the
//! "multiplicative" accumulator used in the lookup argument called
//! ["Plookup"](https://eprint.iacr.org/2020/315.pdf).
//!
//! We will define an accumulator ϕ : H -> F (called the "lookup aggregation" in
//! the codebase) which will contain the "running
//! inner sums" which will be equal to zero to start, and when we finished
//! accumulating, it must equal zero. Note that the initial and final values can
//! be anything. The idea of the equation 4 is that all the values have been
//! read and written to the accumulator the right number of times, with respect
//! to the multiplicities m.
//! More precisely, we will have:
//! ```text
//! - φ(1) = 0
//!                                           h(ω^j)
//!                            /----------------------------------\
//!                           (  k         1             m(ω^j)    )
//! - φ(ω^{j + 1}) = φ(ω^j) + (  ∑   ------------   - -----------  )
//!                           ( i=1  β + f_i(ω^j)      β + t(ω^j)  )
//!
//! - φ(ω^n) = φ(1) = 0
//! ```
//!
//! We will split the inner sums into chunks of size (MAX_SUPPORTED_DEGREE - 2)
//! to avoid having a too large degree for the quotient polynomial.
//! As a reminder, the paper ["Multivariate lookups based on logarithmic
//! derivatives"](https://eprint.iacr.org/2022/1530.pdf) uses the sumcheck
//! protocol to compute the partial sums (equations 16 and 17). However, we use
//! the PlonK polynomial IOP and therefore, we will use the quotient polynomial,
//! and the computation of the partial sums will be translated into a constraint
//! in a new power of alpha.
//!
//! Note that the inner sum h(X) can be constrainted as followed:
//! ```text
//!         k                   k  /             k                \
//! h(X) *  ᴨ  (β + f_{i}(X)) = ∑  | m_{i}(X) *  ᴨ  (β + f_{j}(X)) |     (5)
//!        i=0                 i=0 |            j=0                |
//!                                \            j≠i               /
//! ```
//! (with m_i(X) being the multiplicities for `i = 0` and `-1` otherwise, and
//! f_0(X) being the table t(X)).
//! More than one "inner sum" can be created in the case that `k + 2` is higher
//! than the maximum degree supported.
//! The quotient polynomial, defined at round 3 of the [PlonK
//! protocol](https://eprint.iacr.org/2019/953.pdf), will be something like:
//!
//! ```text
//!         ... + α^i [φ(ω X) - φ(X) - h(X)] + α^(i + 1) (5) + ...
//!  t(X) = ------------------------------------------------------
//!                              Z_H(X)
//! ```
//!
//! `k` can then be seen as the number of lookups we can make per row. The
//! additional cost when we reach the maximum degree supported is to add a new
//! constraint and add a new column.
//! For rows with less than `k` lookups, the prover will add a dummy value,
//! which will be a value known to be in the table, and the multiplicity must be
//! increased appropriately.
//!
//! To handle more than one table, we will use a table ID and transform the
//! single value lookup into a vector lookup, using a random combiner.
//! The protocol can also handle vector lookups, by using the random combiner.
//! The looked-up values therefore become functions f_j: H x H x ... x H -> F
//! and is transformed into a f'_j: H -> F using a random combiner `r`.
//!
//! To summarize, the prover will:
//! - commit to the multiplicities m.
//! - commit to individual looked-up values f (which include the table t) which
//!   should be already included in the PlonK protocol as columns.
//! - coin an evaluation point β.
//! - coin a random combiner j (used to aggregate the table ID and concatenate
//!   vector lookups, if any).
//! - commit to the inner sums/lookup terms h.
//! - commit to the running sum φ.
//! - add constraints to the quotient polynomial.
//! - evaluate all polynomials at the evaluation points ζ and ζω (because we
//!   access the "next" row for the accumulator in the quotient polynomial).
use ark_ff::{Field, PrimeField, Zero};
use kimchi::circuits::{
    berkeley_columns::BerkeleyChallengeTerm,
    expr::{ConstantExpr, ConstantTerm, Expr, ExprInner},
};
use std::{collections::BTreeMap, hash::Hash};

use crate::{
    columns::Column,
    expr::{curr_cell, next_cell, E},
    MAX_SUPPORTED_DEGREE,
};

/// Generic structure to represent a (vector) lookup the table with ID
/// `table_id`.
///
/// The structure represents the individual fraction of the sum described in the
/// Logup protocol (for instance Eq. 8).
///
/// The table ID is added to the random linear combination formed with the
/// values. The combiner for the random linear combination is coined during the
/// proving phase by the prover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logup<F, ID: LookupTableID> {
    pub(crate) table_id: ID,
    pub(crate) numerator: F,
    pub(crate) value: Vec<F>,
}

/// Basic trait for logarithmic lookups.
impl<F, ID> Logup<F, ID>
where
    F: Clone,
    ID: LookupTableID,
{
    /// Creates a new Logup
    pub fn new(table_id: ID, numerator: F, value: &[F]) -> Self {
        Self {
            table_id,
            numerator,
            value: value.to_vec(),
        }
    }
}

/// Trait for lookup table variants
pub trait LookupTableID:
    Send + Sync + Copy + Hash + Eq + PartialEq + Ord + PartialOrd + core::fmt::Debug
{
    /// Assign a unique ID, as a u32 value
    fn to_u32(&self) -> u32;

    /// Build a value from a u32
    fn from_u32(value: u32) -> Self;

    /// Assign a unique ID to the lookup tables.
    fn to_field<F: Field>(&self) -> F {
        F::from(self.to_u32())
    }

    /// Identify fixed and RAMLookups with a boolean.
    /// This can be used to identify the lookups whose table values are fixed,
    /// like range checks.
    fn is_fixed(&self) -> bool;

    /// If a table is runtime table, `true` means we should create an
    /// explicit extra column for it to "read" from. `false` means
    /// that this table will be reading from some existing (e.g.
    /// relation) columns, and no extra columns should be added.
    ///
    /// Panics if the argument is a fixed table.
    fn runtime_create_column(&self) -> bool;

    /// Assign a unique ID to the lookup tables, as an expression.
    fn to_constraint<F: Field>(&self) -> E<F> {
        let f = self.to_field();
        let f = ConstantExpr::from(ConstantTerm::Literal(f));
        E::Atom(ExprInner::Constant(f))
    }

    /// Returns the length of each table.
    fn length(&self) -> usize;

    /// Returns None if the table is runtime (and thus mapping value
    /// -> ix is not known at compile time.
    fn ix_by_value<F: PrimeField>(&self, value: &[F]) -> Option<usize>;

    fn all_variants() -> Vec<Self>;
}

/// A table of values that can be used for a lookup, along with the ID for the table.
#[derive(Debug, Clone)]
pub struct LookupTable<F, ID: LookupTableID> {
    /// Table ID corresponding to this table
    pub table_id: ID,
    /// Vector of values inside each entry of the table
    pub entries: Vec<Vec<F>>,
}

/// Represents a witness of one instance of the lookup argument
// IMPROVEME: Possible to index by a generic const?
// The parameter N is the number of functions/looked-up values per row. It is
// used by the PlonK polynomial IOP to compute the number of partial sums.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogupWitness<F, ID: LookupTableID> {
    /// A list of functions/looked-up values.
    /// Invariant: for fixed lookup tables, the last value of the vector is the
    /// lookup table t. The lookup table values must have a negative sign.
    /// The values are represented as:
    /// [ [f_{1}(1), ..., f_{1}(ω^(n-1)],
    ///   [f_{2}(1), ..., f_{2}(ω^(n-1)]
    ///     ...
    ///   [f_{m}(1), ..., f_{m}(ω^(n-1)]
    /// ]
    //
    // TODO: for efficiency, as we go through columns and after that row, we
    // should reorganize this. While working on the interpreter, we might
    // change this structure.
    //
    // TODO: for efficiency, we might want to have a single flat fixed-size
    // array
    pub f: Vec<Vec<Logup<F, ID>>>,
    /// The multiplicity polynomials; by convention, this is a vector
    /// of columns, corresponding to the `tail` of `f`. That is,
    /// `m[last] ~ f[last]`.
    pub m: Vec<Vec<F>>,
}

/// Represents the proof of the lookup argument
/// It is parametrized by the type `T` which can be either:
/// - `Polycomm<G: KimchiCurve>` for the commitments
/// - `F` for the evaluations at ζ (resp. ζω).
// FIXME: We should have a fixed number of m and h. Should we encode that in
// the type?
#[derive(Debug, Clone)]
pub struct LookupProof<T, ID> {
    /// The multiplicity polynomials
    pub(crate) m: BTreeMap<ID, Vec<T>>,
    /// The polynomial keeping the sum of each row
    pub(crate) h: BTreeMap<ID, Vec<T>>,
    /// The "running-sum" over the rows, coined `φ`
    pub(crate) sum: T,
    /// All fixed lookup tables values, indexed by their ID
    pub(crate) fixed_tables: BTreeMap<ID, T>,
}

/// Iterator implementation to abstract the content of the structure.
/// It can be used to iterate over the commitments (resp. the evaluations)
/// without requiring to have a look at the inner fields.
impl<'lt, G, ID: LookupTableID> IntoIterator for &'lt LookupProof<G, ID> {
    type Item = &'lt G;
    type IntoIter = std::vec::IntoIter<&'lt G>;

    fn into_iter(self) -> Self::IntoIter {
        let mut iter_contents = vec![];
        // First multiplicities
        self.m.values().for_each(|m| iter_contents.extend(m));
        self.h.values().for_each(|h| iter_contents.extend(h));
        iter_contents.push(&self.sum);
        // Fixed tables
        self.fixed_tables
            .values()
            .for_each(|t| iter_contents.push(t));
        iter_contents.into_iter()
    }
}

/// Compute the following constraint:
/// ```text
///                     lhs
///    |------------------------------------------|
///    |                           denominators   |
///    |                         /--------------\ |
/// column * (\prod_{i = 0}^{N} (β + f_{i}(X))) =
/// \sum_{i = 0}^{N} m_{i} * \prod_{j = 1, j \neq i}^{N} (β + f_{j}(X))
///    |             |--------------------------------------------------|
///    |                             Inner part of rhs                  |
///    |                                                                |
///    |                                                               /
///     \                                                             /
///      \                                                           /
///       \---------------------------------------------------------/
///                           rhs
/// ```
/// It is because h(X) (column) is defined as:
/// ```text
///         n      m_i(X)        n         1            m_0(ω^j)
/// h(X) =  ∑    ----------  =   ∑   ------------  -  -----------
///        i=0   β + f_i(X)     i=1  β + f_i(ω^j)      β + t(ω^j)
///```
/// The first form is generic, the second is concrete with f_0 = t; m_0 = m; m_i = 1 for ≠ 1.
/// We will be thinking in the generic form.
///
/// For instance, if N = 2, we have
/// ```text
/// h(X) = m_1(X) / (β + f_1(X)) + m_2(X) / (β + f_{2}(X))
///
///        m_1(X) * (β + f_2(X)) + m_2(X) * (β + f_{1}(X))
///      = ----------------------------------------------
///                  (β + f_2(X)) * (β + f_1(X))
/// ```
/// which is equivalent to
/// ```text
/// h(X) * (β + f_2(X)) * (β + f_1(X)) = m_1(X) * (β + f_2(X)) + m_2(X) * (β + f_{1}(X))
/// ```
/// When we have f_1(X) a looked-up value, t(X) a fixed table and m_2(X) being
/// the multiplicities, we have
/// ```text
/// h(X) * (β + t(X)) * (β + f(X)) = (β + t(X)) + m(X) * (β + f(X))
/// ```
pub fn combine_lookups<F: PrimeField, ID: LookupTableID>(
    column: Column<usize>,
    lookups: Vec<Logup<E<F>, ID>>,
) -> E<F> {
    let joint_combiner = {
        let joint_combiner = ConstantExpr::from(BerkeleyChallengeTerm::JointCombiner);
        E::Atom(ExprInner::Constant(joint_combiner))
    };
    let beta = {
        let beta = ConstantExpr::from(BerkeleyChallengeTerm::Beta);
        E::Atom(ExprInner::Constant(beta))
    };

    // Compute (β + f_{i}(X)) for each i.
    // Note that f_i(X) = table_id + r * x_{1} + r^2 x_{2} + ... r^{N} x_{N}
    let denominators = lookups
        .iter()
        .map(|x| {
            // Compute r * x_{1} + r^2 x_{2} + ... r^{N} x_{N}
            let combined_value = x
                .value
                .iter()
                .rev()
                .fold(E::zero(), |acc, y| acc * joint_combiner.clone() + y.clone())
                * joint_combiner.clone();
            // FIXME: sanity check for the domain, we should consider it in prover.rs.
            // We do only support degree one constraint in the denominator.
            let combined_degree_real = combined_value.degree(1, 0);
            assert!(combined_degree_real <= 1, "Only degree zero and one is supported in the denominator of the lookup because of the maximum degree supported (8); got degree {combined_degree_real}",);
            // add table id + evaluation point
            beta.clone() + combined_value + x.table_id.to_constraint()
        })
        .collect::<Vec<_>>();

    // Compute `column * (\prod_{i = 1}^{N} (β + f_{i}(X)))`
    let lhs = denominators
        .iter()
        .fold(curr_cell(column), |acc, x| acc * x.clone());

    // Compute `\sum_{i = 0}^{N} m_{i} * \prod_{j = 1, j \neq i}^{N} (β + f_{j}(X))`
    let rhs = lookups
        .into_iter()
        .enumerate()
        .map(|(i, x)| {
            denominators.iter().enumerate().fold(
                // Compute individual \sum_{j = 1, j \neq i}^{N} (β + f_{j}(X))
                // This is the inner part of rhs. It multiplies with m_{i}
                x.numerator,
                |acc, (j, y)| {
                    if i == j {
                        acc
                    } else {
                        acc * y.clone()
                    }
                },
            )
        })
        // Individual sums
        .reduce(|x, y| x + y)
        .unwrap_or(E::zero());

    lhs - rhs
}

/// Build the constraints for the lookup protocol.
/// The constraints are the partial sum and the aggregation of the partial sums.
pub fn constraint_lookups<F: PrimeField, ID: LookupTableID>(
    lookup_reads: &BTreeMap<ID, Vec<Vec<E<F>>>>,
    lookup_writes: &BTreeMap<ID, Vec<Vec<E<F>>>>,
) -> Vec<E<F>> {
    let mut constraints: Vec<E<F>> = vec![];
    let mut lookup_terms_cols: Vec<Column<usize>> = vec![];
    lookup_reads.iter().for_each(|(table_id, reads)| {
        let mut idx_partial_sum = 0;
        let table_id_u32 = table_id.to_u32();

        // FIXME: do not clone
        let mut lookups: Vec<_> = reads
            .clone()
            .into_iter()
            .map(|value| Logup {
                table_id: *table_id,
                numerator: Expr::Atom(ExprInner::Constant(ConstantExpr::from(
                    ConstantTerm::Literal(F::one()),
                ))),
                value,
            })
            .collect();

        if table_id.is_fixed() || table_id.runtime_create_column() {
            let table_lookup = Logup {
                table_id: *table_id,
                numerator: -curr_cell(Column::LookupMultiplicity((table_id_u32, 0))),
                value: vec![curr_cell(Column::LookupFixedTable(table_id_u32))],
            };
            lookups.push(table_lookup);
        } else {
            lookup_writes
                .get(table_id)
                .expect("Lookup writes for table_id {table_id:?} not present")
                .iter()
                .enumerate()
                .for_each(|(i, write_columns)| {
                    lookups.push(Logup {
                        table_id: *table_id,
                        numerator: -curr_cell(Column::LookupMultiplicity((table_id_u32, i))),
                        value: write_columns.clone(),
                    });
                });
        }

        // We split in chunks of 6 (MAX_SUPPORTED_DEGREE - 2)
        lookups.chunks(MAX_SUPPORTED_DEGREE - 2).for_each(|chunk| {
            let col = Column::LookupPartialSum((table_id_u32, idx_partial_sum));
            lookup_terms_cols.push(col);
            constraints.push(combine_lookups(col, chunk.to_vec()));
            idx_partial_sum += 1;
        });
    });

    // Generic code over the partial sum
    // Compute φ(ωX) - φ(X) - \sum_{i = 1}^{N} h_i(X)
    {
        let constraint =
            next_cell(Column::LookupAggregation) - curr_cell(Column::LookupAggregation);
        let constraint = lookup_terms_cols
            .into_iter()
            .fold(constraint, |acc, col| acc - curr_cell(col));
        constraints.push(constraint);
    }
    constraints
}

pub mod prover {
    use crate::{
        logup::{Logup, LogupWitness, LookupTableID},
        MAX_SUPPORTED_DEGREE,
    };
    use ark_ff::{FftField, Zero};
    use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
    use kimchi::{circuits::domains::EvaluationDomains, curve::KimchiCurve};
    use mina_poseidon::FqSponge;
    use poly_commitment::{
        commitment::{absorb_commitment, PolyComm},
        OpenProof, SRS as _,
    };
    use rayon::iter::{IntoParallelIterator, ParallelIterator};
    use std::collections::BTreeMap;

    /// The structure used by the prover the compute the quotient polynomial.
    /// The structure contains the evaluations of the inner sums, the
    /// multiplicities, the aggregation and the fixed tables, over the domain d8.
    pub struct QuotientPolynomialEnvironment<'a, F: FftField, ID: LookupTableID> {
        /// The evaluations of the partial sums, over d8.
        pub lookup_terms_evals_d8: &'a BTreeMap<ID, Vec<Evaluations<F, D<F>>>>,
        /// The evaluations of the aggregation, over d8.
        pub lookup_aggregation_evals_d8: &'a Evaluations<F, D<F>>,
        /// The evaluations of the multiplicities, over d8, indexed by the table ID.
        pub lookup_counters_evals_d8: &'a BTreeMap<ID, Vec<Evaluations<F, D<F>>>>,
        /// The evaluations of the fixed tables, over d8, indexed by the table ID.
        pub fixed_tables_evals_d8: &'a BTreeMap<ID, Evaluations<F, D<F>>>,
    }

    /// Represents the environment for the logup argument.
    pub struct Env<G: KimchiCurve, ID: LookupTableID> {
        /// The polynomial of the multiplicities, indexed by the table ID.
        pub lookup_counters_poly_d1: BTreeMap<ID, Vec<DensePolynomial<G::ScalarField>>>,
        /// The commitments to the multiplicities, indexed by the table ID.
        pub lookup_counters_comm_d1: BTreeMap<ID, Vec<PolyComm<G>>>,

        /// The polynomials of the inner sums.
        pub lookup_terms_poly_d1: BTreeMap<ID, Vec<DensePolynomial<G::ScalarField>>>,
        /// The commitments of the inner sums.
        pub lookup_terms_comms_d1: BTreeMap<ID, Vec<PolyComm<G>>>,

        /// The aggregation polynomial.
        pub lookup_aggregation_poly_d1: DensePolynomial<G::ScalarField>,
        /// The commitment to the aggregation polynomial.
        pub lookup_aggregation_comm_d1: PolyComm<G>,

        // Evaluating over d8 for the quotient polynomial
        #[allow(clippy::type_complexity)]
        pub lookup_counters_evals_d8:
            BTreeMap<ID, Vec<Evaluations<G::ScalarField, D<G::ScalarField>>>>,
        #[allow(clippy::type_complexity)]
        pub lookup_terms_evals_d8:
            BTreeMap<ID, Vec<Evaluations<G::ScalarField, D<G::ScalarField>>>>,
        pub lookup_aggregation_evals_d8: Evaluations<G::ScalarField, D<G::ScalarField>>,

        pub fixed_lookup_tables_poly_d1: BTreeMap<ID, DensePolynomial<G::ScalarField>>,
        pub fixed_lookup_tables_comms_d1: BTreeMap<ID, PolyComm<G>>,
        pub fixed_lookup_tables_evals_d8:
            BTreeMap<ID, Evaluations<G::ScalarField, D<G::ScalarField>>>,

        /// The combiner used for vector lookups
        pub joint_combiner: G::ScalarField,

        /// The evaluation point used for the lookup polynomials.
        pub beta: G::ScalarField,
    }

    impl<G: KimchiCurve, ID: LookupTableID> Env<G, ID> {
        /// Create an environment for the prover to create a proof for the Logup protocol.
        /// The protocol does suppose that the individual lookup terms are
        /// committed as part of the columns.
        /// Therefore, the protocol only focus on committing to the "grand
        /// product sum" and the "row-accumulated" values.
        pub fn create<
            OpeningProof: OpenProof<G>,
            Sponge: FqSponge<G::BaseField, G, G::ScalarField>,
        >(
            lookups: BTreeMap<ID, LogupWitness<G::ScalarField, ID>>,
            domain: EvaluationDomains<G::ScalarField>,
            fq_sponge: &mut Sponge,
            srs: &OpeningProof::SRS,
        ) -> Self
        where
            OpeningProof::SRS: Sync,
        {
            // Use parallel iterators where possible.
            // Polynomial m(X)
            // FIXME/IMPROVEME: m(X) is only for fixed table
            let lookup_counters_evals_d1: BTreeMap<
                ID,
                Vec<Evaluations<G::ScalarField, D<G::ScalarField>>>,
            > = {
                lookups
                    .clone()
                    .into_par_iter()
                    .map(|(table_id, logup_witness)| {
                        (
                            table_id,
                            logup_witness.m.into_iter().map(|m|
                                Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                                    m.to_vec(),
                                    domain.d1,
                                )
                            ).collect()
                        )
                    })
                    .collect()
            };

            let lookup_counters_poly_d1: BTreeMap<ID, Vec<DensePolynomial<G::ScalarField>>> =
                (&lookup_counters_evals_d1)
                    .into_par_iter()
                    .map(|(id, evals)| {
                        (*id, evals.iter().map(|e| e.interpolate_by_ref()).collect())
                    })
                    .collect();

            let lookup_counters_evals_d8: BTreeMap<
                ID,
                Vec<Evaluations<G::ScalarField, D<G::ScalarField>>>,
            > = (&lookup_counters_poly_d1)
                .into_par_iter()
                .map(|(id, lookup)| {
                    (
                        *id,
                        lookup
                            .iter()
                            .map(|l| l.evaluate_over_domain_by_ref(domain.d8))
                            .collect(),
                    )
                })
                .collect();

            let lookup_counters_comm_d1: BTreeMap<ID, Vec<PolyComm<G>>> =
                (&lookup_counters_evals_d1)
                    .into_par_iter()
                    .map(|(id, polys)| {
                        (
                            *id,
                            polys
                                .iter()
                                .map(|poly| srs.commit_evaluations_non_hiding(domain.d1, poly))
                                .collect(),
                        )
                    })
                    .collect();

            lookup_counters_comm_d1.values().for_each(|comms| {
                comms
                    .iter()
                    .for_each(|comm| absorb_commitment(fq_sponge, comm))
            });
            // -- end of m(X)

            // -- start computing the row sums h(X)
            // It will be used to compute the running sum in lookup_aggregation
            // Coin a combiner to perform vector lookup.
            // The row sums h are defined as
            // --           n            1                    1
            // h(ω^i) = ∑        -------------------- - --------------
            //            j = 0    (β + f_{j}(ω^i))      (β + t(ω^i))
            let vector_lookup_combiner = fq_sponge.challenge();

            // Coin an evaluation point for the rational functions
            let beta = fq_sponge.challenge();

            //
            // @volhovm TODO make sure this is h_i. It looks like f_i for fixed tables.
            // It is an actual fixed column containing "fixed lookup data".
            //
            // Contain the evalations of the h_i. We divide the looked-up values
            // in chunks of (MAX_SUPPORTED_DEGREE - 2)
            let mut fixed_lookup_tables: BTreeMap<ID, Vec<G::ScalarField>> = BTreeMap::new();

            // @volhovm TODO These are h_i related chunks!
            //
            // We keep the lookup terms in a map, to process them in order in the constraints.
            let mut lookup_terms_map: BTreeMap<ID, Vec<Vec<G::ScalarField>>> = BTreeMap::new();

            // Where are commitments to the last element are made? First "read" columns we don't commit to, right?..

            lookups.into_iter().for_each(|(table_id, logup_witness)| {
                let LogupWitness { f, m: _ } = logup_witness;
                // The number of functions to look up, including the fixed table.
                let n = f.len();
                let n_partial_sums = if n % (MAX_SUPPORTED_DEGREE - 2) == 0 {
                    n / (MAX_SUPPORTED_DEGREE - 2)
                } else {
                    n / (MAX_SUPPORTED_DEGREE - 2) + 1
                };

                let mut partial_sums =
                    vec![
                        Vec::<G::ScalarField>::with_capacity(domain.d1.size as usize);
                        n_partial_sums
                    ];

                // We compute first the denominators of all f_i and t. We gather them in
                // a vector to perform a batch inversion.
                let mut denominators = Vec::with_capacity(n * domain.d1.size as usize);
                // Iterate over the rows
                for j in 0..domain.d1.size {
                    // Iterate over individual columns (i.e. f_i and t)
                    for (i, f_i) in f.iter().enumerate() {
                        let Logup {
                            numerator: _,
                            table_id,
                            value,
                        } = &f_i[j as usize];
                        // Compute x_{1} + r x_{2} + ... r^{N-1} x_{N}
                        // This is what we actually put into the `fixed_lookup_tables`.
                        let combined_value_pow0: G::ScalarField =
                            value.iter().rev().fold(G::ScalarField::zero(), |acc, y| {
                                acc * vector_lookup_combiner + y
                            });
                        // Compute r * x_{1} + r^2 x_{2} + ... r^{N} x_{N}
                        let combined_value: G::ScalarField =
                            combined_value_pow0 * vector_lookup_combiner;
                        // add table id
                        let combined_value = combined_value + table_id.to_field::<G::ScalarField>();

                        // If last element and fixed lookup tables, we keep
                        // the *combined* value of the table.
                        //
                        // Otherwise we're processing a runtime table
                        // with explicit writes, so we don't need to
                        // create any extra columns.
                        if (table_id.is_fixed() || table_id.runtime_create_column()) && i == (n - 1)
                        {
                            fixed_lookup_tables
                                .entry(*table_id)
                                .or_insert_with(Vec::new)
                                .push(combined_value_pow0);
                        }

                        // β + a_{i}
                        let lookup_denominator = beta + combined_value;
                        denominators.push(lookup_denominator);
                    }
                }
                assert!(denominators.len() == n * domain.d1.size as usize);

                // Given a vector {β + a_i}, computes a vector {1/(β + a_i)}
                ark_ff::fields::batch_inversion(&mut denominators);

                // Evals is the sum on the individual columns for each row
                let mut denominator_index = 0;

                // We only need to add the numerator now
                for j in 0..domain.d1.size {
                    let mut partial_sum_idx = 0;
                    let mut row_acc = G::ScalarField::zero();
                    for (i, f_i) in f.iter().enumerate() {
                        let Logup {
                            numerator,
                            table_id: _,
                            value: _,
                        } = &f_i[j as usize];
                        row_acc += *numerator * denominators[denominator_index];
                        denominator_index += 1;
                        // We split in chunks of (MAX_SUPPORTED_DEGREE - 2)
                        // We reset the accumulator for the current partial
                        // sum after keeping it.
                        if (i + 1) % (MAX_SUPPORTED_DEGREE - 2) == 0 {
                            partial_sums[partial_sum_idx].push(row_acc);
                            row_acc = G::ScalarField::zero();
                            partial_sum_idx += 1;
                        }
                    }
                    // Whatever leftover in `row_acc` left in the end of the iteration, we write it into
                    // `partial_sums` too. This is only done in case `n % (MAX_SUPPORTED_DEGREE - 2) != 0`
                    // which means that the similar addition to `partial_sums` a few lines above won't be triggered.
                    // So we have this wrapping up call instead.
                    if n % (MAX_SUPPORTED_DEGREE - 2) != 0 {
                        partial_sums[partial_sum_idx].push(row_acc);
                    }
                }
                lookup_terms_map.insert(table_id, partial_sums);
            });

            // Sanity check to verify that the number of evaluations is correct
            lookup_terms_map.values().for_each(|evals| {
                evals
                    .iter()
                    .for_each(|eval| assert_eq!(eval.len(), domain.d1.size as usize))
            });

            // Sanity check to verify that we have all the evaluations for the fixed lookup tables
            fixed_lookup_tables
                .values()
                .for_each(|evals| assert_eq!(evals.len(), domain.d1.size as usize));

            #[allow(clippy::type_complexity)]
            let lookup_terms_evals_d1: BTreeMap<
                ID,
                Vec<Evaluations<G::ScalarField, D<G::ScalarField>>>,
            > =
                (&lookup_terms_map)
                    .into_par_iter()
                    .map(|(id, lookup_terms)| {
                        let lookup_terms = lookup_terms.into_par_iter().map(|lookup_term| {
                        Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                            lookup_term.to_vec(), domain.d1,
                        )}).collect::<Vec<_>>();
                        (*id, lookup_terms)
                    })
                    .collect();

            let fixed_lookup_tables_evals_d1: BTreeMap<
                ID,
                Evaluations<G::ScalarField, D<G::ScalarField>>,
            > = fixed_lookup_tables
                .into_iter()
                .map(|(id, evals)| {
                    (
                        id,
                        Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                            evals, domain.d1,
                        ),
                    )
                })
                .collect();

            let lookup_terms_poly_d1: BTreeMap<ID, Vec<DensePolynomial<G::ScalarField>>> =
                (&lookup_terms_evals_d1)
                    .into_par_iter()
                    .map(|(id, lookup_terms)| {
                        let lookup_terms: Vec<DensePolynomial<G::ScalarField>> = lookup_terms
                            .into_par_iter()
                            .map(|evals| evals.interpolate_by_ref())
                            .collect();
                        (*id, lookup_terms)
                    })
                    .collect();

            let fixed_lookup_tables_poly_d1: BTreeMap<ID, DensePolynomial<G::ScalarField>> =
                (&fixed_lookup_tables_evals_d1)
                    .into_par_iter()
                    .map(|(id, evals)| (*id, evals.interpolate_by_ref()))
                    .collect();

            #[allow(clippy::type_complexity)]
            let lookup_terms_evals_d8: BTreeMap<
                ID,
                Vec<Evaluations<G::ScalarField, D<G::ScalarField>>>,
            > = (&lookup_terms_poly_d1)
                .into_par_iter()
                .map(|(id, lookup_terms)| {
                    let lookup_terms: Vec<Evaluations<G::ScalarField, D<G::ScalarField>>> =
                        lookup_terms
                            .into_par_iter()
                            .map(|lookup_term| lookup_term.evaluate_over_domain_by_ref(domain.d8))
                            .collect();
                    (*id, lookup_terms)
                })
                .collect();

            let fixed_lookup_tables_evals_d8: BTreeMap<
                ID,
                Evaluations<G::ScalarField, D<G::ScalarField>>,
            > = (&fixed_lookup_tables_poly_d1)
                .into_par_iter()
                .map(|(id, poly)| (*id, poly.evaluate_over_domain_by_ref(domain.d8)))
                .collect();

            let lookup_terms_comms_d1: BTreeMap<ID, Vec<PolyComm<G>>> = lookup_terms_evals_d1
                .iter()
                .map(|(id, lookup_terms)| {
                    let lookup_terms = lookup_terms
                        .into_par_iter()
                        .map(|lookup_term| {
                            srs.commit_evaluations_non_hiding(domain.d1, lookup_term)
                        })
                        .collect();
                    (*id, lookup_terms)
                })
                .collect();

            let fixed_lookup_tables_comms_d1: BTreeMap<ID, PolyComm<G>> =
                (&fixed_lookup_tables_evals_d1)
                    .into_par_iter()
                    .map(|(id, evals)| (*id, srs.commit_evaluations_non_hiding(domain.d1, evals)))
                    .collect();

            lookup_terms_comms_d1.values().for_each(|comms| {
                comms
                    .iter()
                    .for_each(|comm| absorb_commitment(fq_sponge, comm))
            });

            fixed_lookup_tables_comms_d1
                .values()
                .for_each(|comm| absorb_commitment(fq_sponge, comm));
            // -- end computing the row sums h

            // -- start computing the running sum in lookup_aggregation
            // The running sum, φ, is defined recursively over the subgroup as followed:
            // - φ(1) = 0
            // - φ(ω^{j + 1}) = φ(ω^j) + \
            //                         \sum_{i = 1}^{n} (1 / (β + f_i(ω^{j + 1}))) - \
            //                         (m(ω^{j + 1}) / (β + t(ω^{j + 1})))
            // - φ(ω^n) = 0
            let lookup_aggregation_evals_d1 = {
                {
                    for table_id in ID::all_variants().into_iter() {
                        let mut acc = G::ScalarField::zero();
                        for i in 0..domain.d1.size as usize {
                            // φ(1) = 0
                            let lookup_terms = lookup_terms_evals_d1.get(&table_id).unwrap();
                            acc = lookup_terms.iter().fold(acc, |acc, lte| acc + lte[i]);
                        }
                        // Sanity check to verify that the accumulator ends up being zero.
                        assert_eq!(
                            acc,
                            G::ScalarField::zero(),
                            "Logup accumulator for table {table_id:?} must be zero"
                        );
                    }
                }
                let mut evals = Vec::with_capacity(domain.d1.size as usize);
                {
                    let mut acc = G::ScalarField::zero();
                    for i in 0..domain.d1.size as usize {
                        // φ(1) = 0
                        evals.push(acc);
                        lookup_terms_evals_d1.iter().for_each(|(_, lookup_terms)| {
                            acc = lookup_terms.iter().fold(acc, |acc, lte| acc + lte[i]);
                        })
                    }
                    // Sanity check to verify that the accumulator ends up being zero.
                    assert_eq!(
                        acc,
                        G::ScalarField::zero(),
                        "Logup accumulator must be zero"
                    );
                }
                Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                    evals, domain.d1,
                )
            };

            let lookup_aggregation_poly_d1 = lookup_aggregation_evals_d1.interpolate_by_ref();

            let lookup_aggregation_evals_d8 =
                lookup_aggregation_poly_d1.evaluate_over_domain_by_ref(domain.d8);

            let lookup_aggregation_comm_d1 =
                srs.commit_evaluations_non_hiding(domain.d1, &lookup_aggregation_evals_d1);

            absorb_commitment(fq_sponge, &lookup_aggregation_comm_d1);
            Self {
                lookup_counters_poly_d1,
                lookup_counters_comm_d1,

                lookup_terms_poly_d1,
                lookup_terms_comms_d1,

                lookup_aggregation_poly_d1,
                lookup_aggregation_comm_d1,

                lookup_counters_evals_d8,
                lookup_terms_evals_d8,
                lookup_aggregation_evals_d8,

                fixed_lookup_tables_poly_d1,
                fixed_lookup_tables_comms_d1,
                fixed_lookup_tables_evals_d8,

                joint_combiner: vector_lookup_combiner,
                beta,
            }
        }
    }
}
