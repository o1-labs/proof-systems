//! Implement the protocol MVLookup <https://eprint.iacr.org/2022/1530.pdf>

use ark_ff::Field;
use kimchi::circuits::expr::{ConstantExpr, ConstantTerm, ExprInner};
use std::collections::HashMap;
use std::hash::Hash;

use crate::expr::E;

/// Generic structure to represent a (vector) lookup the table with ID
/// `table_id`.
/// The structure represents the individual fraction of the sum described in the
/// MVLookup protocol (for instance Eq. 8).
/// The table ID is added to the random linear combination formed with the
/// values. The combiner for the random linear combination is coined during the
/// proving phase by the prover.
#[derive(Debug, Clone)]
pub struct MVLookup<F, ID: LookupTableID> {
    pub(crate) table_id: ID,
    pub(crate) numerator: F,
    pub(crate) value: Vec<F>,
}

/// Basic trait for MVLookups
impl<F, ID> MVLookup<F, ID>
where
    F: Clone,
    ID: LookupTableID,
{
    /// Creates a new MVLookup
    pub fn new(table_id: ID, numerator: F, value: &[F]) -> Self {
        Self {
            table_id,
            numerator,
            value: value.to_vec(),
        }
    }
}

/// Trait for lookup table variants
pub trait LookupTableID: Send + Sync + Copy + Hash + Eq + PartialEq {
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

    /// Assign a unique ID to the lookup tables, as an expression.
    fn to_constraint<F: Field>(&self) -> E<F> {
        let f = self.to_field();
        let f = ConstantExpr::from(ConstantTerm::Literal(f));
        E::Atom(ExprInner::Constant(f))
    }

    /// Returns the length of each table.
    fn length(&self) -> usize;
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
/// IMPROVEME: Possible to index by a generic const?
// The parameter N is the number of functions/looked-up values per row. It is
// used by the PlonK polynomial IOP to compute the number of partial sums.
#[derive(Debug)]
pub struct MVLookupWitness<F, ID: LookupTableID> {
    /// A list of functions/looked-up values.
    /// Invariant: for fixed lookup tables, the last value of the vector is the
    /// lookup table t. The lookup table values must have a negative sign.
    /// The values are represented as:
    /// [ [f_{1}(1), ..., f_{1}(\omega^n)],
    ///   [f_{2}(1), ..., f_{2}(\omega^n)]
    ///     ...
    ///   [f_{m}(1), ..., f_{m}(\omega^n)]
    /// ]
    /// TODO: for efficiency, as we go through columns and after that row, we
    /// should reorganize this. While working on the interpreter, we might
    /// change this structure.
    /// TODO: for efficiency, we might want to have a single flat fixed-size
    /// array
    pub(crate) f: Vec<Vec<MVLookup<F, ID>>>,
    /// The multiplicity polynomial
    pub(crate) m: Vec<F>,
}

/// Represents the proof of the lookup argument
/// It is parametrized by the type `T` which can be either:
/// - Polycomm<G: KimchiCurve> for the commitments
/// - F for the evaluations at zeta (resp. zeta omega).
/// FIXME: We should have a fixed number of m and h. Should we encode that in
/// the type?
#[derive(Debug, Clone)]
pub struct LookupProof<T, ID> {
    /// The multiplicity polynomials
    pub(crate) m: Vec<T>,
    /// The polynomial keeping the sum of each row
    pub(crate) h: Vec<T>,
    /// The "running-sum" over the rows, coined `\phi`
    pub(crate) sum: T,
    /// All fixed lookup tables values, indexed by their ID
    pub(crate) fixed_tables: HashMap<ID, T>,
}

/// Iterator implementation to abstract the content of the structure.
/// It can be used to iterate over the commitments (resp. the evaluations)
/// without requiring to have a look at the inner fields.
impl<'lt, G, ID: LookupTableID> IntoIterator for &'lt LookupProof<G, ID> {
    type Item = &'lt G;
    type IntoIter = std::vec::IntoIter<&'lt G>;

    fn into_iter(self) -> Self::IntoIter {
        let mut iter_contents = vec![];
        iter_contents.extend(&self.m);
        iter_contents.extend(&self.h);
        iter_contents.push(&self.sum);
        // We must process it in the same order on
        // the prover and verifier side.
        // We order by IDs as iterating directly over the elements of the
        // hashmap is not deterministic
        {
            let mut ft: Vec<(&ID, &G)> = self.fixed_tables.iter().collect();
            ft.sort_by(|(id1, _), (id2, _)| id1.to_u32().cmp(&id2.to_u32()));
            ft.into_iter()
                .for_each(|(_, elem)| iter_contents.push(elem));
        }
        iter_contents.into_iter()
    }
}

pub mod prover {
    use crate::mvlookup::{LookupTableID, MVLookup, MVLookupWitness};
    use crate::MAX_SUPPORTED_DEGREE;
    use ark_ff::{FftField, Zero};
    use ark_poly::Evaluations;
    use ark_poly::{univariate::DensePolynomial, Radix2EvaluationDomain as D};
    use kimchi::circuits::domains::EvaluationDomains;
    use kimchi::curve::KimchiCurve;
    use mina_poseidon::FqSponge;
    use poly_commitment::commitment::{absorb_commitment, PolyComm};
    use poly_commitment::{OpenProof, SRS as _};
    use rayon::iter::IntoParallelIterator;
    use rayon::iter::ParallelIterator;
    use std::collections::HashMap;

    pub struct QuotientPolynomialEnvironment<'a, F: FftField, ID: LookupTableID> {
        pub lookup_terms_evals_d8: &'a Vec<Evaluations<F, D<F>>>,
        pub lookup_aggregation_evals_d8: &'a Evaluations<F, D<F>>,
        pub lookup_counters_evals_d8: &'a Vec<Evaluations<F, D<F>>>,
        pub fixed_tables_evals_d8: &'a HashMap<ID, Evaluations<F, D<F>>>,
    }

    pub struct Env<G: KimchiCurve, ID: LookupTableID> {
        pub lookup_counters_poly_d1: Vec<DensePolynomial<G::ScalarField>>,
        pub lookup_counters_comm_d1: Vec<PolyComm<G>>,

        pub lookup_terms_poly_d1: Vec<DensePolynomial<G::ScalarField>>,
        pub lookup_terms_comms_d1: Vec<PolyComm<G>>,

        pub lookup_aggregation_poly_d1: DensePolynomial<G::ScalarField>,
        pub lookup_aggregation_comm_d1: PolyComm<G>,

        // Evaluating over d8 for the quotient polynomial
        pub lookup_counters_evals_d8: Vec<Evaluations<G::ScalarField, D<G::ScalarField>>>,
        pub lookup_terms_evals_d8: Vec<Evaluations<G::ScalarField, D<G::ScalarField>>>,
        pub lookup_aggregation_evals_d8: Evaluations<G::ScalarField, D<G::ScalarField>>,

        pub fixed_lookup_tables_poly_d1: HashMap<ID, DensePolynomial<G::ScalarField>>,
        pub fixed_lookup_tables_comms_d1: HashMap<ID, PolyComm<G>>,
        pub fixed_lookup_tables_evals_d8:
            HashMap<ID, Evaluations<G::ScalarField, D<G::ScalarField>>>,

        /// The combiner used for vector lookups
        pub joint_combiner: G::ScalarField,

        /// The evaluation point used for the lookup polynomials.
        pub beta: G::ScalarField,
    }

    impl<G: KimchiCurve, ID: LookupTableID> Env<G, ID> {
        /// Create an environment for the prover to create a proof for the MVLookup protocol.
        /// The protocol does suppose that the individual lookup terms are
        /// committed as part of the columns.
        /// Therefore, the protocol only focus on commiting to the "grand
        /// product sum" and the "row-accumulated" values.
        pub fn create<
            OpeningProof: OpenProof<G>,
            Sponge: FqSponge<G::BaseField, G, G::ScalarField>,
        >(
            lookups: Vec<MVLookupWitness<G::ScalarField, ID>>,
            domain: EvaluationDomains<G::ScalarField>,
            fq_sponge: &mut Sponge,
            srs: &OpeningProof::SRS,
        ) -> Self
        where
            OpeningProof::SRS: Sync,
        {
            // Polynomial m(X)
            let lookup_counters_evals_d1 = (&lookups)
                .into_par_iter()
                .map(|lookup| {
                    Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                        lookup.m.to_vec(),
                        domain.d1,
                    )
                })
                .collect::<Vec<Evaluations<G::ScalarField, D<G::ScalarField>>>>();

            let lookup_counters_poly_d1: Vec<DensePolynomial<G::ScalarField>> =
                (&lookup_counters_evals_d1)
                    .into_par_iter()
                    .map(|evals| evals.interpolate_by_ref())
                    .collect();

            let lookup_counters_evals_d8 = (&lookup_counters_poly_d1)
                .into_par_iter()
                .map(|lookup| lookup.evaluate_over_domain_by_ref(domain.d8))
                .collect::<Vec<Evaluations<G::ScalarField, D<G::ScalarField>>>>();

            let lookup_counters_comm_d1: Vec<PolyComm<G>> = (&lookup_counters_evals_d1)
                .into_par_iter()
                .map(|poly| srs.commit_evaluations_non_hiding(domain.d1, poly))
                .collect();

            lookup_counters_comm_d1
                .iter()
                .for_each(|comm| absorb_commitment(fq_sponge, comm));
            // -- end of m(X)

            // -- start computing the row sums h(X)
            // It will be used to compute the running sum in lookup_aggregation
            // Coin a combiner to perform vector lookup.
            // The row sums h are defined as
            // h(\omega^i) = \sum_{j = 0}^{m} (1/\beta + f_{j}(\omega^i)) - (1 / (\beta + t(\omega^i)))
            let vector_lookup_combiner = fq_sponge.challenge();

            // Coin an evaluation point for the rational functions
            let beta = fq_sponge.challenge();

            // Contain the evalations of the h_i. We divide the looked-up values
            // in chunks of (MAX_SUPPORTED_DEGREE - 2)
            let mut fixed_lookup_tables: HashMap<ID, Vec<G::ScalarField>> = HashMap::new();

            let lookup_terms_evals: Vec<Vec<Vec<G::ScalarField>>> = lookups
                .into_iter()
                .map(|lookup| {
                    let MVLookupWitness { f, m: _ } = lookup;
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
                            let MVLookup {
                                numerator: _,
                                table_id,
                                value,
                            } = &f_i[j as usize];
                            // x + r * y + r^2 * z + ... + r^n table_id
                            let combined_value: G::ScalarField =
                                value.iter().rev().fold(G::ScalarField::zero(), |x, y| {
                                    x * vector_lookup_combiner + y
                                }) * vector_lookup_combiner
                                    + table_id.to_field::<G::ScalarField>();

                            // If last element and fixed lookup tables, we keep
                            // the *combined* value of the table.
                            if i == (n - 1) && table_id.is_fixed() {
                                fixed_lookup_tables
                                    .entry(*table_id)
                                    .or_insert_with(Vec::new)
                                    .push(combined_value);
                            }

                            // beta + a_{i}
                            let lookup_denominator = beta + combined_value;
                            denominators.push(lookup_denominator);
                        }
                    }

                    ark_ff::fields::batch_inversion(&mut denominators);

                    // Evals is the sum on the individual columns for each row
                    let mut denominator_index = 0;

                    // We only need to add the numerator now
                    for j in 0..domain.d1.size {
                        let mut partial_sum_idx = 0;
                        let mut row_acc = G::ScalarField::zero();
                        for f_i in f.iter() {
                            let MVLookup {
                                numerator,
                                table_id: _,
                                value: _,
                            } = &f_i[j as usize];
                            row_acc += *numerator * denominators[denominator_index];
                            denominator_index += 1;
                            // We split in chunks of (MAX_SUPPORTED_DEGREE - 2)
                            // We reset the accumulator for the current partial
                            // sum after keeping it.
                            if denominator_index % (MAX_SUPPORTED_DEGREE - 2) == 0 {
                                partial_sums[partial_sum_idx].push(row_acc);
                                row_acc = G::ScalarField::zero();
                                partial_sum_idx += 1;
                            }
                        }
                        if denominator_index % (MAX_SUPPORTED_DEGREE - 2) != 0 {
                            partial_sums[partial_sum_idx].push(row_acc);
                        }
                    }
                    partial_sums
                })
                .collect::<Vec<_>>();

            let lookup_terms_evals: Vec<Vec<G::ScalarField>> =
                lookup_terms_evals.into_iter().flatten().collect();

            // Sanity check to verify that the number of evaluations is correct
            lookup_terms_evals
                .iter()
                .for_each(|evals| assert_eq!(evals.len(), domain.d1.size as usize));

            // Sanity check to verify that we have all the evaluations for the fixed lookup tables
            fixed_lookup_tables
                .iter()
                .for_each(|(_, evals)| assert_eq!(evals.len(), domain.d1.size as usize));

            let lookup_terms_evals_d1: Vec<Evaluations<G::ScalarField, D<G::ScalarField>>> =
                lookup_terms_evals
                    .into_par_iter()
                    .map(|lte| {
                        Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                            lte, domain.d1,
                        )
                    })
                    .collect::<Vec<_>>();

            let fixed_lookup_tables_evals_d1: HashMap<
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

            let lookup_terms_poly_d1: Vec<DensePolynomial<G::ScalarField>> =
                (&lookup_terms_evals_d1)
                    .into_par_iter()
                    .map(|lte| lte.interpolate_by_ref())
                    .collect::<Vec<_>>();

            let fixed_lookup_tables_poly_d1: HashMap<ID, DensePolynomial<G::ScalarField>> =
                (&fixed_lookup_tables_evals_d1)
                    .into_par_iter()
                    .map(|(id, evals)| (*id, evals.interpolate_by_ref()))
                    .collect();

            let lookup_terms_evals_d8: Vec<Evaluations<G::ScalarField, D<G::ScalarField>>> =
                (&lookup_terms_poly_d1)
                    .into_par_iter()
                    .map(|lte| lte.evaluate_over_domain_by_ref(domain.d8))
                    .collect::<Vec<_>>();

            let fixed_lookup_tables_evals_d8: HashMap<
                ID,
                Evaluations<G::ScalarField, D<G::ScalarField>>,
            > = (&fixed_lookup_tables_poly_d1)
                .into_par_iter()
                .map(|(id, poly)| (*id, poly.evaluate_over_domain_by_ref(domain.d8)))
                .collect();

            let lookup_terms_comms_d1: Vec<PolyComm<G>> = (&lookup_terms_evals_d1)
                .into_par_iter()
                .map(|lte| srs.commit_evaluations_non_hiding(domain.d1, lte))
                .collect::<Vec<_>>();

            let fixed_lookup_tables_comms_d1: HashMap<ID, PolyComm<G>> =
                (&fixed_lookup_tables_evals_d1)
                    .into_par_iter()
                    .map(|(id, evals)| (*id, srs.commit_evaluations_non_hiding(domain.d1, evals)))
                    .collect();

            lookup_terms_comms_d1
                .iter()
                .for_each(|comm| absorb_commitment(fq_sponge, comm));

            // Absorbing fixed tables. We must process it in the same order on
            // the prover and verifier side.
            // We order by IDs as iterating directly over the elements of the
            // hashmap is not deterministic
            {
                let mut comms: Vec<(&ID, &PolyComm<G>)> =
                    fixed_lookup_tables_comms_d1.iter().collect();
                comms.sort_by(|(id1, _), (id2, _)| id1.to_u32().cmp(&id2.to_u32()));
                comms
                    .into_iter()
                    .for_each(|(_, comm)| absorb_commitment(fq_sponge, comm));
            }
            // -- end computing the row sums h

            // -- start computing the running sum in lookup_aggregation
            // The running sum, \phi, is defined recursively over the subgroup as followed:
            // - phi(1) = 0
            // - phi(\omega^{j + 1}) = \phi(\omega^j) + \
            //                         \sum_{i = 1}^{n} (1 / \beta + f_i(\omega^{j + 1})) - \
            //                         (m(\omega^{j + 1}) / beta + t(\omega^{j + 1}))
            // - phi(\omega^n) = 0
            let lookup_aggregation_evals_d1 = {
                let mut evals = Vec::with_capacity(domain.d1.size as usize);
                let mut acc = G::ScalarField::zero();
                for i in 0..domain.d1.size as usize {
                    // phi(1) = 0
                    evals.push(acc);
                    for lte in lookup_terms_evals_d1.iter() {
                        acc += lte[i]
                    }
                }
                // Sanity check to verify that the accumulator ends up being zero.
                // FIXME: This should be removed from runtime, and a constraint
                // should be added. For now, the verifier accepts any proof.
                // This will be fixed when constraints are added.
                assert_eq!(acc, G::ScalarField::zero());
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
