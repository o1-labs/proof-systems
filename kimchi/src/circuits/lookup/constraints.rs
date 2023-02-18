use crate::circuits::lookup::lookups::{JointLookup, JointLookupValue, LookupInfo};
use ark_ff::{FftField, Zero};
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain as D};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Number of constraints produced by the argument.
pub const CONSTRAINTS: u32 = 7;

/// The number of random values to append to columns for zero-knowledge.
pub const ZK_ROWS: usize = 3;

/// Pad with zeroes and then add 3 random elements in the last two
/// rows for zero knowledge.
///
/// # Panics
///
/// Will panic if `evaluation` and `domain` length do not meet the requirement.
pub fn zk_patch<R: Rng + ?Sized, F: FftField>(
    mut e: Vec<F>,
    d: D<F>,
    rng: &mut R,
) -> Evaluations<F, D<F>> {
    let n = d.size();
    let k = e.len();
    assert!(k <= n - ZK_ROWS);
    e.extend((0..((n - ZK_ROWS) - k)).map(|_| F::zero()));
    e.extend((0..ZK_ROWS).map(|_| F::rand(rng)));
    Evaluations::<F, D<F>>::from_vec_and_domain(e, d)
}

/// Configuration for the lookup constraint.
/// These values are independent of the choice of lookup values.
// TODO: move to lookup::index
#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound = "F: ark_serialize::CanonicalSerialize + ark_serialize::CanonicalDeserialize")]
pub struct LookupConfiguration<F> {
    /// Information about the specific lookups used
    pub lookup_info: LookupInfo,

    /// A placeholder value that is known to appear in the lookup table.
    /// This is used to pad the lookups to `max_lookups_per_row` when fewer lookups are used in a
    /// particular row, so that we can treat each row uniformly as having the same number of
    /// lookups.
    #[serde_as(as = "JointLookupValue<o1_utils::serialization::SerdeAs>")]
    pub dummy_lookup: JointLookupValue<F>,
}

impl<F: Zero> LookupConfiguration<F> {
    pub fn new(lookup_info: LookupInfo) -> LookupConfiguration<F> {
        // For computational efficiency, we choose the dummy lookup value to be all 0s in table 0.
        let dummy_lookup = JointLookup {
            entry: vec![],
            table_id: F::zero(),
        };

        LookupConfiguration {
            lookup_info,
            dummy_lookup,
        }
    }
}
