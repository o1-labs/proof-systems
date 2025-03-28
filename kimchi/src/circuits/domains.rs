//! This module describes the evaluation domains that can be used by the
//! polynomials.

use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::error::DomainCreationError;

/// The different multiplicaive domain sizes that can be used by the polynomials.
/// We do support up to 8 times the size of the original domain for now.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Domain {
    D1 = 1,
    D2 = 2,
    D4 = 4,
    D8 = 8,
}

#[serde_as]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EvaluationDomains<F: FftField> {
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub d1: Radix2EvaluationDomain<F>, // size n
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub d2: Radix2EvaluationDomain<F>, // size 2n
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub d4: Radix2EvaluationDomain<F>, // size 4n
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub d8: Radix2EvaluationDomain<F>, // size 8n
}

impl<F: FftField> EvaluationDomains<F> {
    /// Creates 4 evaluation domains `d1` (of size `n`), `d2` (of size `2n`),
    /// `d4` (of size `4n`), and `d8` (of size `8n`). If generator of `d8` is
    /// `g`, the generator of `d4` is `g^2`, the generator of `d2` is `g^4`, and
    /// the generator of `d1` is `g^8`.
    pub fn create(n: usize) -> Result<Self, DomainCreationError> {
        let n = Radix2EvaluationDomain::<F>::compute_size_of_domain(n)
            .ok_or(DomainCreationError::DomainSizeFailed(n))?;

        let d1 = Radix2EvaluationDomain::<F>::new(n).ok_or(
            DomainCreationError::DomainConstructionFailed("d1".to_string(), n),
        )?;

        // we also create domains of larger sizes
        // to efficiently operate on polynomials in evaluation form.
        // (in evaluation form, the domain needs to grow as the degree of a
        // polynomial grows)
        let d2 = Radix2EvaluationDomain::<F>::new(2 * n).ok_or(
            DomainCreationError::DomainConstructionFailed("d2".to_string(), 2 * n),
        )?;
        let d4 = Radix2EvaluationDomain::<F>::new(4 * n).ok_or(
            DomainCreationError::DomainConstructionFailed("d4".to_string(), 4 * n),
        )?;
        let d8 = Radix2EvaluationDomain::<F>::new(8 * n).ok_or(
            DomainCreationError::DomainConstructionFailed("d8".to_string(), 8 * n),
        )?;

        // ensure the relationship between the three domains in case the
        // library's behavior changes
        assert_eq!(d2.group_gen.square(), d1.group_gen);
        assert_eq!(d4.group_gen.square(), d2.group_gen);
        assert_eq!(d8.group_gen.square(), d4.group_gen);

        Ok(EvaluationDomains { d1, d2, d4, d8 })
    }
}
