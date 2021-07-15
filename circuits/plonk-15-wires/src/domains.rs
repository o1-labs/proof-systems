use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

#[derive(Debug, Clone, Copy)]
pub struct EvaluationDomains<F: FftField> {
    pub d1: Radix2EvaluationDomain<F>, // size n
    pub d4: Radix2EvaluationDomain<F>, // size 4n
    pub d8: Radix2EvaluationDomain<F>, // size 8n
}

impl<F: FftField> EvaluationDomains<F> {
    pub fn create(n: usize) -> Option<Self> {
        // TODO(mimoo): should we instead panic if any of these return None?
        let n = Radix2EvaluationDomain::<F>::compute_size_of_domain(n)?;

        Some(EvaluationDomains {
            d1: Radix2EvaluationDomain::<F>::new(n)?,
            d4: Radix2EvaluationDomain::<F>::new(4 * n)?,
            d8: Radix2EvaluationDomain::<F>::new(8 * n)?,
        })
    }
}
