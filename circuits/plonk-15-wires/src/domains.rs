use algebra::FftField;
use ff_fft::{EvaluationDomain, Radix2EvaluationDomain as Domain};

#[derive(Debug, Clone, Copy)]
pub struct EvaluationDomains<F: FftField> {
    pub d1: Domain<F>, // size n
    pub d4: Domain<F>, // size 4n
    pub d8: Domain<F>, // size 8n
}

impl<F: FftField> EvaluationDomains<F> {
    pub fn create(n: usize) -> Option<Self> {
        // TODO(mimoo): should we instead panic if any of these return None?
        let n = Domain::<F>::compute_size_of_domain(n)?;

        Some(EvaluationDomains {
            d1: Domain::<F>::new(n)?,
            d4: Domain::<F>::new(4 * n)?,
            d8: Domain::<F>::new(8 * n)?,
        })
    }
}
