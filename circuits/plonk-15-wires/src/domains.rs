use algebra::FftField;
use ff_fft::{EvaluationDomain, Radix2EvaluationDomain as Domain};

#[derive(Debug, Clone, Copy)]
pub struct EvaluationDomains<Field: FftField> {
    pub d1: Domain<Field>, // size n
    pub d4: Domain<Field>, // size 4n
    pub d8: Domain<Field>, // size 8n
}

impl<Field: FftField> EvaluationDomains<Field> {
    pub fn create(n: usize) -> Option<Self> {
        // TODO(mimoo): should we instead panic if any of these return None?
        let n = Domain::<Field>::compute_size_of_domain(n)?;

        Some(EvaluationDomains {
            d1: Domain::<Field>::new(n)?,
            d4: Domain::<Field>::new(4 * n)?,
            d8: Domain::<Field>::new(8 * n)?,
        })
    }
}
