use algebra::FftField;
use ff_fft::{EvaluationDomain, Radix2EvaluationDomain as D};

#[derive(Debug, Clone, Copy)]
pub struct EvaluationDomains<F : FftField>
{
    pub d1: D<F>, // size n
    pub d2: D<F>, // size 4n
    pub d4: D<F>, // size 8n
}

impl<F : FftField> EvaluationDomains<F> {
    pub fn create(n : usize) -> Option<Self>
    {
        let n = D::<F>::compute_size_of_domain(n)?;

        // create domains accounting for the blinders
        Some(EvaluationDomains
        {
            d1: D::<F>::new(n)?,
            d2: D::<F>::new(D::<F>::compute_size_of_domain(2*n+4)?)?,
            d4: D::<F>::new(D::<F>::compute_size_of_domain(4*n+9)?)?,
        })
    }
}
