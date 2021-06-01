use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};

#[derive(Debug, Clone, Copy)]
pub struct EvaluationDomains<F : FftField>
{
    pub d1: D<F>, // size n
    pub d4: D<F>, // size 4n
    pub d8: D<F>, // size 8n
}

impl<F : FftField> EvaluationDomains<F> {
    pub fn create(n : usize) -> Option<Self>
    {
        let n = D::<F>::compute_size_of_domain(n)?;

        Some(EvaluationDomains
        {
            d1: D::<F>::new(n)?,
            d4: D::<F>::new(4*n)?,
            d8: D::<F>::new(8*n)?,
        })
    }
}
