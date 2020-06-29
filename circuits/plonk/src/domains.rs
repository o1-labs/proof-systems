use algebra::FftField;
use ff_fft::{EvaluationDomain, Radix2EvaluationDomain as Domain};

#[derive(Debug, Clone, Copy)]
pub struct EvaluationDomains<F : FftField>
{
    pub d1: Domain<F>,
    pub d2: Domain<F>,
    pub d3: Domain<F>,
    pub d4: Domain<F>,
    pub dp: Domain<F>,
}

impl<F : FftField> EvaluationDomains<F> {
    pub fn create(n : usize) -> Option<Self>
    {
        let n = Domain::<F>::compute_size_of_domain(n)?;

        // create domains accounting for the blinders
        Some(EvaluationDomains
        {
            d1: Domain::<F>::new(n)?,
            d2: Domain::<F>::new(Domain::<F>::compute_size_of_domain(2*n+4)?)?,
            d3: Domain::<F>::new(Domain::<F>::compute_size_of_domain(3*n+6)?)?,
            d4: Domain::<F>::new(Domain::<F>::compute_size_of_domain(4*n+9)?)?,
            dp: Domain::<F>::new(Domain::<F>::compute_size_of_domain((n+2)*oracle::poseidon::SPONGE_BOX+n)?)?,
        })
    }
}
