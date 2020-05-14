use algebra::PrimeField;
use ff_fft::EvaluationDomain;

#[derive(Debug, Clone, Copy)]
pub struct EvaluationDomains<F : PrimeField> {
    pub h: EvaluationDomain<F>,
}

impl<F : PrimeField> EvaluationDomains<F> {
    pub fn create(gates: usize) -> Option<Self> {
        let h = EvaluationDomain::<F>::new(EvaluationDomain::<F>::compute_size_of_domain(gates)?)?;
        Some (EvaluationDomains { h })
    }
}
