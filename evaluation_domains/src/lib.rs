use algebra::FftField;
use ff_fft::{EvaluationDomain, Radix2EvaluationDomain as Domain};

#[derive(Debug, Clone, Copy)]
pub struct EvaluationDomains<F : FftField> {
    pub h: Domain<F>,
    pub k: Domain<F>,
    pub b: Domain<F>,
    pub x: Domain<F>,
}

impl<F : FftField> EvaluationDomains<F> {
    pub fn create(
        variables : usize,
        constraints : usize,
        public_inputs: usize,
        nonzero_entries: usize) -> Option<Self> {

        let h_group_size = {
            let m = if constraints > variables { constraints } else { variables };
            EvaluationDomain::<F>::compute_size_of_domain(m)?
        };
        let x_group_size =
            Domain::<F>::compute_size_of_domain(public_inputs)?;
        let k_group_size =
            Domain::<F>::compute_size_of_domain(nonzero_entries)?;

        let h = EvaluationDomain::<F>::new(h_group_size)?;
        let k = EvaluationDomain::<F>::new(k_group_size)?;
        let b = EvaluationDomain::<F>::new(k_group_size * 3 - 3)?;
        let x = EvaluationDomain::<F>::new(x_group_size)?;

        Some (EvaluationDomains { h, k, b, x })
    }
}
