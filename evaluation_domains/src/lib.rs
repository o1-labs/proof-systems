use algebra::PrimeField;
use ff_fft::EvaluationDomain;

#[derive(Debug, Clone, Copy)]
pub struct EvaluationDomains<F : PrimeField> {
    pub h: EvaluationDomain<F>,
    pub k: EvaluationDomain<F>,
    pub b: EvaluationDomain<F>,
    pub x: EvaluationDomain<F>,
}

impl<F : PrimeField> EvaluationDomains<F> {
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
            EvaluationDomain::<F>::compute_size_of_domain(public_inputs)?;
        let k_group_size =
            EvaluationDomain::<F>::compute_size_of_domain(nonzero_entries)?;

        let h = EvaluationDomain::<F>::new(h_group_size)?;
        let k = EvaluationDomain::<F>::new(k_group_size)?;
        let b = EvaluationDomain::<F>::new(k_group_size * 3 - 3)?;
        let x = EvaluationDomain::<F>::new(x_group_size)?;

        println!("vars, cons, nons: {}, {}, {}", variables, constraints, nonzero_entries);
        println!("h, k, b, x: {}, {}, {}, {}",
                 h.size(),
                 k.size(),
                 b.size(),
                 x.size());

        Some (EvaluationDomains { h, k, b, x })
    }
}
