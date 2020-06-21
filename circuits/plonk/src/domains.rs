use algebra::FftField;
use ff_fft::{EvaluationDomain, Evaluations, GeneralEvaluationDomain, Radix2EvaluationDomain as Domain, DensePolynomial};

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
            d2: Domain::<F>::new(Domain::<F>::compute_size_of_domain(2*n+2)?)?,
            d3: Domain::<F>::new(Domain::<F>::compute_size_of_domain(3*n+4)?)?,
            d4: Domain::<F>::new(Domain::<F>::compute_size_of_domain(4*n+9)?)?,
            dp: Domain::<F>::new(Domain::<F>::compute_size_of_domain((n+2)*oracle::poseidon::SPONGE_BOX+n)?)?,
        })
    }

    pub fn evals_from_coeffs
    (
        v : Vec<F>,
        d : Domain<F>
    ) -> Evaluations<F, GeneralEvaluationDomain<F>>
    {
        Evaluations::<F>::from_vec_and_domain(v, GeneralEvaluationDomain::Radix2(d))
    }

    // utility function for efficient multiplication of several polys
    pub fn multiply(polys: &[&DensePolynomial<F>], domain: Domain<F>) -> Evaluations<F>
    {
        let evals = polys.iter().map
        (
            |p|
            {
                let mut e = p.evaluate_over_domain_by_ref(domain);
                e.evals.resize(domain.size(), F::zero());
                e
            }
        ).collect::<Vec<_>>();

        Evaluations::<F>::from_vec_and_domain
        (
            (0..domain.size()).map(|i| evals.iter().map(|e| e.evals[i]).fold(F::one(), |x, y| x * &y)).collect::<Vec<_>>(),
            GeneralEvaluationDomain::Radix2(domain)
        )
    }
}
