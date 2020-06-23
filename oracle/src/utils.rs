use algebra::FftField;
use ff_fft::{EvaluationDomain, Evaluations, GeneralEvaluationDomain, Radix2EvaluationDomain as Domain, DensePolynomial};

pub trait Utils<F: FftField> {
    fn scale(&self, elm: F) -> Self;
    fn shiftr(&self, size: usize) -> Self;
    fn eval_polynomial(coeffs: &[F], x: F) -> F;
    fn eval(&self, elm: F, size: usize) -> Vec<F>;
    fn evals_from_coeffs(v : Vec<F>, d : Domain<F>) -> Evaluations<F, GeneralEvaluationDomain<F>>;
    fn multiply(polys: &[&DensePolynomial<F>], domain: Domain<F>) -> Evaluations<F>;
}

impl<F: FftField> Utils<F> for DensePolynomial<F> {
    fn eval_polynomial(coeffs: &[F], x: F) -> F {
        let mut res = F::zero();
        for c in coeffs.iter().rev() {
            res *= &x;
            res += c;
        }
        res
    }

    // This function "scales" (multiplies) polynomaial with a scalar
    // It is implemented to have the desired functionality for DensePolynomial
    fn scale(&self, elm: F) -> Self {
        let mut result = self.clone();
        for coeff in &mut result.coeffs {
            *coeff *= &elm
        }
        result
    }

    fn shiftr(&self, size: usize) -> Self {
        let mut result = vec![F::zero(); size];
        result.extend(self.coeffs.clone());
        DensePolynomial::<F>::from_coefficients_vec(result)
    }

    // This function evaluates polynomial in chunks
    fn eval(&self, elm: F, size: usize) -> Vec<F>
    {
        (0..self.coeffs.len()).step_by(size).map
        (
            |i| Self::from_coefficients_slice
                (&self.coeffs[i..if i+size > self.coeffs.len() {self.coeffs.len()} else {i+size}]).evaluate(elm)
        ).collect()
    }

    fn evals_from_coeffs(v : Vec<F>, d : Domain<F>) -> Evaluations<F, GeneralEvaluationDomain<F>>
    {
        Evaluations::<F>::from_vec_and_domain(v, GeneralEvaluationDomain::Radix2(d))
    }

    // utility function for efficient multiplication of several polys
    fn multiply(polys: &[&DensePolynomial<F>], domain: Domain<F>) -> Evaluations<F>
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
