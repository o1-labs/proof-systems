use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as Domain};

#[derive(Debug, Clone, Copy)]
pub struct EvaluationDomains<F: FftField> {
    pub d1: Domain<F>, // size n
    pub d4: Domain<F>, // size 4n
    pub d8: Domain<F>, // size 8n
}

impl<F: FftField> EvaluationDomains<F> {
    /// Creates 3 evaluation domains `d1` (of size `n`), `d4` (of size `4n`),
    /// and `d8` (of size `8n`). If generator of `d8` is `g`, the generator
    /// of `d4` is `g^2` and the generator of `d1` is `g^8`.
    // TODO(mimoo): should we instead panic/return an error if any of these return None?
    pub fn create(n: usize) -> Option<Self> {
        let n = Domain::<F>::compute_size_of_domain(n)?;

        let d1 = Domain::<F>::new(n)?;
        let d4 = Domain::<F>::new(4 * n)?;
        let d8 = Domain::<F>::new(8 * n)?;

        // ensure the relationship between the three domains in case the library's behavior changes
        assert!(d4.group_gen.pow(&[4]) == d1.group_gen);
        assert!(d8.group_gen.pow(&[2]) == d4.group_gen);

        Some(EvaluationDomains { d1, d4, d8 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    use mina_curves::pasta::fp::Fp;

    #[test]
    #[ignore] // TODO(mimoo): wait for fix upstream (https://github.com/arkworks-rs/algebra/pull/307)
    fn test_create_domain() {
        if let Some(d) = EvaluationDomains::<Fp>::create(usize::MAX) {
            assert!(d.d4.group_gen.pow(&[4]) == d.d1.group_gen);
            assert!(d.d8.group_gen.pow(&[2]) == d.d4.group_gen);
            println!("d8 = {:?}", d.d8.group_gen);
            println!("d8^2 = {:?}", d.d8.group_gen.pow(&[2]));
            println!("d4 = {:?}", d.d4.group_gen);
            println!("d4 = {:?}", d.d4.group_gen.pow(&[4]));
            println!("d1 = {:?}", d.d1.group_gen);
        }
    }
}
