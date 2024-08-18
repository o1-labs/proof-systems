use num_integer::binomial;

/// Represents a multivariate polynomial of degree `D` in `N` variables.
pub struct MVPoly<const N: usize, const D: usize> {
    pub n: usize,
    pub d: usize,
}

impl<const N: usize, const D: usize> MVPoly<N, D> {
    pub fn new() -> Self {
        MVPoly { n: N, d: D }
    }

    pub fn degree(&self) -> usize {
        self.d
    }

    pub fn variables(&self) -> usize {
        self.n
    }

    pub fn monomials(&self) -> usize {
        binomial(self.n + self.d, self.d)
    }
}

impl<const N: usize, const D: usize> Default for MVPoly<N, D> {
    fn default() -> Self {
        MVPoly::new()
    }
}
