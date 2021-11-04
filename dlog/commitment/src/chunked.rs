use ark_ec::{ProjectiveCurve};
use ark_ff::{Field, Zero};

use crate::commitment::CommitmentCurve;
use crate::PolyComm;

impl<C> PolyComm<C>
where
    C: CommitmentCurve,
{
    /// Multiplies each commitment chunk of f with powers of zeta^n
    /// Note that it ignores the shifted part.
    // TODO(mimoo): better name for this function
    pub fn chunk_commitment(&self, zeta_n: C::ScalarField) -> Self {
        let mut res = C::Projective::zero();
        // use Horner's to compute chunk[0] + z^n chunk[1] + z^2n chunk[2] + ...
        // as ( chunk[-1] * z^n + chunk[-2] ) * z^n + chunk[-3]
        // (https://en.wikipedia.org/wiki/Horner%27s_method)
        for chunk in self.unshifted.iter().rev() {
            res *= zeta_n;
            res.add_assign_mixed(chunk);
        }

        PolyComm {
            unshifted: vec![res.into_affine()],
            shifted: self.shifted,
        }
    }
}

impl<F> PolyComm<F>
where
    F: Field,
{
    /// Multiplies each blinding chunk of f with powers of zeta^n
    /// Note that it ignores the shifted part.
    // TODO(mimoo): better name for this function
    pub fn chunk_blinding(&self, zeta_n: F) -> F {
        let mut res = F::zero();
        // use Horner's to compute chunk[0] + z^n chunk[1] + z^2n chunk[2] + ...
        // as ( chunk[-1] * z^n + chunk[-2] ) * z^n + chunk[-3]
        // (https://en.wikipedia.org/wiki/Horner%27s_method)
        for chunk in self.unshifted.iter().rev() {
            res *= zeta_n;
            res += chunk
        }
        res
    }
}
