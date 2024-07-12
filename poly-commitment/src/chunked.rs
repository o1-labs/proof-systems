use std::ops::AddAssign;

use ark_ec::CurveGroup;
use ark_ff::{Field, Zero};

use crate::{commitment::CommitmentCurve, PolyComm};

impl<C> PolyComm<C>
where
    C: CommitmentCurve,
{
    /// Multiplies each commitment chunk of f with powers of zeta^n
    // TODO(mimoo): better name for this function
    pub fn chunk_commitment(&self, zeta_n: C::ScalarField) -> Self {
        let mut res = C::Group::zero();
        // use Horner's to compute chunk[0] + z^n chunk[1] + z^2n chunk[2] + ...
        // as ( chunk[-1] * z^n + chunk[-2] ) * z^n + chunk[-3]
        // (https://en.wikipedia.org/wiki/Horner%27s_method)
        for chunk in self.elems.iter().rev() {
            res *= zeta_n;
            res.add_assign(chunk);
        }

        PolyComm {
            elems: vec![res.into_affine()],
        }
    }
}

impl<F> PolyComm<F>
where
    F: Field,
{
    /// Multiplies each blinding chunk of f with powers of zeta^n
    // TODO(mimoo): better name for this function
    pub fn chunk_blinding(&self, zeta_n: F) -> F {
        let mut res = F::zero();
        // use Horner's to compute chunk[0] + z^n chunk[1] + z^2n chunk[2] + ...
        // as ( chunk[-1] * z^n + chunk[-2] ) * z^n + chunk[-3]
        // (https://en.wikipedia.org/wiki/Horner%27s_method)
        for chunk in self.elems.iter().rev() {
            res *= zeta_n;
            res += chunk
        }
        res
    }
}
