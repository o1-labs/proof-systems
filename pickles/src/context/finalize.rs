use ark_ec::AffineCurve;

use circuit_construction::{Constants, Cs, Var};

use ark_ff::{FftField, PrimeField};

use super::context::InnerContext;

impl<Fp, Fr, CsFp, CsFr> InnerContext<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>,
    CsFr: Cs<Fr>,
{
    /// Consumes the context and adds constrains to enforce
    /// the correct "passing" between the two proofs.
    ///
    /// This method is a bit magical and central to how recursion works.
    /// At a high level, it creates circuits to ensure that the values "passed" between the two proofs are consistent.
    ///
    /// To do so, it computes **the commitment** to the public inputs of the other side,
    /// based on the public inputs on this side.
    pub fn finalize<Gp, Gr>(self, srs: ())
    where
        Gp: AffineCurve,
        Gp::BaseField: FftField + PrimeField,
        Gr: AffineCurve,
        Gr::BaseField: FftField + PrimeField,
    {
        // sanity check
        assert_eq!(
            self.fr.public.len(),
            self.fp.public.len(),
            "public inputs does not have the same length, cannot enforce bit-wise equality"
        );

        // compute commitment to public inputs on the Fr side
        // self.fr.public

        // enforce equality between computed commitment (from above) and
        // public input of the Kimchi proof we are verifying on Fr side
    }
}
