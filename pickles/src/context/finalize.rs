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
    ///
    /// Namely it creates circuits that ensure that the public
    /// inputs of the other side are consistent with the values passed.
    /// To do so, it computes **the commitment** to the public inputs of the other side,
    /// based on the public inputs on this side.
    ///
    /// Computes the commitment to Fr's public inputs in the Fp side.
    /// Computes the commitment to Fp's public inputs in the Fr side.
    /// Computes the commitment public input of one proof in the other and vise versa
    pub fn finalize<Gp, Gr>(self)
    where
        Gp: AffineCurve,
        Gp::BaseField: FftField + PrimeField,
        Gr: AffineCurve,
        Gr::BaseField: FftField + PrimeField,
    {
        // compute Fr sides public input:
        // all values passed e.g. if sending Fp element to Fr side and Fr side is smaller,
        // decompose Fp element inside Fp circuit and compute exponentation for the two variables (high_bits, low_bit)
        //
        // convert public Fp public inputs to Scalars for the other curve
        unimplemented!()
    }
}
