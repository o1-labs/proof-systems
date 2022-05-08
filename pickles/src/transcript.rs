use circuit_construction::{Cs, Var};

use ark_ff::{FftField, PrimeField};

/// An efficient transcript hash
/// 
/// 
/// Assumes (for soundness) that there is no ambiguity 
/// in the order between native and foreign field elements
struct Transcript<Fp: FftField + PrimeField, Fr: FftField + PrimeField> {
    fp_vars: Vec<Var<Fp>>,
    fr_vars: Vec<Var<Fr>>,
    comm: Option<Var<Fp>>, // Commitment to Sponge value (last value squeezed after absorbind)
}

impl<Fp, Fr> Transcript<Fp, Fr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
    fn absorb_fp(&mut self, var: Var<Fp>) {
        self.fp_vars.push(var);
        self.comm = None;
    }

    fn absorb_fr(&mut self, var: Var<Fr>) {
        self.fr_vars.push(var);
        self.comm = None;
    }

    /// Get a challenge from the verifier
    /// 
    /// 
    /// Yields a variable in the native field containing a challenge.
    fn sqeeze<Cp: Cs<Fp>, Cr: Cs<Fr>>(
        &mut self, 
        cs_fp: &mut Cp,
        cs_fr: &mut Cr
    ) -> Var<Fp> {
        // apply Fp sponge

        // defer Fr sponge (witness digest)
        

        // squeeze
        unimplemented!()
    }

    /// Squeeze a 128-bit (endo-scalar) challenge
    fn sqeeze_chal() {

    }

    // Flips the fields in the transcript
    fn flip(self) -> Transcript<Fr, Fp> {
        unimplemented!()
    }
}
