use circuit_construction::{Cs, Var, Constants};

use ark_ff::{FftField, PrimeField};

mod sponge;

use sponge::ZkSponge;

/// Defered hash transcript
/// 
/// 
/// # Dealing with Fr elements
/// 
/// A fresh sponge is initialized on the complement side:
/// 
/// The intermediate digest value is then 
/// provided as part of the statement on the current side:
///  
/// Schematically it looks something like this:
/// 
/// ```
/// On current side:
/// 
///   transcript, h1, h2, transcript_new (statement)
///       |       |   |        |
/// m1 -> H       |   |        |
///       |       |   |        |
///       H <-----/   |        |
///       |           |        |
/// c1 <- H (squeeze) |        |
///       |           |        |
/// m2 -> H           |        |
///       |           |        |
///       H <---------/        |
///       |                    |
///       \---------------------
/// 
/// On complement side:
///
///             zero state
///                |
///     a, b, c -> H
///                |
///     a * b = c  |
///                |
///                |
///     
/// 
/// 
/// ```
/// 
/// 
/// Include the final hash state in the statement of the 

/// An efficient transcript hash
/// 
/// 
/// Assumes (for soundness) that there is no ambiguity 
/// in the order between native and foreign field elements
/// 
/// In practice: Fp is always going to be the base field of the Plonk proof,
/// while Fr is the scalar field of the Plonk proof
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

    /// Get an Fp challenge from the verifier
    /// 
    /// Yields a variable in the native field containing a challenge.
    fn squeeze<Cp: Cs<Fp>, Cr: Cs<Fr>>(
        &mut self, 
        cs_fp: &mut Cp,
        cs_fr: &mut Cr
    ) -> Var<Fp> {
        /*
        // "Apply" Fp sponge (to "consume" Fp elements)
        let actual_hash = cs_fp.poseidon(constants, vec![preimage, zero, zero])[0];

        // Defer Fr sponge (and include the digest in the statement)
        //  1. Create a fresh Fr sponge
        //  2. "Consume" Fr elements in the Cr proof system
        //  3. Add the Fr digest to the statmement
        //  4. 
        
        let actual_hash = cs_fq.poseidon(constants, vec![preimage, zero, zero])[0];
        */
        if !self.fr_vars.is_empty() {
            let mut fr_zk_sponge: ZkSponge<Fr> = ZkSponge::new(unimplemented!());
        }


        // Squeeeeze!
        unimplemented!()
    }

    /// Squeeze a 128-bit (endo-scalar) challenge
    fn sqeeze_chal() {

    }

    // Commits to the current transcripts and 
    // flips the fields in the transcript for on the complement side
    fn flip(self) -> Transcript<Fr, Fp> {
        unimplemented!()
    }
}
