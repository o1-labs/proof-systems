use circuit_construction::{Constants, Cs, Var};

use ark_ff::{BigInteger, FftField, FpParameters, PrimeField};

mod sponge;
mod utils;

use super::MutualContext;

use sponge::ZkSponge;

use utils::{lift, decompose, need_decompose};

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
///                        h1 
///                         ^
///     a, b, c -> H        |
///                |        |
///     a * b = c  |        |
///                \--------/
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
pub(crate) struct Transcript<Fp: FftField + PrimeField, Fr: FftField + PrimeField> {
    fp_pubs: Vec<Var<Fp>>, // public inputs to Fp proof
    fr_pubs: Vec<Var<Fr>>, // public inputs to Fr proof
    fp_vars: Vec<Var<Fp>>, // Fp variables to be hashed (not yet consumed by squeeze)
    fr_vars: Vec<Var<Fr>>, // Fr variables to be hashed (not yet consumed by squeeze)
    sponge: ZkSponge<Fp>,  // Native sponge
    comm: Option<Var<Fp>>, // Commitment to Sponge value (last value squeezed after absorbing)
}

impl<Fp, Fr> Transcript<Fp, Fr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
    pub(crate) fn new<CsFp: Cs<Fp>, CsFr: Cs<Fr>>(
        ctx: &mut MutualContext<Fp, Fr, CsFp, CsFr>,
    ) -> Self {
        Self {
            fp_pubs: vec![],
            fr_pubs: vec![],
            fp_vars: vec![],
            fr_vars: vec![],
            sponge: ZkSponge::new(ctx.fp.constants.clone()),
            comm: None,
        }
    }

    pub(crate) fn absorb_fp(&mut self, var: Var<Fp>) {
        self.fp_vars.push(var);
        self.comm = None;
    }

    pub(crate) fn absorb_fr(&mut self, var: Var<Fr>) {
        self.fr_vars.push(var);
        self.comm = None;
    }

    /// Get an Fp challenge from the verifier
    ///
    /// Yields a variable in the native field containing a challenge.
    pub(crate) fn squeeze<CsFp: Cs<Fp>, CsFr: Cs<Fr>>(
        &mut self,
        ctx: &mut MutualContext<Fp, Fr, CsFp, CsFr>, //
    ) -> Var<Fp> {
        // Defer Fr sponge (and include the digest in the statement)
        //  1. Create a fresh Fr sponge
        //  2. "Consume" Fr elements in the Fr proof system
        //  3. Add the Fr digest to the Fr statmement
        //  4. Add the lifted Fr digest to the Fq statement
        //  5. Consume the lifted Fr digest in to the Fp sponge
        if !self.fr_vars.is_empty() {
            // create fresh "foreign sponge"
            let mut fr_zk_sponge: ZkSponge<Fr> = ZkSponge::new(ctx.fr.constants.clone());

            // absorb all queued Fr variables in the Fr side
            fr_zk_sponge.absorb(&mut ctx.fr.cs, self.fr_vars.iter());

            // compute "foreign" digest
            let fr_digest = fr_zk_sponge.squeeze(&mut ctx.fr.cs);

            // include in public inputs on the Fr side
            self.fr_pubs.push(fr_digest);

            // consume "foreign digest"
            if need_decompose::<Fp, Fr>() {
                // decompose hash
                let hash: Option<[Fp; 2]> = fr_digest.value.map(|h| decompose(h));
                let hash_high = ctx.fp.cs.var(|| hash.unwrap()[0]);
                let hash_low = ctx.fp.cs.var(|| hash.unwrap()[1]);

                // enforce binding with other side:
                // include into the public input
                self.fp_pubs.push(hash_high);
                self.fp_pubs.push(hash_low);

                // add them to the "native stonge"
                self.fp_vars.push(hash_high);
                self.fp_vars.push(hash_low);

                // include into public inputs on Fq-side
                self.fp_pubs.push(hash_high);
                self.fp_pubs.push(hash_low);
            } else {
                // lift hash
                let hash = ctx.fp.cs.var(|| lift(fr_digest.val()));

                // absorb lift
                self.fp_pubs.push(hash);
                self.fp_vars.push(hash);
                self.fp_pubs.push(hash);
            }
        }

        // consume all queued Fp elements
        self.sponge.absorb(&mut ctx.fp.cs, self.fp_vars.iter());

        // reset sponge queues
        self.fp_vars.clear();
        self.fr_vars.clear();

        // Squeeze "native sponge" (Fp)
        let out = self.sponge.squeeze(&mut ctx.fp.cs);
        self.comm = Some(out);
        out
    }

    /// Squeeze a 128-bit (endo-scalar) challenge
    fn squeeze_chal() {}

    // Commits to the current transcripts and
    // flips the fields in the transcript for on the complement side
    fn flip(self) -> Transcript<Fr, Fp> {
        unimplemented!()
    }
}
